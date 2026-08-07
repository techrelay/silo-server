package auth

import (
	"context"
	"fmt"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/types/known/structpb"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
	"github.com/Silo-Server/silo-server/internal/models"
)

func TestPluginProvisioningConcurrentFirstLoginDB(t *testing.T) {
	ctx, pool, installationID, suffix := newPluginAuthDBTest(t)
	provider := &PluginProvider{
		config: PluginProviderConfig{
			InstallationID: installationID,
			CapabilityID:   "ldap",
			AutoProvision:  true,
		},
		users:        NewUserRepository(pool),
		identityPool: pool,
	}
	response := &pluginv1.AuthenticateResponse{
		ExternalSubject: "entryuuid:" + suffix,
		DisplayName:     "Concurrent User " + suffix,
		Email:           "concurrent-" + suffix + "@example.invalid",
	}

	start := make(chan struct{})
	results := make(chan *models.User, 2)
	errs := make(chan error, 2)
	var ready sync.WaitGroup
	ready.Add(2)
	for range 2 {
		go func() {
			ready.Done()
			<-start
			user, err := provider.autoProvisionAndLinkUser(ctx, Credentials{Username: response.DisplayName}, response)
			results <- user
			errs <- err
		}()
	}
	ready.Wait()
	close(start)

	users := make([]*models.User, 0, 2)
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatalf("concurrent provisioning error: %v", err)
		}
		user := <-results
		if user == nil {
			t.Fatal("concurrent provisioning returned nil user")
		}
		users = append(users, user)
	}
	if users[0].ID != users[1].ID {
		t.Fatalf("concurrent callers resolved user IDs %d and %d, want one identity", users[0].ID, users[1].ID)
	}

	var identityCount, provisionedUserCount, linkedUserID int
	if err := pool.QueryRow(ctx, `
		SELECT count(*), min(user_id)
		FROM plugin_auth_identities
		WHERE plugin_installation_id = $1 AND external_subject = $2`,
		installationID, response.ExternalSubject,
	).Scan(&identityCount, &linkedUserID); err != nil {
		t.Fatalf("count plugin identities: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE email = $1`, NormalizeEmail(response.Email)).Scan(&provisionedUserCount); err != nil {
		t.Fatalf("count provisioned users: %v", err)
	}
	if identityCount != 1 || provisionedUserCount != 1 {
		t.Fatalf("identity rows = %d, provisioned users = %d; want 1 and 1", identityCount, provisionedUserCount)
	}
	if linkedUserID != users[0].ID {
		t.Fatalf("identity user_id = %d, caller user ID = %d", linkedUserID, users[0].ID)
	}
	if users[0].LocalPasswordLoginEnabled {
		t.Fatal("plugin-provisioned user unexpectedly permits local password login")
	}
	if !slices.Equal(users[0].Permissions, DefaultUserPermissions()) {
		t.Fatalf("plugin-provisioned permissions = %v, want canonical defaults %v", users[0].Permissions, DefaultUserPermissions())
	}

	secondResponse := &pluginv1.AuthenticateResponse{
		ExternalSubject: response.ExternalSubject,
		DisplayName:     "Different User " + suffix,
		Email:           "different-" + suffix + "@example.invalid",
	}
	resolved, err := provider.autoProvisionAndLinkUser(ctx, Credentials{}, secondResponse)
	if err != nil {
		t.Fatalf("resolve existing identity: %v", err)
	}
	if resolved.ID != linkedUserID {
		t.Fatalf("existing identity repointed from user %d to %d", linkedUserID, resolved.ID)
	}
}

func TestPluginManagedRoleSnapshotLifecycleDB(t *testing.T) {
	ctx, pool, installationID, suffix := newPluginAuthDBTest(t)
	groupID := insertPluginAuthAccessGroup(t, ctx, pool, suffix)
	customPermissions := []string{string(PermissionMetadataCuration)}
	users := NewUserRepository(pool)
	user, err := users.Create(ctx, models.CreateUserInput{
		Email:         "role-lifecycle-" + suffix + "@example.invalid",
		Username:      "role-lifecycle-" + suffix,
		Password:      "test-password",
		Role:          "user",
		Permissions:   customPermissions,
		AccessGroupID: &groupID,
	})
	if err != nil {
		t.Fatalf("create role lifecycle user: %v", err)
	}
	externalSubject := "entryuuid:role-lifecycle-" + suffix
	insertPluginAuthIdentity(t, ctx, pool, installationID, externalSubject, user.ID)
	provider := &PluginProvider{
		config:       PluginProviderConfig{InstallationID: installationID, CapabilityID: "ldap", ManagedRoles: true},
		users:        users,
		identityPool: pool,
	}

	promoted, err := provider.synchronizeClaimedRole(ctx, user, managedRoleResponse(t, externalSubject, "admin"))
	if err != nil {
		t.Fatalf("promote managed user: %v", err)
	}
	if promoted.Role != "admin" || promoted.AccessGroupID != nil {
		t.Fatalf("promoted user role = %q, access group = %#v; want admin, nil", promoted.Role, promoted.AccessGroupID)
	}
	snapshot, found, err := provider.loadRoleSnapshot(ctx, externalSubject)
	if err != nil {
		t.Fatalf("load promoted snapshot: %v", err)
	}
	if !found || !slices.Equal(snapshot.Permissions, customPermissions) || snapshot.AccessGroupID == nil || *snapshot.AccessGroupID != groupID {
		t.Fatalf("persisted snapshot = %#v, want permissions %v and group %d", snapshot, customPermissions, groupID)
	}

	demoted, err := provider.synchronizeClaimedRole(ctx, promoted, managedRoleResponse(t, externalSubject, "user"))
	if err != nil {
		t.Fatalf("demote managed user: %v", err)
	}
	if demoted.Role != "user" || !slices.Equal(demoted.Permissions, customPermissions) || demoted.AccessGroupID == nil || *demoted.AccessGroupID != groupID {
		t.Fatalf("demoted user = %#v, want original permissions and access group", demoted)
	}
	if _, found, err := provider.loadRoleSnapshot(ctx, externalSubject); err != nil || found {
		t.Fatalf("snapshot after restoration: found = %v, error = %v; want cleared", found, err)
	}
}

func TestPluginManagedRoleDemotionWithoutSnapshotUsesFallbackDB(t *testing.T) {
	ctx, pool, installationID, suffix := newPluginAuthDBTest(t)
	users := NewUserRepository(pool)
	admin, err := users.Create(ctx, models.CreateUserInput{
		Email:    "role-fallback-" + suffix + "@example.invalid",
		Username: "role-fallback-" + suffix,
		Password: "test-password",
		Role:     "admin",
	})
	if err != nil {
		t.Fatalf("create fallback admin: %v", err)
	}
	externalSubject := "entryuuid:role-fallback-" + suffix
	insertPluginAuthIdentity(t, ctx, pool, installationID, externalSubject, admin.ID)
	provider := &PluginProvider{
		config:       PluginProviderConfig{InstallationID: installationID, CapabilityID: "ldap", ManagedRoles: true},
		users:        users,
		identityPool: pool,
	}

	demoted, err := provider.synchronizeClaimedRole(ctx, admin, managedRoleResponse(t, externalSubject, "user"))
	if err != nil {
		t.Fatalf("demote admin without snapshot: %v", err)
	}
	defaultGroupID, err := users.DefaultAccessGroupID(ctx)
	if err != nil {
		t.Fatalf("load default access group: %v", err)
	}
	if demoted.Role != "user" || !slices.Equal(demoted.Permissions, DefaultUserPermissions()) || !sameOptionalInt64(demoted.AccessGroupID, defaultGroupID) {
		t.Fatalf("fallback-demoted user = %#v, want default permissions and group %#v", demoted, defaultGroupID)
	}
}

func TestPluginMalformedManagedRoleDoesNotModifyDB(t *testing.T) {
	ctx, pool, installationID, suffix := newPluginAuthDBTest(t)
	groupID := insertPluginAuthAccessGroup(t, ctx, pool, suffix)
	permissions := []string{string(PermissionMetadataCuration)}
	users := NewUserRepository(pool)
	user, err := users.Create(ctx, models.CreateUserInput{
		Email:         "role-malformed-" + suffix + "@example.invalid",
		Username:      "role-malformed-" + suffix,
		Password:      "test-password",
		Role:          "user",
		Permissions:   permissions,
		AccessGroupID: &groupID,
	})
	if err != nil {
		t.Fatalf("create malformed-claim user: %v", err)
	}
	externalSubject := "entryuuid:role-malformed-" + suffix
	insertPluginAuthIdentity(t, ctx, pool, installationID, externalSubject, user.ID)
	provider := &PluginProvider{
		config:       PluginProviderConfig{InstallationID: installationID, CapabilityID: "ldap", ManagedRoles: true},
		users:        users,
		identityPool: pool,
	}
	claims, err := structpb.NewStruct(map[string]any{
		pluginRoleManagedClaimKey:  true,
		pluginRoleContractClaimKey: pluginRoleContractV1,
		pluginRoleClaimKey:         "owner",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = provider.synchronizeClaimedRole(ctx, user, &pluginv1.AuthenticateResponse{ExternalSubject: externalSubject, Claims: claims})
	if err == nil {
		t.Fatal("malformed managed-role claim unexpectedly succeeded")
	}
	after, err := users.GetByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("reload malformed-claim user: %v", err)
	}
	if after.Role != user.Role || !slices.Equal(after.Permissions, permissions) || !sameOptionalInt64(after.AccessGroupID, &groupID) {
		t.Fatalf("malformed claim modified user from %#v to %#v", user, after)
	}
	if _, found, err := provider.loadRoleSnapshot(ctx, externalSubject); err != nil || found {
		t.Fatalf("malformed claim snapshot: found = %v, error = %v; want unchanged", found, err)
	}
}

func newPluginAuthDBTest(t *testing.T) (context.Context, *pgxpool.Pool, int, string) {
	t.Helper()
	dsn := os.Getenv("SILO_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("SILO_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect test database: %v", err)
	}
	t.Cleanup(pool.Close)
	for _, requirement := range []struct {
		table  string
		column string
	}{
		{table: "plugin_auth_identities", column: "managed_role_snapshot"},
		{table: "access_groups", column: "is_default"},
	} {
		var exists bool
		if err := pool.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM information_schema.columns
				WHERE table_schema = 'public' AND table_name = $1 AND column_name = $2
			)`, requirement.table, requirement.column).Scan(&exists); err != nil {
			t.Fatalf("check test database schema: %v", err)
		}
		if !exists {
			t.Skipf("test database is missing %s.%s", requirement.table, requirement.column)
		}
	}

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	var installationID int
	if err := pool.QueryRow(ctx, `
		INSERT INTO plugin_installations (plugin_id, version, install_path, enabled)
		VALUES ($1, 'test', $2, true)
		RETURNING id`,
		"plugin-auth-db-test-"+suffix, "/tmp/plugin-auth-db-test-"+suffix,
	).Scan(&installationID); err != nil {
		t.Fatalf("insert plugin installation: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM plugin_installations WHERE id = $1`, installationID)
		_, _ = pool.Exec(ctx, `DELETE FROM users WHERE email LIKE $1`, "%"+suffix+"%")
		_, _ = pool.Exec(ctx, `DELETE FROM access_groups WHERE name = $1`, "Plugin Auth DB Test "+suffix)
	})
	return ctx, pool, installationID, suffix
}

func insertPluginAuthAccessGroup(t *testing.T, ctx context.Context, pool *pgxpool.Pool, suffix string) int64 {
	t.Helper()
	var id int64
	if err := pool.QueryRow(ctx, `INSERT INTO access_groups (name) VALUES ($1) RETURNING id`, "Plugin Auth DB Test "+suffix).Scan(&id); err != nil {
		t.Fatalf("insert plugin auth access group: %v", err)
	}
	return id
}

func insertPluginAuthIdentity(t *testing.T, ctx context.Context, pool *pgxpool.Pool, installationID int, subject string, userID int) {
	t.Helper()
	if _, err := pool.Exec(ctx, `
		INSERT INTO plugin_auth_identities (plugin_installation_id, external_subject, user_id)
		VALUES ($1, $2, $3)`, installationID, subject, userID); err != nil {
		t.Fatalf("insert plugin auth identity: %v", err)
	}
}

func managedRoleResponse(t *testing.T, subject, role string) *pluginv1.AuthenticateResponse {
	t.Helper()
	claims, err := structpb.NewStruct(map[string]any{
		pluginRoleManagedClaimKey:  true,
		pluginRoleContractClaimKey: pluginRoleContractV1,
		pluginRoleClaimKey:         role,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &pluginv1.AuthenticateResponse{ExternalSubject: subject, Claims: claims}
}

func sameOptionalInt64(left, right *int64) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}
