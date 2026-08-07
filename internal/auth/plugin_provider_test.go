package auth

import (
	"slices"
	"testing"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
	"github.com/Silo-Server/silo-server/internal/models"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestRandomPluginOnlyPasswordFitsBcryptLimit(t *testing.T) {
	password, err := randomPluginOnlyPassword()
	if err != nil {
		t.Fatalf("randomPluginOnlyPassword() error = %v", err)
	}
	if len(password) > 72 {
		t.Fatalf("password length = %d, want <= 72", len(password))
	}
	if _, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost); err != nil {
		t.Fatalf("bcrypt.GenerateFromPassword() error = %v", err)
	}
}

func TestPluginRoleFromResponseRequiresManagedMarkerAndContract(t *testing.T) {
	claims, err := structpb.NewStruct(map[string]any{pluginRoleClaimKey: "ADMIN"})
	if err != nil {
		t.Fatal(err)
	}
	role, present, err := pluginRoleFromResponse(&pluginv1.AuthenticateResponse{Claims: claims})
	if err != nil {
		t.Fatalf("pluginRoleFromResponse() error = %v", err)
	}
	if present || role != "" {
		t.Fatalf("bare role = %q, present = %v; want ignored", role, present)
	}

	claims, err = structpb.NewStruct(map[string]any{
		pluginRoleManagedClaimKey:  true,
		pluginRoleContractClaimKey: pluginRoleContractV1,
		pluginRoleClaimKey:         "ADMIN",
	})
	if err != nil {
		t.Fatal(err)
	}
	role, present, err = pluginRoleFromResponse(&pluginv1.AuthenticateResponse{Claims: claims})
	if err != nil {
		t.Fatalf("pluginRoleFromResponse() error = %v", err)
	}
	if !present || role != "admin" {
		t.Fatalf("managed role = %q, present = %v; want admin, true", role, present)
	}
}

func TestPluginProviderRequiresCapabilityOptInForManagedRoles(t *testing.T) {
	claims, err := structpb.NewStruct(map[string]any{
		pluginRoleManagedClaimKey:  true,
		pluginRoleContractClaimKey: pluginRoleContractV1,
		pluginRoleClaimKey:         "admin",
	})
	if err != nil {
		t.Fatal(err)
	}
	response := &pluginv1.AuthenticateResponse{Claims: claims}

	withoutCapability := &PluginProvider{}
	if role, present, err := withoutCapability.pluginRoleFromResponse(response); err != nil || present || role != "" {
		t.Fatalf("unadvertised role = %q, present = %v, error = %v; want ignored", role, present, err)
	}

	withCapability := &PluginProvider{config: PluginProviderConfig{ManagedRoles: true}}
	role, present, err := withCapability.pluginRoleFromResponse(response)
	if err != nil {
		t.Fatalf("advertised role error = %v", err)
	}
	if !present || role != "admin" {
		t.Fatalf("advertised role = %q, present = %v; want admin, true", role, present)
	}
}

func TestManagedRoleCapabilityEnabledFailsClosed(t *testing.T) {
	tests := []struct {
		name     string
		metadata map[string]any
		want     bool
	}{
		{name: "not advertised", metadata: map[string]any{}},
		{name: "exact v1", metadata: map[string]any{"managed_role_contract": pluginRoleContractV1}, want: true},
		{name: "unsupported", metadata: map[string]any{"managed_role_contract": "silo.auth.managed-role.v2"}},
		{name: "not exact", metadata: map[string]any{"managed_role_contract": " " + pluginRoleContractV1}},
		{name: "malformed", metadata: map[string]any{"managed_role_contract": true}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := ManagedRoleCapabilityEnabled(test.metadata); got != test.want {
				t.Fatalf("ManagedRoleCapabilityEnabled() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestPluginRoleFromResponseRejectsMalformedManagedClaims(t *testing.T) {
	tests := []map[string]any{
		{pluginRoleManagedClaimKey: "true", pluginRoleClaimKey: "admin"},
		{pluginRoleManagedClaimKey: true, pluginRoleClaimKey: "admin"},
		{pluginRoleManagedClaimKey: true, pluginRoleContractClaimKey: "silo.auth.managed-role.v2", pluginRoleClaimKey: "admin"},
		{pluginRoleManagedClaimKey: true, pluginRoleContractClaimKey: " " + pluginRoleContractV1, pluginRoleClaimKey: "admin"},
		{pluginRoleManagedClaimKey: true, pluginRoleContractClaimKey: pluginRoleContractV1},
		{pluginRoleManagedClaimKey: true, pluginRoleContractClaimKey: pluginRoleContractV1, pluginRoleClaimKey: "owner"},
	}
	for _, values := range tests {
		claims, err := structpb.NewStruct(values)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := pluginRoleFromResponse(&pluginv1.AuthenticateResponse{Claims: claims}); err == nil {
			t.Fatalf("expected malformed managed claims to be rejected: %#v", values)
		}
	}
}

func TestPluginRoleFromResponseManagedFalseDoesNotChangeRole(t *testing.T) {
	claims, err := structpb.NewStruct(map[string]any{
		pluginRoleManagedClaimKey: false,
		pluginRoleClaimKey:        "admin",
	})
	if err != nil {
		t.Fatal(err)
	}
	role, present, err := pluginRoleFromResponse(&pluginv1.AuthenticateResponse{Claims: claims})
	if err != nil {
		t.Fatalf("pluginRoleFromResponse() error = %v", err)
	}
	if present || role != "" {
		t.Fatalf("role = %q, present = %v; want ignored", role, present)
	}
}

func TestRoleSyncUpdateInputPromotesAndRestoresDemotedState(t *testing.T) {
	groupID := int64(42)
	user := &models.User{ID: 7, Role: "user", AccessGroupID: &groupID}
	promote, changed := roleSyncUpdateInput(user, "admin", nil, nil)
	if !changed || promote.Role == nil || *promote.Role != "admin" {
		t.Fatalf("promotion input = %#v, changed = %v", promote, changed)
	}
	if !promote.AccessGroupIDSet || promote.AccessGroupID != nil {
		t.Fatalf("promotion must remove the normal access group: %#v", promote)
	}

	customPermissions := []string{"custom:one", "custom:two"}
	admin := &models.User{ID: 7, Role: "admin"}
	demote, changed := roleSyncUpdateInput(admin, "user", customPermissions, &groupID)
	if !changed || demote.Role == nil || *demote.Role != "user" {
		t.Fatalf("demotion input = %#v, changed = %v", demote, changed)
	}
	if demote.Permissions == nil || !slices.Equal(*demote.Permissions, customPermissions) {
		t.Fatalf("demotion permissions = %#v, want snapshot %v", demote.Permissions, customPermissions)
	}
	if !demote.AccessGroupIDSet || demote.AccessGroupID == nil || *demote.AccessGroupID != groupID {
		t.Fatalf("demotion must restore the snapshotted access group: %#v", demote)
	}
}

func TestRoleSyncUpdateInputFallsBackToDefaultPermissions(t *testing.T) {
	admin := &models.User{ID: 7, Role: "admin"}
	demote, changed := roleSyncUpdateInput(admin, "user", nil, nil)
	if !changed {
		t.Fatal("expected demotion update")
	}
	if demote.Permissions == nil || !slices.Equal(*demote.Permissions, DefaultUserPermissions()) {
		t.Fatalf("demotion permissions = %#v, want defaults", demote.Permissions)
	}
}
