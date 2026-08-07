package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
	"github.com/Silo-Server/silo-server/internal/models"
	"github.com/Silo-Server/silo-server/internal/pluginhost"
	"github.com/Silo-Server/silo-server/internal/plugins"
)

const (
	pluginRoleClaimKey         = "silo_role"
	pluginRoleManagedClaimKey  = "silo_role_managed"
	pluginRoleContractClaimKey = "silo_role_contract"
	pluginRoleContractV1       = "silo.auth.managed-role.v1"
)

type pluginAuthClient interface {
	Authenticate(ctx context.Context, req *pluginv1.AuthenticateRequest) (*pluginv1.AuthenticateResponse, error)
	InitAuthorize(ctx context.Context, req *pluginv1.InitAuthorizeRequest) (*pluginv1.InitAuthorizeResponse, error)
	ExchangeCode(ctx context.Context, req *pluginv1.ExchangeCodeRequest) (*pluginv1.AuthenticateResponse, error)
}

type pluginAuthClientFactory func(ctx context.Context) (pluginAuthClient, error)

type PluginProviderConfig struct {
	InstallationID int
	CapabilityID   string
	DisplayName    string
	AutoProvision  bool
}

type PluginProvider struct {
	config       PluginProviderConfig
	client       pluginAuthClientFactory
	sessions     *SessionRepository
	users        *UserRepository
	identityPool *pgxpool.Pool
}

type pluginRoleSnapshot struct {
	Permissions   []string `json:"permissions"`
	AccessGroupID *int64   `json:"access_group_id"`
}

func NewPluginProviderWithClientFactory(
	config PluginProviderConfig,
	sessions *SessionRepository,
	users *UserRepository,
	pool *pgxpool.Pool,
	clientFactory pluginAuthClientFactory,
) *PluginProvider {
	return &PluginProvider{
		config:       config,
		client:       clientFactory,
		sessions:     sessions,
		users:        users,
		identityPool: pool,
	}
}

func NewPluginProvider(
	config PluginProviderConfig,
	sessions *SessionRepository,
	users *UserRepository,
	pool *pgxpool.Pool,
	resolver interface {
		AuthProviderClient(ctx context.Context, installationID int, capabilityID string) (*pluginhost.AuthProviderClient, error)
	},
) *PluginProvider {
	return NewPluginProviderWithClientFactory(config, sessions, users, pool, func(ctx context.Context) (pluginAuthClient, error) {
		return resolver.AuthProviderClient(ctx, config.InstallationID, config.CapabilityID)
	})
}

func (p *PluginProvider) Authenticate(ctx context.Context, creds Credentials) (*models.User, error) {
	client, err := p.client(ctx)
	if err != nil {
		if errors.Is(err, ErrInvalidCredentials) || errors.Is(err, ErrUserDisabled) {
			return nil, err
		}
		if errors.Is(err, plugins.ErrInstallationDisabled) {
			return nil, ErrInvalidCredentials
		}
		return nil, fmt.Errorf("load plugin auth client: %w", err)
	}

	response, err := client.Authenticate(ctx, &pluginv1.AuthenticateRequest{
		Username: creds.Username,
		Password: creds.Password,
	})
	if err != nil {
		if errors.Is(err, ErrInvalidCredentials) || errors.Is(err, ErrUserDisabled) {
			return nil, err
		}
		return nil, fmt.Errorf("plugin auth authenticate: %w", err)
	}
	if response.GetExternalSubject() == "" {
		return nil, ErrInvalidCredentials
	}

	user, err := p.lookupIdentity(ctx, response.GetExternalSubject())
	if err == nil && user != nil {
		if !user.Enabled {
			return nil, ErrUserDisabled
		}
		return p.synchronizeClaimedRole(ctx, user, response)
	}
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if !p.config.AutoProvision {
		return nil, ErrInvalidCredentials
	}
	return p.autoProvisionAndLinkUser(ctx, creds, response)
}

func (p *PluginProvider) CompleteOAuth(ctx context.Context, response *pluginv1.AuthenticateResponse) (*models.User, error) {
	if response.GetExternalSubject() == "" {
		return nil, ErrInvalidCredentials
	}

	user, err := p.lookupIdentity(ctx, response.GetExternalSubject())
	if err == nil && user != nil {
		if !user.Enabled {
			return nil, ErrUserDisabled
		}
		return p.synchronizeClaimedRole(ctx, user, response)
	}
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if !p.config.AutoProvision {
		return nil, ErrInvalidCredentials
	}
	return p.autoProvisionAndLinkUser(ctx, Credentials{}, response)
}

func (p *PluginProvider) InstallationID() int  { return p.config.InstallationID }
func (p *PluginProvider) CapabilityID() string { return p.config.CapabilityID }

func (p *PluginProvider) OAuthClient(ctx context.Context) (OAuthClient, error) {
	c, err := p.client(ctx)
	if err != nil {
		return nil, err
	}
	return c, nil
}

func (p *PluginProvider) ValidateSession(ctx context.Context, sessionID string) (bool, error) {
	if p.sessions == nil {
		return false, nil
	}
	if _, err := p.client(ctx); err != nil {
		if errors.Is(err, plugins.ErrInstallationDisabled) {
			return false, nil
		}
		return false, fmt.Errorf("load plugin auth client: %w", err)
	}
	return p.sessions.IsValid(ctx, sessionID)
}

func (p *PluginProvider) lookupIdentity(ctx context.Context, externalSubject string) (*models.User, error) {
	if p.identityPool == nil {
		return nil, fmt.Errorf("plugin auth identity store unavailable")
	}
	var userID int
	err := p.identityPool.QueryRow(ctx, `
		SELECT user_id
		FROM plugin_auth_identities
		WHERE plugin_installation_id = $1 AND external_subject = $2
	`, p.config.InstallationID, externalSubject).Scan(&userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("lookup plugin auth identity: %w", err)
	}
	user, err := p.users.GetByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (p *PluginProvider) synchronizeClaimedRole(ctx context.Context, user *models.User, response *pluginv1.AuthenticateResponse) (*models.User, error) {
	desiredRole, present, err := pluginRoleFromResponse(response)
	if err != nil {
		return nil, err
	}
	if !present || user == nil || user.Role == desiredRole {
		return user, nil
	}

	previousRole := user.Role
	var restorePermissions []string
	var restoreAccessGroupID *int64
	if desiredRole == "admin" {
		if err := p.saveRoleSnapshot(ctx, response.GetExternalSubject(), user); err != nil {
			return nil, err
		}
	} else {
		snapshot, found, err := p.loadRoleSnapshot(ctx, response.GetExternalSubject())
		if err != nil {
			return nil, err
		}
		if found {
			restorePermissions = append([]string(nil), snapshot.Permissions...)
			restoreAccessGroupID = snapshot.AccessGroupID
		} else {
			restorePermissions = DefaultUserPermissions()
			restoreAccessGroupID, err = p.users.DefaultAccessGroupID(ctx)
			if err != nil {
				return nil, err
			}
		}
	}

	input, changed := roleSyncUpdateInput(user, desiredRole, restorePermissions, restoreAccessGroupID)
	if !changed {
		return user, nil
	}
	if err := p.users.Update(ctx, user.ID, input); err != nil {
		return nil, fmt.Errorf("synchronize plugin-authenticated user role: %w", err)
	}
	if desiredRole == "user" {
		if err := p.clearRoleSnapshot(ctx, response.GetExternalSubject()); err != nil {
			slog.WarnContext(ctx, "clear plugin role snapshot failed",
				"component", "auth",
				"plugin_installation_id", p.config.InstallationID,
				"capability_id", p.config.CapabilityID,
				"user_id", user.ID,
				"error", err,
			)
		}
	}

	slog.InfoContext(ctx, "synchronized plugin-authenticated user role",
		"component", "auth",
		"plugin_installation_id", p.config.InstallationID,
		"capability_id", p.config.CapabilityID,
		"user_id", user.ID,
		"previous_role", previousRole,
		"new_role", desiredRole,
	)

	updated, err := p.users.GetByID(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("reload plugin-authenticated user after role synchronization: %w", err)
	}
	return updated, nil
}

func pluginRoleFromResponse(response *pluginv1.AuthenticateResponse) (string, bool, error) {
	if response == nil || response.GetClaims() == nil {
		return "", false, nil
	}
	claims := response.GetClaims().AsMap()
	managedRaw, managedExists := claims[pluginRoleManagedClaimKey]
	if !managedExists || managedRaw == nil {
		return "", false, nil
	}
	managed, ok := managedRaw.(bool)
	if !ok {
		return "", false, fmt.Errorf("plugin auth claim %q must be a boolean", pluginRoleManagedClaimKey)
	}
	if !managed {
		return "", false, nil
	}

	contractRaw, exists := claims[pluginRoleContractClaimKey]
	if !exists || contractRaw == nil {
		return "", false, fmt.Errorf("managed plugin role requires claim %q", pluginRoleContractClaimKey)
	}
	contract, ok := contractRaw.(string)
	if !ok {
		return "", false, fmt.Errorf("plugin auth claim %q must be a string", pluginRoleContractClaimKey)
	}
	if strings.TrimSpace(contract) != pluginRoleContractV1 {
		return "", false, fmt.Errorf("plugin auth claim %q contains unsupported contract %q", pluginRoleContractClaimKey, contract)
	}

	raw, exists := claims[pluginRoleClaimKey]
	if !exists || raw == nil {
		return "", false, fmt.Errorf("managed plugin role requires claim %q", pluginRoleClaimKey)
	}
	text, ok := raw.(string)
	if !ok {
		return "", false, fmt.Errorf("plugin auth claim %q must be a string", pluginRoleClaimKey)
	}
	role := strings.ToLower(strings.TrimSpace(text))
	if role != "user" && role != "admin" {
		return "", false, fmt.Errorf("plugin auth claim %q contains unsupported role %q", pluginRoleClaimKey, text)
	}
	return role, true, nil
}

func roleSyncUpdateInput(user *models.User, desiredRole string, restorePermissions []string, restoreAccessGroupID *int64) (models.UpdateUserInput, bool) {
	if user == nil || user.Role == desiredRole {
		return models.UpdateUserInput{}, false
	}
	role := desiredRole
	input := models.UpdateUserInput{Role: &role}
	if desiredRole == "admin" {
		input.AccessGroupIDSet = true
		input.AccessGroupID = nil
		return input, true
	}
	permissions := append([]string(nil), restorePermissions...)
	if restorePermissions == nil {
		permissions = DefaultUserPermissions()
	}
	input.Permissions = &permissions
	input.AccessGroupIDSet = true
	input.AccessGroupID = restoreAccessGroupID
	return input, true
}

func (p *PluginProvider) saveRoleSnapshot(ctx context.Context, externalSubject string, user *models.User) error {
	if p.identityPool == nil || user == nil {
		return fmt.Errorf("plugin auth identity store unavailable for role snapshot")
	}
	snapshot := pluginRoleSnapshot{Permissions: append([]string(nil), user.Permissions...), AccessGroupID: user.AccessGroupID}
	payload, err := json.Marshal(snapshot)
	if err != nil {
		return fmt.Errorf("encode plugin role snapshot: %w", err)
	}
	tag, err := p.identityPool.Exec(ctx, `
		UPDATE plugin_auth_identities
		SET managed_role_snapshot = $3, updated_at = NOW()
		WHERE plugin_installation_id = $1 AND external_subject = $2
	`, p.config.InstallationID, externalSubject, payload)
	if err != nil {
		return fmt.Errorf("save plugin role snapshot: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("save plugin role snapshot: identity not found")
	}
	return nil
}

func (p *PluginProvider) loadRoleSnapshot(ctx context.Context, externalSubject string) (pluginRoleSnapshot, bool, error) {
	if p.identityPool == nil {
		return pluginRoleSnapshot{}, false, fmt.Errorf("plugin auth identity store unavailable for role snapshot")
	}
	var raw []byte
	err := p.identityPool.QueryRow(ctx, `
		SELECT managed_role_snapshot
		FROM plugin_auth_identities
		WHERE plugin_installation_id = $1 AND external_subject = $2
	`, p.config.InstallationID, externalSubject).Scan(&raw)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return pluginRoleSnapshot{}, false, nil
		}
		return pluginRoleSnapshot{}, false, fmt.Errorf("load plugin role snapshot: %w", err)
	}
	if len(raw) == 0 {
		return pluginRoleSnapshot{}, false, nil
	}
	var snapshot pluginRoleSnapshot
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		return pluginRoleSnapshot{}, false, fmt.Errorf("decode plugin role snapshot: %w", err)
	}
	return snapshot, true, nil
}

func (p *PluginProvider) clearRoleSnapshot(ctx context.Context, externalSubject string) error {
	if p.identityPool == nil {
		return nil
	}
	_, err := p.identityPool.Exec(ctx, `
		UPDATE plugin_auth_identities
		SET managed_role_snapshot = NULL, updated_at = NOW()
		WHERE plugin_installation_id = $1 AND external_subject = $2
	`, p.config.InstallationID, externalSubject)
	if err != nil {
		return fmt.Errorf("clear plugin role snapshot: %w", err)
	}
	return nil
}

func randomPluginOnlyPassword() (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return "plugin-only-" + hex.EncodeToString(buf), nil
}

func sanitizeUsername(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.ReplaceAll(value, " ", "_")
	var b strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '_' || r == '-' || r == '.':
			b.WriteRune(r)
		}
	}
	return strings.Trim(b.String(), "_.-")
}
