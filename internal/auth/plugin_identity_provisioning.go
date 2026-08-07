package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/bcrypt"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
	"github.com/Silo-Server/silo-server/internal/models"
)

// autoProvisionAndLinkUser creates the plugin-only user and claims the
// external identity in one database transaction. A concurrent first login can
// win the identity claim, but the losing transaction rolls its user insert
// back before returning the winner, so no orphan account is committed.
func (p *PluginProvider) autoProvisionAndLinkUser(
	ctx context.Context,
	creds Credentials,
	response *pluginv1.AuthenticateResponse,
) (*models.User, error) {
	if p.identityPool == nil {
		return nil, fmt.Errorf("plugin auth identity store unavailable")
	}

	usernameBase := strings.TrimSpace(response.GetDisplayName())
	if usernameBase == "" {
		usernameBase = strings.TrimSpace(creds.Username)
	}
	if usernameBase == "" {
		usernameBase = response.GetExternalSubject()
	}
	usernameBase = sanitizeUsername(usernameBase)
	if usernameBase == "" {
		usernameBase = fmt.Sprintf("plugin_%d", p.config.InstallationID)
	}

	email := strings.TrimSpace(response.GetEmail())
	if email == "" {
		email = fmt.Sprintf("%s@plugin-%d.local", usernameBase, p.config.InstallationID)
	}

	role := "user"
	claimedRole, hasClaimedRole, err := pluginRoleFromResponse(response)
	if err != nil {
		return nil, err
	}
	if hasClaimedRole {
		role = claimedRole
	}

	password, err := randomPluginOnlyPassword()
	if err != nil {
		return nil, fmt.Errorf("generate plugin-only password: %w", err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("hash plugin-only password: %w", err)
	}

	permissions := []string(nil)
	if role != "admin" {
		permissions = DefaultUserPermissions()
	}
	permissions, err = NormalizePermissions(permissions)
	if err != nil {
		return nil, err
	}

	username := usernameBase
	for attempt := 0; attempt < 10; attempt++ {
		if existing, lookupErr := p.lookupIdentity(ctx, response.GetExternalSubject()); lookupErr == nil && existing != nil {
			if !existing.Enabled {
				return nil, ErrUserDisabled
			}
			return p.synchronizeClaimedRole(ctx, existing, response)
		} else if lookupErr != nil && !errors.Is(lookupErr, ErrNotFound) {
			return nil, lookupErr
		}

		tx, err := p.identityPool.Begin(ctx)
		if err != nil {
			return nil, fmt.Errorf("begin plugin account provisioning: %w", err)
		}

		user, createErr := createPluginUserTx(ctx, tx, pluginUserCreateInput{
			Email:        email,
			Username:     username,
			PasswordHash: string(hash),
			Role:         role,
			Permissions:  permissions,
		})
		if createErr != nil {
			_ = tx.Rollback(ctx)
			if !IsDuplicate(createErr) {
				return nil, fmt.Errorf("auto-provision plugin user: %w", createErr)
			}
			if existing, lookupErr := p.lookupIdentity(ctx, response.GetExternalSubject()); lookupErr == nil && existing != nil {
				if !existing.Enabled {
					return nil, ErrUserDisabled
				}
				return p.synchronizeClaimedRole(ctx, existing, response)
			}
			username = fmt.Sprintf("%s_%d", usernameBase, attempt+2)
			continue
		}

		var claimedUserID int
		claimErr := tx.QueryRow(ctx, `
			INSERT INTO plugin_auth_identities (plugin_installation_id, external_subject, user_id)
			VALUES ($1, $2, $3)
			ON CONFLICT (plugin_installation_id, external_subject) DO NOTHING
			RETURNING user_id
		`, p.config.InstallationID, response.GetExternalSubject(), user.ID).Scan(&claimedUserID)
		if claimErr != nil {
			_ = tx.Rollback(ctx)
			if errors.Is(claimErr, pgx.ErrNoRows) {
				existing, lookupErr := p.lookupIdentity(ctx, response.GetExternalSubject())
				if lookupErr != nil {
					return nil, fmt.Errorf("load concurrently provisioned plugin identity: %w", lookupErr)
				}
				if !existing.Enabled {
					return nil, ErrUserDisabled
				}
				return p.synchronizeClaimedRole(ctx, existing, response)
			}
			return nil, fmt.Errorf("claim plugin auth identity: %w", claimErr)
		}
		if claimedUserID != user.ID {
			_ = tx.Rollback(ctx)
			return nil, fmt.Errorf("plugin auth identity claim returned unexpected user %d", claimedUserID)
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, fmt.Errorf("commit plugin account provisioning: %w", err)
		}
		return user, nil
	}

	return nil, fmt.Errorf("auto-provision plugin user: exhausted username attempts")
}

type pluginUserCreateInput struct {
	Email        string
	Username     string
	PasswordHash string
	Role         string
	Permissions  []string
}

func createPluginUserTx(ctx context.Context, tx pgx.Tx, input pluginUserCreateInput) (*models.User, error) {
	query := `
		INSERT INTO users (
			email, username, password_hash, local_password_login_enabled,
			role, permissions, library_ids, max_playback_quality, access_group_id
		)
		VALUES ($1, $2, $3, FALSE, $4, $5, $6, $7,
			CASE WHEN $4 = 'admin' THEN NULL ELSE (SELECT id FROM access_groups WHERE is_default) END
		)
		RETURNING ` + allColumns

	user, err := scanUser(tx.QueryRow(ctx, query,
		NormalizeEmail(input.Email),
		NormalizeUsername(input.Username),
		input.PasswordHash,
		input.Role,
		input.Permissions,
		[]int(nil),
		"",
	))
	if err != nil {
		if isDuplicateKeyError(err) {
			return nil, fmt.Errorf("%w: %s", ErrDuplicate, extractConstraint(err))
		}
		return nil, err
	}
	return user, nil
}
