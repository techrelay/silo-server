# Authentication-provider host extensions

Silo's plugin SDK currently exposes the generic `auth_provider.v1` authentication RPC but does not yet provide typed RPCs or response fields for configuration probes or provider-managed Silo roles. The server therefore treats the conventions below as **versioned host extensions**, not as unversioned magic claim names.

These extensions should move to typed SDK fields/RPCs if the plugin SDK grows first-class equivalents. Until then, changing a contract token is a breaking protocol change and requires a new version.

## Connection-test extension

Contract identifier: `silo.auth.connection-test.v1`

An auth provider opts in through its `auth_provider.v1` capability metadata:

```json
{
  "connection_test": true,
  "connection_test_contract": "silo.auth.connection-test.v1",
  "connection_test_config_keys": ["ldap"],
  "connection_test_ack_claim": "silo_connection_test_ok",
  "connection_test_response_contract_claim": "silo_connection_test_contract"
}
```

`connection_test_config_keys` associates an admin configuration section with the capability that owns its connection test. The host must not choose a different provider merely because it appears earlier in the manifest.

For the v1 extension the host calls `Authenticate` with no user credentials and request metadata:

```json
{
  "connection_test": true,
  "connection_test_contract": "silo.auth.connection-test.v1"
}
```

A successful provider must explicitly acknowledge the probe in its response claims:

```json
{
  "silo_connection_test_ok": true,
  "silo_connection_test_contract": "silo.auth.connection-test.v1"
}
```

When a provider advertises an acknowledgement claim or contract, a nil RPC error alone is not success. Missing, false, or mismatched acknowledgement is rejected.

Legacy providers that only advertise `connection_test=true` remain supported when they are the only unambiguous connection-test capability; that compatibility path does not gain v1 guarantees.

## Managed-role extension

Contract identifier: `silo.auth.managed-role.v1`

A provider advertises its role contract in capability metadata:

```json
{
  "managed_role_contract": "silo.auth.managed-role.v1",
  "role_contract_claim": "silo_role_contract",
  "role_managed_claim": "silo_role_managed",
  "role_claim": "silo_role",
  "role_values": ["user", "admin"]
}
```

A response requests host role management only when all three values are present and valid:

```json
{
  "silo_role_contract": "silo.auth.managed-role.v1",
  "silo_role_managed": true,
  "silo_role": "admin"
}
```

The host ignores a bare `silo_role` claim and ignores `silo_role_managed=false`. If management is requested, the contract must be exactly v1 and the role must be `user` or `admin`; malformed managed-role claims fail authentication rather than silently escalating or guessing.

Authentication plugins are trusted code, but changing a Silo user's administrator role is still an explicit authorization action. The version token and managed marker prevent unrelated application claims from accidentally acquiring host authorization semantics.

## Role-state ownership

The managed-role extension owns the user's **Silo role**, not their pre-existing local authorization customization.

When an existing normal user is promoted to administrator, Silo snapshots the user's permissions and access-group assignment on the plugin identity. Administrator promotion removes the access-group assignment so role-blind group ceilings do not cap the administrator.

When that same identity is later demoted, Silo restores the saved permissions and access-group assignment. Identities that were originally provisioned as administrators, or legacy identities without a snapshot, fall back to the normal default permissions and current default access group on demotion.

Every applied role transition is logged with the plugin installation, capability, user ID, previous role, and new role.

## Provisioning atomicity

First-time plugin account creation and the corresponding `plugin_auth_identities` claim are committed in one PostgreSQL transaction. Concurrent first logins may race for the same external subject, but only the winning identity/user transaction commits; a losing transaction rolls back its user row and returns the already-linked account. This prevents orphan plugin-only accounts and prevents an `UPSERT` from re-pointing an established external identity.

## Security invariants

- Bare or unknown claims do not grant administrator access.
- Managed-role contract mismatches fail closed.
- A connection test targets the capability associated with the submitted configuration key when that mapping is advertised.
- Auth connection tests with an advertised acknowledgement must positively acknowledge the exact contract version.
- Existing metadata-provider connection probes remain supported, but an entirely disabled provider is not reported as a successful probe.
