package plugins

import (
	"errors"
	"testing"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestPluginConnectionCheckCapabilityUsesAdvertisedAuthProvider(t *testing.T) {
	metadata, err := structpb.NewStruct(map[string]any{
		connectionTestEnabledMetadataKey:    true,
		connectionTestContractMetadataKey:   "silo.auth.connection-test.v1",
		connectionTestConfigKeysMetadataKey: []any{"ldap"},
	})
	if err != nil {
		t.Fatal(err)
	}
	manifest := &pluginv1.PluginManifest{Capabilities: []*pluginv1.CapabilityDescriptor{
		{
			Type:     "auth_provider.v1",
			Id:       "ldap",
			Metadata: metadata,
		},
	}}

	capability, err := pluginConnectionCheckCapabilityForManifest(manifest, "ldap")
	if err != nil {
		t.Fatalf("pluginConnectionCheckCapabilityForManifest returned an error: %v", err)
	}
	if capability.kind != connectionCheckKindAuth || capability.id != "ldap" {
		t.Fatalf("capability = %#v, want auth provider ldap", capability)
	}
	if capability.contract != "silo.auth.connection-test.v1" {
		t.Fatalf("contract = %q", capability.contract)
	}
}

func TestPluginConnectionCheckCapabilityPreservesUnsupportedContract(t *testing.T) {
	metadata, err := structpb.NewStruct(map[string]any{
		connectionTestEnabledMetadataKey:    true,
		connectionTestContractMetadataKey:   " " + connectionTestContractV1,
		connectionTestConfigKeysMetadataKey: []any{"ldap"},
	})
	if err != nil {
		t.Fatal(err)
	}
	manifest := &pluginv1.PluginManifest{Capabilities: []*pluginv1.CapabilityDescriptor{{
		Type: "auth_provider.v1", Id: "ldap", Metadata: metadata,
	}}}
	capability, err := pluginConnectionCheckCapabilityForManifest(manifest, "ldap")
	if err != nil {
		t.Fatalf("select auth capability: %v", err)
	}
	if capability.contract == connectionTestContractV1 {
		t.Fatalf("malformed contract normalized to supported v1: %q", capability.contract)
	}
}

func TestAuthProviderConnectionTestRequiresFixedV1ResponseClaims(t *testing.T) {
	claims, err := structpb.NewStruct(map[string]any{
		connectionTestAckClaimKey:              true,
		connectionTestResponseContractClaimKey: connectionTestContractV1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := validateAuthProviderConnectionTestResponse(&pluginv1.AuthenticateResponse{Claims: claims}); err != nil {
		t.Fatalf("valid fixed response claims rejected: %v", err)
	}

	claims, err = structpb.NewStruct(map[string]any{
		"custom_ack":                           true,
		connectionTestResponseContractClaimKey: connectionTestContractV1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := validateAuthProviderConnectionTestResponse(&pluginv1.AuthenticateResponse{Claims: claims}); !errors.Is(err, ErrConnectionTestUnsupported) {
		t.Fatalf("custom acknowledgement error = %v, want ErrConnectionTestUnsupported", err)
	}

	claims, err = structpb.NewStruct(map[string]any{
		connectionTestAckClaimKey:              true,
		connectionTestResponseContractClaimKey: "silo.auth.connection-test.v2",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := validateAuthProviderConnectionTestResponse(&pluginv1.AuthenticateResponse{Claims: claims}); !errors.Is(err, ErrConnectionTestUnsupported) {
		t.Fatalf("unsupported response contract error = %v, want ErrConnectionTestUnsupported", err)
	}
}

func TestPluginConnectionCheckCapabilityRejectsUnadvertisedAuthProvider(t *testing.T) {
	manifest := &pluginv1.PluginManifest{Capabilities: []*pluginv1.CapabilityDescriptor{
		{
			Type: "auth_provider.v1",
			Id:   "legacy-auth",
		},
	}}

	_, err := pluginConnectionCheckCapabilityForManifest(manifest, "auth")
	if !errors.Is(err, ErrConnectionTestUnsupported) {
		t.Fatalf("error = %v, want ErrConnectionTestUnsupported", err)
	}
}

func TestPluginConnectionCheckCapabilityRejectsDisabledAuthProbe(t *testing.T) {
	metadata, err := structpb.NewStruct(map[string]any{connectionTestEnabledMetadataKey: false})
	if err != nil {
		t.Fatal(err)
	}
	manifest := &pluginv1.PluginManifest{Capabilities: []*pluginv1.CapabilityDescriptor{
		{
			Type:     "auth_provider.v1",
			Id:       "disabled-auth",
			Metadata: metadata,
		},
	}}

	_, err = pluginConnectionCheckCapabilityForManifest(manifest, "auth")
	if !errors.Is(err, ErrConnectionTestUnsupported) {
		t.Fatalf("error = %v, want ErrConnectionTestUnsupported", err)
	}
}

func TestPluginConnectionCheckCapabilityTargetsConfigKey(t *testing.T) {
	authMetadata, err := structpb.NewStruct(map[string]any{
		connectionTestEnabledMetadataKey:    true,
		connectionTestConfigKeysMetadataKey: []any{"ldap"},
	})
	if err != nil {
		t.Fatal(err)
	}
	metadataMetadata, err := structpb.NewStruct(map[string]any{
		connectionTestConfigKeysMetadataKey: []any{"metadata"},
	})
	if err != nil {
		t.Fatal(err)
	}
	manifest := &pluginv1.PluginManifest{Capabilities: []*pluginv1.CapabilityDescriptor{
		{
			Type:     "auth_provider.v1",
			Id:       "ldap",
			Metadata: authMetadata,
		},
		{
			Type:     "metadata_provider.v1",
			Id:       "metadata",
			Metadata: metadataMetadata,
		},
	}}

	capability, err := pluginConnectionCheckCapabilityForManifest(manifest, "ldap")
	if err != nil {
		t.Fatalf("pluginConnectionCheckCapabilityForManifest returned an error: %v", err)
	}
	if capability.kind != connectionCheckKindAuth || capability.id != "ldap" {
		t.Fatalf("capability = %#v, want auth provider ldap", capability)
	}

	capability, err = pluginConnectionCheckCapabilityForManifest(manifest, "metadata")
	if err != nil {
		t.Fatalf("metadata selection returned an error: %v", err)
	}
	if capability.kind != connectionCheckKindMetadata || capability.id != "metadata" {
		t.Fatalf("capability = %#v, want metadata provider", capability)
	}
}

func TestPluginConnectionCheckCapabilityRejectsAmbiguousUnmappedCapabilities(t *testing.T) {
	authMetadata, err := structpb.NewStruct(map[string]any{connectionTestEnabledMetadataKey: true})
	if err != nil {
		t.Fatal(err)
	}
	manifest := &pluginv1.PluginManifest{Capabilities: []*pluginv1.CapabilityDescriptor{
		{Type: "auth_provider.v1", Id: "auth", Metadata: authMetadata},
		{Type: "metadata_provider.v1", Id: "metadata"},
	}}
	_, err = pluginConnectionCheckCapabilityForManifest(manifest, "ldap")
	if !errors.Is(err, ErrConnectionTestUnsupported) {
		t.Fatalf("error = %v, want ambiguity to be unsupported", err)
	}
}

func TestMetadataProviderConnectionProbeTypeRejectsAllDisabled(t *testing.T) {
	metadata, err := structpb.NewStruct(map[string]any{
		"default_priority": map[string]any{"movie": 0, "series": 0},
	})
	if err != nil {
		t.Fatal(err)
	}
	capability := &pluginv1.CapabilityDescriptor{Type: "metadata_provider.v1", Id: "metadata", Metadata: metadata}
	if probeType, ok := metadataProviderConnectionProbeType(capability); ok || probeType != "" {
		t.Fatalf("probe type = %q, ok = %v; want disabled", probeType, ok)
	}
}
