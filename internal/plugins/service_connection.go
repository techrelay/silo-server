package plugins

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/structpb"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
	"github.com/Silo-Server/silo-server/internal/pluginhost"
)

var ErrConnectionTestUnsupported = errors.New("plugin connection test unsupported")

const (
	connectionTestEnabledMetadataKey       = "connection_test"
	connectionTestContractMetadataKey      = "connection_test_contract"
	connectionTestConfigKeysMetadataKey    = "connection_test_config_keys"
	connectionTestAckClaimMetadataKey      = "connection_test_ack_claim"
	connectionTestResponseContractClaimKey = "silo_connection_test_contract"
	connectionTestContractV1               = "silo.auth.connection-test.v1"
)

type ConnectionTestError struct {
	Message string
	Cause   error
}

func (e *ConnectionTestError) Error() string {
	if e == nil {
		return ""
	}
	return e.Message
}

func (e *ConnectionTestError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

type pluginConnectionCheckCapability struct {
	kind       string
	id         string
	configKeys []string
	ackClaim   string
	contract   string
}

const (
	connectionCheckKindMetadata = "metadata_provider"
	connectionCheckKindAuth     = "auth_provider"
)

var runPluginConnectionCheck = func(
	ctx context.Context,
	client pluginClient,
	manifest *pluginv1.PluginManifest,
	configKey string,
) error {
	capability, err := pluginConnectionCheckCapabilityForManifest(manifest, configKey)
	if err != nil {
		return err
	}

	switch capability.kind {
	case connectionCheckKindMetadata:
		return runMetadataProviderConnectionCheck(ctx, client, manifest, capability.id)
	case connectionCheckKindAuth:
		return runAuthProviderConnectionCheck(ctx, client, capability.id, capability.ackClaim, capability.contract)
	default:
		return &ConnectionTestError{
			Message: "Connection checks are not supported for this plugin yet.",
			Cause:   ErrConnectionTestUnsupported,
		}
	}
}

func runMetadataProviderConnectionCheck(
	ctx context.Context,
	client pluginClient,
	manifest *pluginv1.PluginManifest,
	capabilityID string,
) error {
	capability := metadataProviderConnectionCheckCapability(manifest, capabilityID)
	probeType, ok := metadataProviderConnectionProbeType(capability)
	if !ok {
		return &ConnectionTestError{
			Message: "The metadata provider does not advertise any enabled content type that can be probed.",
			Cause:   ErrConnectionTestUnsupported,
		}
	}

	metadataClient, err := client.MetadataProvider(capabilityID)
	if err != nil {
		return &ConnectionTestError{
			Message: fmt.Sprintf("Failed to initialize the metadata provider: %v", err),
			Cause:   err,
		}
	}

	probeCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	if _, err := metadataClient.Search(probeCtx, &pluginv1.SearchMetadataRequest{
		Query:    "The Matrix",
		ItemType: probeType,
		Year:     1999,
		Language: "en",
	}); err != nil {
		return &ConnectionTestError{
			Message: fmt.Sprintf("Connection check failed: %v", err),
			Cause:   err,
		}
	}

	return nil
}

func runAuthProviderConnectionCheck(
	ctx context.Context,
	client pluginClient,
	capabilityID string,
	ackClaim string,
	contract string,
) error {
	if strings.TrimSpace(contract) != connectionTestContractV1 || strings.TrimSpace(ackClaim) == "" {
		return &ConnectionTestError{
			Message: "The authentication provider does not advertise a supported connection-check contract.",
			Cause:   ErrConnectionTestUnsupported,
		}
	}

	authClient, err := client.AuthProvider(capabilityID)
	if err != nil {
		return &ConnectionTestError{
			Message: fmt.Sprintf("Failed to initialize the authentication provider: %v", err),
			Cause:   err,
		}
	}

	metadata, err := structpb.NewStruct(map[string]any{
		connectionTestEnabledMetadataKey:  true,
		connectionTestContractMetadataKey: connectionTestContractV1,
	})
	if err != nil {
		return &ConnectionTestError{
			Message: "Failed to prepare the authentication-provider connection check.",
			Cause:   err,
		}
	}

	probeCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	response, err := authClient.Authenticate(probeCtx, &pluginv1.AuthenticateRequest{Metadata: metadata})
	if err != nil {
		return &ConnectionTestError{
			Message: fmt.Sprintf("Connection check failed: %v", err),
			Cause:   err,
		}
	}
	if response == nil || response.GetClaims() == nil {
		return &ConnectionTestError{
			Message: "The authentication provider did not acknowledge the connection check.",
			Cause:   ErrConnectionTestUnsupported,
		}
	}
	claims := response.GetClaims().AsMap()
	ack, ok := claims[ackClaim].(bool)
	if !ok || !ack {
		return &ConnectionTestError{
			Message: "The authentication provider did not acknowledge the connection check.",
			Cause:   ErrConnectionTestUnsupported,
		}
	}
	responseContract, ok := claims[connectionTestResponseContractClaimKey].(string)
	if !ok || strings.TrimSpace(responseContract) != connectionTestContractV1 {
		return &ConnectionTestError{
			Message: "The authentication provider acknowledged a different connection-check contract.",
			Cause:   ErrConnectionTestUnsupported,
		}
	}
	return nil
}

func (s *Service) TestGlobalConfig(
	ctx context.Context,
	installationID int,
	key string,
	value map[string]any,
) error {
	return s.TestGlobalConfigWithClears(ctx, installationID, key, value, nil)
}

func (s *Service) TestGlobalConfigWithClears(
	ctx context.Context,
	installationID int,
	key string,
	value map[string]any,
	clearSecrets []string,
) error {
	key = strings.TrimSpace(key)
	if key == "" {
		return &ConnectionTestError{Message: "Config key is required"}
	}
	if s.host == nil {
		return fmt.Errorf("plugin host not configured")
	}

	installation, manifest, err := s.ensureInstallationCache(ctx, installationID, false)
	if err != nil {
		return err
	}

	if value == nil {
		value = map[string]any{}
	}
	submitted := value
	secretFields := GlobalConfigSecretFields(manifest, key)
	secretPaths := GlobalConfigSecretPaths(manifest, key)
	clearSet, err := validatedSecretClearSet(key, secretFields, clearSecrets)
	if err != nil {
		return &ConnectionTestError{Message: err.Error(), Cause: err}
	}
	value, err = s.preserveStoredSecrets(ctx, installationID, key, value, secretPaths)
	if err != nil {
		return err
	}
	for field := range clearSet {
		delete(value, field)
	}
	projection := globalConfigValidationProjection(manifest, key, value, submitted)
	if err := ValidateGlobalConfigValue(manifest, key, projection); err != nil {
		return &ConnectionTestError{Message: err.Error(), Cause: err}
	}
	if _, err := pluginConnectionCheckCapabilityForManifest(manifest, key); err != nil {
		return err
	}

	configEntries, err := s.mergedGlobalConfigEntries(ctx, installationID, key, value)
	if err != nil {
		return err
	}

	testInstallationID := -int(s.testConfigSeq.Add(1))
	client, err := s.host.Start(ctx, pluginhost.StartRequest{
		InstallationID: testInstallationID,
		BinaryPath:     installation.InstallPath,
		Manifest:       manifest,
		Config:         configEntries,
	})
	if err != nil {
		return &ConnectionTestError{
			Message: fmt.Sprintf("Failed to start the plugin with the test configuration: %v", err),
			Cause:   err,
		}
	}

	defer func() {
		if stopErr := s.host.Stop(testInstallationID); stopErr != nil && !errors.Is(stopErr, pluginhost.ErrClientNotFound) {
			slog.WarnContext(ctx,
				"stopping temporary plugin connection check instance failed", "component", "plugins",
				"installation_id", installationID,
				"test_installation_id", testInstallationID,
				"error", stopErr,
			)
		}
	}()

	return runPluginConnectionCheck(ctx, client, manifest, key)
}

func (s *Service) mergedGlobalConfigEntries(
	ctx context.Context,
	installationID int,
	key string,
	value map[string]any,
) ([]*pluginv1.ConfigEntry, error) {
	configsByKey := make(map[string]map[string]any)

	if s.configs != nil {
		configs, err := s.configs.ListGlobalConfigs(ctx, installationID)
		if err != nil {
			return nil, fmt.Errorf("list plugin runtime configs for installation %d: %w", installationID, err)
		}
		for _, config := range configs {
			if config == nil {
				continue
			}
			configsByKey[config.Key] = cloneConfigMap(config.Value)
		}
	}

	configsByKey[key] = cloneConfigMap(value)
	return configEntriesFromValues(configsByKey, installationID)
}

func configEntriesFromValues(
	configsByKey map[string]map[string]any,
	installationID int,
) ([]*pluginv1.ConfigEntry, error) {
	if len(configsByKey) == 0 {
		return nil, nil
	}

	keys := make([]string, 0, len(configsByKey))
	for key := range configsByKey {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	entries := make([]*pluginv1.ConfigEntry, 0, len(keys))
	for _, key := range keys {
		value := configsByKey[key]
		if value == nil {
			value = map[string]any{}
		}

		structValue, err := structpb.NewStruct(value)
		if err != nil {
			return nil, fmt.Errorf(
				"encode runtime config %q for installation %d: %w",
				key,
				installationID,
				err,
			)
		}

		entries = append(entries, &pluginv1.ConfigEntry{Key: key, Value: structValue})
	}

	return entries, nil
}

func cloneConfigMap(value map[string]any) map[string]any {
	if value == nil {
		return map[string]any{}
	}
	cloned := make(map[string]any, len(value))
	for key, entry := range value {
		cloned[key] = entry
	}
	return cloned
}

func pluginConnectionCheckCapabilityForManifest(
	manifest *pluginv1.PluginManifest,
	configKey string,
) (pluginConnectionCheckCapability, error) {
	candidates := pluginConnectionCheckCapabilities(manifest)
	if len(candidates) == 0 {
		return pluginConnectionCheckCapability{}, &ConnectionTestError{
			Message: "Connection checks are not supported for this plugin yet.",
			Cause:   ErrConnectionTestUnsupported,
		}
	}

	configKey = strings.TrimSpace(configKey)
	matches := make([]pluginConnectionCheckCapability, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate.matchesConfigKey(configKey) {
			matches = append(matches, candidate)
		}
	}
	if len(matches) == 1 {
		return matches[0], nil
	}
	if len(matches) > 1 {
		return pluginConnectionCheckCapability{}, &ConnectionTestError{
			Message: fmt.Sprintf("Multiple plugin capabilities advertise a connection check for config key %q.", configKey),
			Cause:   ErrConnectionTestUnsupported,
		}
	}
	if len(candidates) == 1 && candidates[0].kind == connectionCheckKindMetadata {
		return candidates[0], nil
	}
	return pluginConnectionCheckCapability{}, &ConnectionTestError{
		Message: fmt.Sprintf("Connection check capability is not explicitly mapped to config key %q.", configKey),
		Cause:   ErrConnectionTestUnsupported,
	}
}

func pluginConnectionCheckCapabilities(manifest *pluginv1.PluginManifest) []pluginConnectionCheckCapability {
	result := make([]pluginConnectionCheckCapability, 0)
	for _, capability := range manifest.GetCapabilities() {
		switch capability.GetType() {
		case "metadata_provider.v1":
			result = append(result, pluginConnectionCheckCapability{
				kind:       connectionCheckKindMetadata,
				id:         capability.GetId(),
				configKeys: capabilityConnectionTestConfigKeys(capability),
			})
		case "auth_provider.v1":
			if capability.GetMetadata() == nil {
				continue
			}
			metadata := capability.GetMetadata().AsMap()
			enabled, ok := metadata[connectionTestEnabledMetadataKey].(bool)
			if !ok || !enabled {
				continue
			}
			ackClaim, _ := metadata[connectionTestAckClaimMetadataKey].(string)
			contract, _ := metadata[connectionTestContractMetadataKey].(string)
			result = append(result, pluginConnectionCheckCapability{
				kind:       connectionCheckKindAuth,
				id:         capability.GetId(),
				configKeys: capabilityConnectionTestConfigKeys(capability),
				ackClaim:   strings.TrimSpace(ackClaim),
				contract:   strings.TrimSpace(contract),
			})
		}
	}
	return result
}

func (c pluginConnectionCheckCapability) matchesConfigKey(key string) bool {
	if key == "" || len(c.configKeys) == 0 {
		return false
	}
	for _, configuredKey := range c.configKeys {
		if configuredKey == key {
			return true
		}
	}
	return false
}

func capabilityConnectionTestConfigKeys(capability *pluginv1.CapabilityDescriptor) []string {
	if capability == nil || capability.GetMetadata() == nil {
		return nil
	}
	raw, ok := capability.GetMetadata().AsMap()[connectionTestConfigKeysMetadataKey].([]any)
	if !ok {
		return nil
	}
	keys := make([]string, 0, len(raw))
	seen := make(map[string]struct{}, len(raw))
	for _, entry := range raw {
		key, ok := entry.(string)
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		keys = append(keys, key)
	}
	return keys
}

func metadataProviderConnectionCheckCapability(
	manifest *pluginv1.PluginManifest,
	capabilityID string,
) *pluginv1.CapabilityDescriptor {
	for _, capability := range manifest.GetCapabilities() {
		if capability.GetType() == "metadata_provider.v1" && capability.GetId() == capabilityID {
			return capability
		}
	}
	return nil
}

func metadataProviderConnectionProbeType(capability *pluginv1.CapabilityDescriptor) (string, bool) {
	priorities, ok := metadataProviderDefaultPriorities(capability)
	if !ok {
		return "movie", true
	}
	keys := make([]string, 0, len(priorities))
	for key, priority := range priorities {
		if priority > 0 {
			keys = append(keys, key)
		}
	}
	if len(keys) == 0 {
		return "", false
	}
	sort.Strings(keys)
	for _, preferred := range []string{"movie", "series", "show", "book"} {
		for _, key := range keys {
			if key == preferred {
				return key, true
			}
		}
	}
	return keys[0], true
}

func metadataProviderDefaultPriorities(
	capability *pluginv1.CapabilityDescriptor,
) (map[string]float64, bool) {
	if capability == nil || capability.GetMetadata() == nil {
		return nil, false
	}

	metadataMap := capability.GetMetadata().AsMap()
	raw, ok := metadataMap["default_priority"]
	if !ok {
		nested, nestedOK := metadataMap["metadata"].(map[string]any)
		if !nestedOK {
			return nil, false
		}
		raw, ok = nested["default_priority"]
		if !ok {
			return nil, false
		}
	}

	rawMap, ok := raw.(map[string]any)
	if !ok {
		return nil, false
	}
	priorities := make(map[string]float64, len(rawMap))
	for key, value := range rawMap {
		switch v := value.(type) {
		case float64:
			priorities[key] = v
		case int:
			priorities[key] = float64(v)
		case int32:
			priorities[key] = float64(v)
		case int64:
			priorities[key] = float64(v)
		}
	}
	return priorities, len(priorities) > 0
}
