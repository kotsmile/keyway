package secrets

import (
	"github.com/kotsmile/keyway/internal/config"
	"github.com/kotsmile/keyway/internal/domains/secrets/entity"
)

// KeyringFor is the keys one own Store seals and opens with, read from its
// declaration's settings: `key_id` (defaulting to "v1"), `key`, and a
// `previous_keys` mapping of retired id to material.
//
// Retired keys stay configured for exactly as long as a version sealed under
// them still exists. This lives in the domain rather than in cmd so the
// mount wiring (main.rs's mount_stores, ported with `serve`) stays thin.
func KeyringFor(declared config.StoreConfig) (*entity.Keyring, error) {
	setting := func(name string) (string, bool) {
		value, ok := declared.Settings[name].(string)
		return value, ok
	}

	active := "v1"
	if id, ok := setting("key_id"); ok {
		active = id
	}
	keys := map[string]string{}
	if key, ok := setting("key"); ok {
		keys[active] = key
	}
	if previous, ok := declared.Settings["previous_keys"].(map[string]any); ok {
		for id, material := range previous {
			if key, ok := material.(string); ok {
				keys[id] = key
			}
		}
	}
	return entity.NewKeyring(active, keys)
}
