package service

import (
	"github.com/kotsmile/keyway/config"
	"github.com/kotsmile/keyway/internal/secrets/entity"
)

// KeyringFor is the keys one own Store seals and opens with, read from its
// declaration's settings: `key_id` (defaulting to "v1"), `key`, and a
// `previous_keys` mapping of retired id to material.
//
// Retired keys stay configured for exactly as long as a version sealed under
// them still exists. This lives in the domain rather than in cmd so the
// mount wiring stays thin — and the settings arrive already read into
// config.KeywaySettings, so what is left here is the one decision that is
// actually the domain's: which id is active, and which material goes with it.
func KeyringFor(declared config.StoreConfig) (*entity.Keyring, error) {
	settings := declared.KeywaySettings()

	keys := make(map[string]string, len(settings.PreviousKeys)+1)
	if settings.Key != "" {
		keys[settings.KeyID] = settings.Key
	}
	// Applied after the active key, which is the order that was always in
	// force: a `previous_keys` entry sharing the active id wins. It is a
	// misconfiguration either way, and changing which side wins would change
	// which key a deployment seals under on the next restart.
	for id, material := range settings.PreviousKeys {
		keys[id] = material
	}
	return entity.NewKeyring(settings.KeyID, keys)
}
