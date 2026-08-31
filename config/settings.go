// A Store's own keys, read once and typed.
//
// `project`, `folder`, `namespace`, `key` are not in the schema, because
// which of them a Store needs depends on the SecretManager it names and only
// that adapter can say. What WAS in cmd/api, and is here now, is the reading:
// `declared.Settings["project"].(string)` repeated per kind, each with its own
// silent `ok` to forget. The mount site now asks for the settings of a kind
// and gets either a value or a sentence naming the store and the key.
//
// The file format is untouched: these are still ordinary keys in the store
// block, still resolved by the same placeholder pass, still stored raw in
// Settings for anything that wants them that way.

package config

import "fmt"

// GcpSettings is what a `gcp` Store needs.
type GcpSettings struct {
	// Project is the Google Cloud project the secrets live in.
	Project string
}

// YcSettings is what a `yc` Store needs.
type YcSettings struct {
	// Folder is the Yandex Cloud folder the Lockbox secrets live in.
	Folder string
	// Secret is the IAM credential. Optional: a deployment inside YC takes
	// the instance's own metadata identity instead.
	Secret string
}

// AwsSettings is what an `aws` Store needs.
type AwsSettings struct {
	// Region is optional — an empty one takes the standard provider chain's
	// own, which is what an instance role or IRSA already carries.
	Region string
}

// K8sSettings is what a `k8s` Store needs.
type K8sSettings struct {
	// Namespace is the one namespace this Store serves.
	Namespace string
}

// KeywaySettings is what keyway's own Store needs: the keys it seals and
// opens with.
//
// Retired keys stay configured for exactly as long as a version sealed under
// them still exists — dropping one before then is what makes a payload
// unopenable.
type KeywaySettings struct {
	// KeyID is the key new versions are sealed under. Defaults to "v1".
	KeyID string
	// Key is the active key's material, base64 of 32 bytes. Absent is
	// allowed here and refused by the keyring: an own Store with no key at
	// all is a misconfiguration the secrets domain reports in its own words.
	Key string
	// PreviousKeys is retired id → material.
	PreviousKeys map[string]string
}

// MissingSettingError is a Store that did not say something its kind needs.
type MissingSettingError struct {
	Store   string
	Setting string
}

func (e *MissingSettingError) Error() string {
	return fmt.Sprintf("store %q needs a `%s`", e.Store, e.Setting)
}

// GcpSettings reads this Store's `gcp` keys.
func (s StoreConfig) GcpSettings() (GcpSettings, error) {
	project, ok := s.setting("project")
	if !ok {
		return GcpSettings{}, &MissingSettingError{Store: s.ID.String(), Setting: "project"}
	}
	return GcpSettings{Project: project}, nil
}

// YcSettings reads this Store's `yc` keys.
func (s StoreConfig) YcSettings() (YcSettings, error) {
	folder, ok := s.setting("folder")
	if !ok {
		return YcSettings{}, &MissingSettingError{Store: s.ID.String(), Setting: "folder"}
	}
	secret, _ := s.setting("secret")
	return YcSettings{Folder: folder, Secret: secret}, nil
}

// AwsSettings reads this Store's `aws` keys. Nothing is required.
func (s StoreConfig) AwsSettings() (AwsSettings, error) {
	region, _ := s.setting("region")
	return AwsSettings{Region: region}, nil
}

// K8sSettings reads this Store's `k8s` keys.
func (s StoreConfig) K8sSettings() (K8sSettings, error) {
	namespace, ok := s.setting("namespace")
	if !ok {
		return K8sSettings{}, &MissingSettingError{Store: s.ID.String(), Setting: "namespace"}
	}
	return K8sSettings{Namespace: namespace}, nil
}

// KeywaySettings reads this Store's own-Store keys.
//
// It never fails: which keys are usable is the keyring's judgement, and it
// gives a better error than this could — "key %q is not 32 bytes of base64"
// names the key and the reason.
func (s StoreConfig) KeywaySettings() KeywaySettings {
	settings := KeywaySettings{KeyID: "v1", PreviousKeys: map[string]string{}}
	if id, ok := s.setting("key_id"); ok {
		settings.KeyID = id
	}
	settings.Key, _ = s.setting("key")
	if previous, ok := s.Settings["previous_keys"].(map[string]any); ok {
		for id, material := range previous {
			if key, ok := material.(string); ok {
				settings.PreviousKeys[id] = key
			}
		}
	}
	return settings
}

// setting is one raw key, as a string.
//
// Every value in the config file is a string (a `namespace: 123` is a
// deployment's typo, not an int this should coerce), so a non-string reads as
// absent and earns the same "needs a `namespace`" as saying nothing.
func (s StoreConfig) setting(name string) (string, bool) {
	value, ok := s.Settings[name].(string)
	return value, ok
}
