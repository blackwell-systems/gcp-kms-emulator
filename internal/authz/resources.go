package authz

import "strings"

// NormalizeKeyRingResource normalizes a key ring resource path
// Input formats:
//   - projects/{p}/locations/{l}/keyRings/{kr}
//   - projects/{p}/locations/{l}/keyRings/{kr}/cryptoKeys/{ck}
//
// Output: projects/{p}/locations/{l}/keyRings/{kr}
func NormalizeKeyRingResource(name string) string {
	parts := strings.Split(name, "/")
	if len(parts) >= 6 && parts[0] == "projects" && parts[2] == "locations" && parts[4] == "keyRings" {
		return strings.Join(parts[:6], "/")
	}
	return name
}

// NormalizeCryptoKeyResource normalizes a crypto key resource path
// Input formats:
//   - projects/{p}/locations/{l}/keyRings/{kr}/cryptoKeys/{ck}
//   - projects/{p}/locations/{l}/keyRings/{kr}/cryptoKeys/{ck}/cryptoKeyVersions/{v}
//
// Output: projects/{p}/locations/{l}/keyRings/{kr}/cryptoKeys/{ck}
func NormalizeCryptoKeyResource(name string) string {
	parts := strings.Split(name, "/")
	if len(parts) >= 8 && parts[0] == "projects" && parts[2] == "locations" && parts[4] == "keyRings" && parts[6] == "cryptoKeys" {
		return strings.Join(parts[:8], "/")
	}
	return name
}

// NormalizeCryptoKeyVersionResource normalizes a crypto key version resource path
// Input: projects/{p}/locations/{l}/keyRings/{kr}/cryptoKeys/{ck}/cryptoKeyVersions/{v}
// Output: projects/{p}/locations/{l}/keyRings/{kr}/cryptoKeys/{ck}/cryptoKeyVersions/{v}
//
// Note: Preserves full path for version-specific permissions
func NormalizeCryptoKeyVersionResource(name string) string {
	// Version resources are already canonical
	return name
}

// NormalizeParentForCreate normalizes a parent resource path for create operations
// Returns the parent resource (where permission check should happen)
//
// For CreateKeyRing:
//
//	Input: projects/{p}/locations/{l}
//	Output: projects/{p}/locations/{l}
//
// For CreateCryptoKey:
//
//	Input: projects/{p}/locations/{l}/keyRings/{kr}
//	Output: projects/{p}/locations/{l}/keyRings/{kr}
//
// For CreateCryptoKeyVersion:
//
//	Input: projects/{p}/locations/{l}/keyRings/{kr}/cryptoKeys/{ck}
//	Output: projects/{p}/locations/{l}/keyRings/{kr}/cryptoKeys/{ck}
func NormalizeParentForCreate(parent string) string {
	// Parent is already in canonical form for create operations
	return parent
}
