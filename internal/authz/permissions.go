package authz

// ResourceTarget defines where the permission check should be performed
type ResourceTarget int

const (
	// ResourceTargetSelf checks permission on the resource itself
	ResourceTargetSelf ResourceTarget = iota
	// ResourceTargetParent checks permission on the parent resource (for create operations)
	ResourceTargetParent
)

// PermissionCheck defines the permission and target for an operation
type PermissionCheck struct {
	Permission string
	Target     ResourceTarget
}

// OperationPermissions maps KMS operations to their required permissions
//
// Based on GCP KMS permission model:
// https://cloud.google.com/kms/docs/reference/permissions-and-roles
var OperationPermissions = map[string]PermissionCheck{
	// KeyRing operations
	"CreateKeyRing": {
		Permission: "cloudkms.keyRings.create",
		Target:     ResourceTargetParent, // Check against parent (projects/{p}/locations/{l})
	},
	"GetKeyRing": {
		Permission: "cloudkms.keyRings.get",
		Target:     ResourceTargetSelf,
	},
	"ListKeyRings": {
		Permission: "cloudkms.keyRings.list",
		Target:     ResourceTargetParent, // Check against parent (projects/{p}/locations/{l})
	},

	// CryptoKey operations
	"CreateCryptoKey": {
		Permission: "cloudkms.cryptoKeys.create",
		Target:     ResourceTargetParent, // Check against keyring
	},
	"GetCryptoKey": {
		Permission: "cloudkms.cryptoKeys.get",
		Target:     ResourceTargetSelf,
	},
	"ListCryptoKeys": {
		Permission: "cloudkms.cryptoKeys.list",
		Target:     ResourceTargetParent, // Check against keyring
	},
	"UpdateCryptoKey": {
		Permission: "cloudkms.cryptoKeys.update",
		Target:     ResourceTargetSelf,
	},
	"Encrypt": {
		Permission: "cloudkms.cryptoKeys.encrypt",
		Target:     ResourceTargetSelf,
	},
	"Decrypt": {
		Permission: "cloudkms.cryptoKeys.decrypt",
		Target:     ResourceTargetSelf,
	},

	// CryptoKeyVersion operations
	"CreateCryptoKeyVersion": {
		Permission: "cloudkms.cryptoKeyVersions.create",
		Target:     ResourceTargetParent, // Check against cryptokey
	},
	"GetCryptoKeyVersion": {
		Permission: "cloudkms.cryptoKeyVersions.get",
		Target:     ResourceTargetSelf,
	},
	"ListCryptoKeyVersions": {
		Permission: "cloudkms.cryptoKeyVersions.list",
		Target:     ResourceTargetParent, // Check against cryptokey
	},
	"UpdateCryptoKeyVersion": {
		Permission: "cloudkms.cryptoKeyVersions.update",
		Target:     ResourceTargetSelf,
	},
	"UpdateCryptoKeyPrimaryVersion": {
		Permission: "cloudkms.cryptoKeys.update",
		Target:     ResourceTargetSelf, // Check against cryptokey
	},
	"DestroyCryptoKeyVersion": {
		Permission: "cloudkms.cryptoKeyVersions.destroy",
		Target:     ResourceTargetSelf,
	},
	"RestoreCryptoKeyVersion": {
		Permission: "cloudkms.cryptoKeyVersions.update",
		Target:     ResourceTargetSelf,
	},

	// Asymmetric operations
	"GetPublicKey": {
		Permission: "cloudkms.cryptoKeyVersions.viewPublicKey",
		Target:     ResourceTargetSelf,
	},
	"AsymmetricSign": {
		Permission: "cloudkms.cryptoKeyVersions.useToSign",
		Target:     ResourceTargetSelf, // Check against cryptokeyversion
	},
	"AsymmetricDecrypt": {
		Permission: "cloudkms.cryptoKeyVersions.useToDecrypt",
		Target:     ResourceTargetSelf, // Check against cryptokeyversion
	},
	"MacSign": {
		Permission: "cloudkms.cryptoKeyVersions.useToMacSign",
		Target:     ResourceTargetSelf, // Check against cryptokeyversion
	},
	"MacVerify": {
		Permission: "cloudkms.cryptoKeyVersions.useToMacVerify",
		Target:     ResourceTargetSelf, // Check against cryptokeyversion
	},
}

// GetPermission returns the permission and target for an operation
func GetPermission(operation string) (PermissionCheck, bool) {
	perm, ok := OperationPermissions[operation]
	return perm, ok
}
