package secrets

// VaultConfig holds the connection parameters for a Vault-backed
// secret provider. The struct is pure data: no logic, no commercial
// dependency. It is consumed by appconfig at parse time so the
// operator's Vault settings can be plumbed through configuration
// regardless of whether the CE-side commercial VaultProvider is
// wired.
//
// The commercial implementation that consumes a VaultConfig
// (NewVaultProvider) lives in the monolith and will move to
// identuum-idp-ce. OSS-only builds never instantiate a VaultProvider
// — operators run with the EnvProvider unless a CE binary is in use
// — but appconfig still needs the struct shape so the configuration
// layer can compile.
//
// Reconstructed in OSS by slice
// identuum-idp-open-core-phase2-appconfig-relocation (2026-05-31)
// using `gograph source secrets.VaultConfig`. Byte-for-byte
// equivalent to the monolith's definition. Drift discipline
// applies: any change to the struct fields MUST be applied
// IDENTICALLY in both the monolith and OSS copies until the future
// flip slice retires the monolith copy.
//
// SECURITY: this struct intentionally carries plaintext fields that
// MAY be populated with secret material at runtime (Token in
// particular). The struct itself contains no secret value at compile
// time. Operators MUST NOT serialize a populated VaultConfig to logs,
// telemetry, or any wire protocol.
type VaultConfig struct {
	Address string
	Token   string
	// MountPath is the path where KV secrets are mounted, e.g., "secret"
	MountPath string
	// SecretPath is the specific path to the secret JSON, e.g., "auth-service/config"
	SecretPath string
}
