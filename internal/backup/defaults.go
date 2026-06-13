package backup

// DefaultKeyPrefixes is the conservative default backup scope: the durable
// security state the proxy depends on (see docs/REDIS_SCHEMA.md). SCAN MATCH is
// applied as "<prefix>*", so "ban" also covers "ban_cidr".
//
// These are defaults; a future `backup:` config block can override them.
var DefaultKeyPrefixes = []string{
	"ban",                  // ban:{ip} and ban_cidr:{cidr}
	"config:dial",          // the blocking dial
	"ip:blacklist",         // IP block list
	"ip:whitelist",         // IP allow list
	"ja4:blacklist",        // JA4 block list
	"ja4:whitelist",        // JA4 allow list
	"management:audit_log", // policy/audit history
	"management:policy_audit",
	"management:gdpr_erasure_log",
	"beacon",    // beaconing suspects/timestamps
	"fp",        // passive fingerprints (fp:os:ip, fp:ip, ...)
	"blocklist", // blocklist refresh state
}

// DefaultExcludePrefixes are skipped even if they match a key prefix: ephemeral /
// regenerable state and — critically — credential/session/MFA material that must
// regenerate rather than be restored. This exclude-list is the security boundary.
var DefaultExcludePrefixes = []string{
	"ratelimit",             // sliding-window rate-limit state (regenerable)
	"concurrent",            // concurrent-connection counters (regenerable)
	"mgmt:totp",             // MFA seeds
	"mgmt:webauthn",         // WebAuthn credentials
	"mgmt:saml",             // SSO session/material
	"mgmt:oidc",             // OIDC session/material
	"mgmt:session",          // live session tokens
	"backup:operation_lock", // never back up the backup lock itself
}
