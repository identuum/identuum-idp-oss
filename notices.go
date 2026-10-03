package identuumidposs

import _ "embed"

// ThirdPartyNotices is THIRD_PARTY_NOTICES, the licences of the third-party
// software the binary contains, embedded so the binary carries its own
// notices (`identuum-idp licenses`). Regenerate it with `make notices`;
// `make notices-check` refuses it once its inputs move.
//
//go:embed THIRD_PARTY_NOTICES
var ThirdPartyNotices string
