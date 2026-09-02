package domain

import "sort"

// RequestObjectSigningAlgValuesSupported is the ONE source for discovery's
// request_object_signing_alg_values_supported (THE-JAR-REQUEST-OBJECT):
// "none" (unsigned request objects by value are accepted — they carry no
// authority a query string lacks) followed by the asymmetric allow-list the
// OP verifies against a client's registered keys. Never a symmetric alg.
func RequestObjectSigningAlgValuesSupported() []string {
	out := []string{"none"}
	for a := range PrivateKeyJWTSigningAlgorithms {
		out = append(out, a)
	}
	sort.Strings(out[1:])
	return out
}
