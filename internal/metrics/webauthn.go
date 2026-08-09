package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// WebAuthnOperations tracks WebAuthn ceremony outcomes per step. The
	// clone_warning result fires only on the FinishLogin Authenticator
	// CloneWarning branch — instrumented so SOC dashboards can spot a clone
	// detection event even before the full §1.10 deferral is mock-tested.
	//
	// Allowed label values:
	//   operation=register_begin   BeginRegistrationWithStore
	//   operation=register_finish  FinishRegistration
	//   operation=login_begin      BeginLogin
	//   operation=login_finish     FinishLogin
	//   operation=delete           DeleteCredential
	//
	//   result=success
	//   result=failure
	//   result=clone_warning       only valid for operation=login_finish
	//
	// NOT INSTRUMENTED: BeginDummyLogin (the user-enumeration-protection
	// dummy assertion path). Adding a counter there would let an attacker
	// derive (begin_login_total - finish_login_total) deltas and distinguish
	// real-vs-dummy flows — which is exactly what the dummy path exists to
	// obscure. See webauthn_service.go BeginDummyLogin for the design
	// rationale; do not instrument that path.
	WebAuthnOperations = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "identuum_idp_webauthn_operations_total",
		Help: "Total WebAuthn flow operations by step and result",
	}, []string{"operation", "result"})
)
