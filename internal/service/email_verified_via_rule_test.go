package service

import "testing"

// OSS-0912-C2 (owner C2 Q2 (a), PQ1 (b)): the service-layer writers that
// activate or verify a user each record how the mailbox was proven, or that
// it was not. Each writer keeps its own test; this rule runs them as one.
// RULE: EMAIL-VERIFIED-VIA-1
func TestRule_EMAIL_VERIFIED_VIA_1(t *testing.T) {
	t.Run("admin create admin_set, self-registrant none", TestUserServiceCreate_RecordsHowTheAddressWasVouched)
	t.Run("admin edit admin_set, cleared on false", TestUserServiceUpdate_AdminSettingIsLabelledNotProven)
	t.Run("claim link admin_link", TestConsumeClaim_OrgAdminIsActivatedByAnAdministratorsLink)
	t.Run("upstream sign-in upstream_idp", TestOIDCCallback_JIT_RecordsTheProvidersProof)
	t.Run("upstream link upstream_idp, an email proof kept", TestOIDCCallback_LinkRecordsTheProofOnly)
	t.Run("email link on an admin-activated user email_link", TestVerifyEmail_AdminActivatedUserRecordsTheProof)
	t.Run("email link on a self-registrant email_link", TestVerifyEmail_SelfRegisteredUserIsActivatedAndProven)
}
