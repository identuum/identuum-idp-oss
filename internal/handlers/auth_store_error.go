package handlers

// auth_store_error.go — THE-SESSION-REJECTION-ROOT-CAUSE (2026-09-02), AUTH-503.
//
// Handler-side counterpart of mw.RespondAuthStoreUnavailable for the
// browser-facing ceremony pages (authorize, consent, step-up): the same
// ERROR log with the same correlation id, but a small HTML page when the
// caller is a browser (Accept: text/html) — status 503 either way, so the
// UI's session helper retries instead of reading the refusal as "your
// session is dead".

import (
	"html"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/identuum/identuum-idp-oss/internal/mw"
)

// respondAuthStoreUnavailable answers an auth-path store error on a
// ceremony page: ERROR log + correlation id (mw.RecordAuthStoreError),
// then 503 — HTML for a browser, the shared JSON body otherwise. The
// request is aborted.
func respondAuthStoreUnavailable(c *gin.Context, where string, err error) {
	cid := mw.RecordAuthStoreError(c, where, err)
	if strings.Contains(c.GetHeader("Accept"), "text/html") {
		c.Data(http.StatusServiceUnavailable, "text/html; charset=utf-8", []byte(
			`<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">`+
				`<title>Temporarily unavailable</title></head><body><main>`+
				`<h1>Temporarily unavailable</h1>`+
				`<p>The sign-in service could not complete a required check. Please try again.</p>`+
				`<p>reference: `+html.EscapeString(cid)+`</p>`+
				`</main></body></html>`))
		c.Abort()
		return
	}
	c.AbortWithStatusJSON(http.StatusServiceUnavailable, mw.AuthStoreUnavailableBody(cid))
}
