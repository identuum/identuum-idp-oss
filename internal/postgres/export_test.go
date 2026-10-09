package postgres

// SetQuotaCounted lets the external tests hold a quota-bound create after it
// counted and before it inserts (OSS-SEAM-5).
func SetQuotaCounted(r *PgxAPIResourceRepository, f func()) { r.quotaCounted = f }
