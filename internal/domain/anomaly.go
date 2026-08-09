package domain

const (
	AnomalyThreshold = 0.7

	// V1 heuristic scoring weights — must sum to 1.0.
	AnomalyWeightTenantJumping = 0.3
	AnomalyWeightErrorDensity  = 0.4
	AnomalyWeightVelocitySpike = 0.3

	// Detection count thresholds.
	AnomalyThresholdTenantJumping = 2   // unique org accesses per window
	AnomalyThresholdErrorDensity  = 5   // non-2xx responses per 5-minute window
	AnomalyThresholdVelocitySpike = 100 // requests per 60-second window
)
