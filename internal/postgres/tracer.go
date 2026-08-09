package postgres

import (
	"context"
	"strings"
	"time"

	"github.com/identuum/identuum-idp-oss/internal/metrics"
	"github.com/jackc/pgx/v5"
)

// DBTracer implements pgx.QueryTracer to record metrics
type DBTracer struct{}

// TraceQueryStart is called at the beginning of a query execution.
func (t *DBTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	ctx = context.WithValue(ctx, traceStartKey, time.Now())
	ctx = context.WithValue(ctx, traceSQLKey, data.SQL)
	return ctx
}

// TraceQueryEnd is called upon completion of a query execution.
func (t *DBTracer) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryEndData) {
	start, ok := ctx.Value(traceStartKey).(time.Time)
	if !ok {
		return
	}

	duration := time.Since(start).Seconds()
	status := "success"
	if data.Err != nil {
		status = "error"
	}

	// Extract command (e.g., SELECT, INSERT)
	command := "OTHER"
	if sql, ok := ctx.Value(traceSQLKey).(string); ok && len(sql) > 0 {
		fields := strings.Fields(sql)
		if len(fields) > 0 {
			command = strings.ToUpper(fields[0])
		}
	}

	metrics.DBRequestDuration.WithLabelValues(command, status).Observe(duration)
}

type traceKey int

const (
	traceStartKey traceKey = iota
	traceSQLKey
)
