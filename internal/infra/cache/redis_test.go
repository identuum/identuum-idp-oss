package cache

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/identuum/identuum-idp-oss/logger"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func getHistogramSampleCount(metricName string, labels map[string]string) uint64 {
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		return 0
	}
	for _, mf := range mfs {
		if mf.GetName() == metricName {
			for _, m := range mf.GetMetric() {
				match := true
				for _, lp := range m.GetLabel() {
					if val, ok := labels[lp.GetName()]; ok && val != lp.GetValue() {
						match = false
						break
					}
				}
				if match && m.GetHistogram() != nil {
					return m.GetHistogram().GetSampleCount()
				}
			}
		}
	}
	return 0
}

func TestMain(m *testing.M) {
	logger.InitializeZapLogger()
	os.Exit(m.Run())
}

type plainTestStruct struct {
	Name string
	Age  int
}

// verify exported functions if I made them exported, OR just test helpers since in same package

func TestGobSerialization(t *testing.T) {
	tests := []struct {
		name    string
		input   plainTestStruct
		wantErr bool
	}{
		{
			name:  "Basic Roundtrip",
			input: plainTestStruct{Name: "Alice", Age: 30},
		},
		{
			name:  "Empty Fields",
			input: plainTestStruct{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encode
			data, err := encode(tt.input)
			if err != nil {
				t.Fatalf("encode() error = %v", err)
			}

			if len(data) == 0 {
				t.Fatal("encode() returned empty bytes")
			}

			// Decode
			var output plainTestStruct
			if err := decode(data, &output); err != nil {
				t.Fatalf("decode() error = %v", err)
			}

			if output != tt.input {
				t.Errorf("Decoded = %v, want %v", output, tt.input)
			}
		})
	}
}

func TestGobDecodeFailures(t *testing.T) {
	// Test decoding JSON data (simulating legacy cache)
	jsonInput := `{"Name":"Bob","Age":40}`
	var output plainTestStruct

	err := decode([]byte(jsonInput), &output)
	if err == nil {
		t.Error("expected decode error for JSON input, got nil")
	}

	// Test decoding garbage
	garbage := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	err = decode(garbage, &output)
	if err == nil {
		t.Error("expected decode error for garbage input, got nil")
	}
}

func TestRedisClient(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()

	client, err := NewRedisClient(mr.Addr(), "")
	require.NoError(t, err)
	defer client.Close()

	assert.NotNil(t, client.Client())

	ctx := context.Background()
	testVal := plainTestStruct{Name: "CacheTest", Age: 99}

	// 1. Get Cache Miss
	var out plainTestStruct
	err = client.Get(ctx, "test-key", &out)
	assert.ErrorIs(t, err, ErrCacheMiss)

	// 2. Set Value
	beforeSet := getHistogramSampleCount("identuum_idp_cache_request_duration_seconds", map[string]string{"operation": "set", "result": "success"})
	err = client.Set(ctx, "test-key", testVal, 1*time.Minute)
	require.NoError(t, err)
	afterSet := getHistogramSampleCount("identuum_idp_cache_request_duration_seconds", map[string]string{"operation": "set", "result": "success"})
	assert.Greater(t, afterSet, beforeSet, "identuum_idp_cache_request_duration_seconds should increment on set success")

	// 3. Get Value
	beforeGet := getHistogramSampleCount("identuum_idp_cache_request_duration_seconds", map[string]string{"operation": "get", "result": "success"})
	err = client.Get(ctx, "test-key", &out)
	require.NoError(t, err)
	assert.Equal(t, testVal, out)
	afterGet := getHistogramSampleCount("identuum_idp_cache_request_duration_seconds", map[string]string{"operation": "get", "result": "success"})
	assert.Greater(t, afterGet, beforeGet, "identuum_idp_cache_request_duration_seconds should increment on get success")

	// 4. Delete Value
	err = client.Del(ctx, "test-key")
	require.NoError(t, err)

	// 5. Get after delete (Miss)
	err = client.Get(ctx, "test-key", &out)
	assert.ErrorIs(t, err, ErrCacheMiss)
}

func TestRedisClient_Failures(t *testing.T) {
	// 1. connection failure
	_, err := NewRedisClient("127.0.0.1:0", "bad")
	assert.ErrorContains(t, err, "failed to connect to redis")

	// Start miniredis for other tests
	mr, err := miniredis.Run()
	require.NoError(t, err)
	client, err := NewRedisClient(mr.Addr(), "")
	require.NoError(t, err)

	ctx := context.Background()

	// 2. Encode failure (Set)
	err = client.Set(ctx, "bad-key", make(chan int), time.Minute) // chan is not gob encodable
	assert.ErrorContains(t, err, "failed to gob encode")

	// 3. Decode failure (Get) — wrapped with ErrCacheDecode so callers can
	//    distinguish payload decode failures from connectivity errors.
	// Manually set bad gob data in miniredis
	mr.Set("bad-data", "not-a-gob")
	var out plainTestStruct
	err = client.Get(ctx, "bad-data", &out)
	assert.ErrorIs(t, err, ErrCacheDecode)

	// 4. Redis backend failure (Close miniredis then try)
	mr.Close()
	err = client.Set(ctx, "fail-key", "val", time.Minute)
	assert.ErrorContains(t, err, "connection refused") // or similar io error

	err = client.Get(ctx, "fail-key", &out)
	assert.ErrorContains(t, err, "connection refused")

	err = client.Del(ctx, "fail-key")
	assert.ErrorContains(t, err, "connection refused")
}

// TestRedisClient_TTLExpiration pins §6.2's "handling TTL expiration globally"
// claim — a Set with TTL must become a cache miss after the TTL elapses, and
// pre-TTL entries must NOT be spuriously evicted.
func TestRedisClient_TTLExpiration(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()

	client, err := NewRedisClient(mr.Addr(), "")
	require.NoError(t, err)
	defer client.Close()

	ctx := context.Background()

	// 1. Pre-TTL: entry must still be present after a fast-forward shorter than TTL.
	longVal := plainTestStruct{Name: "Long", Age: 1}
	require.NoError(t, client.Set(ctx, "long-ttl", longVal, 10*time.Second))
	mr.FastForward(1 * time.Second)

	var longOut plainTestStruct
	require.NoError(t, client.Get(ctx, "long-ttl", &longOut))
	assert.Equal(t, longVal, longOut)

	// 2. Post-TTL: entry must expire to ErrCacheMiss after a fast-forward past TTL.
	shortVal := plainTestStruct{Name: "Short", Age: 2}
	require.NoError(t, client.Set(ctx, "short-ttl", shortVal, 50*time.Millisecond))
	mr.FastForward(1 * time.Second)

	var shortOut plainTestStruct
	err = client.Get(ctx, "short-ttl", &shortOut)
	assert.ErrorIs(t, err, ErrCacheMiss)
}
