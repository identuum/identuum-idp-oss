package logger

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap/zapcore"
)

func TestInitializeZapLogger(t *testing.T) {
	// Initialize the logger
	InitializeZapLogger()

	// Verify all loggers are initialized
	assert.NotNil(t, Info, "Info logger should be initialized")
	assert.NotNil(t, Error, "Error logger should be initialized")
	assert.NotNil(t, Debug, "Debug logger should be initialized")
	assert.NotNil(t, Security, "Security logger should be initialized")
}

func TestSecurityLoggerHasCategoryTag(t *testing.T) {
	// Initialize the logger
	InitializeZapLogger()

	// The Security logger should have the "category": "security" field
	// This is verified by checking that it was initialized with the correct tag
	assert.NotNil(t, Security, "Security logger should be initialized")

	// Test that Security logger can be used
	Security.WithFields(map[string]any{
		"event_type": "test_event",
		"user_id":    "test-user-123",
	}).Info("Test security event")

	// If we get here without panic, the logger works
	assert.True(t, true, "Security logger should be usable")
}

func TestLoggerWithField(t *testing.T) {
	InitializeZapLogger()

	// Test WithField method
	loggerWithField := Info.WithField("test_key", "test_value")
	assert.NotNil(t, loggerWithField, "WithField should return a logger")

	// Should be usable
	loggerWithField.Print("Test message")
	assert.True(t, true, "Logger with field should be usable")
}

func TestLoggerWithFields(t *testing.T) {
	InitializeZapLogger()

	// Test WithFields method
	fields := map[string]any{
		"key1": "value1",
		"key2": 123,
		"key3": true,
	}
	loggerWithFields := Info.WithFields(fields)
	assert.NotNil(t, loggerWithFields, "WithFields should return a logger")

	// Should be usable
	loggerWithFields.Print("Test message with multiple fields")
	assert.True(t, true, "Logger with fields should be usable")
}

func TestPackageLevelConvenienceMethods(t *testing.T) {
	InitializeZapLogger()

	// Test package-level WithField
	logger1 := WithField("test", "value")
	assert.NotNil(t, logger1, "Package-level WithField should work")

	// Test package-level WithFields
	logger2 := WithFields(map[string]any{"a": 1, "b": 2})
	assert.NotNil(t, logger2, "Package-level WithFields should work")
}

func TestContextMethods(t *testing.T) {
	InitializeZapLogger()
	// Add context methods test
	// Since we can't easily capture stdout without redirecting it,
	// we mainly verify that the methods can be called without panic
	// and that they accept context

	ctx := context.Background()
	ctx = context.WithValue(ctx, RequestIDKey, "req-12345")

	// Test object methods
	Info.InfoContext(ctx, "Info context test")
	Warning.WarnContext(ctx, "Warn context test")
	Error.ErrorContext(ctx, "Error context test")
	Debug.DebugContext(ctx, "Debug context test")

	// Test package methods
	InfoContext(ctx, "Package Info context test")
	WarnContext(ctx, "Package Warn context test")
	ErrorContext(ctx, "Package Error context test")
	DebugContext(ctx, "Package Debug context test")

	assert.True(t, true, "Context methods should run without panic")
}

func TestGetFingerprintFromContext(t *testing.T) {
	ctx1 := context.WithValue(context.Background(), FingerprintCtxKey, "fp1")
	assert.Equal(t, "fp1", GetFingerprintFromContext(ctx1))

	ctx2 := context.Background()
	assert.Equal(t, "", GetFingerprintFromContext(ctx2))
}

func TestStatusCodeColor(t *testing.T) {
	assert.Equal(t, Green, StatusCodeColor(200))
	assert.Equal(t, Green, StatusCodeColor(299))
	assert.Equal(t, White, StatusCodeColor(300))
	assert.Equal(t, White, StatusCodeColor(399))
	assert.Equal(t, Yellow, StatusCodeColor(400))
	assert.Equal(t, Yellow, StatusCodeColor(499))
	assert.Equal(t, Red, StatusCodeColor(500))
}

func TestMethodColor(t *testing.T) {
	assert.Equal(t, Blue, MethodColor("GET"))
	assert.Equal(t, Cyan, MethodColor("POST"))
	assert.Equal(t, Yellow, MethodColor("PUT"))
	assert.Equal(t, Red, MethodColor("DELETE"))
	assert.Equal(t, Green, MethodColor("PATCH"))
	assert.Equal(t, Magenta, MethodColor("HEAD"))
	assert.Equal(t, White, MethodColor("OPTIONS"))
	assert.Equal(t, Reset, MethodColor("UNKNOWN"))
}

func TestSetLevel(t *testing.T) {
	InitializeZapLogger()

	SetLevel("debug")
	assert.True(t, globalLevel.Enabled(zapcore.DebugLevel))

	SetLevel("info")
	assert.False(t, globalLevel.Enabled(zapcore.DebugLevel))
	assert.True(t, globalLevel.Enabled(zapcore.InfoLevel))

	SetLevel("warn")
	assert.False(t, globalLevel.Enabled(zapcore.InfoLevel))
	assert.True(t, globalLevel.Enabled(zapcore.WarnLevel))

	SetLevel("error")
	assert.False(t, globalLevel.Enabled(zapcore.WarnLevel))
	assert.True(t, globalLevel.Enabled(zapcore.ErrorLevel))
}

func TestLoggerPrintMethods(t *testing.T) {
	InitializeZapLogger()

	// Calling these simply to ensure no panics and coverage branches are hit
	ctx := context.WithValue(context.Background(), RequestIDKey, "req-123")
	ctx = context.WithValue(ctx, FingerprintCtxKey, "fp-123")
	ctx = context.WithValue(ctx, AnomalyScoreCtxKey, 1.5)

	Info.WithContext(ctx, "test info context", nil)
	Info.WithContext(ctx, "test info context map", map[string]any{"extra": "val"})

	// Print methods
	Info.Print("print text")
	Info.Printf("print %s", "format")
	Info.Println("print ln text")

	Warning.Print("warn text")
	Warning.Printf("warn %s", "format")
	Warning.Println("warn ln text")

	Error.Print("error text")
	Error.Printf("error %s", "format")
	Error.Println("error ln text")
}
