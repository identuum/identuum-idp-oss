package logger

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type contextKey string

const RequestIDKey contextKey = "request_id"
const CorrelationIDKey contextKey = "correlation_id"
const FingerprintCtxKey contextKey = "fingerprint_id"
const AnomalyScoreCtxKey contextKey = "anomaly_score"

func GetFingerprintFromContext(ctx context.Context) string {
	if fingerprintID, ok := ctx.Value(FingerprintCtxKey).(string); ok {
		return fingerprintID
	}
	return ""
}

// Logger wraps zap.Logger to provide additional functionality
type Logger struct {
	*zap.Logger
	level zapcore.Level
}

// NewLogger constructs a Logger from an existing *zap.Logger and a level hint.
// The level hint is used only by DebugContext to gate debug output; all other
// methods delegate directly to the underlying zap logger's level configuration.
// This is the intended constructor for test-only logger replacements.
func NewLogger(zapLogger *zap.Logger, level zapcore.Level) *Logger {
	return &Logger{zapLogger, level}
}

var (
	// Info logs informational messages
	Info *Logger
	// Warning logs warning messages
	Warning *Logger
	// Error logs error messages
	Error *Logger
	// Debug logs debug messages
	Debug *Logger
	// Security logs security-related events for compliance
	Security *Logger

	// globalLevel allows runtime adjustment of the logging level
	globalLevel zap.AtomicLevel
)

// init seeds the five package-level loggers with no-op
// implementations so any caller that lands here BEFORE
// InitializeZapLogger() runs does not nil-panic. Until
// InitializeZapLogger() runs, Debug/Info/Warning/Error/Security are
// safe to call but produce no output.
//
// P3-12 (2026-07-25): the SERVING runtime initializes the real logger —
// internal/runtime.Runtime.Start calls InitializeZapLogger() as its
// first act, and buildDeps threads the backing zap logger into every
// internal/service Config. An earlier version of this comment claimed
// the package loggers "were only ever consumed by inherited
// monolith-style debug breadcrumbs" and that the (since-removed
// `--gin-serve`) runtime deliberately never initialized zap; both
// claims were false — 103 logger.<Level>. call sites plus 26
// package-level *Context calls exist in non-test code, including 56
// error-class emissions (P-018 requires faults surfaced via
// ERROR-level logs) and the two SOC 2 Security events (SSRF block,
// rate-limit breach). The nop seeding below now exists ONLY for
// library/test contexts and the one-shot operator tools (migrate /
// bootstrap / recover-site-admin), which keep their fmt-based UX and
// stay silent by design.
func init() {
	nop := zap.NewNop()
	Info = &Logger{nop, zapcore.InfoLevel}
	Warning = &Logger{nop, zapcore.WarnLevel}
	Error = &Logger{nop, zapcore.ErrorLevel}
	Debug = &Logger{nop, zapcore.DebugLevel}
	Security = &Logger{nop, zapcore.InfoLevel}
}

func findProjectRoot() string {
	// Start from current working directory
	dir, err := os.Getwd()
	if err != nil {
		return ""
	}

	// Traverse up the directory tree looking for go.mod
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			// Reached filesystem root
			break
		}
		dir = parent
	}

	return ""
}

// ANSI color codes
const (
	Reset       = "\033[0m"
	Red         = "\033[31m"
	Green       = "\033[32m"
	Yellow      = "\033[33m"
	Blue        = "\033[34m"
	Magenta     = "\033[35m"
	Cyan        = "\033[36m"
	White       = "\033[37m"
	BoldRed     = "\033[1;31m"
	BoldGreen   = "\033[1;32m"
	BoldYellow  = "\033[1;33m"
	BoldBlue    = "\033[1;34m"
	BoldMagenta = "\033[1;35m"
	BoldCyan    = "\033[1;36m"
	BoldWhite   = "\033[1;37m"
)

// StatusCodeColor returns the color for HTTP status code
func StatusCodeColor(code int) string {
	switch {
	case code >= 200 && code < 300:
		return Green
	case code >= 300 && code < 400:
		return White
	case code >= 400 && code < 500:
		return Yellow
	default:
		return Red
	}
}

// MethodColor returns the color for HTTP method
func MethodColor(method string) string {
	switch method {
	case "GET":
		return Blue
	case "POST":
		return Cyan
	case "PUT":
		return Yellow
	case "DELETE":
		return Red
	case "PATCH":
		return Green
	case "HEAD":
		return Magenta
	case "OPTIONS":
		return White
	default:
		return Reset
	}
}

// coloredLevelEncoder colors log levels
func coloredLevelEncoder(level zapcore.Level, enc zapcore.PrimitiveArrayEncoder) {
	var color string
	switch level {
	case zapcore.DebugLevel:
		color = Magenta
	case zapcore.InfoLevel:
		color = Green
	case zapcore.WarnLevel:
		color = Yellow
	case zapcore.ErrorLevel:
		color = Red
	case zapcore.DPanicLevel, zapcore.PanicLevel, zapcore.FatalLevel:
		color = BoldRed
	default:
		color = Reset
	}
	enc.AppendString(color + level.CapitalString() + Reset)
}

// InitializeZapLogger initializes the Zap logger with the specified configuration
func InitializeZapLogger() {
	// Determine if we should use colors (development mode or terminal detection)
	useColors := os.Getenv("GIN_MODE") != "release" && isTerminal()

	// Create a custom encoder config
	encoderConfig := zapcore.EncoderConfig{
		TimeKey:        "timestamp",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "caller",
		MessageKey:     "message",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.CapitalLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.SecondsDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}

	// Use colored encoder if in development mode
	if useColors {
		encoderConfig.EncodeLevel = coloredLevelEncoder
	}

	// Create a custom caller encoder that includes file and line number
	encoderConfig.EncodeCaller = func(caller zapcore.EntryCaller, enc zapcore.PrimitiveArrayEncoder) {
		// Get the absolute path
		absPath, err := filepath.Abs(caller.File)
		if err != nil {
			enc.AppendString(caller.TrimmedPath())
			return
		}

		// Try to get the relative path from the workspace
		workspacePath := findProjectRoot()
		if strings.HasPrefix(absPath, workspacePath) {
			// Return path relative to workspace root
			relativePath := strings.TrimPrefix(absPath, workspacePath+"/")
			enc.AppendString(relativePath + ":" + caller.String())
			return
		}

		// If not in workspace, just return the filename and line
		enc.AppendString(filepath.Base(caller.File) + ":" + caller.String())
	}

	// Create the core - use console encoder for colors in dev, JSON for production
	var encoder zapcore.Encoder
	if useColors {
		encoder = zapcore.NewConsoleEncoder(encoderConfig)
	} else {
		encoder = zapcore.NewJSONEncoder(encoderConfig)
	}

	// Determine default log level
	logLevelStr := strings.ToLower(os.Getenv("AUTH_SERVICE_LOG_LEVEL"))
	var zapLevel zapcore.Level

	switch logLevelStr {
	case "debug":
		zapLevel = zapcore.DebugLevel
	case "info":
		zapLevel = zapcore.InfoLevel
	case "warn", "warning":
		zapLevel = zapcore.WarnLevel
	case "error":
		zapLevel = zapcore.ErrorLevel
	default:
		// Default to InfoLevel
		zapLevel = zapcore.InfoLevel
	}

	globalLevel = zap.NewAtomicLevelAt(zapLevel)

	core := zapcore.NewCore(
		encoder,
		zapcore.AddSync(os.Stdout),
		globalLevel,
	)

	// Create the logger with caller information enabled
	baseLogger := zap.New(core, zap.AddCaller(), zap.AddCallerSkip(1))

	// Initialize the package-level loggers
	Info = &Logger{baseLogger, zapcore.InfoLevel}
	Warning = &Logger{baseLogger, zapcore.WarnLevel}
	Error = &Logger{baseLogger, zapcore.ErrorLevel}

	// If atomicLevel is higher than Debug, use a Nop logger for Debug to ensure nothing is logged
	if zapLevel > zapcore.DebugLevel {
		Debug = &Logger{zap.NewNop(), zapcore.DebugLevel}
	} else {
		Debug = &Logger{baseLogger, zapcore.DebugLevel}
	}

	Security = &Logger{baseLogger.With(zap.String("category", "security")), zapcore.WarnLevel} // Tag security events for SOC 2 compliance
}

// SetLevel dynamically adjusts the global logging level
func SetLevel(level string) {
	switch strings.ToLower(level) {
	case "debug":
		globalLevel.SetLevel(zapcore.DebugLevel)
	case "info":
		globalLevel.SetLevel(zapcore.InfoLevel)
	case "warn", "warning":
		globalLevel.SetLevel(zapcore.WarnLevel)
	case "error":
		globalLevel.SetLevel(zapcore.ErrorLevel)
	case "fatal":
		globalLevel.SetLevel(zapcore.FatalLevel)
	}
}

// WithContext adds context values to the logger
func (l *Logger) WithContext(ctx context.Context, message string, fields map[string]any) {
	if fields == nil {
		fields = make(map[string]any)
	}

	if requestID, ok := ctx.Value(RequestIDKey).(string); ok {
		fields["request_id"] = requestID
	}
	if fp := GetFingerprintFromContext(ctx); fp != "" {
		fields["fingerprint_id"] = fp
	}
	if score, ok := ctx.Value(AnomalyScoreCtxKey).(float64); ok {
		fields["anomaly_score"] = score
	}

	// Convert fields to zap fields
	zapFields := make([]zap.Field, 0, len(fields))
	for k, v := range fields {
		zapFields = append(zapFields, zap.Any(k, v))
	}

	l.Info(message, zapFields...)
}

// WithField adds a field to the logger
func (l *Logger) WithField(key string, value any) *Logger {
	return &Logger{l.With(zap.Any(key, value)), l.level}
}

// extractContextFields extracts metadata from context (e.g. RequestID)
func (l *Logger) extractContextFields(ctx context.Context, fields []zap.Field) []zap.Field {
	if requestID, ok := ctx.Value(RequestIDKey).(string); ok {
		fields = append(fields, zap.String("request_id", requestID))
	}
	if fp := GetFingerprintFromContext(ctx); fp != "" {
		fields = append(fields, zap.String("fingerprint_id", fp))
	}
	if score, ok := ctx.Value(AnomalyScoreCtxKey).(float64); ok {
		fields = append(fields, zap.Float64("anomaly_score", score))
	}
	return fields
}

// InfoContext logs a message at InfoLevel with context metadata
func (l *Logger) InfoContext(ctx context.Context, msg string, fields ...zap.Field) {
	l.Info(msg, l.extractContextFields(ctx, fields)...)
}

// WarnContext logs a message at WarnLevel with context metadata
func (l *Logger) WarnContext(ctx context.Context, msg string, fields ...zap.Field) {
	l.Warn(msg, l.extractContextFields(ctx, fields)...)
}

// ErrorContext logs a message at ErrorLevel with context metadata
func (l *Logger) ErrorContext(ctx context.Context, msg string, fields ...zap.Field) {
	l.Error(msg, l.extractContextFields(ctx, fields)...)
}

// DebugContext logs a message at DebugLevel with context metadata
func (l *Logger) DebugContext(ctx context.Context, msg string, fields ...zap.Field) {
	if l.level > zapcore.DebugLevel {
		return
	}
	l.Debug(msg, l.extractContextFields(ctx, fields)...)
}

// WithFields adds multiple fields to the logger
func (l *Logger) WithFields(fields map[string]any) *Logger {
	zapFields := make([]zap.Field, 0, len(fields))
	for k, v := range fields {
		zapFields = append(zapFields, zap.Any(k, v))
	}
	return &Logger{l.With(zapFields...), l.level}
}

// Package-level context methods for convenience

// InfoContext logs at Info level using the global Info logger
func InfoContext(ctx context.Context, msg string, fields ...zap.Field) {
	Info.InfoContext(ctx, msg, fields...)
}

// WarnContext logs at Warn level using the global Warning logger
func WarnContext(ctx context.Context, msg string, fields ...zap.Field) {
	Warning.WarnContext(ctx, msg, fields...)
}

// ErrorContext logs at Error level using the global Error logger
func ErrorContext(ctx context.Context, msg string, fields ...zap.Field) {
	Error.ErrorContext(ctx, msg, fields...)
}

// DebugContext logs at Debug level using the global Debug logger
func DebugContext(ctx context.Context, msg string, fields ...zap.Field) {
	Debug.DebugContext(ctx, msg, fields...)
}

// Print/Printf methods to maintain compatibility with the old logger interface
// These now respect the logger level
func (l *Logger) Print(v ...any) {
	if !l.Logger.Core().Enabled(l.level) {
		return
	}
	msg := fmt.Sprint(v...)
	switch l.level {
	case zapcore.DebugLevel:
		l.Debug(msg)
	case zapcore.InfoLevel:
		l.Info(msg)
	case zapcore.WarnLevel:
		l.Warn(msg)
	case zapcore.ErrorLevel:
		l.Error(msg)
	default:
		l.Info(msg)
	}
}

func (l *Logger) Printf(format string, v ...any) {
	if !l.Logger.Core().Enabled(l.level) {
		return
	}
	msg := fmt.Sprintf(format, v...)
	switch l.level {
	case zapcore.DebugLevel:
		l.Debug(msg)
	case zapcore.InfoLevel:
		l.Info(msg)
	case zapcore.WarnLevel:
		l.Warn(msg)
	case zapcore.ErrorLevel:
		l.Error(msg)
	default:
		l.Info(msg)
	}
}

func (l *Logger) Println(v ...any) {
	if !l.Logger.Core().Enabled(l.level) {
		return
	}
	msg := fmt.Sprintln(v...)
	switch l.level {
	case zapcore.DebugLevel:
		l.Debug(msg)
	case zapcore.InfoLevel:
		l.Info(msg)
	case zapcore.WarnLevel:
		l.Warn(msg)
	case zapcore.ErrorLevel:
		l.Error(msg)
	default:
		l.Info(msg)
	}
}

func (l *Logger) Fatal(v ...any) {
	l.Logger.Fatal(fmt.Sprint(v...))
	os.Exit(1)
}

func (l *Logger) Fatalf(format string, v ...any) {
	l.Logger.Fatal(fmt.Sprintf(format, v...))
	os.Exit(1)
}

func (l *Logger) Fatalln(v ...any) {
	l.Logger.Fatal(fmt.Sprintln(v...))
	os.Exit(1)
}

// Package-level convenience methods
func WithField(key string, value any) *Logger {
	return Info.WithField(key, value)
}

func WithFields(fields map[string]any) *Logger {
	return Info.WithFields(fields)
}

// Package-level WithContext for backward compatibility
func WithContext(ctx context.Context, message string, fields map[string]any) {
	Info.WithContext(ctx, message, fields)
}

// isTerminal checks if stdout is a terminal
func isTerminal() bool {
	fileInfo, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (fileInfo.Mode() & os.ModeCharDevice) != 0
}
