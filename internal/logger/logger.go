package logger

import (
	"os"
	"time"

	"github.com/rs/zerolog"
)

// Logger wraps zerolog.Logger with application-specific methods
type Logger struct {
	zerolog.Logger
}

// New creates a new Logger instance
func New(level string, format string) *Logger {
	// Set global log level
	lvl, err := zerolog.ParseLevel(level)
	if err != nil {
		lvl = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(lvl)

	var logger zerolog.Logger

	if format == "text" || format == "console" {
		// Human-readable output for development
		output := zerolog.ConsoleWriter{
			Out:        os.Stdout,
			TimeFormat: time.RFC3339,
		}
		logger = zerolog.New(output).With().Timestamp().Caller().Logger()
	} else {
		// JSON output for production
		logger = zerolog.New(os.Stdout).With().Timestamp().Caller().Logger()
	}

	return &Logger{Logger: logger}
}

// WithRequestID returns a new logger with the request ID attached
func (l *Logger) WithRequestID(requestID string) *Logger {
	return &Logger{
		Logger: l.With().Str("request_id", requestID).Logger(),
	}
}

// WithUserID returns a new logger with the user ID attached
func (l *Logger) WithUserID(userID string) *Logger {
	return &Logger{
		Logger: l.With().Str("user_id", userID).Logger(),
	}
}

// WithComponent returns a new logger with the component name attached
func (l *Logger) WithComponent(component string) *Logger {
	return &Logger{
		Logger: l.With().Str("component", component).Logger(),
	}
}

// HTTPRequest logs an HTTP request
func (l *Logger) HTTPRequest(method, path string, statusCode int, duration time.Duration, clientIP string) {
	l.Info().
		Str("method", method).
		Str("path", path).
		Int("status", statusCode).
		Dur("duration", duration).
		Str("client_ip", clientIP).
		Msg("HTTP request")
}

// AuditLog creates an audit log entry
func (l *Logger) AuditLog(userID, action, resourceType, resourceID string, metadata map[string]interface{}) {
	event := l.Info().
		Str("audit", "true").
		Str("user_id", userID).
		Str("action", action).
		Str("resource_type", resourceType).
		Str("resource_id", resourceID)

	if metadata != nil {
		event.Interface("metadata", metadata)
	}

	event.Msg("audit log")
}
