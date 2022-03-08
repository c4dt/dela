// Package dela defines the logger.
//
// Dela stands for DEDIS Ledger Architecture. It defines the modules that will
// be combined to deploy a distributed public ledger.
//
// Dela is using a global logger with some default parameters. It is disabled by
// default and the level can be increased using a environment variable:
//
//   LLVL=trace go test ./...
//   LLVL=info go test ./...
//
package dela

import (
	"os"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/rs/zerolog"
)

// EnvLogLevel is the name of the environment variable to change the logging
// level.
const EnvLogLevel = "LLVL"

// defines prometheus metrics
var (
	promWarns = promauto.NewCounter(prometheus.CounterOpts{
		Name: "dela_log_warns",
		Help: "total number of warnings from the log",
	})

	promErrs = promauto.NewCounter(prometheus.CounterOpts{
		Name: "dela_log_errs",
		Help: "total number of errors from the log",
	})
)

const defaultLevel = zerolog.NoLevel

func init() {
	lvl := os.Getenv(EnvLogLevel)

	var level zerolog.Level

	switch lvl {
	case "error":
		level = zerolog.ErrorLevel
	case "warn":
		level = zerolog.WarnLevel
	case "info":
		level = zerolog.InfoLevel
	case "debug":
		level = zerolog.DebugLevel
	case "trace":
		level = zerolog.TraceLevel
	case "":
		level = defaultLevel
	default:
		level = zerolog.TraceLevel
	}

	Logger = Logger.Level(level)
}

var logout = zerolog.ConsoleWriter{
	Out:        os.Stdout,
	TimeFormat: time.RFC3339,
}

// Logger is a globally available logger instance. By default, it only prints
// error level messages but it can be changed through a environment variable.
var Logger = zerolog.New(logout).Level(defaultLevel).
	With().Timestamp().Logger().
	With().Caller().Logger().
	Hook(promHook{})

// promHook defines a zerolog hook that logs Prometheus metrics. Note that the
// log level MUST be set to at least the WARN level to get metrics.
//
// - implements zerolog.Hook
type promHook struct{}

// Run implements zerolog.Hook
func (promHook) Run(e *zerolog.Event, level zerolog.Level, message string) {
	switch level {
	case zerolog.WarnLevel:
		promWarns.Inc()
	case zerolog.ErrorLevel:
		promErrs.Inc()
	}
}
