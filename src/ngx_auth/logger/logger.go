package logger

import (
	"fmt"
	"log"
	"sync"
	"time"
)

const (
	LevelMinimum = iota
	LevelNormal
	LevelMaximum
)

var (
	mu       sync.RWMutex
	progName string
	logLevel int
)

func SetProgramName(name string) {
	mu.Lock()
	progName = name
	mu.Unlock()
}

// SetLoggingLevel sets the logging verbosity level.
// "minimum" = LevelMinimum (auth failures only)
// "normal" = LevelNormal (+ auth successes)
// "maximum" = LevelMaximum (+ authz successes)
func SetLoggingLevel(level string) {
	mu.Lock()
	switch {
	case level == "minimum", level == "MINIMUM":
		logLevel = LevelMinimum
	case level == "maximum", level == "MAXIMUM":
		logLevel = LevelMaximum
	default:
		// default to "normal"
		logLevel = LevelNormal
	}
	mu.Unlock()
}

// GetLoggingLevel returns the current logging level.
func GetLoggingLevel() int {
	mu.RLock()
	defer mu.RUnlock()
	return logLevel
}

func LogWithTime(format string, v ...interface{}) {
	timestamp := time.Now().Format("2006/01/02 15:04:05")
	msg := fmt.Sprintf(format, v...)

	mu.RLock()
	pname := progName
	mu.RUnlock()

	var out string
	if pname != "" {
		out = fmt.Sprintf("%s [%s] %s", timestamp, pname, msg)
	} else {
		out = fmt.Sprintf("%s %s", timestamp, msg)
	}

	log.Print(out)
}
