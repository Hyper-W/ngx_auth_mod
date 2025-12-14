package logger

import (
	"fmt"
	"log"
	"sync"
	"time"
)

var (
	mu       sync.RWMutex
	progName string
)

func SetProgramName(name string) {
	mu.Lock()
	progName = name
	mu.Unlock()
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
