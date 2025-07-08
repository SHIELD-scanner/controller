package internal

import (
	"os"
	"os/signal"
	"syscall"

	l "github.com/ricardomolendijk/loggerz"
)

func SetupLogger(logLevel string, logDir string, saveLogs bool) {
	debug := logLevel == "DEBUG" || logLevel == "debug"
	logFile, err := l.NewLogger(debug, logDir, saveLogs)
	if err != nil {
		l.Fatal("Failed to set up logging", "error", err)
	}
	if logFile != nil {
		go func() {
			c := make(chan os.Signal, 1)
			signal.Notify(c, os.Interrupt, syscall.SIGTERM)
			<-c
			logFile.Close()
			os.Exit(0)
		}()
	}
}
