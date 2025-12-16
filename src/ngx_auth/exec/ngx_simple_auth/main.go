package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/l4go/task"

	"ngx_auth/htstat"

	cfgloader "ngx_auth/config_loader"
	logger "ngx_auth/logger"
)

func die(format string, v ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", v...)
	os.Exit(1)
}

func warn(format string, v ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", v...)
}

type TestAuthConfig struct {
	SocketType      string            `json:"socket_type" yaml:"socket_type"`
	SocketPath      string            `json:"socket_path" yaml:"socket_path"`
	CacheSeconds    uint              `toml:",omitempty" json:"cache_seconds,omitempty" yaml:"cache_seconds,omitempty"`
	NegCacheSeconds uint              `toml:",omitempty" json:"neg_cache_seconds,omitempty" yaml:"neg_cache_seconds,omitempty"`
	UseEtag         bool              `toml:",omitempty" json:"use_etag,omitempty" yaml:"use_etag,omitempty"`
	Password        map[string]string `json:"password" yaml:"password"`
	AuthRealm       string            `json:"auth_realm" yaml:"auth_realm"`

	Response htstat.HttpStatusTbl `toml:",omitempty" json:"response,omitempty" yaml:"response,omitempty"`

	Logging struct {
		EnableConsole bool   `toml:"enable_console,omitempty" json:"enable_console,omitempty" yaml:"enable_console,omitempty"`
		Logfile       string `toml:"logfile,omitempty" json:"logfile,omitempty" yaml:"logfile,omitempty"`
		LoggingLevel  string `toml:"logging_level,omitempty" json:"logging_level,omitempty" yaml:"logging_level,omitempty"`
	} `toml:"logging,omitempty" json:"logging,omitempty" yaml:"logging,omitempty"`
}

var SocketType string
var SocketPath string
var CacheSeconds uint = 0
var NegCacheSeconds uint = 0
var UseEtag bool

var Password map[string]string
var AuthRealm string

var HttpResponse htstat.HttpStatusTbl

var StartTimeMS int64

func init() {
	flag.CommandLine.SetOutput(os.Stderr)
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(),
			"Usage: %s [options ...] <config_file>\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.CommandLine.SetOutput(os.Stderr)

	progName := filepath.Base(os.Args[0])
	log.SetFlags(0)
	logger.SetProgramName(progName)

	flag.Parse()

	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(1)
	}

	cfg_f, err := os.Open(flag.Arg(0))
	if err != nil {
		die("Config file open error: %s", err)
	}
	defer cfg_f.Close()

	cfg := &TestAuthConfig{}
	if err := cfgloader.LoadConfig(cfg_f, flag.Arg(0), cfg); err != nil {
		die("Config file parse error: %s", err)
	}

	// Configure logging
	logger.SetLoggingLevel(cfg.Logging.LoggingLevel)

	SocketType = cfg.SocketType
	SocketPath = cfg.SocketPath

	if SocketType != "tcp" && SocketType != "unix" {
		die("Bad socket type: %s", SocketType)
	}

	CacheSeconds = cfg.CacheSeconds
	NegCacheSeconds = cfg.NegCacheSeconds
	UseEtag = cfg.UseEtag

	if cfg.AuthRealm == "" {
		die("relm is required")
	}
	AuthRealm = cfg.AuthRealm
	Password = cfg.Password

	cfg.Response.SetDefault()
	if !cfg.Response.IsValid() {
		die("response code config error.")
		return
	}
	HttpResponse = cfg.Response

	StartTimeMS = time.Now().UnixMicro()
}

var ErrUnsupportedSocketType = errors.New("unsupported socket type.")

func listen(cc task.Canceller, stype string, spath string) (net.Listener, error) {
	lcnf := &net.ListenConfig{}

	switch stype {
	default:
		return nil, ErrUnsupportedSocketType
	case "unix":
	case "tcp":
	}

	return lcnf.Listen(cc.AsContext(), stype, spath)
}

func main() {
	signal_chan := make(chan os.Signal, 1)
	signal.Notify(signal_chan, syscall.SIGINT, syscall.SIGTERM)

	srv := &http.Server{Addr: SocketPath}

	cc := task.NewCancel()
	defer cc.Cancel()
	go func() {
		select {
		case <-cc.RecvCancel():
		case <-signal_chan:
			cc.Cancel()
		}
		srv.Close()
	}()

	http.HandleFunc("/", TestAuthHandler)

	lstn, lerr := listen(cc, SocketType, SocketPath)
	switch lerr {
	case nil:
	case context.Canceled:
	default:
		die("socket listen error: %v.", lerr)
	}
	if SocketType == "unix" {
		defer os.Remove(SocketPath)
		os.Chmod(SocketPath, 0777)
	}

	if SocketType == "unix" {
		logger.LogWithTime("Server started: socket_type=unix socket_path=%s", SocketPath)
	} else {
		logger.LogWithTime("Server started: socket_type=tcp socket_path=%s", SocketPath)
	}

	serr := srv.Serve(lstn)
	switch serr {
	case nil:
	case http.ErrServerClosed:
	default:
		die("HTTP server error: %v.", serr)
	}
}
