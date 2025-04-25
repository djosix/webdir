package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/djosix/webdir/internal"
)

func parseArgs() internal.Options {
	opts := internal.Options{}

	flag.StringVar(&opts.DocumentRoot, "root", ".", "document root")
	flag.StringVar(&opts.Host, "host", "0.0.0.0", "bind host")
	flag.IntVar(&opts.Port, "port", 9999, "bind port")
	flag.BoolVar(&opts.HTTPS, "https", false, "enable TLS")
	flag.StringVar(&opts.BasicAuth, "basic-auth", "", "authentication (<USER:PASS>)")
	flag.BoolVar(&opts.NoList, "no-list", false, "disable directory listing")
	flag.StringVar(&opts.BasePath, "base-path", "", "base web path for the application")
	flag.StringVar(&opts.IndexFile, "index-file", "", "if a directory is requested, serve the index file by default otherwise directory listing")
	flag.BoolVar(&opts.ViewOnly, "view-only", false, "disable modification feature")
	flag.BoolVar(&opts.CreateWritable, "create-writable", false, "create writable directories and files for other users")
	flag.Int64Var(&opts.UploadLimitMiB, "upload-limit", 4096, "maximum upload size in MiB")
	flag.StringVar(&opts.LogLevel, "log", "info", "log level (info, debug, warn, error)")

	// Define short flags
	flag.BoolVar(&opts.NoList, "L", false, "shorthand for -no-list")
	flag.BoolVar(&opts.ViewOnly, "V", false, "shorthand for -view-only")
	flag.BoolVar(&opts.CreateWritable, "W", false, "shorthand for -create-writable")
	flag.StringVar(&opts.BasePath, "B", "", "shorthand for -base-path")
	flag.StringVar(&opts.IndexFile, "I", "", "shorthand for -index-file")
	flag.StringVar(&opts.BasicAuth, "A", "", "shorthand for -basic-auth")
	flag.BoolVar(&opts.HTTPS, "T", false, "shorthand for -https")
	flag.IntVar(&opts.Port, "P", 9999, "shorthand for -port")
	flag.StringVar(&opts.Host, "H", "0.0.0.0", "shorthand for -host")
	flag.StringVar(&opts.DocumentRoot, "R", ".", "shorthand for -root")

	flag.Parse()

	args := flag.Args()
	if len(args) > 0 {
		panic("this command does not accept arguments")
	}

	// Resolve absolute path for document root
	absPath, err := filepath.Abs(opts.DocumentRoot)
	if err != nil {
		panic("cannot resolve document root path")
	}
	opts.DocumentRoot = absPath

	// Clean base path
	if opts.BasePath != "" {
		if !strings.HasPrefix(opts.BasePath, "/") {
			opts.BasePath = "/" + opts.BasePath
		}
		opts.BasePath = strings.TrimSuffix(opts.BasePath, "/")
	}

	return opts
}

func setupLogger(levelString string) {
	var level slog.Level
	if err := level.UnmarshalText([]byte(levelString)); err != nil {
		fmt.Printf("error: invalid log level %q\n", levelString)
		os.Exit(1)
	}

	handler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
	})

	slog.SetDefault(slog.New(handler))
}

func main() {
	opts := parseArgs()

	setupLogger(opts.LogLevel)

	// Initialize and start the server
	server := internal.NewServer(opts)
	server.Start()
}
