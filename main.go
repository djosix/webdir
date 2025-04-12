package main

import (
	"flag"
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
	flag.BoolVar(&opts.NoModify, "no-modify", false, "disable modification feature")
	flag.BoolVar(&opts.CreateWritable, "create-writable", false, "create writable directories and files for other users")

	// Define short flags
	flag.BoolVar(&opts.NoList, "L", false, "shorthand for -no-list")
	flag.BoolVar(&opts.NoModify, "M", false, "shorthand for -no-modify")
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

func init() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, nil)))
}

func main() {
	opts := parseArgs()

	// Initialize and start the server
	server := internal.NewServer(opts)
	server.Start()
}
