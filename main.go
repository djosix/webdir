package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/djosix/webdir/internal"
)

func parseArgs() internal.Options {
	opts := internal.Options{}

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
	flag.BoolVar(&opts.NoList, "L", false, "disable directory listing (shorthand)")
	flag.BoolVar(&opts.NoModify, "M", false, "disable modification feature (shorthand)")
	flag.BoolVar(&opts.CreateWritable, "W", false, "create writable directories and files for other users (shorthand)")
	flag.StringVar(&opts.BasePath, "P", "", "base web path for the application (shorthand)")
	flag.StringVar(&opts.IndexFile, "I", "", "if a directory is requested, serve the index file (shorthand)")

	// Custom usage
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: webdir [-h] [-host HOST] [-port PORT] [-https]\n")
		fmt.Fprintf(os.Stderr, "              [-basic-auth <USER:PASS>]\n")
		fmt.Fprintf(os.Stderr, "              [-no-list/-L] [-no-modify/-M]\n")
		fmt.Fprintf(os.Stderr, "              [-create-writable/-W] [-base-path/-P BASE_PATH]\n")
		fmt.Fprintf(os.Stderr, "              [-index-file/-I INDEX_FILE]\n")
		fmt.Fprintf(os.Stderr, "              [DOCUMENT_ROOT]\n\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	args := flag.Args()
	if len(args) > 0 {
		opts.DocumentRoot = args[0]
	} else {
		opts.DocumentRoot = "."
	}

	// Resolve absolute path for document root
	absPath, err := filepath.Abs(opts.DocumentRoot)
	if err != nil {
		log.Fatalf("Error resolving document root path: %v", err)
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

func main() {
	opts := parseArgs()

	// Initialize and start the server
	server := internal.NewServer(opts)
	server.Start()
}
