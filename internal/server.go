package internal

import (
	"crypto/tls"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Server encapsulates the HTTP server and its configuration
type Server struct {
	Options Options
	Mux     *http.ServeMux
}

// NewServer creates a new server instance
func NewServer(opts Options) *Server {
	server := &Server{
		Options: opts,
		Mux:     http.NewServeMux(),
	}

	// Setup routes
	server.setupRoutes()

	return server
}

// Start begins the HTTP server
func (s *Server) Start() {
	addr := fmt.Sprintf("%s:%d", s.Options.Host, s.Options.Port)

	// Create server
	srv := &http.Server{
		Addr:    addr,
		Handler: s.authMiddleware(s.Mux),
	}

	// Start server
	slog.Info("start server", "addr", addr, "root", s.Options.DocumentRoot)
	var serveErr error

	if s.Options.HTTPS {
		// Load the embedded self-signed certificate
		cert, err := newSelfSignedCert()
		if err != nil {
			slog.Error("failed to load tls certificate", "error", err)
		}

		srv.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
		}

		slog.Info("https enabled with self-signed certificate")
		serveErr = srv.ListenAndServeTLS("", "")
	} else {
		serveErr = srv.ListenAndServe()
	}

	if serveErr != nil {
		slog.Error("server shutdown", "error", serveErr)
	}
}

// setupRoutes initializes the HTTP route handlers
func (s *Server) setupRoutes() {
	// Catch-all handler for both API requests and file/directory access
	s.Mux.HandleFunc(s.prefixPath("/"), s.handleRequest)
}

// prefixPath adds the base path prefix to the given path
func (s *Server) prefixPath(path string) string {
	if s.Options.BasePath == "" {
		return path
	}
	return s.Options.BasePath + path
}

// relativePath converts a web path to a filesystem path
func (s *Server) relativePath(webPath string) string {
	// Remove the base path prefix if it exists
	if s.Options.BasePath != "" && strings.HasPrefix(webPath, s.Options.BasePath) {
		webPath = webPath[len(s.Options.BasePath):]
	}

	// Ensure the path starts with / for consistency
	if !strings.HasPrefix(webPath, "/") {
		webPath = "/" + webPath
	}

	// Convert to a relative path
	rel := strings.TrimPrefix(webPath, "/")
	if rel == "" {
		return "."
	}
	return rel
}

// absolutePath converts a web path to an absolute filesystem path
func (s *Server) absolutePath(webPath string) string {
	relPath := s.relativePath(webPath)
	absPath := filepath.Join(s.Options.DocumentRoot, relPath)
	return absPath
}

// webPath converts a filesystem path to a web path
func (s *Server) webPath(fsPath string) string {
	// Convert absolute path to relative to document root
	rel, err := filepath.Rel(s.Options.DocumentRoot, fsPath)
	if err != nil {
		return ""
	}

	// Convert to web path format (use forward slashes)
	webPath := filepath.ToSlash(rel)

	// Add leading slash
	if !strings.HasPrefix(webPath, "/") {
		webPath = "/" + webPath
	}

	// Add base path if configured
	if s.Options.BasePath != "" {
		webPath = s.Options.BasePath + webPath
	}

	return webPath
}

// authMiddleware implements HTTP Basic Authentication if enabled
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip auth if not configured
		if s.Options.BasicAuth == "" {
			next.ServeHTTP(w, r)
			return
		}

		// Check for Authorization header
		auth := r.Header.Get("Authorization")
		if auth == "" {
			w.Header().Set("WWW-Authenticate", `Basic realm="webdir"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Decode the Authorization header
		prefix := "Basic "
		if !strings.HasPrefix(auth, prefix) {
			http.Error(w, "Invalid Authorization header", http.StatusUnauthorized)
			return
		}

		decoded, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
		if err != nil {
			http.Error(w, "Invalid Authorization header", http.StatusUnauthorized)
			return
		}

		// Check credentials
		if string(decoded) != s.Options.BasicAuth {
			w.Header().Set("WWW-Authenticate", `Basic realm="webdir"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Authentication successful
		next.ServeHTTP(w, r)
	})
}

// isPathSafe checks if a path is safe to access (doesn't escape document root)
func (s *Server) isPathSafe(path string) bool {
	// Convert to absolute path
	absPath, err := filepath.Abs(path)
	if err != nil {
		return false
	}

	// Check if the path is within document root
	docRoot, err := filepath.Abs(s.Options.DocumentRoot)
	if err != nil {
		return false
	}

	return strings.HasPrefix(absPath, docRoot)
}

// handleRequest handles both API requests and file/directory access
func (s *Server) handleRequest(w http.ResponseWriter, r *http.Request) {
	// Check if this is an API request
	if apiType := r.URL.Query().Get("api"); apiType != "" {
		// Handle API request
		s.handleAPIRequest(w, r, apiType)
		return
	}

	// Regular file/directory request
	// Get the relative path from the URL
	urlPath := r.URL.Path
	fsPath := s.absolutePath(urlPath)

	// Check for curl upload using multipart/form-data with 'upload' field
	if r.Method == http.MethodPost && strings.Contains(r.Header.Get("Content-Type"), "multipart/form-data") {
		var sizeLimit int64 = 4 << 30 // 4 GiB
		if err := r.ParseMultipartForm(sizeLimit); err != nil {
			http.Error(w, "File too large for upload", http.StatusBadRequest)
			return
		}
		if r.MultipartForm == nil || len(r.MultipartForm.File["upload"]) == 0 {
			http.Error(w, "Invalid upload request", http.StatusBadRequest)
			return
		}
		// Handle as a file upload request
		s.handleAPIRequest(w, r, "upload")
		return
	}

	// Check if the path is safe
	if !s.isPathSafe(fsPath) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Get file info
	info, err := os.Stat(fsPath)
	if err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "Not Found", http.StatusNotFound)
		} else {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
		return
	}

	// Handle directory
	if info.IsDir() {
		// Check for index file if configured
		if s.Options.IndexFile != "" {
			indexPath := filepath.Join(fsPath, s.Options.IndexFile)
			if _, err := os.Stat(indexPath); err == nil {
				http.ServeFile(w, r, indexPath)
				return
			}
		}

		// Handle directory listing
		if s.Options.NoList {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		// Serve directory listing HTML
		s.serveDirectoryListing(w, r, fsPath, urlPath)
		return
	}

	// Serve file directly using ServeContent to prevent unwanted redirections
	file, err := os.Open(fsPath)
	if err != nil {
		http.Error(w, "Error opening file", http.StatusInternalServerError)
		return
	}
	defer file.Close()

	// Get file information for the modtime
	stat, err := file.Stat()
	if err != nil {
		http.Error(w, "Error getting file info", http.StatusInternalServerError)
		return
	}

	// Set content type based on file extension
	contentType := mime.TypeByExtension(filepath.Ext(fsPath))
	if contentType != "" {
		w.Header().Set("Content-Type", contentType)
	}

	// Use ServeContent which doesn't do redirections for /index.html
	http.ServeContent(w, r, filepath.Base(fsPath), stat.ModTime(), file)
}

//go:embed index.html
var directoryListingTemplate string

// serveDirectoryListing generates and serves the HTML for directory listing
func (s *Server) serveDirectoryListing(w http.ResponseWriter, r *http.Request, fsPath, urlPath string) {
	htmlContent := directoryListingTemplate

	// Add no-modify indicator if modifications are disabled
	if s.Options.NoModify {
		htmlContent = strings.Replace(htmlContent, "<body>", "<body data-no-modify=\"true\">", 1)
	}

	// Set proper caching headers to improve performance
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(htmlContent))
}

// FileInfo represents information about a file or directory for the API
type FileInfo struct {
	Name       string    `json:"name"`
	Path       string    `json:"path"`
	Size       int64     `json:"size"`
	HumanSize  string    `json:"humanSize"`
	IsDir      bool      `json:"isDir"`
	Permission string    `json:"permission"`
	ModTime    time.Time `json:"modTime"`
}

// DirectoryContents represents the contents of a directory for the API
type DirectoryContents struct {
	Path     string     `json:"path"`
	Entries  []FileInfo `json:"entries"`
	Writable bool       `json:"writable"`
}

// APIResponse represents a standard API response
type APIResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// handleAPIList handles the list directory API endpoint
func (s *Server) handleAPIList(w http.ResponseWriter, r *http.Request) {
	// Only allow GET requests
	if r.Method != http.MethodGet {
		sendJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get the path from the query string
	path := r.URL.Query().Get("path")
	if path == "" {
		path = "/"
	}

	// Get the absolute filesystem path
	fsPath := s.absolutePath(path)
	if !s.isPathSafe(fsPath) {
		sendJSONError(w, "Forbidden: Path outside document root", http.StatusForbidden)
		return
	}

	// Get filter pattern if provided
	filterPattern := r.URL.Query().Get("filter")
	var re *regexp.Regexp
	if filterPattern != "" {
		var err error
		re, err = regexp.Compile(filterPattern)
		if err != nil {
			sendJSONError(w, "Invalid filter pattern", http.StatusBadRequest)
			return
		}
	}

	// Check if the directory exists
	info, err := os.Stat(fsPath)
	if err != nil {
		if os.IsNotExist(err) {
			sendJSONError(w, "Directory not found", http.StatusNotFound)
		} else {
			sendJSONError(w, "Failed to access directory", http.StatusInternalServerError)
		}
		return
	}

	// Ensure it's a directory
	if !info.IsDir() {
		sendJSONError(w, "Not a directory", http.StatusBadRequest)
		return
	}

	// Read directory contents
	contents, err := s.readDirectoryContents(fsPath, re)
	if err != nil {
		sendJSONError(w, "Failed to read directory: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Send response
	sendJSONResponse(w, APIResponse{
		Success: true,
		Message: "Directory listed successfully",
		Data:    contents,
	})
}

// readDirectoryContents reads and returns the contents of a directory
func (s *Server) readDirectoryContents(dirPath string, filter *regexp.Regexp) (DirectoryContents, error) {
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return DirectoryContents{}, err
	}

	// Check if the directory is writable
	writable := isWritable(dirPath)

	// Create result
	result := DirectoryContents{
		Path:     s.webPath(dirPath),
		Writable: writable,
		Entries:  make([]FileInfo, 0, len(entries)),
	}

	// Process each entry
	for _, entry := range entries {
		name := entry.Name()

		// Apply filter if set
		if filter != nil && !filter.MatchString(name) {
			continue
		}

		entryPath := filepath.Join(dirPath, name)
		info, err := entry.Info()
		if err != nil {
			continue // Skip entries with errors
		}

		// Create file info
		fileInfo := FileInfo{
			Name:       name,
			Path:       s.webPath(entryPath),
			Size:       info.Size(),
			HumanSize:  humanReadableSize(info.Size()),
			IsDir:      info.IsDir(),
			Permission: getPermissionString(entryPath),
			ModTime:    info.ModTime(),
		}

		// Add trailing slash for directories in path
		if info.IsDir() && !strings.HasSuffix(fileInfo.Path, "/") {
			fileInfo.Path += "/"
			fileInfo.Name += "/"
		}

		result.Entries = append(result.Entries, fileInfo)
	}

	// Sort entries: directories first, then by name
	sort.Slice(result.Entries, func(i, j int) bool {
		if result.Entries[i].IsDir != result.Entries[j].IsDir {
			return result.Entries[i].IsDir
		}
		return result.Entries[i].Name < result.Entries[j].Name
	})

	return result, nil
}

// handleAPIRequest dispatches API requests to the appropriate handler
func (s *Server) handleAPIRequest(w http.ResponseWriter, r *http.Request, apiType string) {
	// Set common headers
	w.Header().Set("Content-Type", "application/json")

	// Dispatch to the appropriate handler based on apiType
	switch apiType {
	case "list":
		s.handleAPIList(w, r)
	case "mkdir":
		s.handleAPIMkdir(w, r)
	case "upload":
		s.handleAPIUpload(w, r)
	case "move":
		s.handleAPIMove(w, r)
	case "copy":
		s.handleAPICopy(w, r)
	case "delete":
		s.handleAPIDelete(w, r)
	case "edit":
		s.handleAPIEdit(w, r)
	default:
		sendJSONError(w, "Unknown API endpoint", http.StatusNotFound)
	}
}

// sendJSONResponse sends a JSON response
func sendJSONResponse(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")

	jsonData, err := json.Marshal(data)
	if err != nil {
		http.Error(w, "Failed to encode JSON", http.StatusInternalServerError)
		return
	}

	w.Write(jsonData)
}

// sendJSONError sends a JSON error response
func sendJSONError(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	response := APIResponse{
		Success: false,
		Message: message,
	}

	jsonData, err := json.Marshal(response)
	if err != nil {
		http.Error(w, "Failed to encode JSON", http.StatusInternalServerError)
		return
	}

	w.Write(jsonData)
}

// humanReadableSize converts a size in bytes to a human-readable string using IEC binary prefixes (KiB, MiB, etc.).
func humanReadableSize(size int64) string {
	const unit = 1024
	units := []string{"B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"}

	if size == 0 {
		return "0 B"
	}

	if size < unit {
		return fmt.Sprintf("%d B", size)
	}

	value := float64(size)
	exponent := 0

	for value >= unit && exponent < len(units)-1 {
		value /= unit
		exponent++
	}

	formattedValue := fmt.Sprintf("%.1f", value)
	formattedValue = strings.TrimSuffix(formattedValue, ".0")

	return fmt.Sprintf("%s %s", formattedValue, units[exponent])
}

// getPermissionString returns a permission string ("Read", "Write", "Read, Write", or "")
func getPermissionString(path string) string {
	var permissions []string

	// Get file info to check permissions
	info, err := os.Stat(path)
	if err != nil {
		return ""
	}

	// Get file mode and check read permission
	mode := info.Mode()

	// Check read permission
	if mode&0444 != 0 {
		permissions = append(permissions, "Read")
	}

	// Check write permission
	if mode&0222 != 0 {
		permissions = append(permissions, "Write")
	}

	// Join the permissions with a comma
	return strings.Join(permissions, ", ")
}

// isWritable checks if a file or directory is writable using file stat
func isWritable(path string) bool {
	// Get file info to check permissions
	info, err := os.Stat(path)
	if err != nil {
		return false
	}

	// Get file mode and check write permission
	mode := info.Mode()

	// Check if writable by owner, group, or others
	return mode&0222 != 0
}

// APIRequest represents a standard API request structure
type APIRequest struct {
	Action  string   `json:"action"`
	Path    string   `json:"path"`
	Target  string   `json:"target,omitempty"`
	Paths   []string `json:"paths,omitempty"`
	Content string   `json:"content,omitempty"`
}

// handleAPIMkdir handles the create directory API endpoint
func (s *Server) handleAPIMkdir(w http.ResponseWriter, r *http.Request) {
	// Only allow POST requests
	if r.Method != http.MethodPost {
		sendJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Reject if modification is disabled
	if s.Options.NoModify {
		sendJSONError(w, "Modification is disabled", http.StatusForbidden)
		return
	}

	// Parse the request body
	var req APIRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSONError(w, "Invalid request: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Ensure path is provided
	if req.Path == "" {
		sendJSONError(w, "Path is required", http.StatusBadRequest)
		return
	}

	// Get the absolute filesystem path
	fsPath := s.absolutePath(req.Path)
	if !s.isPathSafe(fsPath) {
		sendJSONError(w, "Forbidden: Path outside document root", http.StatusForbidden)
		return
	}

	// Create the directory with all parents (mkdir -p behavior)
	if err := os.MkdirAll(fsPath, 0755); err != nil {
		sendJSONError(w, "Failed to create directory: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// If create writable flag is set, make the directory writable for others
	if s.Options.CreateWritable {
		if err := os.Chmod(fsPath, 0777); err != nil {
			// Log but don't fail the request
			slog.Warn("failed to set directory permissions", "error", err)
		}
	}

	// Send success response
	sendJSONResponse(w, APIResponse{
		Success: true,
		Message: "Directory created successfully",
		Data: map[string]string{
			"path": req.Path,
		},
	})
}

// handleAPIUpload handles file uploads
func (s *Server) handleAPIUpload(w http.ResponseWriter, r *http.Request) {
	// Only allow POST requests
	if r.Method != http.MethodPost {
		sendJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Reject if modification is disabled
	if s.Options.NoModify {
		sendJSONError(w, "Modification is disabled", http.StatusForbidden)
		return
	}

	// Parse multipart form with 10MB limit (adjustable) if not already parsed
	if r.MultipartForm == nil {
		if err := r.ParseMultipartForm(10 << 20); err != nil {
			sendJSONError(w, "Failed to parse upload form: "+err.Error(), http.StatusBadRequest)
			return
		}
	}

	// Get the destination path from form or URL query parameter
	destPath := r.FormValue("path")
	if destPath == "" {
		// Try to get from URL query
		destPath = r.URL.Path
	}

	if destPath == "" {
		destPath = "/"
	}

	// Convert to filesystem path and ensure it's safe
	destFsPath := s.absolutePath(destPath)
	if !s.isPathSafe(destFsPath) {
		sendJSONError(w, "Forbidden: Path outside document root", http.StatusForbidden)
		return
	}

	// Check if destination is a directory
	destInfo, err := os.Stat(destFsPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Check if the destFsPath has an extension, which would indicate it's a file
			if filepath.Ext(destFsPath) != "" {
				// Create parent directories if they don't exist
				if err := os.MkdirAll(filepath.Dir(destFsPath), 0755); err != nil {
					sendJSONError(w, "Failed to create parent directories: "+err.Error(), http.StatusInternalServerError)
					return
				}
			} else {
				// If no extension, treat as a directory and create it
				if err := os.MkdirAll(destFsPath, 0755); err != nil {
					sendJSONError(w, "Failed to create directory: "+err.Error(), http.StatusInternalServerError)
					return
				}
				// Update destInfo after creating the directory
				destInfo, _ = os.Stat(destFsPath)
			}
		} else {
			sendJSONError(w, "Failed to access destination: "+err.Error(), http.StatusInternalServerError)
			return
		}
	} else if destInfo.IsDir() {
		// If destination is a directory, we'll save the files in it
	} else {
		// Destination exists but is not a directory - we'll replace the file
	}

	// Process uploaded files
	fileCount := 0
	var uploadedFiles []string

	// Handle files from multipart form
	for _, fileHeaders := range r.MultipartForm.File {
		for _, fileHeader := range fileHeaders {
			// Open the uploaded file
			file, err := fileHeader.Open()
			if err != nil {
				sendJSONError(w, "Failed to open uploaded file: "+err.Error(), http.StatusInternalServerError)
				return
			}
			defer file.Close()

			// Determine the target path
			var targetPath string
			if destInfo != nil && destInfo.IsDir() {
				targetPath = filepath.Join(destFsPath, fileHeader.Filename)
			} else {
				targetPath = destFsPath
			}

			// Create the destination file
			destFile, err := os.Create(targetPath)
			if err != nil {
				sendJSONError(w, "Failed to create file: "+err.Error(), http.StatusInternalServerError)
				return
			}
			defer destFile.Close()

			// Copy the file contents using io.Copy
			bytesWritten, err := io.Copy(destFile, file)
			if err != nil {
				sendJSONError(w, "Failed to save file: "+err.Error(), http.StatusInternalServerError)
				return
			}
			// Log the file size
			slog.Debug("uploaded file", "filename", fileHeader.Filename, "size", bytesWritten, "path", targetPath)

			// If create writable flag is set, make the file writable for others
			if s.Options.CreateWritable {
				if err := os.Chmod(targetPath, 0666); err != nil {
					// Log but don't fail the request
					slog.Warn("failed to set file permissions", "error", err)
				}
			}

			fileCount++
			uploadedFiles = append(uploadedFiles, s.webPath(targetPath))
		}
	}

	// If no files were uploaded through the multipart form, check for a raw file upload
	if fileCount == 0 {
		// Create the target file
		var targetPath string
		if destInfo != nil && destInfo.IsDir() {
			// If destination is a directory and no filename is specified, use a default
			targetPath = filepath.Join(destFsPath, "upload")
		} else {
			targetPath = destFsPath
		}

		// Create the destination file
		destFile, err := os.Create(targetPath)
		if err != nil {
			sendJSONError(w, "Failed to create file: "+err.Error(), http.StatusInternalServerError)
			return
		}
		defer destFile.Close()

		// Copy the request body to the file
		if _, err := io.Copy(destFile, r.Body); err != nil {
			sendJSONError(w, "Failed to save file: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// If create writable flag is set, make the file writable for others
		if s.Options.CreateWritable {
			if err := os.Chmod(targetPath, 0666); err != nil {
				// Log but don't fail the request
				slog.Warn("failed to set file permissions", "error", err)
			}
		}

		fileCount++
		uploadedFiles = append(uploadedFiles, s.webPath(targetPath))
	}

	// Send success response
	sendJSONResponse(w, APIResponse{
		Success: true,
		Message: fmt.Sprintf("Successfully uploaded %d file(s)", fileCount),
		Data: map[string]interface{}{
			"count": fileCount,
			"files": uploadedFiles,
		},
	})
}

// handleAPICopy handles copy operations (similar to cp -r)
func (s *Server) handleAPICopy(w http.ResponseWriter, r *http.Request) {
	// Only allow POST requests
	if r.Method != http.MethodPost {
		sendJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Reject if modification is disabled
	if s.Options.NoModify {
		sendJSONError(w, "Modification is disabled", http.StatusForbidden)
		return
	}

	// Parse the request body
	var req APIRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSONError(w, "Invalid request: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Validate request - we need source paths and a target
	if len(req.Paths) == 0 && req.Path == "" {
		sendJSONError(w, "Source path(s) required", http.StatusBadRequest)
		return
	}
	if req.Target == "" {
		sendJSONError(w, "Target path required", http.StatusBadRequest)
		return
	}

	// If single path is provided, add it to paths array
	paths := req.Paths
	if req.Path != "" && len(paths) == 0 {
		paths = []string{req.Path}
	}

	// Convert target to filesystem path and ensure it's safe
	targetFsPath := s.absolutePath(req.Target)
	if !s.isPathSafe(targetFsPath) {
		sendJSONError(w, "Forbidden: Target path outside document root", http.StatusForbidden)
		return
	}

	// Check if target is a directory
	targetInfo, err := os.Stat(targetFsPath)
	isTargetDir := err == nil && targetInfo.IsDir()

	// Process each source path
	copied := 0
	errors := []string{}

	for _, path := range paths {
		// Convert to filesystem path and ensure it's safe
		sourceFsPath := s.absolutePath(path)
		if !s.isPathSafe(sourceFsPath) {
			errors = append(errors, fmt.Sprintf("Forbidden: Source path outside document root: %s", path))
			continue
		}

		// Determine the final target path
		var finalTargetPath string
		if isTargetDir {
			// When target is a directory, always copy into it
			finalTargetPath = filepath.Join(targetFsPath, filepath.Base(sourceFsPath))
		} else {
			finalTargetPath = targetFsPath
		}

		// Create parent directories if they don't exist
		if err := os.MkdirAll(filepath.Dir(finalTargetPath), 0755); err != nil {
			errors = append(errors, fmt.Sprintf("Failed to create parent directories for %s: %s", path, err.Error()))
			continue
		}

		// Get source file info
		sourceInfo, err := os.Stat(sourceFsPath)
		if err != nil {
			errors = append(errors, fmt.Sprintf("Failed to access source %s: %s", path, err.Error()))
			continue
		}

		// Perform the copy operation based on whether it's a file or directory
		if sourceInfo.IsDir() {
			// Copy directory recursively
			if err := copyDir(sourceFsPath, finalTargetPath); err != nil {
				errors = append(errors, fmt.Sprintf("Failed to copy directory %s: %s", path, err.Error()))
				continue
			}
		} else {
			// Copy file
			if err := copyFile(sourceFsPath, finalTargetPath); err != nil {
				errors = append(errors, fmt.Sprintf("Failed to copy file %s: %s", path, err.Error()))
				continue
			}
		}

		copied++
	}

	// Send response
	if len(errors) > 0 {
		sendJSONResponse(w, APIResponse{
			Success: copied > 0,
			Message: fmt.Sprintf("Copied %d out of %d items. Errors: %s", copied, len(paths), strings.Join(errors, "; ")),
			Data: map[string]interface{}{
				"copied": copied,
				"total":  len(paths),
				"errors": errors,
			},
		})
	} else {
		sendJSONResponse(w, APIResponse{
			Success: true,
			Message: fmt.Sprintf("Successfully copied %d item(s)", copied),
			Data: map[string]interface{}{
				"copied": copied,
				"total":  len(paths),
			},
		})
	}
}

// copyFile copies a single file from src to dst
func copyFile(src, dst string) error {
	// Open source file
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	// Create destination file
	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destFile.Close()

	// Copy content
	if _, err := io.Copy(destFile, sourceFile); err != nil {
		return err
	}

	// Get source file info to copy permissions
	sourceInfo, err := os.Stat(src)
	if err != nil {
		return err
	}

	// Copy file permissions
	return os.Chmod(dst, sourceInfo.Mode())
}

// copyDir recursively copies a directory from src to dst
func copyDir(src, dst string) error {
	// Get source directory info
	srcInfo, err := os.Stat(src)
	if err != nil {
		return err
	}

	// Create destination directory with same permissions
	if err := os.MkdirAll(dst, srcInfo.Mode()); err != nil {
		return err
	}

	// Read source directory entries
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}

	// Process each entry
	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())

		if entry.IsDir() {
			// Recursively copy subdirectory
			if err := copyDir(srcPath, dstPath); err != nil {
				return err
			}
		} else {
			// Copy file
			if err := copyFile(srcPath, dstPath); err != nil {
				return err
			}
		}
	}

	return nil
}

// handleAPIMove handles move/rename operations
func (s *Server) handleAPIMove(w http.ResponseWriter, r *http.Request) {
	// Only allow POST requests
	if r.Method != http.MethodPost {
		sendJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Reject if modification is disabled
	if s.Options.NoModify {
		sendJSONError(w, "Modification is disabled", http.StatusForbidden)
		return
	}

	// Parse the request body
	var req APIRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSONError(w, "Invalid request: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Validate request - we need source paths and a target
	if len(req.Paths) == 0 && req.Path == "" {
		sendJSONError(w, "Source path(s) required", http.StatusBadRequest)
		return
	}
	if req.Target == "" {
		sendJSONError(w, "Target path required", http.StatusBadRequest)
		return
	}

	// If single path is provided, add it to paths array
	paths := req.Paths
	if req.Path != "" && len(paths) == 0 {
		paths = []string{req.Path}
	}

	// Convert target to filesystem path and ensure it's safe
	targetFsPath := s.absolutePath(req.Target)
	if !s.isPathSafe(targetFsPath) {
		sendJSONError(w, "Forbidden: Target path outside document root", http.StatusForbidden)
		return
	}

	// Check if target is a directory
	targetInfo, err := os.Stat(targetFsPath)
	isTargetDir := err == nil && targetInfo.IsDir()

	// Process each source path
	moved := 0
	errors := []string{}

	for _, path := range paths {
		// Convert to filesystem path and ensure it's safe
		sourceFsPath := s.absolutePath(path)
		if !s.isPathSafe(sourceFsPath) {
			errors = append(errors, fmt.Sprintf("Forbidden: Source path outside document root: %s", path))
			continue
		}

		// Determine the final target path
		var finalTargetPath string
		if isTargetDir && len(paths) > 1 {
			// When moving multiple items to a directory
			finalTargetPath = filepath.Join(targetFsPath, filepath.Base(sourceFsPath))
		} else {
			finalTargetPath = targetFsPath
		}

		// Create parent directories if they don't exist
		if err := os.MkdirAll(filepath.Dir(finalTargetPath), 0755); err != nil {
			errors = append(errors, fmt.Sprintf("Failed to create parent directories for %s: %s", path, err.Error()))
			continue
		}

		// Perform the move operation
		if err := os.Rename(sourceFsPath, finalTargetPath); err != nil {
			errors = append(errors, fmt.Sprintf("Failed to move %s: %s", path, err.Error()))
			continue
		}

		moved++
	}

	// Send response
	if len(errors) > 0 {
		sendJSONResponse(w, APIResponse{
			Success: moved > 0,
			Message: fmt.Sprintf("Moved %d out of %d items. Errors: %s", moved, len(paths), strings.Join(errors, "; ")),
			Data: map[string]interface{}{
				"moved":  moved,
				"total":  len(paths),
				"errors": errors,
			},
		})
	} else {
		sendJSONResponse(w, APIResponse{
			Success: true,
			Message: fmt.Sprintf("Successfully moved %d item(s)", moved),
			Data: map[string]interface{}{
				"moved": moved,
				"total": len(paths),
			},
		})
	}
}

// handleAPIDelete handles file and directory deletion
func (s *Server) handleAPIDelete(w http.ResponseWriter, r *http.Request) {
	// Only allow POST requests
	if r.Method != http.MethodPost {
		sendJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Reject if modification is disabled
	if s.Options.NoModify {
		sendJSONError(w, "Modification is disabled", http.StatusForbidden)
		return
	}

	// Parse the request body
	var req APIRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSONError(w, "Invalid request: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Validate request - we need paths to delete
	if len(req.Paths) == 0 && req.Path == "" {
		sendJSONError(w, "Path(s) required for deletion", http.StatusBadRequest)
		return
	}

	// If single path is provided, add it to paths array
	paths := req.Paths
	if req.Path != "" && len(paths) == 0 {
		paths = []string{req.Path}
	}

	// Process each path
	deleted := 0
	errors := []string{}

	for _, path := range paths {
		// Convert to filesystem path and ensure it's safe
		fsPath := s.absolutePath(path)
		if !s.isPathSafe(fsPath) {
			errors = append(errors, fmt.Sprintf("Forbidden: Path outside document root: %s", path))
			continue
		}

		// Check if the path exists
		info, err := os.Stat(fsPath)
		if err != nil {
			if os.IsNotExist(err) {
				errors = append(errors, fmt.Sprintf("Path does not exist: %s", path))
			} else {
				errors = append(errors, fmt.Sprintf("Failed to access %s: %s", path, err.Error()))
			}
			continue
		}

		// Remove the file or directory
		var err2 error
		if info.IsDir() {
			err2 = os.RemoveAll(fsPath)
		} else {
			err2 = os.Remove(fsPath)
		}

		if err2 != nil {
			errors = append(errors, fmt.Sprintf("Failed to delete %s: %s", path, err2.Error()))
			continue
		}

		deleted++
	}

	// Send response
	if len(errors) > 0 {
		sendJSONResponse(w, APIResponse{
			Success: deleted > 0,
			Message: fmt.Sprintf("Deleted %d out of %d items. Errors: %s", deleted, len(paths), strings.Join(errors, "; ")),
			Data: map[string]interface{}{
				"deleted": deleted,
				"total":   len(paths),
				"errors":  errors,
			},
		})
	} else {
		sendJSONResponse(w, APIResponse{
			Success: true,
			Message: fmt.Sprintf("Successfully deleted %d item(s)", deleted),
			Data: map[string]interface{}{
				"deleted": deleted,
				"total":   len(paths),
			},
		})
	}
}

// MaxEditableFileSize is the maximum size of a file that can be edited (16 MiB)
const MaxEditableFileSize = 16 * 1024 * 1024

// handleAPIEdit handles file editing
func (s *Server) handleAPIEdit(w http.ResponseWriter, r *http.Request) {
	// Only allow GET and POST requests
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		sendJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// GET request: get file content
	if r.Method == http.MethodGet {
		path := r.URL.Query().Get("path")
		if path == "" {
			sendJSONError(w, "Path is required", http.StatusBadRequest)
			return
		}

		// Get the absolute filesystem path
		fsPath := s.absolutePath(path)
		if !s.isPathSafe(fsPath) {
			sendJSONError(w, "Forbidden: Path outside document root", http.StatusForbidden)
			return
		}

		// Check if the file exists and is a regular file
		info, err := os.Stat(fsPath)
		if err != nil {
			if os.IsNotExist(err) {
				sendJSONError(w, "File not found", http.StatusNotFound)
			} else {
				sendJSONError(w, "Failed to access file: "+err.Error(), http.StatusInternalServerError)
			}
			return
		}

		if info.IsDir() {
			sendJSONError(w, "Cannot edit directories", http.StatusBadRequest)
			return
		}

		// Check file size limit
		if info.Size() > MaxEditableFileSize {
			sendJSONError(w, fmt.Sprintf("File too large for editing (max %d bytes)", MaxEditableFileSize), http.StatusBadRequest)
			return
		}

		// Read the file content
		content, err := os.ReadFile(fsPath)
		if err != nil {
			sendJSONError(w, "Failed to read file: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Send the file content
		sendJSONResponse(w, APIResponse{
			Success: true,
			Data: map[string]interface{}{
				"path":    path,
				"content": string(content),
				"size":    info.Size(),
			},
		})
		return
	}

	// POST request: save file content
	if r.Method == http.MethodPost {
		// Reject if modification is disabled
		if s.Options.NoModify {
			sendJSONError(w, "Modification is disabled", http.StatusForbidden)
			return
		}

		// Parse the request body
		var req APIRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			sendJSONError(w, "Invalid request: "+err.Error(), http.StatusBadRequest)
			return
		}

		// Ensure path and content are provided
		if req.Path == "" {
			sendJSONError(w, "Path is required", http.StatusBadRequest)
			return
		}

		// Get the absolute filesystem path
		fsPath := s.absolutePath(req.Path)
		if !s.isPathSafe(fsPath) {
			sendJSONError(w, "Forbidden: Path outside document root", http.StatusForbidden)
			return
		}

		// Check if the file exists
		info, err := os.Stat(fsPath)
		if err == nil && info.IsDir() {
			sendJSONError(w, "Cannot edit directories", http.StatusBadRequest)
			return
		}

		// Create parent directories if they don't exist
		if err := os.MkdirAll(filepath.Dir(fsPath), 0755); err != nil {
			sendJSONError(w, "Failed to create parent directories: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Write the content to the file
		if err := os.WriteFile(fsPath, []byte(req.Content), 0644); err != nil {
			sendJSONError(w, "Failed to write file: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// If create writable flag is set, make the file writable for others
		if s.Options.CreateWritable {
			if err := os.Chmod(fsPath, 0666); err != nil {
				// Log but don't fail the request
				slog.Warn("failed to set file permissions", "error", err)
			}
		}

		// Send success response
		sendJSONResponse(w, APIResponse{
			Success: true,
			Message: "File saved successfully",
			Data: map[string]string{
				"path": req.Path,
			},
		})
	}
}
