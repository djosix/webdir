package internal

type Options struct {
	Host           string
	Port           int
	HTTPS          bool
	BasicAuth      string
	NoList         bool
	ViewOnly       bool
	CreateWritable bool
	BasePath       string
	IndexFile      string
	DocumentRoot   string
	UploadLimitMiB int64
	LogLevel       string
}
