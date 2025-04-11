package internal

type Options struct {
	Host           string
	Port           int
	HTTPS          bool
	BasicAuth      string
	NoList         bool
	NoModify       bool
	CreateWritable bool
	BasePath       string
	IndexFile      string
	DocumentRoot   string
}
