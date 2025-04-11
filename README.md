# WebDir

A simple web server for serving files and directories.

<img width="1205" alt="image" src="https://github.com/user-attachments/assets/630691de-e257-4db1-9f94-dd7bd026f81c" />

## Quickstart

**Install and Run:**

```sh
go install github.com/djosix/webdir@latest
webdir
```

**Run Directly:**

```sh
go run github.com/djosix/webdir@latest
```

## Features

- Lists directory entries
- Operations:
    - Create folders
    - Create text files
    - Upload files
    - Move files and folders
    - Rename files
    - Delete files and folders
    - Edit text files (supports indentation)
- Opens files in a popup window (click) or a new tab (Ctrl-click)
- Dark mode and light mode
- Basic authentication using username and password (`-basic-auth USERNAME:PASSWORD`)
- HTTPS using self-signed certificate (`-https`)
- View-only mode (`-no-modify`)
- Disable listing (`-no-list`)
- Easy curl upload using `curl http://webdir/folder -F upload=@/path/to/the/file`
- Drag-and-drop file upload
