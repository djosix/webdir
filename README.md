# WebDir

A simple web server that serves files and directories and offers management functionality.

<img width="1109" alt="image" src="https://github.com/user-attachments/assets/70d696f0-5f70-426d-8548-5b8fd66a7c53" />

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
    - Create directory
    - Create empty file
    - Upload files
    - Move/Rename entries
    - Copy entries
    - Delete entries
    - Edit text files (supports indentation)
- Opens files in a popup window (click) or a new tab (Ctrl-click)
- Dark mode and light mode
- Basic authentication using username and password (`-basic-auth USERNAME:PASSWORD`)
- HTTPS using self-signed certificate (`-https`)
- View-only mode (`-no-modify`)
- Disable listing (`-no-list`)
- Easy curl upload using `curl http://webdir/folder -F upload=@/path/to/the/file`
- Drag-and-drop file upload
- Keyboard shortcuts for efficient operations

## Keyboard Shortcuts

- `ArrowDown`: Navigate to the next entry
- `ArrowUp`: Navigate to the previous entry
- `ArrowLeft`: Go to the parent directory
- `ArrowRight`: Go to the selected directory
- `Enter`: Open the selected file or go to the selected directory
- `Escape`: Defocus any focused element
- `s`: Focus on search
- `f`: New file
- `d`: New directory
- `u`: Upload files
- `m`: Move the selected file or directory
- `c`: Copy the selected file or directory
- `Backspace`/`Delete`: Delete the selected file or directory
- `e`: Edit the selected file
