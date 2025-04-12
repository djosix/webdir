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

- Operations: List, Create, Upload, Move, Copy, Delete, Edit
- Open file in a popup window (Shift-click) or a new tab (click or press Enter on focused file)
- Dark mode and light mode
- Basic authentication using username and password (`-basic-auth USERNAME:PASSWORD`)
- HTTPS using self-signed certificate (`-https`)
- View-only mode (`-view-only`)
- Disable listing (`-no-list`)
- Upload using `curl http://webdir/folder -F file=@/path/to/the/file`
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
