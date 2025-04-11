# WebDir

A simple web server for serving files and directories.

<img width="1249" alt="image" src="https://github.com/user-attachments/assets/71113c36-d559-4a92-b0f4-7e8136121027" />

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
- `f`: New file
- `d`: New directory
- `u`: Upload files
- `m`: Move the selected file or directory
- `c`: Copy the selected file or directory
- `Backspace`/`Delete`: Delete the selected file or directory
- `e`: Edit the selected file
