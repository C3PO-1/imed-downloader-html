# IPTV Player for Xtream Codes

This is a simple Python GUI application for macOS (including Apple Silicon) that connects to an Xtream Codes IPTV server, lists available bouquets (groups), allows searching channels and opens streams with the default video player.

## Requirements

- Python 3 with Tkinter (included with standard Python on macOS)
- `requests` library (`pip install requests`)
- A video player installed (e.g., VLC). Streams are opened using the default handler via the `open` command.

## Usage

```
python3 iptv_player.py
```

On startup, enter the server URL (without trailing slash), your username and password. After successful login, select a bouquet, search for channels, and double-click a channel to play it.

## Disclaimer

Use this application only with services you are authorized to access.
