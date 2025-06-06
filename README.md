# IPTV Player for M3U Playlists

This is a simple Python GUI application for macOS (including Apple Silicon) that loads an M3U playlist, lists available bouquets (groups), allows searching channels and opens streams with the default video player.

## Requirements

- Python 3 with Tkinter (included with standard Python on macOS)
- `requests` library (`pip install requests`)
- A video player installed (e.g., VLC). Streams are opened using the default handler via the `open` command.

## Usage

```
python3 iptv_player.py
```

On startup, enter the URL or path to an M3U playlist. After the playlist is loaded, select a bouquet, search for channels, and double-click a channel to play it.

## Disclaimer

Use this application only with services you are authorized to access.
