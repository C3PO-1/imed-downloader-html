 (cd "$(git rev-parse --show-toplevel)" && git apply --3way <<'EOF' 
diff --git a/README.md b/README.md
index b21b706581863b395f58e91c8293fcfe7957a3e6..f75f54a621fbd0da6d473f446218269ce4913e68 100644
--- a/README.md
+++ b/README.md
@@ -1,21 +1,21 @@
-# IPTV Player for Xtream Codes
+# IPTV Player for M3U Playlists
 
-This is a simple Python GUI application for macOS (including Apple Silicon) that connects to an Xtream Codes IPTV server, lists available bouquets (groups), allows searching channels and opens streams with the default video player.
+This is a simple Python GUI application for macOS (including Apple Silicon) that loads an M3U playlist, lists available bouquets (groups), allows searching channels and opens streams with VLC by default on macOS.
 
 ## Requirements
 
 - Python 3 with Tkinter (included with standard Python on macOS)
 - `requests` library (`pip install requests`)
-- A video player installed (e.g., VLC). Streams are opened using the default handler via the `open` command.
+- A video player installed (e.g., VLC). On macOS the streams are opened in VLC using `open -a VLC`; other platforms use the system default handler.
 
 ## Usage
 
 ```
 python3 iptv_player.py
 ```
 
-On startup, enter the server URL (without trailing slash), your username and password. After successful login, select a bouquet, search for channels, and double-click a channel to play it.
+On startup, choose or enter the URL/path to an M3U playlist. Previously used playlists are stored so you can easily pick them again. After the playlist is loaded a bouquet named **All Channels** is available for searching across the entire list. Double-click a channel to play it.
 
 ## Disclaimer
 
 Use this application only with services you are authorized to access.
 
EOF
)
