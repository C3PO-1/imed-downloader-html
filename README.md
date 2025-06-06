# IPTV Player for M3U Playlists
 
This is a simple Python GUI application for macOS (including Apple Silicon) that loads an M3U playlist, lists available bouquets (groups), allows searching channels and opens streams with VLC by default on macOS.
 
 ## Requirements
 
 
A video player installed (e.g., VLC). On macOS the streams are opened in VLC using `open -a VLC`; other platforms use the system default handler.
 
 ## Usage
 
 ```
 python3 iptv_player.py
 ```
 

On startup, choose or enter the URL/path to an M3U playlist. Previously used playlists are stored so you can easily pick them again. After the playlist is loaded a bouquet named **All Channels** is available for searching across the entire list. Double-click a channel to play it.
 
 ## Disclaimer
 
 Use this application only with services you are authorized to access.
 
EOF
)
