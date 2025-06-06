import tkinter as tk
from tkinter import ttk, messagebox
import requests
import re
import subprocess
import sys
import os

class LoginFrame(ttk.Frame):
    """Frame asking for an M3U playlist."""

    def __init__(self, master, on_login):
        super().__init__(master)
        self.on_login = on_login
        self.columnconfigure(1, weight=1)

        ttk.Label(self, text="M3U Playlist URL or Path").grid(row=0, column=0, sticky=tk.W)
        self.playlist_var = tk.StringVar()
        ttk.Entry(self, textvariable=self.playlist_var).grid(row=0, column=1, sticky=tk.EW)

        self.login_btn = ttk.Button(self, text="Load", command=self.load)
        self.login_btn.grid(row=1, column=0, columnspan=2, pady=5)

    def load(self):
        playlist = self.playlist_var.get().strip()
        if not playlist:
            messagebox.showerror("Error", "Please enter a playlist path or URL")
            return
        try:
            if playlist.startswith("http://") or playlist.startswith("https://"):
                resp = requests.get(playlist, timeout=10)
                resp.raise_for_status()
                text = resp.text
            else:
                with open(playlist, "r", encoding="utf-8") as fh:
                    text = fh.read()
        except Exception as exc:
            messagebox.showerror("Error", f"Failed to load playlist: {exc}")
            return
        self.on_login(text)

class PlayerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("IPTV Player")
        self.geometry("700x500")
        self.playlist = []
        self.groups = {}
        self._show_login()

    def _show_login(self):
        for child in self.winfo_children():
            child.destroy()
        LoginFrame(self, self._load_playlist).pack(fill=tk.BOTH, expand=True)

    def _load_playlist(self, playlist_text):
        self.playlist = self._parse_m3u(playlist_text)
        self._build_ui()

    def _parse_m3u(self, text):
        entries = []
        group_re = re.compile(r'group-title="([^"]*)"')
        lines = text.splitlines()
        current = {}
        for line in lines:
            line = line.strip()
            if line.startswith('#EXTINF:'):
                m = group_re.search(line)
                group = m.group(1) if m else 'Other'
                title = line.split(',')[-1]
                current = {'group': group, 'title': title}
            elif line and not line.startswith('#') and current:
                current['url'] = line
                entries.append(current)
                current = {}
        # build groups mapping
        groups = {}
        for entry in entries:
            groups.setdefault(entry['group'], []).append(entry)
        self.groups = groups
        return entries

    def _build_ui(self):
        for child in self.winfo_children():
            child.destroy()
        top_frame = ttk.Frame(self)
        top_frame.pack(fill=tk.X, pady=5)

        ttk.Label(top_frame, text="Bouquet:").pack(side=tk.LEFT)
        self.group_var = tk.StringVar()
        group_cb = ttk.Combobox(top_frame, textvariable=self.group_var, state="readonly")
        group_cb['values'] = sorted(self.groups)
        group_cb.pack(side=tk.LEFT, padx=5)
        if group_cb['values']:
            self.group_var.set(group_cb['values'][0])

        ttk.Label(top_frame, text="Search:").pack(side=tk.LEFT, padx=(10,0))
        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(top_frame, textvariable=self.search_var)
        search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        search_entry.bind('<KeyRelease>', lambda e: self._refresh_list())

        self.listbox = tk.Listbox(self)
        self.listbox.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.listbox.bind('<Double-1>', self._play_selected)

        group_cb.bind('<<ComboboxSelected>>', lambda e: self._refresh_list())
        self._refresh_list()

    def _refresh_list(self):
        group = self.group_var.get()
        search_term = self.search_var.get().lower()
        self.listbox.delete(0, tk.END)
        if not group:
            return
        for item in self.groups.get(group, []):
            if search_term in item['title'].lower():
                self.listbox.insert(tk.END, item['title'])
        self.listbox.selection_clear(0, tk.END)

    def _play_selected(self, event=None):
        group = self.group_var.get()
        index = self.listbox.curselection()
        if not index:
            return
        title = self.listbox.get(index[0])
        item = next((i for i in self.groups.get(group, []) if i['title'] == title), None)
        if not item:
            return
        url = item['url']
        self._open_stream(url)

    def _open_stream(self, url):
        try:
            if sys.platform == "darwin":
                subprocess.Popen(['open', url])
            elif sys.platform.startswith('win'):
                os.startfile(url)
            else:
                subprocess.Popen(['xdg-open', url])
        except Exception as exc:
            messagebox.showerror("Error", f"Failed to open stream: {exc}")

if __name__ == '__main__':
    app = PlayerApp()
    app.mainloop()
