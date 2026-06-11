#!/usr/bin/env python3
"""xss_hunter_gui.py - Graphical front-end for xss_hunter.py.

Zero-dependency GUI (Python stdlib tkinter only, no pip install). It does NOT
re-implement the engine: it builds the exact xss_hunter.py command from the
form and runs the real CLI as a subprocess, streaming its output live. Same
engine as the command line, friendlier controls.

Features: light / dark theme toggle, hover tooltips, a Help field guide, and a
"Show request" preview that prints the raw HTTP request the tool will send.

It always passes --no-color (clean text in the panel) and -y (so the CLI's
interactive cookie prompt never blocks a windowed process). The cookie-safety
confirmation is shown by the GUI instead, so the session cookie stays sacred.

Run:  python xss_hunter_gui.py
"""

import codecs
import os
import queue
import re
import subprocess
import sys
import threading
import urllib.parse

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext

HERE = os.path.dirname(os.path.abspath(__file__))
CLI = os.path.join(HERE, 'xss_hunter.py')

MONO = ('Consolas', 10)
UI = ('Segoe UI', 10)

# ---- two themes ----
DARK = {
    'BG': '#0d111b', 'PANEL': '#161c2c', 'FIELD': '#0b0f18', 'LOGBG': '#0a0e16',
    'ACCENT': '#36c5f0', 'GOOD': '#2ecc71', 'WARN': '#f1c40f', 'BAD': '#ff6b6b',
    'FG': '#e6e9ef', 'MUTED': '#8a93a6', 'BORDER': '#27314c',
    'BTN': '#22304a', 'BTN_ACTIVE': '#2c3c5c', 'BTNFG': '#e6e9ef',
    'WARNBG': '#2a1d0a', 'WARNFG': '#ffd479',
    'RUN': '#2ecc71', 'RUNFG': '#06210f', 'STOP': '#5a2230', 'STOPFG': '#e6e9ef',
}
LIGHT = {
    'BG': '#e7ecf3', 'PANEL': '#f5f7fb', 'FIELD': '#ffffff', 'LOGBG': '#ffffff',
    'ACCENT': '#0b66c3', 'GOOD': '#1e8e4e', 'WARN': '#9a6a00', 'BAD': '#c0392b',
    'FG': '#1b2430', 'MUTED': '#5a6577', 'BORDER': '#cbd5e3',
    'BTN': '#e3e9f3', 'BTN_ACTIVE': '#d3dcec', 'BTNFG': '#1b2430',
    'WARNBG': '#fff3d4', 'WARNFG': '#7a5600',
    'RUN': '#2ecc71', 'RUNFG': '#06210f', 'STOP': '#e7c3c3', 'STOPFG': '#5a2230',
}

# Field guide shown by the Help button. Each item is (style, text).
HELP_SECTIONS = [
    ('h', 'What this window does'),
    ('p', 'The GUI builds a real xss_hunter.py command from the fields on the '
          'left and runs the actual tool, streaming its output on the right. The '
          '"Command preview" box always shows exactly what is being run, and '
          '"Show request" prints the raw HTTP request that will be sent.'),
    ('h', 'Finding the parameter  (-p)   <- the step people miss'),
    ('p', '-p is the form field your payload is injected into. You read it from '
          'the page HTML, you never guess it. Right-click the challenge page, '
          'choose View Source (or press F12), find the form, and copy the input '
          'name. Example from mock-exam challenge 2:'),
    ('c', '<form method="POST" action="/challenge.php?challenge=2">'),
    ('c', '    <input type="text" name="alert">   <-- this name is your -p'),
    ('c', '    <input type="submit" value="Submit">'),
    ('c', '</form>'),
    ('p', 'That form means:  Method = POST,  URL = the action,  Parameter = alert.'),
    ('h', 'What goes in the Cookie field'),
    ('p', 'Paste the WHOLE cookie as name=value, not just the id. Correct:'),
    ('c', 'PHPSESSID=8f3a9c2b7e1d4a6f0c5b'),
    ('p', 'Wrong (value only):'),
    ('c', '8f3a9c2b7e1d4a6f0c5b'),
    ('p', 'You can include several, separated by a semicolon: '
          'PHPSESSID=8f3a...; KeyChallenge8=xyz . Get the value from your browser '
          'DevTools > Application > Cookies. It is sent verbatim on every request '
          'and the GUI shows it for confirmation before the first request.'),
    ('h', 'How a winner is decided'),
    ('p', 'Grep keyword (--grep): if the response contains this word, it is an '
          'instant winner. On the Howest mock exam every solved challenge returns '
          'the word "congratulations", so Grep = congratulations is usually all '
          'you need. With no grep, a hit = the payload is reflected AND the '
          'response shows JavaScript-execution markers (script, onerror, alert).'),
    ('h', 'Slow target?  Tune these (important)'),
    ('p', 'If the summary shows lots of Errors, the server is too slow for your '
          'settings. The mock exam answers in about 7 seconds. Use Threads 5, '
          'Delay 0.2, Timeout 25. High threads + low timeout on a slow server '
          'makes every request time out, which shows up as Errors, not hits.'),
    ('h', 'Full reference: every field and check box'),
    ('o', 'TARGET'),
    ('p', '• URL / Burp request file (radio): how you point at the target. URL = '
          'type the address; Request file = replay a saved raw request.'),
    ('p', '• Target URL (-u): the form action, including any ?challenge=N part.'),
    ('p', '• Method (POST or GET): how the form submits. Default POST.'),
    ('p', '• Request file (--request): a raw HTTP request saved from Burp. Put FUZZ '
          '(or §§) where the payload should go.'),
    ('o', 'INJECTION'),
    ('p', '• Parameter (-p): the form field name to inject, read from '
          '<input name="...">.'),
    ('p', '• Extra params: fixed key=value pairs sent on every request, one per line '
          '(e.g. challenge=2).'),
    ('p', '• Auto-detect injectable parameter (--auto-detect) [check]: probe common '
          'field names with a marker and report which one reflects. Needs URL; '
          'ignores Parameter.'),
    ('o', 'PAYLOADS'),
    ('p', '• Payload list (-f): your wordlist, one payload per line. Optional.'),
    ('p', '• Skip built-in payloads (--no-common) [check]: do not try the ~25 '
          'built-in payloads, only your file.'),
    ('p', '• Built-in payloads only (--common-only) [check]: try ONLY the built-in '
          'list, ignore the file. Fast first probe.'),
    ('p', '• Limit (--limit): test only the first N payloads (smoke test).'),
    ('o', 'DETECTION'),
    ('p', '• Grep keyword (--grep): if the response contains this word, that payload '
          'wins instantly. Use congratulations on the mock exam.'),
    ('p', '• Test every payload (--all) [check]: do not stop at the first hit; list '
          'every working payload.'),
    ('o', 'NETWORK & SESSION'),
    ('p', '• Cookie: the full cookie string as name=value; carries your session.'),
    ('p', '• Extra headers: one per line, "Key: Value" (e.g. X-Forwarded-For: '
          '127.0.0.1).'),
    ('p', '• Threads (-t): parallel requests. Default 20, hard cap 30. Lower on slow '
          'servers.'),
    ('p', '• Delay (-d): seconds between requests per thread. Raise on fragile '
          'servers.'),
    ('p', '• Timeout: seconds before a request is given up. Keep it above the server '
          'response time.'),
    ('p', '• Skip TLS certificate verification (--insecure) [check]: accept '
          'self-signed lab certificates.'),
    ('o', 'OUTPUT'),
    ('p', '• Save hits to (-o): append winning payloads to a file for your writeup.'),
    ('p', '• Verbose (-v) [check]: show every result (reflected, blocked, errors), '
          'not only hits.'),
    ('h', 'Quick checklist'),
    ('p', '1. URL from the form action.'),
    ('p', '2. Parameter from the input name.'),
    ('p', '3. Cookie = PHPSESSID=your-live-value.'),
    ('p', '4. Grep = congratulations (mock exam).'),
    ('p', '5. Tick Skip TLS verify (self-signed lab certificates).'),
    ('p', '6. Slow server: lower threads, raise timeout.'),
]


class Tooltip:
    """A small hover popup that explains a widget."""

    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tip = None
        widget.bind('<Enter>', self._show, add='+')
        widget.bind('<Leave>', self._hide, add='+')

    def _show(self, _e=None):
        if self.tip or not self.text:
            return
        x = self.widget.winfo_rootx() + 18
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 6
        self.tip = tk.Toplevel(self.widget)
        self.tip.wm_overrideredirect(True)
        self.tip.wm_geometry('+%d+%d' % (x, y))
        tk.Label(self.tip, text=self.text, justify='left', bg='#1f2a3d', fg='#e6e9ef',
                 font=('Segoe UI', 9), relief='solid', borderwidth=1, padx=8, pady=6,
                 wraplength=340).pack()

    def _hide(self, _e=None):
        if self.tip:
            self.tip.destroy()
            self.tip = None


class ScrollFrame(ttk.Frame):
    """A vertically scrollable frame. Put widgets in self.body."""

    def __init__(self, master, bg, **kw):
        super().__init__(master, **kw)
        self.canvas = tk.Canvas(self, bg=bg, highlightthickness=0, borderwidth=0)
        vsb = ttk.Scrollbar(self, orient='vertical', command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=vsb.set)
        vsb.pack(side='right', fill='y')
        self.canvas.pack(side='left', fill='both', expand=True)
        self.body = ttk.Frame(self.canvas)
        self._win = self.canvas.create_window((0, 0), window=self.body, anchor='nw')
        self.body.bind('<Configure>',
                       lambda e: self.canvas.configure(scrollregion=self.canvas.bbox('all')))
        self.canvas.bind('<Configure>',
                         lambda e: self.canvas.itemconfigure(self._win, width=e.width))
        self.canvas.bind('<Enter>', lambda e: self.canvas.bind_all('<MouseWheel>', self._wheel))
        self.canvas.bind('<Leave>', lambda e: self.canvas.unbind_all('<MouseWheel>'))

    def _wheel(self, e):
        self.canvas.yview_scroll(int(-e.delta / 120), 'units')


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title('XSS-Hunter - GUI')
        self.geometry('1200x820')
        self.minsize(980, 640)
        self.is_dark = True
        self.palette = dict(DARK)
        self.proc = None
        self.q = None
        self._text_widgets = []
        self._build_style()
        self._build_header()
        self._build_body()
        self._apply_theme()
        self.protocol('WM_DELETE_WINDOW', self._on_close)

    # ---------- theming ----------
    def _build_style(self):
        p = self.palette
        st = ttk.Style(self)
        try:
            st.theme_use('clam')
        except tk.TclError:
            pass
        st.configure('.', background=p['PANEL'], foreground=p['FG'], fieldbackground=p['FIELD'], font=UI)
        st.configure('TFrame', background=p['PANEL'])
        st.configure('TLabel', background=p['PANEL'], foreground=p['FG'])
        st.configure('Hint.TLabel', background=p['PANEL'], foreground=p['MUTED'], font=('Segoe UI', 9))
        st.configure('TCheckbutton', background=p['PANEL'], foreground=p['FG'])
        st.map('TCheckbutton', background=[('active', p['PANEL'])])
        st.configure('TRadiobutton', background=p['PANEL'], foreground=p['FG'])
        st.map('TRadiobutton', background=[('active', p['PANEL'])])
        st.configure('TButton', background=p['BTN'], foreground=p['BTNFG'], padding=6, borderwidth=0)
        st.map('TButton', background=[('active', p['BTN_ACTIVE'])])
        st.configure('Run.TButton', background=p['RUN'], foreground=p['RUNFG'], font=('Segoe UI Semibold', 10))
        st.map('Run.TButton', background=[('active', p['RUN'])])
        st.configure('Stop.TButton', background=p['STOP'], foreground=p['STOPFG'])
        st.map('Stop.TButton', background=[('active', p['STOP'])])
        st.configure('TEntry', fieldbackground=p['FIELD'], foreground=p['FG'],
                     insertcolor=p['FG'], bordercolor=p['BORDER'])
        st.configure('TCombobox', fieldbackground=p['FIELD'], foreground=p['FG'], bordercolor=p['BORDER'])
        st.configure('TLabelframe', background=p['PANEL'], bordercolor=p['BORDER'])
        st.configure('TLabelframe.Label', background=p['PANEL'], foreground=p['ACCENT'],
                     font=('Segoe UI Semibold', 10))
        st.configure('Vertical.TScrollbar', background=p['BTN'], troughcolor=p['PANEL'], borderwidth=0)
        self.option_add('*TCombobox*Listbox.background', p['FIELD'])
        self.option_add('*TCombobox*Listbox.foreground', p['FG'])
        self.option_add('*TCombobox*Listbox.selectBackground', p['ACCENT'])

    def _apply_theme(self):
        self._build_style()
        p = self.palette
        self.configure(bg=p['BG'])
        self._w_headerframe.configure(bg=p['BG'])
        for w in self._w_headbits:
            w.configure(bg=p['BG'])
        self._w_title.configure(bg=p['BG'], fg=p['ACCENT'])
        self._w_sub.configure(bg=p['BG'], fg=p['MUTED'])
        self._w_warn.configure(bg=p['WARNBG'], fg=p['WARNFG'])
        self._w_paned.configure(bg=p['BG'])
        self._scroll.canvas.configure(bg=p['PANEL'])
        for t in self._text_widgets:
            t.configure(bg=p['FIELD'], fg=p['FG'], insertbackground=p['FG'])
        self.log.configure(bg=p['LOGBG'], fg=p['FG'], insertbackground=p['FG'])
        self._w_status.configure(bg=p['PANEL'], fg=p['ACCENT'])
        self.log.tag_configure('good', foreground=p['GOOD'])
        self.log.tag_configure('bad', foreground=p['BAD'])
        self.log.tag_configure('warn', foreground=p['WARN'])
        self.log.tag_configure('accent', foreground=p['ACCENT'])
        self.log.tag_configure('cmd', foreground=p['ACCENT'])
        self.log.tag_configure('muted', foreground=p['MUTED'])

    def toggle_theme(self):
        self.is_dark = not self.is_dark
        self.palette = dict(DARK if self.is_dark else LIGHT)
        self._apply_theme()
        self.btn_theme.configure(text='☀ Light' if self.is_dark else '🌙 Dark')

    # ---------- header ----------
    def _build_header(self):
        p = self.palette
        top = tk.Frame(self, bg=p['BG'])
        top.pack(fill='x')
        self._w_headerframe = top
        row = tk.Frame(top, bg=p['BG'])
        row.pack(fill='x')
        left = tk.Frame(row, bg=p['BG'])
        left.pack(side='left', fill='x', expand=True)
        self._w_title = tk.Label(left, text='💉 XSS-Hunter', bg=p['BG'], fg=p['ACCENT'],
                                 font=('Segoe UI Semibold', 18))
        self._w_title.pack(anchor='w', padx=16, pady=(12, 0))
        self._w_sub = tk.Label(left, text='Exam-grade reflected-XSS fuzzer  -  graphical front-end',
                               bg=p['BG'], fg=p['MUTED'], font=('Segoe UI', 10))
        self._w_sub.pack(anchor='w', padx=16)
        rb = tk.Frame(row, bg=p['BG'])
        rb.pack(side='right', padx=14, pady=12)
        self.btn_theme = ttk.Button(rb, text='☀ Light', width=9, command=self.toggle_theme)
        self.btn_theme.pack(side='left', padx=(0, 6))
        ttk.Button(rb, text='❔ Help', width=8, command=self.on_help).pack(side='left')
        self._w_headbits = [row, left, rb]
        self._w_warn = tk.Label(
            top,
            text=('  Session cookie is sacred: never change your PHPSESSID and never switch '
                  'browser mid-exam. The cookie is sent verbatim, untouched, on every request.'),
            bg=p['WARNBG'], fg=p['WARNFG'], font=('Segoe UI', 9), anchor='w', justify='left',
            padx=10, pady=6,
        )
        self._w_warn.pack(fill='x', padx=16, pady=(8, 10))

    # ---------- field helpers ----------
    def _e(self, frame, row, label, var, hint='', tip=''):
        lab = ttk.Label(frame, text=label)
        lab.grid(row=row, column=0, sticky='w', padx=8, pady=4)
        ent = ttk.Entry(frame, textvariable=var)
        ent.grid(row=row, column=1, sticky='ew', padx=8, pady=4)
        if hint:
            ttk.Label(frame, text=hint, style='Hint.TLabel').grid(row=row, column=2, sticky='w', padx=4)
        if tip:
            Tooltip(lab, tip)
            Tooltip(ent, tip)
        return ent

    def _f(self, frame, row, label, var, hint='', save=False, tip=''):
        lab = ttk.Label(frame, text=label)
        lab.grid(row=row, column=0, sticky='w', padx=8, pady=4)
        box = ttk.Frame(frame)
        box.grid(row=row, column=1, sticky='ew', padx=8, pady=4)
        box.columnconfigure(0, weight=1)
        ent = ttk.Entry(box, textvariable=var)
        ent.grid(row=0, column=0, sticky='ew')
        ttk.Button(box, text='Browse', width=8,
                   command=lambda: self._browse(var, save)).grid(row=0, column=1, padx=(6, 0))
        if hint:
            ttk.Label(frame, text=hint, style='Hint.TLabel').grid(row=row, column=2, sticky='w', padx=4)
        if tip:
            Tooltip(lab, tip)
            Tooltip(ent, tip)

    def _c(self, frame, row, text, var, hint='', tip=''):
        chk = ttk.Checkbutton(frame, text=text, variable=var)
        chk.grid(row=row, column=1, sticky='w', padx=8, pady=3)
        if hint:
            ttk.Label(frame, text=hint, style='Hint.TLabel').grid(row=row, column=2, sticky='w')
        if tip:
            Tooltip(chk, tip)

    def _cb(self, frame, row, label, var, values):
        ttk.Label(frame, text=label).grid(row=row, column=0, sticky='w', padx=8, pady=4)
        ttk.Combobox(frame, textvariable=var, values=values, state='readonly').grid(
            row=row, column=1, sticky='ew', padx=8, pady=4)

    def _note(self, frame, row, text):
        ttk.Label(frame, text=text, style='Hint.TLabel', wraplength=560,
                  justify='left').grid(row=row, column=1, columnspan=2, sticky='w', padx=8, pady=(0, 4))

    def _text(self, frame, row, label, height, hint=''):
        ttk.Label(frame, text=label).grid(row=row, column=0, sticky='nw', padx=8, pady=4)
        t = tk.Text(frame, height=height, bg=self.palette['FIELD'], fg=self.palette['FG'],
                    insertbackground=self.palette['FG'], font=MONO, wrap='none',
                    borderwidth=1, relief='solid', highlightthickness=0)
        t.grid(row=row, column=1, sticky='ew', padx=8, pady=4)
        if hint:
            ttk.Label(frame, text=hint, style='Hint.TLabel').grid(row=row, column=2, sticky='nw', padx=4)
        self._text_widgets.append(t)
        return t

    def _section(self, parent, title):
        lf = ttk.Labelframe(parent, text='  ' + title + '  ')
        lf.pack(fill='x', padx=10, pady=(10, 0))
        lf.columnconfigure(1, weight=1)
        return lf

    def _browse(self, var, save=False):
        path = (filedialog.asksaveasfilename() if save else filedialog.askopenfilename())
        if path:
            var.set(path)

    # ---------- body ----------
    def _build_body(self):
        main = tk.PanedWindow(self, orient='horizontal', bg=self.palette['BG'], sashwidth=6, bd=0)
        main.pack(fill='both', expand=True, padx=12, pady=(0, 12))
        self._w_paned = main

        self._scroll = ScrollFrame(main, bg=self.palette['PANEL'])
        main.add(self._scroll, minsize=400, width=620)
        form = self._scroll.body

        right = ttk.Frame(main)
        main.add(right, minsize=380)

        self._build_form(form)
        self._build_right(right)

    def _build_form(self, form):
        # ---- Target ----
        lf = self._section(form, 'Target')
        self.v_target = tk.StringVar(value='url')
        tr = ttk.Frame(lf)
        tr.grid(row=0, column=0, columnspan=3, sticky='w', padx=8, pady=4)
        ttk.Radiobutton(tr, text='URL', value='url', variable=self.v_target).pack(side='left')
        ttk.Radiobutton(tr, text='Burp request file', value='request',
                        variable=self.v_target).pack(side='left', padx=12)
        self.v_url = tk.StringVar()
        self._e(lf, 1, 'Target URL', self.v_url, 'e.g. https://site/challenge.php?challenge=2',
                tip='The page that contains the vulnerable form. Copy it including '
                    'any ?challenge=N part. This is the form action.')
        self.v_method = tk.StringVar(value='POST')
        self._cb(lf, 2, 'Method', self.v_method, ['POST', 'GET'])
        self.v_reqfile = tk.StringVar()
        self._f(lf, 3, 'Request file', self.v_reqfile, 'mark inject point with FUZZ or §§')

        # ---- Injection ----
        lf = self._section(form, 'Injection')
        self.v_param = tk.StringVar()
        self._e(lf, 0, 'Parameter (-p)', self.v_param, 'field to inject, e.g. alert',
                tip='The form field your payload goes into. Read it from the page: '
                    'View Source (F12), find <input name="...">, and use that name. '
                    'Example: <input name="alert"> means Parameter = alert.')
        self.t_extra = self._text(lf, 1, 'Extra params', 3, 'fixed values, one per line, "key=value"')
        self.v_autodetect = tk.BooleanVar()
        self._c(lf, 2, 'Auto-detect injectable parameter (--auto-detect)', self.v_autodetect,
                'needs URL; ignores -p',
                tip='Do not know which field reflects? Tick this and run. It fires a '
                    'marker at common field names and reports which one echoes back. '
                    'Then untick it and put that name in Parameter.')

        # ---- Payloads ----
        lf = self._section(form, 'Payloads')
        self.v_file = tk.StringVar()
        self._f(lf, 0, 'Payload list (-f)', self.v_file, 'one payload per line (optional)',
                tip='Optional. ~25 strong payloads are built in and tried first, so '
                    'easy challenges fall without a wordlist.')
        self.v_nocommon = tk.BooleanVar()
        self._c(lf, 1, 'Skip built-in payloads (--no-common)', self.v_nocommon)
        self.v_commononly = tk.BooleanVar()
        self._c(lf, 2, 'Built-in payloads only (--common-only)', self.v_commononly)
        self.v_limit = tk.StringVar()
        self._e(lf, 3, 'Limit (--limit)', self.v_limit, 'test only the first N payloads')

        # ---- Detection ----
        lf = self._section(form, 'Detection')
        self.v_grep = tk.StringVar()
        self._e(lf, 0, 'Grep keyword (--grep)', self.v_grep,
                'response contains this = instant winner',
                tip='If the response body contains this word, that payload wins. '
                    'On the Howest mock exam every solved challenge returns the word '
                    '"congratulations", so Grep = congratulations is usually enough.')
        self.v_all = tk.BooleanVar()
        self._c(lf, 1, 'Test every payload, do not stop on first hit (--all)', self.v_all)

        # ---- Network & Session ----
        lf = self._section(form, 'Network & Session')
        self.v_cookie = tk.StringVar()
        self._e(lf, 0, 'Cookie', self.v_cookie, 'paste the whole thing: PHPSESSID=abc123...',
                tip='Paste name=value, e.g. PHPSESSID=8f3a9c... NOT just the id. '
                    'Several allowed, separated by ;. From DevTools > Application > '
                    'Cookies. Sent verbatim on every request.')
        self._note(lf, 1, 'Paste as name=value, e.g.  PHPSESSID=8f3a9c2b...  (not just the id). '
                          'Multiple allowed, separated by ;')
        self.t_headers = self._text(lf, 2, 'Extra headers', 3, 'one per line, "Key: Value"')
        self.v_threads = tk.StringVar(value='20')
        self._e(lf, 3, 'Threads (-t)', self.v_threads, 'default 20, hard cap 30',
                tip='Parallel requests. On a SLOW server (like the mock exam, ~7s '
                    'per response) drop this to 5 or it floods and everything times '
                    'out as Errors.')
        self.v_delay = tk.StringVar(value='0.0')
        self._e(lf, 4, 'Delay (-d)', self.v_delay, 'raise to ~0.2 if you see 429s',
                tip='Pause between requests per thread. Raise to 0.2 on a slow or '
                    'fragile server.')
        self.v_timeout = tk.StringVar(value='8')
        self._e(lf, 5, 'Timeout', self.v_timeout, 'per request, seconds',
                tip='Give up on a request after this many seconds. Must be HIGHER '
                    'than the server response time. Mock exam answers in ~7s, so use '
                    '25 there. Too low = Errors instead of hits.')
        self.v_insecure = tk.BooleanVar()
        self._c(lf, 6, 'Skip TLS certificate verification (--insecure)', self.v_insecure,
                tip='Lab and exam servers use self-signed certificates. Tick this or '
                    'every request fails with a TLS error.')

        # ---- Output ----
        lf = self._section(form, 'Output')
        self.v_output = tk.StringVar()
        self._f(lf, 0, 'Save hits to (-o)', self.v_output, 'append winning payloads', save=True)
        self.v_verbose = tk.BooleanVar()
        self._c(lf, 1, 'Verbose: show every result (-v)', self.v_verbose)

        ttk.Frame(form).pack(pady=8)

    def _build_right(self, rc):
        cmdf = ttk.Frame(rc)
        cmdf.pack(fill='x', padx=8, pady=(10, 4))
        ttk.Label(cmdf, text='Command preview', style='Hint.TLabel').pack(anchor='w')
        crow = ttk.Frame(cmdf)
        crow.pack(fill='x')
        self.cmd_var = tk.StringVar(value='(press Preview or Run)')
        ttk.Entry(crow, textvariable=self.cmd_var, state='readonly').pack(
            side='left', fill='x', expand=True)
        ttk.Button(crow, text='Copy', width=7, command=self._copy_cmd).pack(side='left', padx=(6, 0))

        btns = ttk.Frame(rc)
        btns.pack(fill='x', padx=8, pady=6)
        self.btn_run = ttk.Button(btns, text='▶  Run', style='Run.TButton', command=self.on_run)
        self.btn_run.pack(side='left')
        self.btn_stop = ttk.Button(btns, text='■  Stop', style='Stop.TButton',
                                   command=self.on_stop, state='disabled')
        self.btn_stop.pack(side='left', padx=6)
        ttk.Button(btns, text='Preview', command=self.on_preview).pack(side='left')
        ttk.Button(btns, text='📡 Show request', command=self.on_request).pack(side='left', padx=6)
        ttk.Button(btns, text='Clear log', command=self._clear_log).pack(side='left')

        self.log = scrolledtext.ScrolledText(
            rc, bg=self.palette['LOGBG'], fg=self.palette['FG'], insertbackground=self.palette['FG'],
            font=MONO, wrap='word', state='disabled', borderwidth=0, highlightthickness=0)
        self.log.pack(fill='both', expand=True, padx=8, pady=4)

        self.status_var = tk.StringVar(value='Idle.')
        self._w_status = tk.Label(rc, textvariable=self.status_var, bg=self.palette['PANEL'],
                                  fg=self.palette['ACCENT'], font=MONO, anchor='w')
        self._w_status.pack(fill='x', padx=8, pady=(0, 8))

    # ---------- command building ----------
    def _extra_params(self):
        out = []
        for ln in self.t_extra.get('1.0', 'end').splitlines():
            ln = ln.strip()
            if ln and '=' in ln:
                k, _, v = ln.partition('=')
                out.append((k, v))
        return out

    def build_command(self):
        a = [sys.executable, CLI]
        if self.v_target.get() == 'request':
            rf = self.v_reqfile.get().strip()
            if not rf:
                raise ValueError('Pick a Burp request file, or switch Target back to URL.')
            a += ['--request', rf]
        else:
            u = self.v_url.get().strip()
            if not u:
                raise ValueError('Enter the target URL, or switch Target to Request file.')
            a += ['-u', u, '-X', self.v_method.get()]

        if self.v_autodetect.get():
            a += ['--auto-detect']
        elif self.v_param.get().strip():
            a += ['-p', self.v_param.get().strip()]
        for ln in self.t_extra.get('1.0', 'end').splitlines():
            if ln.strip():
                a += ['--extra-param', ln.strip()]

        if self.v_file.get().strip():
            a += ['-f', self.v_file.get().strip()]
        if self.v_nocommon.get():
            a += ['--no-common']
        if self.v_commononly.get():
            a += ['--common-only']
        if self.v_limit.get().strip():
            a += ['--limit', self.v_limit.get().strip()]

        if self.v_grep.get().strip():
            a += ['--grep', self.v_grep.get().strip()]
        if self.v_all.get():
            a += ['--all']

        if self.v_cookie.get().strip():
            a += ['--cookie', self.v_cookie.get().strip()]
        for ln in self.t_headers.get('1.0', 'end').splitlines():
            if ln.strip():
                a += ['--header', ln.strip()]
        if self.v_threads.get().strip():
            a += ['-t', self.v_threads.get().strip()]
        if self.v_delay.get().strip():
            a += ['-d', self.v_delay.get().strip()]
        if self.v_timeout.get().strip():
            a += ['--timeout', self.v_timeout.get().strip()]
        if self.v_insecure.get():
            a += ['--insecure']

        if self.v_output.get().strip():
            a += ['-o', self.v_output.get().strip()]
        if self.v_verbose.get():
            a += ['-v']

        a += ['--no-color', '-y']
        return a

    def _display_cmd(self, args):
        parts = []
        for x in args:
            if x == sys.executable:
                parts.append('python')
            elif x == CLI:
                parts.append(os.path.basename(CLI))
            elif re.search(r'\s', x):
                parts.append('"%s"' % x)
            else:
                parts.append(x)
        return ' '.join(parts)

    # ---------- example raw request ----------
    def _example_request(self):
        sample = '<svg onload=alert(1)>'
        if self.v_target.get() == 'request':
            rf = self.v_reqfile.get().strip()
            if not rf:
                return 'Pick a request file first (Target = Burp request file).'
            try:
                with open(rf, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read()
            except OSError as e:
                return 'Cannot read request file: %s' % e
            shown = content.replace('FUZZ', sample).replace('§§', sample)
            return ('# Your request file is sent as-is, with FUZZ (or the markers) replaced\n'
                    '# by each payload. One request per payload. Sample payload shown: %s\n'
                    '# ----------------------------------------------------------------\n\n%s'
                    % (sample, shown))

        url = self.v_url.get().strip()
        if not url:
            return 'Enter the Target URL first.'
        method = self.v_method.get()
        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname or '(host)'
        if parsed.port:
            host = '%s:%d' % (host, parsed.port)
        path = parsed.path or '/'
        query = parsed.query

        pairs = list(self._extra_params())
        if not self.v_autodetect.get() and self.v_param.get().strip():
            pairs.append((self.v_param.get().strip(), sample))
        elif self.v_autodetect.get():
            pairs.append(('(auto-detect probes common names)', 'XSSHUNTERCANARY'))
        encoded = urllib.parse.urlencode(pairs)

        if method == 'GET':
            sep = '&' if query else '?'
            full = path + (('?' + query) if query else '') + (sep + encoded if encoded else '')
            body = ''
        else:
            full = path + (('?' + query) if query else '')
            body = encoded

        headers = []
        headers.append(('Host', host))
        headers.append(('User-Agent', 'Mozilla/5.0 (XSS-Hunter/1.0)'))
        headers.append(('Accept', '*/*'))
        headers.append(('Connection', 'keep-alive'))
        if self.v_cookie.get().strip():
            headers.append(('Cookie', self.v_cookie.get().strip()))
        for ln in self.t_headers.get('1.0', 'end').splitlines():
            ln = ln.strip()
            if ln and ':' in ln:
                k, _, v = ln.partition(':')
                headers.append((k.strip(), v.strip()))
        if method == 'POST':
            headers.append(('Content-Type', 'application/x-www-form-urlencoded'))
            headers.append(('Content-Length', str(len(body.encode('utf-8')))))

        out = ['# Example of ONE request the tool sends (a sample payload is shown).',
               '# The real run sends one like this per payload, swapping the payload each time.',
               '# ----------------------------------------------------------------', '']
        out.append('%s %s HTTP/1.1' % (method, full))
        for k, v in headers:
            out.append('%s: %s' % (k, v))
        out.append('')
        out.append(body)
        return '\n'.join(out)

    def on_request(self):
        self._popup_text('Example HTTP request', self._example_request())

    def _popup_text(self, title, text):
        p = self.palette
        win = tk.Toplevel(self)
        win.title(title)
        win.configure(bg=p['BG'])
        win.geometry('780x600')
        win.transient(self)
        tk.Label(win, text=title, bg=p['BG'], fg=p['ACCENT'],
                 font=('Segoe UI Semibold', 14)).pack(anchor='w', padx=16, pady=(12, 6))
        box = scrolledtext.ScrolledText(win, bg=p['LOGBG'], fg=p['FG'], insertbackground=p['FG'],
                                        font=MONO, wrap='none', borderwidth=0,
                                        highlightthickness=0, padx=12, pady=10)
        box.pack(fill='both', expand=True, padx=12, pady=(0, 8))
        box.insert('end', text)
        box.configure(state='disabled')
        bar = tk.Frame(win, bg=p['BG'])
        bar.pack(fill='x', pady=(0, 12))
        ttk.Button(bar, text='Copy', command=lambda: (self.clipboard_clear(),
                   self.clipboard_append(text))).pack(side='left', padx=16)
        ttk.Button(bar, text='Close', command=win.destroy).pack(side='right', padx=16)

    # ---------- actions ----------
    def on_preview(self):
        try:
            args = self.build_command()
        except ValueError as e:
            messagebox.showwarning('Missing input', str(e))
            return
        self.cmd_var.set(self._display_cmd(args))

    def on_run(self):
        if self.proc is not None:
            return
        try:
            args = self.build_command()
        except ValueError as e:
            messagebox.showwarning('Missing input', str(e))
            return
        if not os.path.exists(CLI):
            messagebox.showerror('Engine not found',
                                 'Cannot find %s next to this GUI.\nKeep both files in the '
                                 'same folder.' % os.path.basename(CLI))
            return
        if self.v_cookie.get().strip() and not self._confirm_cookie():
            return
        self.cmd_var.set(self._display_cmd(args))
        self._log('\n$ ' + self._display_cmd(args) + '\n', 'cmd')
        self._set_running(True)
        self._start(args)

    def on_stop(self):
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.terminate()
            except Exception:
                pass
            self.status_var.set('Stopping...')

    def _confirm_cookie(self):
        names = []
        for seg in self.v_cookie.get().split(';'):
            seg = seg.strip()
            if '=' in seg:
                k, _, v = seg.partition('=')
                red = v[:6] + '...' + v[-4:] if len(v) > 12 else v
                names.append('  %s = %s' % (k.strip(), red))
        body = ('These cookies will be sent VERBATIM with every request:\n\n'
                + '\n'.join(names)
                + '\n\nConfirm this is your current, active session before starting.')
        return messagebox.askokcancel('Cookie safety check', body)

    # ---------- subprocess streaming ----------
    def _start(self, args):
        flags = 0x08000000 if os.name == 'nt' else 0  # CREATE_NO_WINDOW
        try:
            self.proc = subprocess.Popen(
                args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL, bufsize=0, creationflags=flags)
        except Exception as e:
            self._log('\n[!] Failed to launch: %s\n' % e, 'bad')
            self._set_running(False)
            self.proc = None
            return
        self.q = queue.Queue()
        threading.Thread(target=self._reader, args=(self.proc,), daemon=True).start()
        self.after(40, self._poll)

    def _feed(self, ch, buf, pend):
        if pend:
            if ch == '\n':
                self.q.put(('line', buf))
                return '', False
            self.q.put(('cr', buf))
            buf, pend = '', False
        if ch == '\r':
            return buf, True
        if ch == '\n':
            self.q.put(('line', buf))
            return '', False
        return buf + ch, False

    def _reader(self, proc):
        dec = codecs.getincrementaldecoder('utf-8')(errors='replace')
        buf, pend = '', False
        while True:
            chunk = proc.stdout.read(80)
            if not chunk:
                for ch in dec.decode(b'', final=True):
                    buf, pend = self._feed(ch, buf, pend)
                if buf:
                    self.q.put(('line', buf))
                self.q.put(('done', proc.wait()))
                return
            for ch in dec.decode(chunk):
                buf, pend = self._feed(ch, buf, pend)

    def _poll(self):
        try:
            while True:
                kind, payload = self.q.get_nowait()
                if kind == 'line':
                    self._log(payload + '\n')
                elif kind == 'cr':
                    self.status_var.set(payload.rstrip() or 'running...')
                elif kind == 'done':
                    self._on_done(payload)
                    return
        except queue.Empty:
            pass
        if self.proc is not None:
            self.after(40, self._poll)

    def _on_done(self, code):
        meaning = {0: 'at least one hit', 1: 'zero hits',
                   2: 'argument / network error'}.get(code, 'stopped')
        tag = 'good' if code == 0 else ('warn' if code == 1 else 'bad')
        self._log('\n---- finished: exit %s  (%s) ----\n' % (code, meaning), tag)
        self.status_var.set('Finished (exit %s).' % code)
        self.proc = None
        self._set_running(False)

    # ---------- log helpers ----------
    def _auto_tag(self, text):
        s = text.strip()
        u = s.upper()
        if not s:
            return None
        if 'GREP-HIT' in u or 'WINNING' in u or '[+ XSS' in u or s.startswith('[+'):
            return 'good'
        if s.startswith('[x') or 'BLOCKED' in u or s.startswith('No payload'):
            return 'bad'
        if s.startswith('[~') or 'REFLECTED' in u:
            return 'warn'
        if s.startswith('[!') or 'TLS' in u:
            return 'warn'
        if (s[0] in '╔║╚' or s.startswith('===')
                or s.split(' ')[0] in ('Target', 'Payloads', 'Mode', 'Grep')):
            return 'accent'
        return None

    def _log(self, text, tag=None):
        if tag is None:
            tag = self._auto_tag(text)
        self.log.configure(state='normal')
        self.log.insert('end', text, tag)
        self.log.see('end')
        self.log.configure(state='disabled')

    def _clear_log(self):
        self.log.configure(state='normal')
        self.log.delete('1.0', 'end')
        self.log.configure(state='disabled')
        self.status_var.set('Idle.')

    def _copy_cmd(self):
        self.clipboard_clear()
        self.clipboard_append(self.cmd_var.get())
        self.status_var.set('Command copied to clipboard.')

    def on_help(self):
        p = self.palette
        win = tk.Toplevel(self)
        win.title('XSS-Hunter - Help & Field Guide')
        win.configure(bg=p['BG'])
        win.geometry('760x680')
        win.transient(self)
        tk.Label(win, text='XSS-Hunter  ·  Field Guide', bg=p['BG'], fg=p['ACCENT'],
                 font=('Segoe UI Semibold', 15)).pack(anchor='w', padx=16, pady=(14, 2))
        tk.Label(win, text='Hover any field in the main window for a quick tip. '
                           'This guide is the long version.',
                 bg=p['BG'], fg=p['MUTED'], font=('Segoe UI', 9)).pack(anchor='w', padx=16, pady=(0, 8))
        txt = scrolledtext.ScrolledText(win, bg=p['LOGBG'], fg=p['FG'], insertbackground=p['FG'],
                                        font=('Segoe UI', 10), wrap='word', borderwidth=0,
                                        highlightthickness=0, padx=14, pady=10)
        txt.pack(fill='both', expand=True, padx=12, pady=(0, 10))
        txt.tag_configure('h', foreground=p['ACCENT'], font=('Segoe UI Semibold', 12),
                          spacing1=12, spacing3=4)
        txt.tag_configure('p', foreground=p['FG'], font=('Segoe UI', 10), spacing3=4,
                          lmargin1=4, lmargin2=4)
        txt.tag_configure('c', foreground=p['ACCENT'], font=('Consolas', 10), lmargin1=16, lmargin2=16)
        txt.tag_configure('o', foreground=p['ACCENT'], font=('Segoe UI Semibold', 10),
                          spacing1=8, spacing3=2, lmargin1=4, lmargin2=4)
        for style, line in HELP_SECTIONS:
            txt.insert('end', line + '\n', style)
        txt.configure(state='disabled')
        ttk.Button(win, text='Close', command=win.destroy).pack(pady=(0, 12))

    def _set_running(self, running):
        self.btn_run.configure(state='disabled' if running else 'normal')
        self.btn_stop.configure(state='normal' if running else 'disabled')
        if running:
            self.status_var.set('Running...')

    def _on_close(self):
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.terminate()
            except Exception:
                pass
        self.destroy()


def main():
    selftest = '--selftest' in sys.argv
    app = App()
    if selftest:
        app.withdraw()
        app.update_idletasks()
        app.update()
        app.toggle_theme()   # exercise light theme
        app.update_idletasks()
        app.update()
        print('selftest OK')
        app.destroy()
        return
    app.mainloop()


if __name__ == '__main__':
    main()
