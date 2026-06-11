#!/usr/bin/env python3
"""xss_hunter_gui.py - Graphical front-end for xss_hunter.py.

Zero-dependency GUI (Python stdlib tkinter only, no pip install). It does NOT
re-implement the engine: it builds the exact xss_hunter.py command from the
form and runs the real CLI as a subprocess, streaming its output live. Same
engine as the command line, friendlier controls.

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

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext

HERE = os.path.dirname(os.path.abspath(__file__))
CLI = os.path.join(HERE, 'xss_hunter.py')

# ---- palette (dark theme) ----
BG = '#0d111b'
PANEL = '#161c2c'
FIELD = '#0b0f18'
ACCENT = '#36c5f0'
GOOD = '#2ecc71'
WARN = '#f1c40f'
BAD = '#ff6b6b'
FG = '#e6e9ef'
MUTED = '#8a93a6'
MONO = ('Consolas', 10)
UI = ('Segoe UI', 10)


class ScrollFrame(ttk.Frame):
    """A vertically scrollable frame. Put widgets in self.body."""

    def __init__(self, master, **kw):
        super().__init__(master, **kw)
        self.canvas = tk.Canvas(self, bg=PANEL, highlightthickness=0, borderwidth=0)
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


# Field guide shown by the Help button. Each item is (style, text); blank text
# is a spacer line.
HELP_SECTIONS = [
    ('h', 'What this window does'),
    ('p', 'The GUI builds a real xss_hunter.py command from the fields on the '
          'left and runs the actual tool, streaming its output on the right. The '
          '"Command preview" box always shows exactly what is being run.'),
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
    ('p', 'If a form has several inputs and you are unsure which reflects, tick '
          '"Auto-detect" and run. It tells you which field echoes your input. '
          'Then put that name into Parameter and run for real.'),
    ('h', 'The session cookie is sacred'),
    ('p', 'Most exam challenges only count if the request carries your exact '
          'PHPSESSID. Paste it into the Cookie field as PHPSESSID=... (get it from '
          'DevTools > Application > Cookies). Never let it change mid-exam. Before '
          'the first request the GUI shows the cookie and asks you to confirm.'),
    ('h', 'How a winner is decided'),
    ('p', 'Grep keyword (--grep): if the response contains this word, it is an '
          'instant winner. On the Howest mock exam every solved challenge returns '
          'the word "congratulations", so Grep = congratulations is usually all '
          'you need.'),
    ('p', 'With no grep, a hit = the payload is reflected AND the response shows '
          'JavaScript-execution markers (script, onerror, onload, alert, ...).'),
    ('h', 'Slow target?  Tune these (important)'),
    ('p', 'If the summary shows lots of Errors, the server is too slow for your '
          'settings. The mock exam answers in about 7 seconds. Use Threads 5, '
          'Delay 0.2, Timeout 25. High threads + low timeout on a slow server '
          'makes every request time out, which shows up as Errors, not hits.'),
    ('h', 'Quick checklist'),
    ('p', '1. URL from the form action.'),
    ('p', '2. Parameter from the input name.'),
    ('p', '3. Cookie = your live PHPSESSID.'),
    ('p', '4. Grep = congratulations (mock exam).'),
    ('p', '5. Tick Skip TLS verify (self-signed lab certificates).'),
    ('p', '6. Slow server: lower threads, raise timeout.'),
]


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title('XSS-Hunter - GUI')
        self.geometry('1180x800')
        self.minsize(960, 640)
        self.configure(bg=BG)
        self.proc = None
        self.q = None
        self._build_style()
        self._build_header()
        self._build_body()
        self.protocol('WM_DELETE_WINDOW', self._on_close)

    # ---------- styling ----------
    def _build_style(self):
        st = ttk.Style(self)
        try:
            st.theme_use('clam')
        except tk.TclError:
            pass
        st.configure('.', background=PANEL, foreground=FG, fieldbackground=FIELD, font=UI)
        st.configure('TFrame', background=PANEL)
        st.configure('TLabel', background=PANEL, foreground=FG)
        st.configure('Hint.TLabel', background=PANEL, foreground=MUTED, font=('Segoe UI', 9))
        st.configure('TCheckbutton', background=PANEL, foreground=FG)
        st.map('TCheckbutton', background=[('active', PANEL)])
        st.configure('TRadiobutton', background=PANEL, foreground=FG)
        st.map('TRadiobutton', background=[('active', PANEL)])
        st.configure('TButton', background='#22304a', foreground=FG, padding=6, borderwidth=0)
        st.map('TButton', background=[('active', '#2c3c5c')])
        st.configure('Run.TButton', background=GOOD, foreground='#06210f', font=('Segoe UI Semibold', 10))
        st.map('Run.TButton', background=[('active', '#3fe089')])
        st.configure('Stop.TButton', background='#5a2230', foreground=FG)
        st.map('Stop.TButton', background=[('active', '#7a2c40')])
        st.configure('TEntry', fieldbackground=FIELD, foreground=FG, insertcolor=FG)
        st.configure('TCombobox', fieldbackground=FIELD, foreground=FG)
        st.configure('TLabelframe', background=PANEL, bordercolor='#27314c')
        st.configure('TLabelframe.Label', background=PANEL, foreground=ACCENT,
                     font=('Segoe UI Semibold', 10))
        st.configure('Vertical.TScrollbar', background='#22304a', troughcolor=PANEL, borderwidth=0)

    # ---------- header ----------
    def _build_header(self):
        top = tk.Frame(self, bg=BG)
        top.pack(fill='x')
        tk.Label(top, text='XSS-Hunter', bg=BG, fg=ACCENT,
                 font=('Segoe UI Semibold', 18)).pack(anchor='w', padx=16, pady=(12, 0))
        tk.Label(top, text='Exam-grade reflected-XSS fuzzer  -  graphical front-end',
                 bg=BG, fg=MUTED, font=('Segoe UI', 10)).pack(anchor='w', padx=16)
        warn = tk.Label(
            top,
            text=('  Session cookie is sacred: never change your PHPSESSID and never switch '
                  'browser mid-exam. The cookie is sent verbatim, untouched, on every request.'),
            bg='#2a1d0a', fg='#ffd479', font=('Segoe UI', 9), anchor='w', justify='left',
            padx=10, pady=6,
        )
        warn.pack(fill='x', padx=16, pady=(8, 10))

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

    def _f(self, frame, row, label, var, hint='', save=False):
        ttk.Label(frame, text=label).grid(row=row, column=0, sticky='w', padx=8, pady=4)
        box = ttk.Frame(frame)
        box.grid(row=row, column=1, sticky='ew', padx=8, pady=4)
        box.columnconfigure(0, weight=1)
        ttk.Entry(box, textvariable=var).grid(row=0, column=0, sticky='ew')
        ttk.Button(box, text='Browse', width=8,
                   command=lambda: self._browse(var, save)).grid(row=0, column=1, padx=(6, 0))
        if hint:
            ttk.Label(frame, text=hint, style='Hint.TLabel').grid(row=row, column=2, sticky='w', padx=4)

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

    def _text(self, frame, row, label, height, hint=''):
        ttk.Label(frame, text=label).grid(row=row, column=0, sticky='nw', padx=8, pady=4)
        t = tk.Text(frame, height=height, bg=FIELD, fg=FG, insertbackground=FG, font=MONO,
                    wrap='none', borderwidth=1, relief='solid', highlightthickness=0)
        t.grid(row=row, column=1, sticky='ew', padx=8, pady=4)
        if hint:
            ttk.Label(frame, text=hint, style='Hint.TLabel').grid(row=row, column=2, sticky='nw', padx=4)
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
        main = tk.PanedWindow(self, orient='horizontal', bg=BG, sashwidth=6, bd=0)
        main.pack(fill='both', expand=True, padx=12, pady=(0, 12))

        left = ScrollFrame(main)
        main.add(left, minsize=400, width=600)
        form = left.body

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
        self._e(lf, 1, 'Target URL', self.v_url, 'e.g. https://site/challenge.php?challenge=2')
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
        self._f(lf, 0, 'Payload list (-f)', self.v_file, 'one payload per line (optional)')
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
        self._e(lf, 0, 'Cookie', self.v_cookie, 'PHPSESSID=...  (sent verbatim)',
                tip='Your live session, sent verbatim on every request. Get it from '
                    'DevTools > Application > Cookies. Most exam challenges only count '
                    'with the correct PHPSESSID. Never let it change mid-exam.')
        self.t_headers = self._text(lf, 1, 'Extra headers', 3, 'one per line, "Key: Value"')
        self.v_threads = tk.StringVar(value='20')
        self._e(lf, 2, 'Threads (-t)', self.v_threads, 'default 20, hard cap 30',
                tip='Parallel requests. On a SLOW server (like the mock exam, ~7s '
                    'per response) drop this to 5 or it floods and everything times '
                    'out as Errors.')
        self.v_delay = tk.StringVar(value='0.0')
        self._e(lf, 3, 'Delay (-d)', self.v_delay, 'raise to ~0.2 if you see 429s',
                tip='Pause between requests per thread. Raise to 0.2 on a slow or '
                    'fragile server.')
        self.v_timeout = tk.StringVar(value='8')
        self._e(lf, 4, 'Timeout', self.v_timeout, 'per request, seconds',
                tip='Give up on a request after this many seconds. Must be HIGHER '
                    'than the server response time. Mock exam answers in ~7s, so use '
                    '25 there. Too low = Errors instead of hits.')
        self.v_insecure = tk.BooleanVar()
        self._c(lf, 5, 'Skip TLS certificate verification (--insecure)', self.v_insecure)

        # ---- Output ----
        lf = self._section(form, 'Output')
        self.v_output = tk.StringVar()
        self._f(lf, 0, 'Save hits to (-o)', self.v_output, 'append winning payloads', save=True)
        self.v_verbose = tk.BooleanVar()
        self._c(lf, 1, 'Verbose: show every result (-v)', self.v_verbose)

        spacer = ttk.Frame(form)
        spacer.pack(pady=8)

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
        ttk.Button(btns, text='Clear log', command=self._clear_log).pack(side='left', padx=6)
        ttk.Button(btns, text='❔ Help', command=self.on_help).pack(side='right')

        self.log = scrolledtext.ScrolledText(
            rc, bg='#0a0e16', fg=FG, insertbackground=FG, font=MONO, wrap='word',
            state='disabled', borderwidth=0, highlightthickness=0)
        self.log.pack(fill='both', expand=True, padx=8, pady=4)
        self.log.tag_configure('good', foreground=GOOD)
        self.log.tag_configure('bad', foreground=BAD)
        self.log.tag_configure('warn', foreground=WARN)
        self.log.tag_configure('accent', foreground=ACCENT)
        self.log.tag_configure('cmd', foreground='#9bdcff')
        self.log.tag_configure('muted', foreground=MUTED)

        self.status_var = tk.StringVar(value='Idle.')
        tk.Label(rc, textvariable=self.status_var, bg=PANEL, fg=ACCENT, font=MONO,
                 anchor='w').pack(fill='x', padx=8, pady=(0, 8))

    # ---------- command building ----------
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
        win = tk.Toplevel(self)
        win.title('XSS-Hunter - Help & Field Guide')
        win.configure(bg=BG)
        win.geometry('740x660')
        win.transient(self)
        tk.Label(win, text='XSS-Hunter  ·  Field Guide', bg=BG, fg=ACCENT,
                 font=('Segoe UI Semibold', 15)).pack(anchor='w', padx=16, pady=(14, 2))
        tk.Label(win, text='Hover any field in the main window for a quick tip. '
                           'This guide is the long version.',
                 bg=BG, fg=MUTED, font=('Segoe UI', 9)).pack(anchor='w', padx=16, pady=(0, 8))
        txt = scrolledtext.ScrolledText(win, bg='#0a0e16', fg=FG, insertbackground=FG,
                                        font=('Segoe UI', 10), wrap='word', borderwidth=0,
                                        highlightthickness=0, padx=14, pady=10)
        txt.pack(fill='both', expand=True, padx=12, pady=(0, 10))
        txt.tag_configure('h', foreground=ACCENT, font=('Segoe UI Semibold', 12),
                          spacing1=12, spacing3=4)
        txt.tag_configure('p', foreground=FG, font=('Segoe UI', 10), spacing3=4,
                          lmargin1=4, lmargin2=4)
        txt.tag_configure('c', foreground='#9bdcff', font=('Consolas', 10), lmargin1=16, lmargin2=16)
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
        print('selftest OK')
        app.destroy()
        return
    app.mainloop()


if __name__ == '__main__':
    main()
