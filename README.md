<div align="center">

# 💉 XSS-Hunter

### Exam-grade reflected-XSS fuzzer. Single file. Zero dependencies.

*Built to replace Burp Intruder when you need speed under exam pressure.*

<br>

![Python](https://img.shields.io/badge/Python-3.7%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Dependencies](https://img.shields.io/badge/Dependencies-NONE-2ECC71?style=for-the-badge)
![GUI](https://img.shields.io/badge/GUI-tkinter-9B59B6?style=for-the-badge&logo=windowsterminal&logoColor=white)
![Platform](https://img.shields.io/badge/Windows%20%7C%20Linux%20%7C%20Kali-1F6FEB?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-F1C40F?style=for-the-badge)
![Authorized use only](https://img.shields.io/badge/Authorized%20use-ONLY-E74C3C?style=for-the-badge)

```text
╔══════════════════════════════════════════════════════╗
║          XSS Hunter - Exam-Grade Fuzzer              ║
║  Threaded | Grep-filter | Auto-detect | Burp-aware   ║
║          stdlib only · no DoS · polite               ║
╚══════════════════════════════════════════════════════╝
```

</div>

XSS-Hunter is a threaded reflected-XSS fuzzer built to replace Burp Intruder for
the kind of web challenges you meet in a pentesting exam. It is one Python file
with zero dependencies, so it runs anywhere Python 3 runs: Kali, Windows, a fresh
exam VM, a locked-down lab box. No `pip install`, no virtualenv, nothing to break
five minutes before the clock starts.

It is built for **authorized** testing only: web pentesting labs, CTFs, and exam
environments where you have permission to attack the target.

---

## 📖 Table of contents

- [💡 Why this tool exists](#-why-this-tool-exists)
- [🍪 The session cookie warning (read this first)](#-the-session-cookie-warning-read-this-first)
- [⚙️ Install and requirements](#-install-and-requirements)
- [🖥️ Graphical interface (GUI)](#-graphical-interface-gui)
- [🚀 Quick start](#-quick-start)
- [🧭 Finding the parameter to attack](#-finding-the-parameter-to-attack)
- [🎯 The four usage scenarios](#-the-four-usage-scenarios)
- [🔍 How detection works](#-how-detection-works)
- [🛰️ Auto-detect: finding the injectable parameter](#-auto-detect-finding-the-injectable-parameter)
- [🚩 Every flag, explained](#-every-flag-explained)
- [🍪 Cookies and sessions in detail](#-cookies-and-sessions-in-detail)
- [📨 Using a Burp request file](#-using-a-burp-request-file)
- [💣 The built-in payload list](#-the-built-in-payload-list)
- [📤 Output and exit codes](#-output-and-exit-codes)
- [🛡️ Politeness and safety caps](#-politeness-and-safety-caps)
- [🩹 Troubleshooting](#-troubleshooting)
- [👤 Author](#-author)

---

## 💡 Why this tool exists

In an exam you do not have time to fight your tools. Burp Intruder is powerful,
but on the free edition it is throttled to a crawl, and setting up positions,
payload sets, and grep-match rules under a timer is slow. When the professor
drops a hint like "grep for the word trouble", you want to point a tool at the
parameter, feed it payloads, and have it shout the moment a payload makes that
word appear.

XSS-Hunter does exactly the few things that matter in a web XSS exam:

- **It always sends your session cookie verbatim.** Most exam challenges only
  work if the request carries the exact `PHPSESSID` the server handed you.
  XSS-Hunter never strips, rotates, or regenerates it. See the warning below, it
  is the single most important thing in this README.
- **It has a grep mode for the classic exam hint.** When the prof says "grep for
  X", `--grep X` makes any response containing that word an instant winner.
- **It auto-detects the injectable parameter** when you do not know which field
  reflects, by firing a unique canary at a list of common parameter names.
- **It ships about 25 high-probability payloads** that it tries first, so easy
  challenges often fall in a second or two before your wordlist even starts.
- **It reads Burp requests directly**, so headers, cookies, and odd body shapes
  are replayed exactly as captured.
- **It is polite** and connection-reusing, so it is fast without being a flood.
- **The help text is the manual.** Run `-h` once and you never re-ask what a flag
  does.

---

## 🍪 The session cookie warning (read this first)

This is written in bold because students lose marks over it every single year.

> ### Treat your session cookie as sacred
>
> **Do NOT change your browser during the exam.** If you absolutely must,
> carry the session over to the new browser by hand. Switching browsers can
> silently drop your session and the exam stops responding.
>
> **Do NOT change your `sessionID` / `PHPSESSID`.** If it changes, the exam
> stops. The challenge state is tied to that one cookie value.
>
> **Treat the cookie as sacred:** never strip it, never regenerate it, never
> let a tool rotate it. XSS-Hunter is built around this rule. It sends your
> cookie exactly as you give it, on every single request, and it shows you the
> cookie it parsed before it sends anything so you can confirm it is the right
> one.

Every request XSS-Hunter sends carries the cookie you pass with `--cookie`
(or the `Cookie:` header inside your `--request` file). It is never touched.
Before the first request goes out, the tool prints the cookie it is about to use
and waits for you to press ENTER. If it looks wrong, press Ctrl-C and fix it.
Nothing has been sent yet. If you run with no cookie at all, it warns you so you
do not accidentally fuzz an unauthenticated session.

---

## ⚙️ Install and requirements

- **Python 3.7 or newer.** That is the only requirement.
- No third-party packages. Everything used (`http.client`, `ssl`, `argparse`,
  `threading`) ships with Python itself.

```bash
git clone https://github.com/mizazhaider-ceh/XSS-Hunter.git
cd XSS-Hunter
python xss_hunter.py -h
```

On Windows use `python`, on most Linux boxes use `python3`. Both work.

---

## 🖥️ Graphical interface (GUI)

If you prefer clicking over typing, there is a full graphical front-end:
`xss_hunter_gui.py`. It is also pure standard library (Python's built-in
tkinter), so there is still nothing to install.

```bash
python xss_hunter_gui.py
```

There is nothing to `pip install`: the GUI uses Python's built-in tkinter. On
Windows and macOS it just works. On some Linux distros tkinter is a separate
system package, so if the GUI complains `No module named 'tkinter'`, install it
with `sudo apt install python3-tk` (Debian / Ubuntu / Kali). See
`requirements.txt` for the full note.

Keep `xss_hunter_gui.py` in the same folder as `xss_hunter.py`. The GUI does not
re-implement anything: it builds the exact `xss_hunter.py` command from the form
you fill in and runs the real tool underneath, streaming its live output into the
window. Whatever the command line does, the GUI does identically.

What you get:

- **Every flag as a form field**, grouped into Target, Injection, Payloads,
  Detection, Network and Session, and Output, with a short hint next to each one.
- **A live output panel** with the banner, winning payloads in green, reflected
  results in yellow, and the running progress shown on the status bar.
- **A command preview box** that shows the exact command being run, so you learn
  the command line by using the GUI. There is a Copy button to grab it.
- **A cookie safety dialog**: before the first request, the GUI lists the cookies
  it is about to send (partly redacted) and asks you to confirm, so the session
  cookie stays sacred. Internally it passes `-y` to the engine so nothing hangs
  waiting on a terminal prompt.
- **Run and Stop buttons.** Stop cleanly terminates the run.

The GUI always runs the engine with `--no-color` (so the panel text stays clean)
and `-y` (so the confirmation is handled by the dialog above). Everything else is
exactly what you selected.

---

## 🚀 Quick start

The most common exam case: the professor tells you to grep for a keyword.

```bash
python xss_hunter.py \
    -u "https://target/challenge.php?challenge=2" \
    -p alert \
    -f payloads.txt \
    --grep trouble \
    --cookie "PHPSESSID=your_real_session_value_here"
```

Read that command top to bottom:

- `-u` is the target URL, including any fixed query parameters like `challenge=2`.
- `-p alert` is the parameter the payload is injected into.
- `-f payloads.txt` is your payload wordlist (tried after the built-in list).
- `--grep trouble` means any response containing "trouble" is the winner. When a
  hint says "grep for tr0uble (replace 0 with o)", the word to pass is `trouble`.
- `--cookie "PHPSESSID=..."` carries your exam session. This is the part most
  people forget.

---

## 🧭 Finding the parameter to attack

`-p` tells the tool **which form field to inject the payload into**. You never
guess it. You read it straight from the page's own HTML.

Open the challenge, right-click and choose **View Source** (or press `F12` for
DevTools), and look at the form. Here is the real HTML from mock-exam
challenge 2:

```html
<p class="lead cover-copy">
    You're trying to escape and run into Jasmine - quick create an alert to distract everybody!
    <form method="POST" action="/challenge.php?challenge=2">
        <input type="text" name="alert">      <!-- THIS name is your -p -->
        <input type="submit" value="Submit">
    </form>
</p>
```

Read the form like a map:

| What you see in the HTML              | What it gives the tool          |
| ------------------------------------- | ------------------------------- |
| `method="POST"`                       | `-X POST` (already the default) |
| `action="/challenge.php?challenge=2"` | the `-u` URL                    |
| `<input ... name="alert">`            | **`-p alert`**                  |

So that single form turns into this command:

```bash
python xss_hunter.py \
    -u "https://mockexam.wpt.edu.technet.howest.be/challenge.php?challenge=2" \
    -p alert \
    --grep congratulations \
    --cookie "PHPSESSID=your_live_session" \
    --insecure
```

> 💡 **Not sure which input reflects?** If the form has several fields, run once
> with `--auto-detect` (plus your cookie). The tool fires a marker at each common
> field name and reports which one echoes it back. Put that name into `-p` and
> run for real.

---

## 🎯 The four usage scenarios

These are the four shapes nearly every XSS challenge takes. Pick the one that
matches your situation.

### A. The professor drops a "grep for X" hint

The HTML or the brief says something like "grep for 'tr0uble' (replace 0 with o)".
That means the winning payload makes the response contain "trouble".

```bash
python xss_hunter.py \
    -u "https://site/challenge.php?challenge=2" \
    -p alert -f payloads.txt --grep trouble \
    --cookie "PHPSESSID=abc; other=xyz"
```

### B. You captured the request in Burp

The cleanest way to handle custom headers, odd body shapes, and exact field
positions. Save the request to `req.txt`, put the literal word `FUZZ` (or `§§`)
where the payload should go, and everything else is reused verbatim.

```bash
python xss_hunter.py --request req.txt -f payloads.txt --grep trouble
```

### C. You do not know which field is injectable

Let the tool probe common parameter names with a unique canary and report which
ones reflect it.

```bash
python xss_hunter.py -u URL --auto-detect --cookie "..."
```

It probes `q, search, input, alert, name, data, msg, text, comment, s, query,
pin, code`. Pick one that reflects, then re-run in mode A or D against it.

### D. No hint, you just want any working XSS

Fuzz the parameter and let the tool confirm execution by reflection plus
JavaScript-execution markers.

```bash
python xss_hunter.py -u URL -p alert -f payloads.txt
```

A hit here means the payload was reflected AND the response shows
script-execution markers like `<script`, `onerror=`, or `alert(`.

---

## 🔍 How detection works

XSS-Hunter labels every response with one of four outcomes, in strict priority
order. The first two are hits; the last two are not.

| Label | Meaning | Is it a win |
|-------|---------|-------------|
| `[+] GREP-HIT` | Your `--grep` keyword was found in the response. | **Yes.** Overrides everything else. This is your winner. |
| `[+] XSS` | The payload was reflected AND the response contains JavaScript-execution markers. | **Yes.** A confirmed reflected XSS. |
| `[~] REFLECTED` | The payload was echoed back but appears inert (no execution markers). | No, but worth a manual look with `-v`. |
| `[x] BLOCKED` | The payload was not reflected at all. | No. Filtered or encoded out. |

**How `--grep` wins.** When you pass `--grep WORD`, the only thing that matters is
whether that word (case-insensitive) appears in the response body. If it does,
that payload is the winner and, unless you pass `--all`, the run stops
immediately. This is the exact behaviour you want for the "grep for X" exam hint.

**How auto XSS detection works without grep.** A response counts as a confirmed
`XSS` when the payload (or its HTML-unescaped form) is reflected in the body and
the body also contains one of the execution clues: `<script`, `onerror=`,
`onload=`, `javascript:`, `alert(`, `confirm(`, `prompt(`, `onfocus=`, `ondrag=`,
`onclick=`, or `onmouseover=`. Reflection alone, with no such marker, is labelled
`REFLECTED` so you know to inspect it by hand.

---

## 🛰️ Auto-detect: finding the injectable parameter

When you do not yet know which field reflects user input, run with `--auto-detect`
and a URL. The tool sends a unique canary string (for example
`XSSHUNTERCANARY1718000000`) to each common parameter name in turn and reports
which ones echo it back:

```bash
python xss_hunter.py -u "https://target/challenge.php" --auto-detect \
    --cookie "PHPSESSID=..." -X GET
```

Output tells you, per parameter, whether it reflected the canary. When it finds
candidates it prints the exact follow-up command to run, for example
`-p search -f payloads.txt --grep WORD`. From there you switch to scenario A or D.

---

## 🚩 Every flag, explained

### Target (use `-u` OR `--request`)

| Flag | What it does |
|------|--------------|
| `-u`, `--url URL` | The full target URL, including fixed query parameters. Pair with `-p` to say which parameter to fuzz. |
| `--request FILE` | Path to a Burp-style raw HTTP request file. Put the word `FUZZ` (or `§§`) where the payload should be inserted. Method, URL, headers, cookies, and body are reused from the file. |

### Injection

| Flag | What it does |
|------|--------------|
| `-p`, `--param NAME` | The parameter name to inject into. Ignored if `--request` contains `FUZZ`, or when using `--auto-detect`. |
| `-X`, `--method {GET,POST}` | HTTP method. Default `POST`. Use `-X GET` for `?q=payload` style URLs. |
| `--extra-param K=V` | A fixed parameter sent with every request. Repeatable. Use it for things like `challenge=2` or `submit=Submit`. |
| `--auto-detect` | Send a unique canary to a list of common parameter names and report which ones reflect it. Use when you do not know `-p` yet. |

### Payloads

| Flag | What it does |
|------|--------------|
| `-f`, `--file FILE` | Payload list, one per line. Blank lines and lines starting with `#` are ignored. Optional: if omitted, only the built-in common list runs. |
| `--no-common` | Skip the built-in high-probability list. By default the common payloads are tried FIRST, then your wordlist. |
| `--common-only` | Run ONLY the built-in list and ignore any wordlist. The fastest first probe. |
| `--limit N` | Only test the first N payloads. A quick smoke-test before a full run. |

### Detection

| Flag | What it does |
|------|--------------|
| `--grep WORD` | Case-insensitive keyword to search for in each response. If present, that payload is an instant winner and overrides all other detection. Use it for the "grep for X" hint. |
| `--all` | Test every payload instead of stopping at the first hit. Default is to stop the moment a GREP-HIT or XSS is found. Use `--all` to enumerate every working payload. |

### Network and session

| Flag | What it does |
|------|--------------|
| `--cookie STR` | The Cookie header sent with every request. Example: `--cookie "PHPSESSID=abc123; _ga=GA1.1.x"`. The tool echoes the parsed value before the run. |
| `--header K:V` | An extra HTTP header. Repeatable. Example: `--header "X-Forwarded-For: 127.0.0.1"`. |
| `-t`, `--threads N` | Worker threads. Default 20. Hard-capped at 30 to stay polite. Higher helps when the lab server is slow (latency-bound). |
| `-d`, `--delay N` | Per-thread sleep between requests, in seconds. Default 0.0. Raise to about 0.2 if the lab is fragile or you see 429 responses. |
| `--timeout N` | Per-request timeout in seconds. Default 8. |
| `--insecure` | Skip TLS certificate verification. Lab use only, but lab use is nearly always, because lab certs are self-signed. |

### Output

| Flag | What it does |
|------|--------------|
| `-o`, `--output FILE` | Append hits to this file (index, label, status, payload). Good for the writeup. |
| `-v`, `--verbose` | Show every result, including reflected, blocked, and errors, not just hits. |
| `--no-color` | Disable ANSI colors, for piping or dumb terminals. |
| `-y`, `--yes` | Skip the cookie-confirmation prompt. Use it only once you have confirmed the cookie. |

### Misc

| Flag | What it does |
|------|--------------|
| `-h`, `--help` | Show the full built-in help, which is a complete manual on its own. |
| `--cheatsheet` | Print a one-screen cheat sheet of the four scenarios and exit. |

---

## 🍪 Cookies and sessions in detail

There are two ways to attach a session, and they cover every situation:

1. **`--cookie` on the command line** when you are using `-u`:

   ```bash
   python xss_hunter.py -u URL -p alert -f payloads.txt \
       --grep trouble --cookie "PHPSESSID=your_value"
   ```

2. **A `Cookie:` header inside your `--request` file** when you are replaying a
   Burp capture. It is reused exactly as captured. If you also pass `--cookie` on
   the command line, that value takes over the `Cookie` header in the file, which
   is handy when your captured session has expired and you want to swap in a fresh
   one without re-saving the file.

Either way, before the first request the tool prints a **cookie safety check**:
it lists each cookie name with the value partly redacted, reminds you the cookie
will be sent verbatim, and waits for ENTER. This is your last chance to confirm
you are about to attack with the correct session. Press Ctrl-C to abort with
nothing sent. Pass `-y` to skip this prompt once you trust the value.

---

## 📨 Using a Burp request file

This mode is the most reliable for anything with custom headers or an unusual
body. Capture the request in Burp, copy it to a file, and mark the one spot where
the payload belongs.

`req.txt`:

```http
POST /challenge.php?challenge=2 HTTP/1.1
Host: target.lab
Cookie: PHPSESSID=your_real_session_value
Content-Type: application/x-www-form-urlencoded

alert=FUZZ&submit=Submit
```

Then run:

```bash
python xss_hunter.py --request req.txt -f payloads.txt --grep trouble
```

Notes that save time:

- The marker is the literal word `FUZZ`. If that is awkward, `§§` is also
  accepted. It can sit in the URL, the body, or a header value.
- At least one marker must be present, or the tool stops and tells you.
- The scheme is guessed from the `Host` header: a host ending in `:80` is treated
  as `http`, everything else as `https`.
- The `Content-Length` header is recomputed for you on every request.
- The payload is URL-encoded when inserted into the URL or body, and stripped of
  stray carriage returns when inserted into a header value.

---

## 💣 The built-in payload list

When you do not pass `--no-common`, XSS-Hunter tries about 25 curated, high-
probability payloads before your wordlist. They are ordered most-likely-first and
cover the contexts that come up most in labs:

- Plain script tags, for example `<script>alert(1)</script>`.
- Self-triggering tags that need no interaction, for example `<svg onload=alert(1)>`,
  `<body onload=alert(1)>`, `<iframe onload=alert(1)>`.
- Image and media error handlers, for example `<img src=x onerror=alert(1)>`.
- Auto-focus handlers, for example `<input autofocus onfocus=alert(1)>`.
- Attribute break-outs for when input lands inside an attribute value, for
  example `"><script>alert(1)</script>` and `" onmouseover=alert(1) x="`.
- `javascript:` URI payloads for href and src contexts.

Because they run first and are de-duplicated against your wordlist, easy
challenges usually fall within the first few requests. Use `--common-only` to run
just this list as a fast first probe.

---

## 📤 Output and exit codes

A winning payload is printed in green with its label (GREP-HIT or XSS), the HTTP
status, and the payload itself, so you can paste it straight into your report.
With `-o` the same line is appended to your output file, timestamped per run.

The progress bar shows payloads completed, percentage, and live request rate, and
the summary breaks results down into hits, reflected, blocked, and errors. On
Ctrl-C the run stops cleanly and prints whatever it found so far.

**Exit codes** (useful for scripting):

| Code | Meaning |
|------|---------|
| `0` | At least one hit (or a completed `--auto-detect` run). |
| `1` | Zero hits. |
| `2` | Argument or network error (bad flags, unreadable payload file, missing parameter). |

---

## 🛡️ Politeness and safety caps

XSS-Hunter is deliberately not a denial-of-service tool.

- Threads default to **20** and are **hard-capped at 30**. Ask for more and it
  quietly clamps and tells you.
- The default delay is **0** because fuzzing a reflection endpoint is light, but
  raise it to about `0.2` with `-d` the moment you see `429` responses or the lab
  looks fragile.
- Connections are kept alive per thread, so speed comes from reuse rather than
  from hammering the server with a flood of new sockets.

---

## 🩹 Troubleshooting

**Nothing is a hit but you expected one.** Check your `--grep` keyword against the
exact word the challenge wants, and confirm `--cookie` is the active session. A
stale session is the most common reason a known-good payload reports nothing.

**Everything is BLOCKED.** The input is probably not being reflected at the
parameter you chose. Run `--auto-detect` to find a parameter that does reflect,
or try `-X GET` if the form actually uses the query string.

**Lots of REFLECTED, no XSS.** The payload is echoed but the page encodes it or it
lands in an inert context. Re-run with `-v` to read the reflected payloads and
adjust, or add a context break-out payload like `"><svg onload=alert(1)>`.

**TLS certificate error.** Add `--insecure`. Lab and exam servers almost always
use self-signed certificates. The tool also detects this and reminds you.

**It is too aggressive or you see 429s.** Lower threads and add a delay, for
example `-t 10 -d 0.2`.

**The session seems to have died mid-run.** Re-read
[the cookie warning](#the-session-cookie-warning-read-this-first). Do not switch
browsers, do not let anything regenerate the cookie. Grab a fresh `PHPSESSID`,
pass it with `--cookie`, and run again.

---

## 👤 Author

Built by **Muhammad Izaz Haider**, Student of CyberSecurity at Howest, lover of
AI and offensive security.

- GitHub: [@mizazhaider-ceh](https://github.com/mizazhaider-ceh)

Made for students, by a student. If it helped you pass, pass it on.

---

### Legal and ethical use

XSS-Hunter is for **authorized** security testing only: your own systems,
explicit-permission engagements, CTFs, and exam labs where attacking the target
is the point. Testing a site you do not have permission to test is illegal in
most countries. You are responsible for how you use it.

---

<div align="center">

### ⭐ If XSS-Hunter helped you, drop a star and share it with your class.

**Made with care for students, by a student.**

![Built by Muhammad Izaz Haider](https://img.shields.io/badge/Built%20by-Muhammad%20Izaz%20Haider-36C5F0?style=for-the-badge)
![AI x Offensive Security](https://img.shields.io/badge/AI%20x%20Offensive%20Security-9B59B6?style=for-the-badge)

</div>
