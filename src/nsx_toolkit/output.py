"""Console output: color, tables, spinners, prompts, and run-mode state.

Run-mode state (color / JSON / interactive / assume-yes / debug) lives here
behind setter functions rather than as imported globals, so the package build
and the amalgamated single-file build behave identically.
"""

import os
import re
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from .errors import UserAbort

W = 76
_ANSI_RE = re.compile(r"\033\[[0-9;]*m")


# === RUN MODE ===
def _enable_ansi_windows():
    if os.name != "nt":
        return True
    try:
        import ctypes
        k = ctypes.windll.kernel32
        h = k.GetStdHandle(-11)
        m = ctypes.c_ulong()
        k.GetConsoleMode(h, ctypes.byref(m))
        k.SetConsoleMode(h, m.value | 0x0004)
        return True
    except Exception:
        return False


_color_enabled = (sys.stdout.isatty() and "NO_COLOR" not in os.environ
                  and _enable_ansi_windows())
_json_mode = False
_interactive = sys.stdin.isatty()
_assume_yes = False
_debug = False

# When buffering, say() collects instead of printing, so a caller that later
# discovers the run found nothing new can drop the whole report before it
# reaches stdout. That is what makes a nightly cron job silent on a quiet
# night -- and errors are deliberately never buffered.
_buffer = None


def set_color(enabled):
    global _color_enabled
    _color_enabled = bool(enabled)


def set_json_mode(enabled):
    """JSON mode implies no color and no prompting: stdout must stay parseable."""
    global _json_mode, _color_enabled, _interactive
    _json_mode = bool(enabled)
    if _json_mode:
        _color_enabled = False
        _interactive = False


def is_json_mode():
    return _json_mode


def set_interactive(enabled):
    global _interactive
    _interactive = bool(enabled)


def is_interactive():
    return _interactive


def set_assume_yes(enabled):
    global _assume_yes
    _assume_yes = bool(enabled)


def assume_yes():
    return _assume_yes


def set_debug(enabled):
    global _debug
    _debug = bool(enabled)


def is_debug():
    return _debug


def start_buffering():
    """Collect console output instead of printing it."""
    global _buffer
    _buffer = []


def is_buffering():
    return _buffer is not None


def flush_buffered():
    """Print everything collected, and stop buffering."""
    global _buffer
    lines, _buffer = _buffer, None
    for line in (lines or []):
        print(line, flush=True)
    return len(lines or [])


def drop_buffered():
    """Discard everything collected, and stop buffering."""
    global _buffer
    dropped, _buffer = _buffer, None
    return len(dropped or [])


# === COLOR ===
def _c(code, text):
    return "\033[{}m{}\033[0m".format(code, text) if _color_enabled else str(text)


def cG(t):
    return _c("32", t)


def cR(t):
    return _c("31", t)


def cY(t):
    return _c("33", t)


def cC(t):
    return _c("36", t)


def cB(t):
    return _c("1", t)


def cD(t):
    return _c("2", t)


def cBG(t):
    return _c("1;32", t)


def cBR(t):
    return _c("1;31", t)


def cBY(t):
    return _c("1;33", t)


def cBC(t):
    return _c("1;36", t)


def strip_ansi(text):
    return _ANSI_RE.sub("", str(text))


# === MESSAGES ===
def say(msg=""):
    if _json_mode:
        return
    if _buffer is not None:
        _buffer.append(msg)
        return
    print(msg, flush=True)


def err(msg):
    print("  {} {}".format(cBR("[ERROR]"), msg), file=sys.stderr, flush=True)


def warn(msg):
    if not _json_mode:
        print("  {}  {}".format(cBY("[WARN]"), msg), flush=True)


def ok_msg(msg):
    if not _json_mode:
        print("  {}    {}".format(cBG("[OK]"), msg), flush=True)


def debug(msg):
    """Diagnostic trace. Goes to stderr so it never pollutes --json stdout."""
    if _debug:
        print("  {} {}".format(cD("[debug]"), msg), file=sys.stderr, flush=True)


def hr(char="-"):
    say(cD(char * W))


def section(title):
    say("\n{}\n  {}\n{}".format(cBC("=" * W), cB(title), cBC("=" * W)))


def progress_bar(cur, total, width=25):
    if total == 0:
        return "[" + " " * width + "]   0%"
    filled = int(width * cur / total)
    bar = "=" * filled + " " * (width - filled)
    pct = int(100 * cur / total)
    fn = cBG if pct >= 80 else (cBY if pct >= 50 else cBR)
    return "[{}] {}".format(fn(bar), fn("{:3d}%".format(pct)))


def table(headers, rows, indent=2):
    if not rows:
        say(" " * indent + cD("(no data)"))
        return
    widths = [len(h) for h in headers]
    sr = []
    for row in rows:
        cells = [str(c) for c in row]
        while len(cells) < len(headers):
            cells.append("")
        sr.append(cells)
        for i, c in enumerate(cells):
            if i < len(widths):
                widths[i] = max(widths[i], len(strip_ansi(c)))
    pad = " " * indent
    say(pad + "  ".join(cB(h.ljust(widths[i])) for i, h in enumerate(headers)))
    say(pad + "  ".join(cD("-" * widths[i]) for i in range(len(headers))))
    for cells in sr:
        parts = []
        for i, c in enumerate(cells):
            cl = len(strip_ansi(c))
            parts.append(c.ljust(widths[i] + len(c) - cl))
        say(pad + "  ".join(parts))


def more_note(shown, total, where="full set in export"):
    """Console truncation notice. Truncation is display-only -- exports and
    JSON always carry every row."""
    if total > shown:
        say("    {}".format(cD("... +{} more ({})".format(total - shown, where))))


class Spinner:
    FRAMES = ["|", "/", "-", "\\"]

    def __init__(self, label="Working"):
        self._label = label
        self._stop = threading.Event()
        self._thread = None

    def __enter__(self):
        if _json_mode or not sys.stdout.isatty():
            return self
        self._stop.clear()
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *_):
        if self._thread:
            self._stop.set()
            self._thread.join(timeout=2)
            sys.stdout.write("\r" + " " * (len(self._label) + 12) + "\r")
            sys.stdout.flush()

    def _spin(self):
        i = 0
        while not self._stop.is_set():
            sys.stdout.write("\r  {} {} ...".format(cC(self.FRAMES[i % 4]), self._label))
            sys.stdout.flush()
            i += 1
            self._stop.wait(0.15)


def parallel_run(items, fn, label="Querying", max_workers=8, key=None):
    """Run fn over items concurrently. Returns {key(item): result_or_Exception}.

    Exceptions are captured per item rather than raised, so one unreachable
    manager never aborts a sweep across the rest.
    """
    results = {}
    n = len(items)
    if n == 0:
        return results
    if key is None:
        def key(x):
            return getattr(x, "name", x)
    with ThreadPoolExecutor(max_workers=min(n, max_workers)) as pool:
        futures = {pool.submit(fn, it): it for it in items}
        done = 0
        for future in as_completed(futures):
            done += 1
            it = futures[future]
            if not _json_mode and sys.stdout.isatty():
                counter = cC("[{}/{}]".format(done, n))
                sys.stdout.write("\r  {} {} ...".format(counter, label))
                sys.stdout.flush()
            try:
                results[key(it)] = future.result()
            except Exception as e:
                results[key(it)] = e
    if not _json_mode and sys.stdout.isatty():
        sys.stdout.write("\r" + " " * 60 + "\r")
        sys.stdout.flush()
    return results


# === PROMPTS ===
def ask(prompt, default=None, allow_back=True):
    """Prompt for input. In non-interactive mode the default is returned
    rather than blocking on a stdin that will never deliver."""
    if not _interactive:
        if default is not None:
            return default
        raise UserAbort()
    try:
        val = input(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        raise UserAbort() from None
    if allow_back and val.lower() == "b":
        raise UserAbort()
    return val if val else (default if default is not None else val)


def confirm(prompt):
    """Yes/no gate. --yes auto-confirms; non-interactive without --yes is a
    refusal, never an assumed yes."""
    if _assume_yes:
        say("{}{}".format(prompt, cG("yes (--yes)")))
        return True
    if not _interactive:
        return False
    return ask(prompt, default="n", allow_back=False).lower() in ("y", "yes")
