#!/usr/bin/env python3
"""
linWinPwn Web UI - PTY-backed dashboard for lefayjey's linWinPwn.

Design
------
The real logic stays in ../linWinPwn.sh. This server only:
  * launches that script inside a pseudo-terminal (one "session" PTY), driven
    by the dashboard menu buttons and/or typed input, and
  * exposes a second, independent raw shell PTY ("embedded terminal").

Both PTYs stream to the browser over WebSockets and render in xterm.js, so
every interactive sub-prompt the script asks (read -rp ">> ") is answered
naturally by typing into the terminal. No command logic is re-implemented here.

Security: this is a local operator console that runs attack tooling with the
privileges of the user who starts it. Bind to 127.0.0.1 and keep it off any
network you do not control. An optional auth token (LWP_WEB_TOKEN) gates every
HTTP and WebSocket entry point.
"""
import os
import sys
import pty
import json
import fcntl
import termios
import struct
import select
import signal
import threading
import time
import secrets
import shlex
from pathlib import Path

from flask import Flask, request, jsonify, send_from_directory, abort, Response
from flask_sock import Sock

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent
LINWINPWN = REPO_ROOT / "linWinPwn.sh"
STATIC_DIR = HERE / "static"
MENUS_FILE = HERE / "menus.json"

# Output directory the script writes loot/logs into (mounted/visible to UI).
DEFAULT_OUTPUT = Path(os.environ.get("LWP_OUTPUT", str(REPO_ROOT / "lwp-output")))
DEFAULT_OUTPUT.mkdir(parents=True, exist_ok=True)

AUTH_TOKEN = os.environ.get("LWP_WEB_TOKEN", "")  # empty = no auth (localhost only)

app = Flask(__name__, static_folder=None)
sock = Sock(app)


# --------------------------------------------------------------------------- #
# PTY session management
# --------------------------------------------------------------------------- #
class PtySession:
    """A single child process attached to a PTY master fd."""

    def __init__(self, argv, cwd=None, env=None, name="pty"):
        self.name = name
        self.argv = argv
        self.cwd = cwd or str(REPO_ROOT)
        self.env = env
        self.fd = None
        self.pid = None
        self.lock = threading.Lock()
        self.alive = False
        self._ring = bytearray()          # scrollback replayed to late joiners
        self._ring_max = 256 * 1024

    def start(self):
        pid, fd = pty.fork()
        if pid == 0:
            # child: drop every inherited fd (listening socket, other PTYs...)
            # so tools never keep the web server's port or sessions alive.
            try:
                os.closerange(3, os.sysconf("SC_OPEN_MAX"))
            except Exception:
                os.closerange(3, 4096)
            try:
                os.chdir(self.cwd)
            except Exception:
                pass
            env = dict(os.environ)
            env["TERM"] = "xterm-256color"
            if self.env:
                env.update(self.env)
            os.execvpe(self.argv[0], self.argv, env)
            os._exit(127)  # exec failed
        # parent
        self.pid = pid
        self.fd = fd
        self.alive = True
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
        self.set_winsize(40, 120)

    def set_winsize(self, rows, cols):
        if self.fd is None:
            return
        try:
            winsize = struct.pack("HHHH", rows, cols, 0, 0)
            fcntl.ioctl(self.fd, termios.TIOCSWINSZ, winsize)
        except Exception:
            pass

    def write(self, data: bytes):
        with self.lock:
            if self.fd is not None and self.alive:
                try:
                    os.write(self.fd, data)
                except OSError:
                    pass

    def read(self, timeout=0.1):
        if self.fd is None:
            return b""
        try:
            r, _, _ = select.select([self.fd], [], [], timeout)
        except (OSError, ValueError):
            self.alive = False
            return b""
        if not r:
            return b""
        try:
            data = os.read(self.fd, 65536)
        except OSError:
            self.alive = False
            return b""
        if not data:
            self.alive = False
            return b""
        with self.lock:
            self._ring.extend(data)
            if len(self._ring) > self._ring_max:
                del self._ring[: len(self._ring) - self._ring_max]
        return data

    def is_alive(self) -> bool:
        """Reap the child if it exited so the UI sees the real state."""
        if not self.pid or not self.alive:
            return False
        try:
            pid, _ = os.waitpid(self.pid, os.WNOHANG)
            if pid == self.pid:
                self.alive = False
        except ChildProcessError:
            self.alive = False
        return self.alive

    def scrollback(self) -> bytes:
        with self.lock:
            return bytes(self._ring)

    def stop(self):
        self.alive = False
        if self.pid:
            try:
                os.kill(self.pid, signal.SIGTERM)
                time.sleep(0.2)
                os.kill(self.pid, signal.SIGKILL)
            except OSError:
                pass
        if self.fd is not None:
            try:
                os.close(self.fd)
            except OSError:
                pass
            self.fd = None


SESSIONS = {}          # name -> PtySession
SESSIONS_LOCK = threading.Lock()


def get_session(name):
    with SESSIONS_LOCK:
        return SESSIONS.get(name)


def set_session(name, sess):
    with SESSIONS_LOCK:
        old = SESSIONS.get(name)
        if old:
            old.stop()
        SESSIONS[name] = sess


# --------------------------------------------------------------------------- #
# Launch-argument builder (mirrors linWinPwn.sh CLI flags)
# --------------------------------------------------------------------------- #
def build_argv(cfg):
    """Translate the config form into a safe linWinPwn.sh argv list."""
    if not LINWINPWN.exists():
        raise FileNotFoundError(f"linWinPwn.sh not found at {LINWINPWN}")
    argv = ["/bin/bash", str(LINWINPWN)]
    # --offline wipes credentials when it is parsed, so it goes first: then the
    # credentials typed in the form are kept and the printed commands use them.
    if cfg.get("offline"):
        argv.append("--offline")

    target = (cfg.get("target") or "").strip()
    if not target and not cfg.get("offline"):
        raise ValueError("Target DC IP (-t) is required")
    if target:
        argv += ["-t", target]

    simple = {
        "domain": "-d",
        "user": "-u",
        "password": "-p",
        "hash": "-H",
        "aeskey": "-A",
        "kerb": "-K",
        "cert": "-C",
        "certpass": "--cert-pass",
        "dc_domain": "--dc-domain",
        "ldap_port": "--ldap-port",
        "dns_ip": "--dns-ip",
        "interface": "-I",
        "attacker_ip": "-a",
        "targets": "-T",
        "user_wordlist": "-U",
        "pass_wordlist": "-P",
    }
    for key, flag in simple.items():
        val = (cfg.get(key) or "").strip()
        if val:
            argv += [flag, val]

    flags = {
        "ldaps": "--ldaps",
        "ldap_sign": "--ldap-sign",
        "ldap_bind": "--ldap-bind",
        "force_kerb": "--force-kerb",
        "dns_tcp": "--dns-tcp",
        "use_ip": "--use-ip",
        "no_exec": "--no-exec",
        "verbose": "--verbose",
        "auto_config": "--auto-config",
    }
    for key, flag in flags.items():
        if cfg.get(key):
            argv.append(flag)

    # Output dir always set so loot lands somewhere the UI can browse.
    out = (cfg.get("output") or str(DEFAULT_OUTPUT)).strip()
    argv += ["-o", out]

    if cfg.get("auto"):
        argv.append("--auto")
    return argv


# --------------------------------------------------------------------------- #
# Auth helpers
# --------------------------------------------------------------------------- #
def check_token_http():
    if not AUTH_TOKEN:
        return True
    tok = request.headers.get("X-Auth-Token") or request.args.get("token", "")
    return secrets.compare_digest(tok, AUTH_TOKEN)


def check_token_ws(ws):
    if not AUTH_TOKEN:
        return True
    tok = request.args.get("token", "")
    return secrets.compare_digest(tok, AUTH_TOKEN)


@app.before_request
def _gate():
    if request.path.startswith("/api/") and not check_token_http():
        abort(401)


# --------------------------------------------------------------------------- #
# Static / index
# --------------------------------------------------------------------------- #
@app.route("/")
def index():
    return send_from_directory(STATIC_DIR, "index.html")


@app.route("/favicon.ico")
def favicon():
    return send_from_directory(STATIC_DIR, "favicon.svg", mimetype="image/svg+xml")


@app.route("/static/<path:path>")
def static_files(path):
    return send_from_directory(STATIC_DIR, path)


# --------------------------------------------------------------------------- #
# API
# --------------------------------------------------------------------------- #
@app.route("/api/menus")
def api_menus():
    with open(MENUS_FILE) as f:
        return Response(f.read(), mimetype="application/json")


@app.route("/api/config")
def api_config():
    return jsonify({
        "auth_required": bool(AUTH_TOKEN),
        "script_present": LINWINPWN.exists(),
        "default_output": str(DEFAULT_OUTPUT),
        "repo_root": str(REPO_ROOT),
    })


LAST_CFG = {}


@app.route("/api/session/restart", methods=["POST"])
def api_session_restart():
    if not LAST_CFG:
        return jsonify({"ok": False, "error": "no previous session config"}), 409
    return _start(dict(LAST_CFG))


@app.route("/api/session/start", methods=["POST"])
def api_session_start():
    cfg = request.get_json(force=True, silent=True) or {}
    return _start(cfg)


def _start(cfg):
    global LAST_CFG
    try:
        argv = build_argv(cfg)
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    sess = PtySession(argv, cwd=str(REPO_ROOT), name="linwinpwn")
    try:
        sess.start()
    except Exception as e:
        return jsonify({"ok": False, "error": f"launch failed: {e}"}), 500
    set_session("linwinpwn", sess)
    LAST_CFG = dict(cfg)
    # Redact secrets before echoing the command line back to the UI.
    shown = []
    redact_next = False
    for a in argv:
        if redact_next:
            shown.append("********")
            redact_next = False
        elif a in ("-p", "-H", "-A", "--cert-pass"):
            shown.append(a)
            redact_next = True
        else:
            shown.append(a)
    return jsonify({"ok": True, "argv": shown, "cmdline": " ".join(shlex.quote(x) for x in shown)})


@app.route("/api/session/stop", methods=["POST"])
def api_session_stop():
    sess = get_session("linwinpwn")
    if sess:
        sess.stop()
    return jsonify({"ok": True})


def _children_map():
    """ppid -> [pid] from /proc (no psutil dependency)."""
    kids = {}
    for d in os.listdir("/proc"):
        if not d.isdigit():
            continue
        try:
            with open(f"/proc/{d}/stat") as f:
                st = f.read()
            ppid = int(st[st.rfind(")") + 2:].split()[1])
        except (OSError, ValueError, IndexError):
            continue
        kids.setdefault(ppid, []).append(int(d))
    return kids


def _descendants(pid):
    kids, out, stack = _children_map(), [], [pid]
    while stack:
        for c in kids.get(stack.pop(), []):
            out.append(c)
            stack.append(c)
    return out


def _cmdline(pid):
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            return f.read().replace(b"\0", b" ").decode(errors="replace").strip()[:200]
    except OSError:
        return ""


def _signal_all(pids, sig):
    for p in pids:
        try:
            os.kill(p, sig)
        except OSError:
            pass


def _escalate(pids):
    """Ctrl+C first; if a tool ignores it, SIGTERM after 3s, SIGKILL after 5s."""
    time.sleep(3)
    alive = [p for p in pids if os.path.exists(f"/proc/{p}")]
    if alive:
        _signal_all(alive, signal.SIGTERM)
        time.sleep(2)
        _signal_all([p for p in alive if os.path.exists(f"/proc/{p}")], signal.SIGKILL)


@app.route("/api/session/stop_task", methods=["POST"])
def api_stop_task():
    """Stop button = Ctrl+C for the running command only.

    A real Ctrl+C reaches the whole foreground process group, and linWinPwn.sh
    has no trap, so the script itself would die. Here SIGINT goes only to the
    processes started by the script (the tool, its tee, subshells). The script
    sees its command end and goes back to its menu; the session stays alive.
    """
    sess = get_session("linwinpwn")
    if not sess or not sess.is_alive():
        return jsonify({"ok": False, "error": "no running session"}), 409
    pids = _descendants(sess.pid)
    if not pids:
        return jsonify({"ok": True, "stopped": []})
    stopped = [{"pid": p, "cmd": _cmdline(p)} for p in pids]
    _signal_all(pids, signal.SIGINT)
    threading.Thread(target=_escalate, args=(pids,), daemon=True).start()
    return jsonify({"ok": True, "stopped": stopped})


@app.route("/api/session/status")
def api_session_status():
    sess = get_session("linwinpwn")
    return jsonify({"running": bool(sess and sess.is_alive())})


@app.route("/api/action", methods=["POST"])
def api_action():
    """Send a sequence of menu keys to the running linWinPwn PTY.

    body: {"keys": ["2", "1"]}  -> types each key followed by Enter, so the
    script navigates into a submenu and runs an option. Sub-prompts after that
    are answered by the user typing in the terminal.
    """
    sess = get_session("linwinpwn")
    if not sess or not sess.is_alive():
        return jsonify({"ok": False, "error": "no running session (the script exited, check the terminal output)"}), 409
    body = request.get_json(force=True, silent=True) or {}
    keys = body.get("keys") or []
    if not isinstance(keys, list):
        return jsonify({"ok": False, "error": "keys must be a list"}), 400
    for k in keys:
        sess.write(f"{k}\n".encode())
        time.sleep(0.15)  # let the menu redraw between selections
    return jsonify({"ok": True, "sent": keys})


# --------------------------------------------------------------------------- #
# Output file browser (read-only) over the loot directory
# --------------------------------------------------------------------------- #
def _safe_output_path(rel):
    base = DEFAULT_OUTPUT.resolve()
    p = (base / rel).resolve()
    if base != p and base not in p.parents:
        abort(403)
    return p


@app.route("/api/files")
def api_files():
    rel = request.args.get("path", "")
    p = _safe_output_path(rel)
    if not p.exists():
        return jsonify({"ok": False, "error": "not found"}), 404
    if p.is_dir():
        entries = []
        for child in sorted(p.iterdir()):
            try:
                st = child.stat()
                entries.append({
                    "name": child.name,
                    "dir": child.is_dir(),
                    "size": st.st_size,
                    "mtime": int(st.st_mtime),
                })
            except OSError:
                continue
        return jsonify({"ok": True, "dir": True, "entries": entries, "path": rel})
    # file: return content if small & texty, else offer download
    if p.stat().st_size > 2 * 1024 * 1024:
        return jsonify({"ok": True, "dir": False, "too_big": True, "path": rel})
    try:
        text = p.read_text(errors="replace")
        return jsonify({"ok": True, "dir": False, "content": text, "path": rel})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/download")
def api_download():
    rel = request.args.get("path", "")
    p = _safe_output_path(rel)
    if not p.exists() or p.is_dir():
        abort(404)
    return send_from_directory(p.parent, p.name, as_attachment=True)


# --------------------------------------------------------------------------- #
# WebSockets
# --------------------------------------------------------------------------- #
def _pump(ws, sess):
    """Stream PTY output to the websocket until either side closes."""
    # replay scrollback so a reconnecting tab sees prior output
    sb = sess.scrollback()
    if sb:
        try:
            ws.send(sb.decode(errors="replace"))
        except Exception:
            return
    while True:
        if not sess.alive and sess.fd is None:
            break
        data = sess.read(timeout=0.1)
        if data:
            try:
                ws.send(data.decode(errors="replace"))
            except Exception:
                break
        else:
            if not sess.alive:
                # drain anything left then exit
                tail = sess.read(timeout=0.05)
                if tail:
                    try:
                        ws.send(tail.decode(errors="replace"))
                    except Exception:
                        pass
                try:
                    ws.send("\r\n\x1b[33m[web-ui] process exited\x1b[0m\r\n")
                    ws.close()
                except Exception:
                    pass
                break


@sock.route("/ws/linwinpwn")
def ws_linwinpwn(ws):
    if not check_token_ws(ws):
        ws.close()
        return
    sess = get_session("linwinpwn")
    if not sess:
        ws.send("\r\n[linWinPwn session not started - configure and press Start]\r\n")
        return

    reader = threading.Thread(target=_pump, args=(ws, sess), daemon=True)
    reader.start()
    try:
        while True:
            msg = ws.receive()
            if msg is None:
                break
            _handle_ws_input(msg, sess)
    except Exception:
        pass


@sock.route("/ws/shell")
def ws_shell(ws):
    if not check_token_ws(ws):
        ws.close()
        return
    sess = get_session("shell")
    if not sess or not sess.alive:
        shell = os.environ.get("SHELL", "/bin/bash")
        sess = PtySession([shell], cwd=str(REPO_ROOT), name="shell")
        sess.start()
        set_session("shell", sess)

    reader = threading.Thread(target=_pump, args=(ws, sess), daemon=True)
    reader.start()
    try:
        while True:
            msg = ws.receive()
            if msg is None:
                break
            _handle_ws_input(msg, sess)
    except Exception:
        pass


def _handle_ws_input(msg, sess):
    """Client frames: either raw keystrokes (str) or a control JSON object."""
    if isinstance(msg, (bytes, bytearray)):
        sess.write(bytes(msg))
        return
    if msg.startswith("\x00json:"):
        try:
            obj = json.loads(msg[6:])
        except Exception:
            return
        if obj.get("type") == "resize":
            sess.set_winsize(int(obj.get("rows", 40)), int(obj.get("cols", 120)))
        elif obj.get("type") == "input":
            sess.write(obj.get("data", "").encode())
        return
    sess.write(msg.encode())


# --------------------------------------------------------------------------- #
def main():
    import argparse
    ap = argparse.ArgumentParser(description="linWinPwn Web UI")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8777)
    ap.add_argument("--debug", action="store_true")
    args = ap.parse_args()

    if not LINWINPWN.exists():
        print(f"[!] WARNING: {LINWINPWN} not found - the Start button will fail "
              f"until the web_ui/ folder sits next to linWinPwn.sh.", file=sys.stderr)
    banner_tok = AUTH_TOKEN or "(none - localhost only)"
    print(f"[+] linWinPwn Web UI on http://{args.host}:{args.port}")
    print(f"[+] Auth token: {banner_tok}")
    print(f"[+] Output dir: {DEFAULT_OUTPUT}")
    # threaded=True so each websocket pump + HTTP calls run concurrently.
    app.run(host=args.host, port=args.port, debug=args.debug, threaded=True)


if __name__ == "__main__":
    main()
