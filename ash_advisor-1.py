#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════╗
║        ASH_AGENT v2 — Pen Test Methodology Advisor       ║
║  AI advises. YOU execute. Full audit log maintained.     ║
╚══════════════════════════════════════════════════════════╝

INSTALL:
    pip install flask flask-sock flask-cors google-generativeai

RUN:
    export GEMINI_API_KEY=your_key_here
    python ash_advisor.py

OPEN:
    ash_advisor.html  (double-click  OR  python -m http.server 8080)

BUGS FIXED v2:
    - ws.receive(timeout=) removed       → flask-sock does not support it
    - Thread-safe ws.send() via Lock     → prevents race conditions
    - stop_event for reader thread       → clean exit on disconnect
    - CORS wildcard                      → handles file://, localhost, 127.*
    - os._exit(1) in PTY child           → no zombie processes
    - OPTIONS preflight on every route   → no CORS errors from browser
    - build_gemini_chat() helper         → clean history conversion
    - Grouped TOOL_LIST dict             → richer /api/tools response
"""

import os, sys, json, secrets, logging, threading, shutil
import struct, fcntl, termios, pty, select, signal

from flask import Flask, request, jsonify
from flask_sock import Sock
from flask_cors import CORS
import google.generativeai as genai

# ── Config ────────────────────────────────────────────────────────────────────
ADMIN_EMAIL    = os.environ.get("ADMIN_EMAIL",    "kevlarmackenzie@gmail.com")
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
GEMINI_MODEL   = os.environ.get("GEMINI_MODEL",   "gemini-2.0-flash")
PORT           = int(os.environ.get("PORT",  5000))
HOST           = os.environ.get("HOST",      "127.0.0.1")
LOG_FILE       = "ash_audit.log"

# ── Flask ─────────────────────────────────────────────────────────────────────
app  = Flask(__name__)
sock = Sock(app)

# supports_credentials must be False when origins="*"
CORS(app, origins="*", supports_credentials=False,
     allow_headers=["Content-Type", "X-Auth-Token"],
     methods=["GET", "POST", "OPTIONS"])

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler(sys.stdout)]
)
log = logging.getLogger("ASH")

def audit(action, detail=""):
    log.info(f"{action} | {detail}")

# ── Sessions ──────────────────────────────────────────────────────────────────
SESSIONS = {}   # token → {email, phase, history}
PTY_SESSIONS = {}   # token → {pid, fd}

def get_sess(req):
    return SESSIONS.get(req.headers.get("X-Auth-Token", ""))
# ── Gemini ────────────────────────────────────────────────────────────────────
genai.configure(api_key=GEMINI_API_KEY)

SYSTEM_PROMPT = """
You are ASH_AGENT — an elite penetration testing methodology advisor.
You run locally on the operative's workstation. You ADVISE; the operative EXECUTES.

CORE RULES:
- Senior offensive security advisor across all pen test domains
- NEVER execute commands — craft precise, ready-to-run commands for the operative
- ALWAYS confirm authorisation/scope before active commands
- Severity tags: [CRITICAL] [HIGH] [MEDIUM] [LOW] [INFO]
- OPSEC awareness in every recommendation (noise, detection, evasion)
- Follow PTES, OWASP Testing Guide, OSSTMM methodology

ENGAGEMENT PHASES:

[PHASE 0] PRE-ENGAGEMENT
  Scope, rules of engagement, NDA, emergency contacts, legal auth,
  kickoff docs, threat modelling

[PHASE 1] PASSIVE RECONNAISSANCE
  OSINT: theHarvester, recon-ng, Maltego, SpiderFoot
  DNS: amass, subfinder, assetfinder, dnsx, dnsrecon, fierce, dnsenum
  Certs: crt.sh, certspotter, censys
  Web archive: waybackurls, gau, hakrawler
  Shodan/Censys/FOFA, Google dorks, LinkedIn, email harvesting, breach data

[PHASE 2] ACTIVE RECONNAISSANCE
  Port scan: nmap, masscan, rustscan
  Service/OS: nmap -sV -sC -O
  Banner grab: nc, curl, telnet
  Host discovery: netdiscover, arp-scan, fping
  Firewall/WAF: nmap -sA, wafw00f, hping3

[PHASE 3] ENUMERATION
  Web dirs: gobuster, ffuf, feroxbuster, dirsearch, wfuzz
  Web info: nikto, nuclei, whatweb, wafw00f, wappalyzer, wpscan
  Vhosts: gobuster vhost, ffuf -H Host:FUZZ
  SMB: enum4linux-ng, crackmapexec smb, smbclient, smbmap, rpcclient
  LDAP: ldapsearch, ldapdomaindump, bloodhound-python
  DNS zone: dnsenum, dnsrecon --type AXFR
  SNMP: snmpwalk, onesixtyone, snmpcheck
  NFS: showmount -e
  SMTP: smtp-user-enum, swaks
  SSL/TLS: sslyze, testssl.sh, sslscan

[PHASE 4] VULNERABILITY ANALYSIS
  Scanners: OpenVAS/GVM, Nessus, nuclei, Nexpose
  Exploit DB: searchsploit
  CVE research: NVD, MITRE, vendor advisories
  Web: Burp Suite active scan, manual OWASP Top 10
  NSE: nmap --script vuln, nmap --script safe

[PHASE 5] EXPLOITATION
  Web: SQLi (sqlmap, manual), XSS, SSRF, XXE, IDOR, RCE,
       LFI/RFI, file upload bypass, auth bypass, CSRF, SSTI,
       deserialization, OAuth misconfig, JWT attacks
  Network: Metasploit, manual exploit (searchsploit -m)
  Passwords: hydra, medusa, hashcat, john, spray, kerbrute
  AD: Kerberoasting, ASREPRoasting, Pass-the-Hash, Pass-the-Ticket,
      DCSync, Zerologon, PrintNightmare
  Wireless: airmon-ng, airodump-ng, aireplay-ng, aircrack-ng, wifite
  Phishing: GoPhish, SET, evilginx2

[PHASE 6] POST-EXPLOITATION
  Linux privesc: linpeas.sh, linenum.sh, pspy, GTFOBins,
                 sudo -l, SUID/SGID, cron, world-writable
  Windows privesc: winpeas.exe, PowerUp.ps1, Seatbelt,
                   token impersonation, AlwaysInstallElevated, DLL hijack
  Lateral movement: crackmapexec, evil-winrm, impacket (psexec/wmiexec/smbexec)
  Cred dumping: mimikatz, secretsdump.py, LaZagne, lsassy
  Persistence: cron/schtasks, registry, startup, backdoors, golden ticket
  Pivoting: chisel, ligolo-ng, proxychains, SSH -D/-L/-R, socat
  Cleanup: per ROE — remove shells/tools, log all changes

[PHASE 7] REPORTING
  Executive Summary, Scope, Methodology, Attack Narrative,
  Findings table (severity/CVSS v3.1), Detailed findings, Evidence,
  Remediation, Risk ratings, Appendices
  Tools: dradis, serpico, pwndoc, faraday

COMMAND FORMAT — always use this:
**Objective:** What this achieves
**Command:**
```
<exact command>
```
**OPSEC Level:** Loud | Moderate | Quiet | Silent
**Expected Output:** What to look for
**Next Step:** Recommended follow-up

For pasted output: summarise findings with severity tags, identify attack
surface, suggest next steps, note OPSEC concerns.
"""

try:
    _model = genai.GenerativeModel(
        model_name=GEMINI_MODEL,
        system_instruction=SYSTEM_PROMPT
    )
    audit("GEMINI_OK", f"model={GEMINI_MODEL}")
except Exception as e:
    _model = None
    audit("GEMINI_FAIL", str(e))

def gemini_chat(history, message):
    """Send message to Gemini, return reply text."""
    if not _model:
        raise RuntimeError("Gemini not initialised — check GEMINI_API_KEY")
    gh = []
    for m in history:
        gh.append({"role": "user" if m["role"] == "user" else "model",
                   "parts": [{"text": m["content"]}]})
    cs   = _model.start_chat(history=gh)
    resp = cs.send_message(message)
    return resp.text

PHASES = ["PRE-ENGAGEMENT","PASSIVE RECON","ACTIVE RECON","ENUMERATION",
          "VULNERABILITY","EXPLOITATION","POST-EXPLOITATION","REPORTING"]

def detect_phase(text):
    t = text.lower()
    for p in PHASES:
        if p.lower() in t:
            return p
    return None

# ── CORS preflight helper ─────────────────────────────────────────────────────
def ok():
    return jsonify({}), 200

# ── Auth ──────────────────────────────────────────────────────────────────────
@app.route("/api/login", methods=["POST", "OPTIONS"])
def login():
    if request.method == "OPTIONS":
        return ok()
    d     = request.get_json(silent=True) or {}
    email = (d.get("email") or "").strip().lower()
    if email != ADMIN_EMAIL.lower():
        audit("LOGIN_DENIED", f"ip={request.remote_addr} email={email}")
        return jsonify({"success": False, "message": "Access denied."}), 403
    token = secrets.token_hex(32)
    SESSIONS[token] = {"email": email, "phase": "PRE-ENGAGEMENT", "history": []}
    audit("LOGIN_OK", f"email={email}")
    return jsonify({"success": True, "token": token})

@app.route("/api/logout", methods=["POST", "OPTIONS"])
def logout():
    if request.method == "OPTIONS":
        return ok()
    token = request.headers.get("X-Auth-Token", "")
    s = SESSIONS.pop(token, None)
    if s:
        audit("LOGOUT", f"email={s['email']}")
    return jsonify({"success": True})

@app.route("/api/verify", methods=["GET", "OPTIONS"])
def verify():
    if request.method == "OPTIONS":
        return ok()
    s = get_sess(request)
    if not s:
        return jsonify({"valid": False}), 401
    return jsonify({"valid": True, "phase": s.get("phase", "")})

# ── Chat ──────────────────────────────────────────────────────────────────────
@app.route("/api/chat", methods=["POST", "OPTIONS"])
def chat():
    if request.method == "OPTIONS":
        return ok()
    s = get_sess(request)
    if not s:
        return jsonify({"error": "Unauthorised"}), 401
    d   = request.get_json(silent=True) or {}
    msg = (d.get("message") or "").strip()
    if not msg:
        return jsonify({"error": "Empty message"}), 400
    try:
        reply = gemini_chat(s["history"], msg)
    except Exception as e:
        audit("CHAT_ERR", str(e))
        return jsonify({"error": str(e)}), 500
    s["history"].append({"role": "user",      "content": msg})
    s["history"].append({"role": "assistant", "content": reply})
    s["history"] = s["history"][-40:]
    if p := detect_phase(reply):
        s["phase"] = p
    audit("CHAT", f"email={s['email']}")
    return jsonify({"reply": reply, "phase": s.get("phase", "")})

# ── Phase ─────────────────────────────────────────────────────────────────────
@app.route("/api/phase", methods=["POST", "OPTIONS"])
def set_phase():
    if request.method == "OPTIONS":
        return ok()
    s = get_sess(request)
    if not s:
        return jsonify({"error": "Unauthorised"}), 401
    phase = (request.get_json(silent=True) or {}).get("phase", "")
    s["phase"] = phase
    sys_msg = (f"[Operative moved to: {phase}] "
               f"Briefly state this phase's objectives and give the first 2-3 recommended steps.")
    try:
        reply = gemini_chat(s["history"], sys_msg)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    s["history"].append({"role": "user",      "content": sys_msg})
    s["history"].append({"role": "assistant", "content": reply})
    s["history"] = s["history"][-40:]
    audit("PHASE", f"email={s['email']} phase={phase}")
    return jsonify({"reply": reply, "phase": phase})

# ── Clear ─────────────────────────────────────────────────────────────────────
@app.route("/api/clear", methods=["POST", "OPTIONS"])
def clear_history():
    if request.method == "OPTIONS":
        return ok()
    s = get_sess(request)
    if not s:
        return jsonify({"error": "Unauthorised"}), 401
    s["history"] = []
    s["phase"]   = "PRE-ENGAGEMENT"
    audit("CLEAR", f"email={s['email']}")
    return jsonify({"success": True})

# ── Tools ─────────────────────────────────────────────────────────────────────
TOOL_GROUPS = {
    "Recon":        ["nmap","masscan","rustscan","amass","subfinder","theHarvester","netdiscover","arp-scan"],
    "Web Enum":     ["gobuster","ffuf","feroxbuster","dirsearch","nikto","nuclei","whatweb","wafw00f","wpscan"],
    "Web Exploit":  ["sqlmap","commix","dalfox"],
    "Passwords":    ["hashcat","john","hydra","medusa","kerbrute"],
    "Network":      ["tshark","tcpdump","responder","bettercap","wireshark"],
    "Exploit FW":   ["msfconsole","msfvenom","searchsploit"],
    "Post-Exploit": ["crackmapexec","evil-winrm","bloodhound-python"],
    "AD/SMB":       ["enum4linux","smbclient","smbmap","ldapsearch","rpcclient"],
    "Pivoting":     ["chisel","proxychains","socat","ligolo-ng"],
    "Wireless":     ["airmon-ng","airodump-ng","aircrack-ng","wifite"],
    "Core":         ["ssh","curl","wget","python3","perl","ruby","nc"],
}

@app.route("/api/tools", methods=["GET", "OPTIONS"])
def tools_status():
    if request.method == "OPTIONS":
        return ok()
    if not get_sess(request):
        return jsonify({"error": "Unauthorised"}), 401
    return jsonify({g: {t: bool(shutil.which(t)) for t in tl}
                    for g, tl in TOOL_GROUPS.items()})

# ── SSH command builder ───────────────────────────────────────────────────────
@app.route("/api/ssh-command", methods=["POST", "OPTIONS"])
def ssh_command():
    if request.method == "OPTIONS":
        return ok()
    if not get_sess(request):
        return jsonify({"error": "Unauthorised"}), 401
    d    = request.get_json(silent=True) or {}
    host = (d.get("host") or "").strip()
    user = (d.get("user") or "root").strip()
    port = int(d.get("port") or 22)
    key  = (d.get("key") or "").strip()
    if not host:
        return jsonify({"error": "host required"}), 400
    parts = ["ssh", "-o", "StrictHostKeyChecking=no", "-p", str(port)]
    if key:
        parts += ["-i", key]
    parts.append(f"{user}@{host}")
    return jsonify({"command": " ".join(parts)})

# ── Health ────────────────────────────────────────────────────────────────────
@app.route("/health")
def health():
    return jsonify({"status": "ok", "agent": "ASH_AGENT v2",
                    "model": GEMINI_MODEL, "sessions": len(SESSIONS)})

# ── WebSocket PTY Terminal ────────────────────────────────────────────────────
#
#  FIXES vs v1:
#  1. ws.receive() called with NO timeout param  (not supported by flask-sock)
#  2. ws.send() protected by threading.Lock      (thread-safe concurrent access)
#  3. stop_event signals reader thread to exit   (clean shutdown)
#  4. os._exit(1) in child after exec            (no zombie processes)
#  5. os.waitpid() in cleanup                    (reap child)
#

@sock.route("/ws/terminal")
def terminal(ws):
    token = request.args.get("token", "")
    sess  = SESSIONS.get(token)
    if not sess:
        try:
            ws.send(json.dumps({"type":"error","data":"\r\n[ASH] Unauthorised\r\n"}))
        except Exception:
            pass
        return

    audit("TERM_OPEN", f"email={sess['email']}")

    env = os.environ.copy()
    env.update({"TERM": "xterm-256color", "COLORTERM": "truecolor", "LANG": "en_US.UTF-8"})

    try:
        pid, master_fd = pty.fork()
    except OSError as e:
        try:
            ws.send(json.dumps({"type":"error","data":f"\r\n[ASH] PTY error: {e}\r\n"}))
        except Exception:
            pass
        return

    if pid == 0:                              # ── child process ──
        shell = os.environ.get("SHELL", "/bin/bash")
        try:
            os.execvpe(shell, [shell, "--login"], env)
        except Exception:
            pass
        os._exit(1)                           # never reached normally

    # ── parent process ──────────────────────────────────────────
    PTY_SESSIONS[token] = {"pid": pid, "fd": master_fd}
    stop   = threading.Event()
    ws_lck = threading.Lock()

    def safe_send(payload):
        if stop.is_set():
            return
        try:
            with ws_lck:
                ws.send(payload)
        except Exception:
            stop.set()

    def pty_reader():
        """Read PTY output → send to browser (runs in daemon thread)."""
        while not stop.is_set():
            try:
                r, _, _ = select.select([master_fd], [], [], 0.04)
                if r:
                    raw = os.read(master_fd, 4096)
                    if not raw:
                        break
                    safe_send(json.dumps({
                        "type": "output",
                        "data": raw.decode("utf-8", errors="replace")
                    }))
            except (OSError, ValueError):
                break
        stop.set()

    threading.Thread(target=pty_reader, daemon=True).start()

    try:
        while not stop.is_set():
            msg = ws.receive()          # blocks; returns None on close
            if msg is None:
                break
            try:
                pkt = json.loads(msg)
            except (json.JSONDecodeError, TypeError):
                continue

            t = pkt.get("type", "")
            if t == "input":
                data = pkt.get("data", "")
                if data:
                    os.write(master_fd, data.encode())
            elif t == "resize":
                try:
                    cols = max(1, int(pkt.get("cols", 80)))
                    rows = max(1, int(pkt.get("rows", 24)))
                    fcntl.ioctl(master_fd, termios.TIOCSWINSZ,
                                struct.pack("HHHH", rows, cols, 0, 0))
                except (OSError, ValueError):
                    pass
            elif t == "ping":
                safe_send(json.dumps({"type": "pong"}))

    except Exception as e:
        audit("TERM_ERR", str(e))
    finally:
        stop.set()
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass
        try:
            os.waitpid(pid, 0)
        except OSError:
            pass
        try:
            os.close(master_fd)
        except OSError:
            pass
        PTY_SESSIONS.pop(token, None)
        audit("TERM_CLOSE", f"email={sess['email']}")

# ── Entry ─────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("""
╔══════════════════════════════════════════════════════════╗
║            ASH_AGENT v2 — Local Pen Test Advisor         ║
╠══════════════════════════════════════════════════════════╣""")
    if not GEMINI_API_KEY:
        print("║  ⚠  GEMINI_API_KEY not set — chat will fail             ║")
        print("║     export GEMINI_API_KEY=your_key_here                 ║")
    else:
        k = GEMINI_API_KEY[:6] + "..." + GEMINI_API_KEY[-4:]
        print(f"║  ✓  Gemini key  : {k:<38}║")
    print(f"║  ✓  Model       : {GEMINI_MODEL:<38}║")
    print(f"║  ✓  Server      : http://{HOST}:{PORT:<30}║")
    print(f"║  ✓  Admin       : {ADMIN_EMAIL:<38}║")
    print("""╚══════════════════════════════════════════════════════════╝
Open ash_advisor.html in your browser — or serve it:
    python -m http.server 8080
""")
    app.run(host=HOST, port=PORT, debug=False, threaded=True, use_reloader=False)
