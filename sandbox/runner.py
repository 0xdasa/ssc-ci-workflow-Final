import sys
import os
import json  
import subprocess
import time
import re
import tarfile
import tempfile
import base64
import threading
import urllib.request
import string
import math
import ipaddress
from collections import Counter
from http.server import BaseHTTPRequestHandler, HTTPServer
from dnslib.server import DNSServer, BaseResolver
from dnslib import RR, A

# ============================================================
# ============================================================
# STORAGE
# ============================================================

captured_requests = []
captured_dns      = []

# ============================================================
# HELPERS
# ============================================================

def is_readable(s):
    if not s: return False
    printable = set(string.printable)
    return sum(c in printable for c in s) / len(s) > 0.85

def try_decode_base64(s):
    try:
        d = base64.b64decode(s).decode("utf-8", errors="ignore")
        if len(d) > 20 and is_readable(d):
            return d
    except Exception:
        pass
    return None

def is_private_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return True

# ============================================================
# DOMAIN FILTERING
# ============================================================

def is_real_domain(d):
    if not d or len(d) < 4: return False
    if "." not in d: return False
    if "/" in d: return False
    if d.startswith('.') or d.endswith('.'): return False
    if re.search(r'[^\x20-\x7E]', d): return False
    if re.match(r'^\d+\.\d+\.\d+\.\d+$', d): return False
    if not re.search(r'[a-zA-Z]', d): return False

    # Reject system/library file extensions
    bad_suffixes = (
        ".so", ".cnf", ".json", ".py", ".log", ".conf", ".cfg",
        ".res", ".cache", ".preload", ".db", ".dat", ".tmp",
        ".pid", ".lock", ".sock", ".map", ".pem", ".crt", ".key",
    )
    if d.endswith(bad_suffixes): return False

    code_keywords = ['function','return','const','let','var','import','export',
                     'require','module','window','document','console','process',
                     'buffer','stream','event','error','object','array','string',
                     'number','boolean','promise','async','await','this','node','index','exports','netsvc']
    first_part = d.split('.')[0].lower()
    for keyword in code_keywords:
        if first_part.startswith(keyword): return False

    # Only accept known real TLDs
    known_tlds = {
        'com','net','org','io','dev','gov','edu','co','uk','de','fr',
        'ru','cn','jp','br','au','nl','se','no','fi','dk','pl','it',
        'es','ca','mx','in','sg','hk','app','cloud','xyz','info',
        'biz','name','pro','site','online','tech','surf','live',
        'shop','store','news','media','ai','me','tv','us','eu',
    }
    tld = d.split('.')[-1].lower()
    return tld in known_tlds
   

def filter_domains(domains_set):
    real_domains, junk_domains = [], []
    for d in domains_set:
        (real_domains if is_real_domain(d) else junk_domains).append(d)
    return list(set(real_domains)), list(set(junk_domains))

# ============================================================
# FAKE HTTP SERVER
# ============================================================

class SmartFakeHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        entry = {"method": "GET", "path": self.path, "headers": dict(self.headers)}
        response = {"status": "ok"}
        if "/api/config" in self.path: response = {"mode": "active", "token": "eyJhbGciOiJIUzI1NiJ9.fake"}
        if "/api/key"    in self.path: response = {"api_key": "honey_sk-proj-fake123456"}
        if "/api/update" in self.path: response = {"version": "2.1.0", "url": "http://127.0.0.1:8080/payload"}
        entry["response"] = response
        captured_requests.append(entry)
        self.send_response(200); self.end_headers()
        self.wfile.write(json.dumps(response).encode())

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body   = self.rfile.read(length)
        analysis = self._analyze_payload(body)
        captured_requests.append({
            "method": "POST", "path": self.path,
            "body_text": body.decode("utf-8", errors="ignore")[:500],
            "content_type": self.headers.get("Content-Type", ""),
            "user_agent":   self.headers.get("User-Agent", ""),
            "analysis": analysis,
        })
        self.send_response(200); self.end_headers()
        self.wfile.write(b'{"status":"ok","session":"accepted"}')

    def _analyze_payload(self, body):
        findings = {"payload_size": len(body)}
        try:
            decoded = base64.b64decode(body).decode("utf-8", errors="ignore")
            if len(decoded) > 10 and is_readable(decoded):
                findings["base64_decoded"] = decoded[:300]
        except Exception: pass
        try:
            data = json.loads(body)
            sensitive = [k for k in data if any(w in str(k).lower() for w in ['password','token','key','secret','credential','auth'])]
            if sensitive: findings["sensitive_json_keys"] = sensitive
        except Exception: pass
        if len(body) > 1024: findings["large_exfil_attempt"] = True
        return findings

    def log_message(self, *args): pass

def start_http():
    HTTPServer(("0.0.0.0", 8080), SmartFakeHandler).serve_forever()

threading.Thread(target=start_http, daemon=True).start()

# ============================================================
# FAKE DNS SERVER
# ============================================================

class FakeResolver(BaseResolver):
    def resolve(self, request, handler):
        qname = str(request.q.qname)
        captured_dns.append({"query": qname, "timestamp": round(time.time(), 3)})
        reply = request.reply()
        reply.add_answer(RR(qname, rdata=A("127.0.0.1"), ttl=60))
        return reply

def start_dns():
    DNSServer(FakeResolver(), port=5353, address="0.0.0.0").start()

threading.Thread(target=start_dns, daemon=True).start()

def analyze_package_metadata(package_dir):
    findings = {}
    setup_py = os.path.join(package_dir, "setup.py")
    if os.path.exists(setup_py):
        with open(setup_py, errors="ignore") as f: content = f.read()
        if re.search(r'cmdclass|post_install|entry_points', content): findings["python_install_hooks"] = True
        pkg_name = re.search(r'name\s*=\s*["\']([\w.-]+)["\']', content)
        if pkg_name:
            findings["package_name"] = pkg_name.group(1)
    pkg_json = os.path.join(package_dir, "package.json")
    if os.path.exists(pkg_json):
        try:
            with open(pkg_json) as f: data = json.load(f)
            for hook in ("preinstall","postinstall","prepare","install"):
                if hook in data.get("scripts",{}): findings[f"npm_{hook}_script"] = data["scripts"][hook]
            if data.get("name"):
                findings["package_name"] = data["name"]
        except Exception: pass
    return findings

# ============================================================
# BEHAVIORAL PHASES
# ============================================================

PHASE_PATTERNS = {
    "reconnaissance":    [r'/proc/cpuinfo', r'/etc/os-release', r'uname', r'/proc/net', r'ifconfig', r'hostname'],
    "defense_evasion":   [r'chmod.*777|chmod.*\+x', r'unlink\(', r'/proc/self/exe', r'prctl.*PR_SET_NAME'],
    "credential_access": [r'/etc/passwd', r'\.ssh/', r'\.aws/', r'\.env', r'Keychain', r'libsecret'],
    "exfiltration":      [r'connect.*443', r'connect.*80\b', r'sendto\(', r'POST.*http'],
    "execution":         [r'execve\(', r'system\(', r'popen\(', r'posix_spawn'],
    "persistence":       [r'crontab', r'\.bashrc', r'\.profile', r'/etc/init\.d', r'systemctl enable'],
    "discovery":         [r'getdents', r'stat\("/etc', r'/proc/\d+/status', r'sysinfo\('],
}

def build_behavioral_phases(timeline):
    phases = {k: [] for k in PHASE_PATTERNS}
    for event in timeline:
        evt = event.get("event", "")
        for phase, patterns in PHASE_PATTERNS.items():
            for p in patterns:
                if re.search(p, evt, re.IGNORECASE):
                    phases[phase].append({"time": event["time"], "event": evt[:150]})
                    break
    return {k: v[:20] for k, v in phases.items()}



# ============================================================
# IP ENRICHMENT
# ============================================================

def check_domain_virustotal(domain: str) -> str:
    """
    Checks a domain against VirusTotal.
    Returns 'True' if 3+ engines flag it as malicious, 'False' otherwise.
    Returns 'False' silently if no API key or any error occurs.
    Runs with a 10-second timeout to avoid blocking the pipeline.
    """
    key = os.environ.get("VIRUSTOTAL_API_KEY", "")
    if not key or not domain or domain == "none":
        return "False"
    try:
        import urllib.request as _req
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        request = _req.Request(
            url,
            headers={"x-apikey": key, "User-Agent": "Mozilla/5.0"},
        )
        raw  = _req.urlopen(request, timeout=10).read()
        data = json.loads(raw)
        stats     = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0) or 0)
        suspicious= int(stats.get("suspicious", 0) or 0)
        result    = str((malicious + suspicious) >= 3)
        print(f"[virustotal] {domain} → malicious={malicious} suspicious={suspicious} → {result}")
        return result
    except Exception as e:
        print(f"[virustotal] {domain} → skipped ({type(e).__name__})")
        return "False"


def post_run_enrich_ips(ip_set):
    enriched = []
    for ip in ip_set:
        if is_private_ip(ip):
            enriched.append({"ip": ip, "private": True, "risk": "low"})
            continue
        try:
            req  = urllib.request.Request(f"http://ip-api.com/json/{ip}", headers={"User-Agent": "Mozilla/5.0"})
            raw  = urllib.request.urlopen(req, timeout=5).read()
            data = json.loads(raw)
            risk = "high" if data.get("proxy") or data.get("hosting") else "medium"
            enriched.append({"ip": ip, "country": data.get("country"), "countryCode": data.get("countryCode"),
                              "region": data.get("regionName"), "city": data.get("city"),
                              "isp": data.get("isp"), "org": data.get("org"), "as": data.get("as"),
                              "risk": risk, "private": False})
        except Exception:
            enriched.append({"ip": ip, "error": "lookup_failed", "private": False, "risk": "unknown"})
    return enriched

def enrich_network_data(ips, domains, dns_queries, http_requests):
    real_domains, junk_domains = filter_domains(domains)
    enriched_ips = post_run_enrich_ips(ips)
    external_ips = [ip for ip in enriched_ips if not ip.get("private", True)]
    dns_summary  = {}
    for d in dns_queries:
        query  = d.get("query","") if isinstance(d,dict) else str(d)
        domain = query.rstrip('.')
        if is_real_domain(domain): dns_summary[domain] = dns_summary.get(domain,0)+1
    return {
        "real_domains": real_domains, "junk_domains": junk_domains[:50],
        "enriched_ips": enriched_ips, "external_ips": external_ips,
        "dns_summary": dns_summary,
        "total_unique_ips": len(ips),
        "total_dns_queries": len(dns_queries),
        "total_http_requests": len(http_requests),
    }

# ============================================================
# STATIC ANALYSIS (no YARA — moved to run_analysis.py)
# ============================================================

def static_analysis(file_path):
    """
    Lightweight static analysis inside sandbox.
    Extracts domains hardcoded in source as fallback for network capture.
    YARA and Semgrep run in run_analysis.py outside Docker.
    """
    findings = {}
    try:
        with open(file_path, "r", errors="ignore") as f:
            source = f.read()
    except Exception:
        return {"error": "unreadable", "static_domains": []}

    findings["entropy"]         = 0.0
    findings["has_obfuscation"] = False
    if source:
        from collections import Counter as _C
        import math as _m
        counts  = _C(source)
        total   = len(source)
        entropy = -sum((c/total)*_m.log2(c/total) for c in counts.values())
        findings["entropy"]         = round(entropy, 3)
        findings["has_obfuscation"] = entropy > 5.5

    for label, pattern in {
        "reverse_shell_pattern": r'nc\s+-e|bash\s+-i\s+>&|/dev/tcp/',
        "env_access":            r'os\.environ|process\.env',
    }.items():
        if re.search(pattern, source, re.IGNORECASE):
            findings[label] = True

    # Extract hardcoded URLs and domains — fallback for network detection
    url_domains  = re.findall(r'https?://([a-zA-Z0-9._-]+\.[a-zA-Z]{2,})', source)
    bare_domains = re.findall(r'["\']([a-zA-Z0-9][a-zA-Z0-9._-]{2,}\.[a-zA-Z]{2,10})["\']', source)
    findings["static_domains"] = list(dict.fromkeys(
        [d for d in url_domains + bare_domains if is_real_domain(d)]
    ))
    return findings



# ============================================================
# MEMORY STRINGS
# ============================================================

def dump_process_strings(pid):
    results = []
    try:
        maps_path = f"/proc/{pid}/maps"
        mem_path  = f"/proc/{pid}/mem"
        with open(maps_path,"r") as maps_f:
            for line in maps_f:
                parts = line.split()
                if len(parts)<2 or "r" not in parts[1]: continue
                start_s, end_s = parts[0].split("-")
                start, end = int(start_s,16), int(end_s,16)
                size = end - start
                if size > 8*1024*1024: continue
                try:
                    with open(mem_path,"rb") as mem_f:
                        mem_f.seek(start); chunk = mem_f.read(size)
                    results.extend(_extract_strings_from_bytes(chunk))
                except Exception: pass
    except Exception: pass
    return list(set(results))[:100]

def _extract_strings_from_bytes(data):
    found = []
    patterns = [
        rb'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
        rb'https?://[^\x00\s]{8,80}',
        rb'[A-Za-z0-9+/]{24,}={0,2}',
        rb'AKIA[A-Z0-9]{16}',
        rb'sk-[A-Za-z0-9]{10,}',
        rb'eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+',
    ]
    for p in patterns:
        for m in re.finditer(p, data):
            try:
                s = m.group().decode("utf-8", errors="ignore")
                if is_readable(s): found.append(s)
            except Exception: pass
    return found

# ============================================================
# FILESYSTEM SNAPSHOT
# ============================================================

def take_filesystem_snapshot(base_dir):
    snapshot = {}
    for root, _, files in os.walk(base_dir):
        for f in files:
            full_path = os.path.join(root, f)
            try: snapshot[full_path] = os.path.getsize(full_path)
            except Exception: pass
    return snapshot

def diff_filesystem_snapshots(before, after):
    new_files = []; modified_files = []
    for path, size in after.items():
        if path not in before: new_files.append(path)
        elif before[path] != size: modified_files.append(path)
    return new_files, modified_files

# ============================================================
# DYNAMIC FEATURES EXTRACTION
# ============================================================

SENSITIVE_FILE_PATTERNS = [
    "/etc/passwd","/etc/shadow","/etc/hosts",
    "/.ssh/","/.aws/","/.env","/.bashrc","/.profile","/root/",
    "/secrets","/credentials",
]

# ============================================================
# PROC-BASED BEHAVIORAL MONITOR
# Pure Python — no kernel access needed, works on GitHub Actions
# Replaces Falco/eBPF features using /proc + psutil
# ============================================================

def monitor_process_behavior(pid: int, duration: int = 120) -> dict:
    features = {
        "proc_privilege_escalation":    False,
        "proc_write_binary_dir":        False,
        "proc_ptrace_detected":         False,
        "proc_package_install_runtime": False,
    }

    try:
        import psutil
    except ImportError:
        print("[monitor] psutil not available — skipping")
        return features

    binary_dirs  = {"/bin/", "/usr/bin/", "/sbin/", "/usr/sbin/", "/usr/local/bin/"}
    pkg_managers = {"pip", "pip3", "npm", "apt-get", "apt", "apk", "yum", "conda"}
    start        = time.time()
    seen_pids    = set()

    try:
        root        = psutil.Process(pid)
        initial_uid = root.uids().real
    except Exception:
        return features

    while time.time() - start < duration:
        try:
            children  = root.children(recursive=True)
            all_procs = [root] + children

            for proc in all_procs:
                try:
                    # ── proc_package_install_runtime ──
                    name    = proc.name().lower()
                    cmdline = " ".join(proc.cmdline()).lower()
                    if any(pm in name or pm in cmdline for pm in pkg_managers):
                        features["proc_package_install_runtime"] = True
                        
                        # ── proc_privilege_escalation ──
                    if any(kw in cmdline for kw in [
                        "chmod", "setuid", "sudo", "chown",
                        "setreuid", "setresuid", "capset"
                    ]):
                        features["proc_privilege_escalation"] = True

                    # ── proc_write_binary_dir ──
                    if proc.pid not in seen_pids:
                        seen_pids.add(proc.pid)
                        try:
                            for f in proc.open_files():
                                if any(f.path.startswith(d) for d in binary_dirs):
                                    features["proc_write_binary_dir"] = True
                        except Exception:
                            pass

                    # ── proc_ptrace_detected ──
                    try:
                        with open(f"/proc/{proc.pid}/status") as sf:
                            for line in sf:
                                if line.startswith("TracerPid:"):
                                    if int(line.split(":")[1].strip()) > 0:
                                        features["proc_ptrace_detected"] = True
                                    break
                    except Exception:
                        pass

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            break

        if all(features.values()):
            break

        time.sleep(0.5)

    print(f"[monitor] proc features: {features}")
    return features
    
def extract_dynamic_features(
    processes, accessed_files, new_files, modified_files,
    network_analysis, captured_requests,
    strace_all_lines, behavioral_phases,
    static_results,
    behavioral_monitor=None,
):
    if behavioral_monitor is None:
        behavioral_monitor = {}
        
    unique_processes = list(set(processes))
    spawned_shell    = any(re.search(r'\b(bash|sh|dash|cmd\.exe|powershell)\b', p) for p in unique_processes)

    # Fix 4: Combine runtime (strace) and static indicators for sensitive_file_read
    # Runtime: files actually accessed during execution
    runtime_sensitive = [f for f in set(accessed_files) if any(pat in f for pat in SENSITIVE_FILE_PATTERNS)]

    # Static: semgrep/yara detected credential access patterns in source code
    static_sensitive = False
    for analysis in static_results.values():
        if isinstance(analysis, dict):
            # YARA credential theft or env access detected statically
            yara_result = analysis.get("yara", {})
            if yara_result.get("high_confidence_malware") == "True":
                static_sensitive = True
            # Static domain extraction found credential-related patterns
            src = analysis.get("env_access") or analysis.get("reverse_shell_pattern")
            if src:
                static_sensitive = True

    # sensitive_file_read = True if EITHER runtime access OR static detection
    sensitive_accessed = runtime_sensitive
    sensitive_file_read = bool(runtime_sensitive) or static_sensitive
    new_files_value      = "|".join(new_files[:20])      if new_files      else "none"
    modified_files_value = "|".join(modified_files[:20]) if modified_files else "none"

    real_domains = network_analysis.get("real_domains", [])
    external_ips = network_analysis.get("external_ips", [])
    countries    = list(set(ip.get("country","") for ip in external_ips if ip.get("country")))
    isps         = list(set(ip.get("isp",    "") for ip in external_ips if ip.get("isp")))

    # Fallback: look up country from C2 domain in captured HTTP Host header
    if not countries and captured_requests:
        for req in captured_requests:
            host = req.get("headers", {}).get("Host", "")
            if host and is_real_domain(host):
                try:
                    raw  = urllib.request.urlopen(f"http://ip-api.com/json/{host}", timeout=5).read()
                    data = json.loads(raw)
                    if data.get("country"):
                        countries = [data["country"]]
                        isps      = [data.get("isp", "none")]
                except: pass
                break

    http_methods = list(set(r.get("method","")     for r in captured_requests if r.get("method")))
    http_paths   = list(set(r.get("path","")       for r in captured_requests if r.get("path")))
    http_agents  = list(set(r.get("user_agent","") for r in captured_requests if r.get("user_agent")))
    has_exfil    = any(r.get("analysis",{}).get("large_exfil_attempt") for r in captured_requests)

    # Extract domains from fake DNS server captures
    dns_captured_domain = None
    for d in captured_dns:
        query = d.get("query", "").rstrip(".")
        if is_real_domain(query):
            dns_captured_domain = query
            break

    # Fix 3: Also extract DNS queries from strace connect() calls to port 53
    # Packages may use system resolver (port 53) which bypasses our fake DNS server
    strace_dns_domains = []
    for line in strace_all_lines:
        # Look for connect() calls with sin_port=53 (DNS) followed by domain in nearby lines
        if re.search(r'connect.*sin_port=53|sendto.*port.*53', line, re.IGNORECASE):
            # Extract any domain-like strings from surrounding context
            domain_matches = re.findall(r'[a-zA-Z0-9._-]{3,}\.[a-zA-Z]{2,10}', line)
            for d in domain_matches:
                if is_real_domain(d):
                    strace_dns_domains.append(d)
        # Also catch getaddrinfo/gethostbyname calls which show hostname
        if re.search(r'getaddrinfo|gethostbyname', line, re.IGNORECASE):
            domain_matches = re.findall(r'"([a-zA-Z0-9._-]{3,}\.[a-zA-Z]{2,10})"', line)
            for d in domain_matches:
                if is_real_domain(d):
                    strace_dns_domains.append(d)

    # Extract domains from HTTP request paths
    # e.g. path = "http://evil-c2-server.com/collect"
    http_contacted_domains = []
    for req in captured_requests:
        path = req.get("path", "")
        if path and ("http://" in path or "https://" in path):
            try:
                domain = path.split("://")[1].split("/")[0].split(":")[0]
                if is_real_domain(domain):
                    http_contacted_domains.append(domain)
            except Exception:
                pass
        # Also check Host header
        headers = req.get("headers", {})
        if isinstance(headers, dict):
            host = headers.get("Host", "")
            if host and is_real_domain(host):
                http_contacted_domains.append(host)

    # Extract domains hardcoded in source code (static analysis fallback)
    static_domains = []
    for analysis in static_results.values():
        if isinstance(analysis, dict):
            static_domains.extend(analysis.get("static_domains", []))
    static_domains = list(dict.fromkeys(static_domains))

    # Fix 2 + Fix 3: Combine all external domains from all sources
    # Priority: fake DNS > strace DNS > HTTP headers > strace domains > static code
    all_external_domains = list(dict.fromkeys(
        ([dns_captured_domain] if dns_captured_domain else []) +
        strace_dns_domains +
        http_contacted_domains +
        real_domains +
        static_domains
    ))

    dns_external_domain = all_external_domains[0]          if all_external_domains else "none"
    contacted_domain    = all_external_domains[0]          if all_external_domains else "none"

    # ── VirusTotal domain reputation (optional — skips gracefully if no key) ──
    domain_is_known_malicious = check_domain_virustotal(contacted_domain)

    return {
        "feat_has_exfiltration_phase":      str(bool(behavioral_phases.get("exfiltration"))),
        "feat_has_credential_access_phase": str(bool(behavioral_phases.get("credential_access"))),
        "feat_has_persistence_phase":       str(bool(behavioral_phases.get("persistence"))),
        "feat_contacted_external_domain":   contacted_domain,
        "feat_sensitive_file_read":         str(sensitive_file_read),
        "feat_spawned_shell":               str(spawned_shell),
        "feat_dns_query_to_external":       dns_external_domain,
        "feat_http_method":                 "|".join(http_methods) if http_methods else "none",
        "feat_http_exfil_attempt":          str(has_exfil),
        "feat_domain_is_known_malicious":   domain_is_known_malicious,
        "feat_contacted_countries":         "|".join(countries)   if countries   else "none",
        "feat_contacted_isps":              "|".join(isps)        if isps        else "none",
        "feat_http_user_agents":            "|".join(http_agents) if http_agents else "none",
        "decoy_processes_spawned":          "|".join(unique_processes) if unique_processes else "none",
        "decoy_sensitive_files_accessed":   "|".join(sensitive_accessed) if sensitive_accessed else "none",
        "decoy_new_files_created":          new_files_value,
        "decoy_modified_files":             modified_files_value,
          # ── Proc monitor features — replaces Falco/eBPF ──
        "proc_privilege_escalation":    str(behavioral_monitor.get("proc_privilege_escalation",    False)),
        "proc_write_binary_dir":        str(behavioral_monitor.get("proc_write_binary_dir",        False)),
        "proc_ptrace_detected":         str(behavioral_monitor.get("proc_ptrace_detected",         False)),
        "proc_package_install_runtime": str(behavioral_monitor.get("proc_package_install_runtime", False)),
        
    }

# ============================================================
# MAIN EXECUTION
# ============================================================

if len(sys.argv) < 2:
    print("Usage: python3 sandbox/runner.py <package_path>")
    sys.exit(1)

original_input = sys.argv[1]

def extract_package_if_needed(path):
    if path.endswith(".tgz") or path.endswith(".tar.gz"):
        temp_dir = tempfile.mkdtemp()
        with tarfile.open(path, "r:gz") as tar:
            tar.extractall(temp_dir)
        return temp_dir
    return path

file_path = extract_package_if_needed(original_input)

# Snapshot
snapshot_before = take_filesystem_snapshot(file_path)

static_results   = {}
package_metadata = analyze_package_metadata(file_path)

targets = []
for root, _, fs in os.walk(file_path):
    for f in fs:
        if f.endswith(".js") or f.endswith(".py"):
            targets.append(os.path.join(root, f))

for t in targets:
    static_results[os.path.basename(t)] = static_analysis(t)


env = os.environ.copy()
env["HTTP_PROXY"]  = "http://127.0.0.1:8080"
env["HTTPS_PROXY"] = "http://127.0.0.1:8080"
env["NO_PROXY"]    = ""

ips              = set()
domains          = set()
accessed_files   = []
processes        = []
timeline         = []
decoded_payloads = []
memory_strings   = []
strace_all_lines = []

for target in targets:
    run_cmd = ["node", target] if target.endswith(".js") else ["python3", target]
    processes.append(os.path.basename(target))
    processes.append(os.path.basename(run_cmd[0]))

    proc = subprocess.Popen(
        ["strace", "-ttt", "-f", "-e", "trace=all"] + run_cmd,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        stdin=subprocess.PIPE, text=True, env=env,
    )

    def _mem_dump(pid):
        time.sleep(1)
        memory_strings.extend(dump_process_strings(pid))

    mem_thread = threading.Thread(target=_mem_dump, args=(proc.pid,), daemon=True)
    mem_thread.start()

    # ── Start proc behavioral monitor ──
    behavioral_monitor_result = {}
    def _run_monitor():
        behavioral_monitor_result.update(
            monitor_process_behavior(proc.pid, duration=120)
        )
    monitor_thread = threading.Thread(target=_run_monitor, daemon=True)
    monitor_thread.start()

    try:
        # Fix 3: Increased timeout from 60s to 120s to capture delayed network activity
        stdout, stderr = proc.communicate(input="trigger\n", timeout=120)
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout, stderr = proc.communicate()

    for line in stderr.split("\n"):
        if not line: continue
        m = re.match(r'^(\d+\.\d+)\s+(.*)', line)
        if not m: continue
        timestamp = float(m.group(1))
        event     = m.group(2)
        strace_all_lines.append(event)
        timeline.append({"time": timestamp, "event": event[:500]})
        if "execve(" in event:
            m2 = re.search(r'execve\("([^"]+)"', event)
            if m2: processes.append(os.path.basename(m2.group(1)))
        for ip in re.findall(r'\d+\.\d+\.\d+\.\d+', event):
            ips.add(ip)
        for d in re.findall(r'[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', event):
            domains.add(d)
        if "open(" in event or "openat(" in event:
            fmatch = re.search(r'"([^"]+)"', event)
            if fmatch: accessed_files.append(fmatch.group(1))
        for s in re.findall(r'[A-Za-z0-9+/=]{20,}', event):
            decoded = try_decode_base64(s)
            if decoded: decoded_payloads.append(decoded)

# Filesystem diff
snapshot_after = take_filesystem_snapshot(file_path)
new_files, modified_files = diff_filesystem_snapshots(snapshot_before, snapshot_after)


# Enrich network
network_analysis  = enrich_network_data(ips, domains, captured_dns, captured_requests)
# Merge captured DNS queries into real_domains
for d in captured_dns:
    query = d.get("query", "").rstrip(".")
    if is_real_domain(query) and query not in network_analysis["real_domains"]:
        network_analysis["real_domains"].append(query)
        
external_ips_info = network_analysis.get("external_ips", [])

# Behavioral phases
behavioral_phases = build_behavioral_phases(timeline)

# Dynamic features
# Wait for monitor thread
monitor_thread.join(timeout=5)

dynamic_features = extract_dynamic_features(
    processes=processes,
    accessed_files=accessed_files,
    new_files=new_files,
    modified_files=modified_files,
    network_analysis=network_analysis,
    captured_requests=captured_requests,
    strace_all_lines=strace_all_lines,
    behavioral_phases=behavioral_phases,
    static_results=static_results,
    behavioral_monitor=behavioral_monitor_result,
)


# ============================================================
# SAVE
# ============================================================

os.makedirs("decoy_logs/decoy_runs", exist_ok=True)

log = {
    "package": os.path.basename(original_input),
    "run_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "behavioral_phases": behavioral_phases,
    "static_analysis":   static_results,
    "package_metadata":  package_metadata,
    "network_analysis":  network_analysis,
    "dns":               captured_dns,
    "http_requests":     captured_requests,
    "processes":         list(set(processes)),
    "accessed_files":    list(set(accessed_files)),
    "decoded_payloads":  decoded_payloads,
    "memory_strings":    list(set(memory_strings))[:100],
    "timeline":          timeline,
    "dns_queries":       [d.get("query","")  for d in captured_dns      if d.get("query")],
    "http_hosts":        [r.get("host","")   for r in captured_requests if r.get("host")],
    "http_methods":      [r.get("method","") for r in captured_requests if r.get("method")],
    "http_paths":        [r.get("path","")   for r in captured_requests if r.get("path")],
    "dynamic_features":  dynamic_features,
}

pkg_basename = os.path.basename(original_input)
for ext in (".tar.gz",".tgz",".whl",".zip"):
    if pkg_basename.endswith(ext):
        pkg_stem = pkg_basename[:-len(ext)]; break
else:
    pkg_stem = os.path.splitext(pkg_basename)[0]

pkg_stem = re.sub(r"[^\w.\-]", "_", pkg_stem)
run_id   = os.environ.get("GH_RUN_NUMBER", str(int(time.time())))
log_name = f"{pkg_stem}_run{run_id}_sandbox"
log_path = f"decoy_logs/decoy_runs/{log_name}.json"

with open(log_path, "w") as f:
    json.dump(log, f, indent=4, ensure_ascii=False)

# Update latest.json for dashboard display
with open("decoy_logs/latest.json", "w") as f:
    json.dump(log, f, indent=4, ensure_ascii=False)

# Save pointer file named after original package — used by CI to find this log
ptr_name = os.path.basename(original_input)
ptr_path = f"decoy_logs/ptr_{ptr_name}.txt"
with open(ptr_path, "w") as f:
    f.write(log_path)

print(f"Saved runtime analysis log: {log_path}")
print(f"Dynamic features saved: {list(dynamic_features.keys())}")
