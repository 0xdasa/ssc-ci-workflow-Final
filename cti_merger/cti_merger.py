"""
CTI Dataset Merger — YARA Clean Version
---------------------------------------
Produces the original dataset columns plus decoy-derived CTI features.

Changes:
  - Removed Volatility-only features.
  - Removed cti_ prefixes from final feature names.
  - Added YARA rule-specific features as single-value True/False columns.
  - Supports both old logs using cti_yara_* keys and new logs using clean YARA keys.
"""

import os
import re
import json
import csv
import glob
import time

ML_LOGS_DIR     = "decoy_logs/ml_logs"
BENIGN_LOGS_DIR = "decoy_logs/benign_runs"
DECOY_LOGS_DIR  = "decoy_logs/decoy_runs"
OUTPUT_CSV      = "CTI_Storage/enriched_cti_dataset.csv"
PROCESSED_LOG   = "CTI_Storage/processed_runs.json"

DATASET_COLUMNS = [
    "Malicious", "Package Repository", "Package Name",
    "Number of Words in source code", "Number of lines in source code",
    "plus ratio mean", "plus ratio max", "plus ratio std", "plus ratio q3",
    "eq ratio mean", "eq ratio max", "eq ratio std", "eq ratio q3",
    "bracket ratio mean", "bracket ratio max", "bracket ratio std", "bracket ratio q3",
    "Number of base64 chunks in source code", "Number of IP adress in source code",
    "Number of sospicious token in source code",
    "Number of Words in metadata", "Number of lines in metadata",
    "Number of base64 chunks in metadata", "Number of IP adress in metadata",
    "Number of sospicious token in metadata",
    ".bat", ".bz2", ".c", ".cert", ".conf", ".cpp", ".crt", ".css", ".csv",
    ".deb", ".erb", ".gemspec", ".gif", ".gz", ".h", ".html", ".ico", ".ini",
    ".jar", ".java", ".jpg", ".js", ".json", ".key", ".m4v", ".markdown", ".md",
    ".pdf", ".pem", ".png", ".ps", ".py", ".rb", ".rpm", ".rst", ".sh", ".svg",
    ".toml", ".ttf", ".txt", ".xml", ".yaml", ".yml", ".eot", ".exe", ".jpeg",
    ".properties", ".sql", ".swf", ".tar", ".woff", ".woff2", ".aac", ".bmp",
    ".cfg", ".dcm", ".dll", ".doc", ".flac", ".flv", ".ipynb", ".m4a", ".mid",
    ".mkv", ".mp3", ".mp4", ".mpg", ".ogg", ".otf", ".pickle", ".pkl", ".psd",
    ".pxd", ".pxi", ".pyc", ".pyx", ".r", ".rtf", ".so", ".sqlite", ".tif",
    ".tp", ".wav", ".webp", ".whl", ".xcf", ".xz", ".zip", ".mov", ".wasm", ".webm",
    "presence of installation script",
    "shannon mean ID source code", "shannon std ID source code",
    "shannon max ID source code", "shannon q3 ID source code",
    "shannon mean string source code", "shannon std string source code",
    "shannon max string source code", "shannon q3 string source code",
    "homogeneous identifiers in source code", "homogeneous strings in source code",
    "heteregeneous identifiers in source code", "heterogeneous strings in source code",
    "URLs in source code",
    "shannon mean ID metadata", "shannon std ID metadata",
    "shannon max ID metadata", "shannon q3 ID metadata",
    "shannon mean string metadata", "shannon std string metadata",
    "shannon max string metadata", "shannon q3 string metadata",
    "homogeneous identifiers in metadata", "homogeneous strings in metadata",
    "heterogeneous strings in metadata", "URLs in metadata",
    "heteregeneous identifiers in metadata",
]

# Additional decoy-derived features with clean names
CTI_COLUMNS = [
    # ── Dynamic — sandbox (strace + fake servers) ──
    "contacted_external_domain",
    "sensitive_file_read",
    "dns_query_to_external",
    "http_method",
    "domain_is_known_malicious",
  
    # ── Static — YARA ──
    "yara_credential_theft_indicators",
    "yara_exfiltration_indicators",
    "yara_shell_execution_indicators",
    "yara_command_execution_indicators",
    "yara_obfuscation_indicators",
    "yara_persistence_indicators",
    "yara_install_hook_indicators",
    "yara_suspicious_imports_indicators",
    # ── Static — Semgrep ──
    "semgrep_has_exec_call",
    "semgrep_has_subprocess",
    "semgrep_has_network_request",
    "semgrep_has_secret_access",
     # ── Proc monitor — replaces Falco/eBPF ──
    "proc_privilege_escalation",
    "proc_write_binary_dir",
    "proc_ptrace_detected",
    "proc_package_install_runtime",
    "ebpf_accessed_root",
    "ebpf_accessed_ssh",
    "ebpf_accessed_etc",
    "ebpf_privilege_escalation",
    "ebpf_network_activity",
    "ebpf_spawned_process",
    "ebpf_c2_port_suspected",
    "c2_port_4444",
    "c2_port_1337",
    "c2_port_6667",
    "c2_port_31337",
    "c2_port_9001",
    "c2_port_8080",
    "c2_port_2323",
    "c2_port_1234",
]

ALL_COLUMNS = DATASET_COLUMNS + CTI_COLUMNS

DEFAULTS = {
    "contacted_external_domain":          "none",
    "sensitive_file_read":                "False",
    "dns_query_to_external":              "none",
    "http_method":                        "none",
    "domain_is_known_malicious":          "False",
    "yara_credential_theft_indicators":   "False",
    "yara_exfiltration_indicators":       "False",
    "yara_shell_execution_indicators":    "False",
    "yara_command_execution_indicators":  "False",
    "yara_obfuscation_indicators":        "False",
    "yara_persistence_indicators":        "False",
    "yara_install_hook_indicators":       "False",
    "yara_suspicious_imports_indicators": "False",
    "semgrep_has_exec_call":              "False",
    "semgrep_has_subprocess":             "False",
    "semgrep_has_network_request":        "False",
    "semgrep_has_secret_access":          "False",
    "proc_privilege_escalation":          "False",
    "proc_write_binary_dir":              "False",
    "proc_ptrace_detected":               "False",
    "proc_package_install_runtime":       "False",
    # ── AWS EC2 eBPF features ──
    "ebpf_accessed_root":           "False",
    "ebpf_accessed_ssh":            "False",
    "ebpf_accessed_etc":            "False",
    "ebpf_privilege_escalation":    "False",
    "ebpf_network_activity":        "False",
    "ebpf_spawned_process":         "False",
    "ebpf_c2_port_suspected":       "False",
    "c2_port_4444":                 "False",
    "c2_port_1337":                 "False",
    "c2_port_6667":                 "False",
    "c2_port_31337":                "False",
    "c2_port_9001":                 "False",
    "c2_port_8080":                 "False",
    "c2_port_2323":                 "False",
    "c2_port_1234":                 "False",  
}


def load_processed():
    if os.path.exists(PROCESSED_LOG):
        with open(PROCESSED_LOG) as f:
            return set(json.load(f))
    return set()


def save_processed(processed):
    os.makedirs(os.path.dirname(PROCESSED_LOG), exist_ok=True)
    with open(PROCESSED_LOG, "w") as f:
        json.dump(list(processed), f, indent=2)


def get_pkg_stem(pkg_path):
    basename = os.path.basename(pkg_path)
    for ext in (".tar.gz", ".tgz", ".tar", ".whl", ".zip"):
        if basename.endswith(ext):
            return basename[:-len(ext)]
    return os.path.splitext(basename)[0]


def load_all_ml_logs():
    latest = {}
    for path in glob.glob(os.path.join(ML_LOGS_DIR, "*.json")):
        try:
            with open(path) as f:
                log = json.load(f)
            pkg_name = get_pkg_stem(log.get("package", ""))
            ts = int(log.get("run_id", 0))
            if pkg_name not in latest or ts > int(latest[pkg_name]["run_id"]):
                latest[pkg_name] = log
                latest[pkg_name]["_log_file"] = os.path.basename(path)
        except Exception as e:
            print(f"  [!] {path}: {e}")
    return latest


def find_behavioral_log(pkg_name):
    candidates = []
    for log_dir, source in [(DECOY_LOGS_DIR, "decoy"), (BENIGN_LOGS_DIR, "benign")]:
        for path in glob.glob(os.path.join(log_dir, "*.json")):
            basename = os.path.basename(path).replace(".json", "")

            # New format: pkgname_runNNN_sandbox.json
            if re.match(rf"^{re.escape(pkg_name)}_run(\d+)_sandbox$", basename):
                try:
                    run_num = int(re.search(r'_run(\d+)_sandbox$', basename).group(1))
                    with open(path) as f: d = json.load(f)
                    candidates.append((run_num, d, source, "sandbox"))
                except Exception: continue

            # New format: pkgname_runNNN_ebpf.json
            elif re.match(rf"^{re.escape(pkg_name)}_run(\d+)_ebpf$", basename):
                try:
                    run_num = int(re.search(r'_run(\d+)_ebpf$', basename).group(1))
                    with open(path) as f: d = json.load(f)
                    dyn  = d.get("dynamic_features", {})
                    ebpf = d.get("ebpf_features", {})
                    merged_dyn = {}
                    for k, v in {**ebpf, **dyn}.items():
                        if isinstance(v, str):
                            if v.lower() == "true":    merged_dyn[k] = True
                            elif v.lower() == "false": merged_dyn[k] = False
                            else:
                                try:    merged_dyn[k] = int(v)
                                except: merged_dyn[k] = v
                        else:
                            merged_dyn[k] = v
                    d["dynamic_features"] = merged_dyn
                    candidates.append((run_num, d, "ebpf", "ebpf"))
                except Exception: continue

            # Old format: pkgname_timestamp.json
            elif re.match(rf"^{re.escape(pkg_name)}_\d+$", basename):
                try:
                    ts = int(basename.split("_")[-1])
                    with open(path) as f: d = json.load(f)
                    candidates.append((ts, d, source, "sandbox"))
                except Exception: continue

            # Old format: pkgname_timestamp_ebpf.json
            elif re.match(rf"^{re.escape(pkg_name)}_\d+_ebpf$", basename):
                try:
                    ts = int(basename.split("_")[-2])
                    with open(path) as f: d = json.load(f)
                    dyn  = d.get("dynamic_features", {})
                    ebpf = d.get("ebpf_features", {})
                    merged_dyn = {}
                    for k, v in {**ebpf, **dyn}.items():
                        if isinstance(v, str):
                            if v.lower() == "true":    merged_dyn[k] = True
                            elif v.lower() == "false": merged_dyn[k] = False
                            else:
                                try:    merged_dyn[k] = int(v)
                                except: merged_dyn[k] = v
                        else:
                            merged_dyn[k] = v
                    d["dynamic_features"] = merged_dyn
                    candidates.append((ts, d, "ebpf", "ebpf"))
                except Exception: continue

    if not candidates: return None, None
    candidates.sort(key=lambda x: x[0], reverse=True)

    sandbox_logs = [(n, d) for n, d, s, t in candidates if t == "sandbox"]
    ebpf_logs    = [(n, d) for n, d, s, t in candidates if t == "ebpf"]

    # Best case: same run number
    for s_num, s_log in sandbox_logs:
        for e_num, e_log in ebpf_logs:
            if s_num == e_num:
                s_log.setdefault("dynamic_features", {}).update(e_log.get("dynamic_features", {}))
                return s_log, "merged"

    # Fallback: merge best of each
    regular_log = sandbox_logs[0][1] if sandbox_logs else None
    ebpf_log    = ebpf_logs[0][1]    if ebpf_logs    else None

    if regular_log and ebpf_log:
        regular_log.setdefault("dynamic_features", {}).update(ebpf_log.get("dynamic_features", {}))
        return regular_log, "merged"

    if ebpf_log and not regular_log:
        return ebpf_log, "ebpf"

    return candidates[0][1], candidates[0][2]


def extract_ml_row(ml_log):
    row      = {}
    features = ml_log.get("features", {})
    row["Malicious"] = ml_log.get("prediction", "")
    for col in DATASET_COLUMNS:
        if col == "Malicious": continue
        if col in features:
            val = features[col]
            row[col] = list(val.values())[0] if isinstance(val, dict) else val
        else:
            row[col] = ""
    row["Package Name"] = get_pkg_stem(ml_log.get("package", ""))
    return row


def _str_bool(val, default="False"):
    """Normalize any truthy value to True/False string."""
    if isinstance(val, bool):
        return str(val)
    if isinstance(val, str):
        if val.lower() in ("true", "1", "yes"):
            return "True"
        return "False"
    return default


def _collect_yara_rules(behavioral_log, dynamic):
    """
    Collect YARA rule names from both:
      1. new/old dynamic_features
      2. static_analysis[*].yara.rules_matched
    """
    rules = set()

    raw = dynamic.get("yara_rules_matched", dynamic.get("cti_yara_rules_matched", ""))
    if isinstance(raw, str):
        for r in raw.split("|"):
            if r.strip():
                rules.add(r.strip())
    elif isinstance(raw, list):
        rules.update(str(r).strip() for r in raw if str(r).strip())

    for _, analysis in behavioral_log.get("static_analysis", {}).items():
        yara_info = analysis.get("yara", {})
        matched = yara_info.get("rules_matched", [])
        if isinstance(matched, list):
            rules.update(str(r).strip() for r in matched if str(r).strip())
        elif isinstance(matched, str):
            rules.update(r.strip() for r in matched.split("|") if r.strip())

    return rules


def _set_yara_flags(row, behavioral_log, dynamic):
    rules = _collect_yara_rules(behavioral_log, dynamic)
    normalized = {r.lower() for r in rules}

    def has_any(*needles):
        return any(any(n.lower() in r for n in needles) for r in normalized)

    row["yara_credential_theft_indicators"] = str(has_any("credential", "theft"))
    row["yara_exfiltration_indicators"]     = str(has_any("exfiltration"))
    row["yara_shell_execution_indicators"]  = str(has_any("shell"))
    row["yara_command_execution_indicators"]= str(has_any("command_execution"))
    row["yara_obfuscation_indicators"]      = str(has_any("obfuscation"))
    row["yara_persistence_indicators"]      = str(has_any("persistence"))
    row["yara_install_hook_indicators"]     = str(has_any("install_hook"))
    row["yara_suspicious_imports_indicators"]= str(has_any("suspicious_imports"))


def extract_cti(ml_log, behavioral_log):
    """
    Extract exactly 18 CTI features.
    - Dynamic features from behavioral_log (decoy sandbox)
    - Static features (YARA + semgrep) from ml_log (run_analysis.py)
    """
    row = dict(DEFAULTS)

    # ── YARA + Semgrep from ML log (run_analysis.py) ──
    static = ml_log.get("static_analysis", {})
    row["yara_credential_theft_indicators"]  = static.get("yara_credential_theft_indicators",  "False")
    row["yara_exfiltration_indicators"]      = static.get("yara_exfiltration_indicators",      "False")
    row["yara_shell_execution_indicators"]   = static.get("yara_shell_execution_indicators",   "False")
    row["yara_command_execution_indicators"] = static.get("yara_command_execution_indicators", "False")
    row["yara_obfuscation_indicators"]       = static.get("yara_obfuscation_indicators",       "False")
    row["yara_persistence_indicators"]       = static.get("yara_persistence_indicators",       "False")
    row["yara_install_hook_indicators"]      = static.get("yara_install_hook_indicators",      "False")
    row["yara_suspicious_imports_indicators"]= static.get("yara_suspicious_imports_indicators","False")
    row["semgrep_has_exec_call"]             = static.get("semgrep_has_exec_call",             "False")
    row["semgrep_has_subprocess"]            = static.get("semgrep_has_subprocess",            "False")
    row["semgrep_has_network_request"]       = static.get("semgrep_has_network_request",       "False")
    row["semgrep_has_secret_access"]         = static.get("semgrep_has_secret_access",         "False")

    if not behavioral_log:
        return row

    dynamic = behavioral_log.get("dynamic_features", {})

    if dynamic:
        # contacted_external_domain — single domain
        contacted_raw = dynamic.get("feat_contacted_external_domain", "none") or "none"
        contacted = contacted_raw.split("|")[0].strip() if "|" in contacted_raw else contacted_raw.strip()
        row["contacted_external_domain"] = contacted if contacted and contacted != "" else "none"

        # sensitive_file_read — True/False
        row["sensitive_file_read"] = _str_bool(dynamic.get("feat_sensitive_file_read", "False"))

        # dns_query_to_external — single domain
        dns_val = dynamic.get("feat_dns_query_to_external", "none") or "none"
        if dns_val in ("True", "False", "true", "false", "", None, "none"):
            dns_val = contacted
        else:
            dns_val = dns_val.split("|")[0].strip()
        row["dns_query_to_external"] = dns_val if dns_val and dns_val != "" else "none"

        # http_method — POST/GET/none
        http = dynamic.get("feat_http_method", "none") or "none"
        row["http_method"] = http.split("|")[0].strip() if "|" in http else http

        # domain_is_known_malicious — True/False from VirusTotal
        row["domain_is_known_malicious"] = _str_bool(dynamic.get("feat_domain_is_known_malicious", "False"))


        row["proc_privilege_escalation"]    = _str_bool(dynamic.get("proc_privilege_escalation",    "False"))
        row["proc_write_binary_dir"]        = _str_bool(dynamic.get("proc_write_binary_dir",        "False"))
        row["proc_ptrace_detected"]         = _str_bool(dynamic.get("proc_ptrace_detected",         "False"))
        row["proc_package_install_runtime"] = _str_bool(dynamic.get("proc_package_install_runtime", "False"))
       # ── AWS EC2 eBPF features ──
        row["ebpf_accessed_root"]           = _str_bool(dynamic.get("ebpf_accessed_root",           "False"))
        row["ebpf_accessed_ssh"]            = _str_bool(dynamic.get("ebpf_accessed_ssh",            "False"))
        row["ebpf_accessed_etc"]            = _str_bool(dynamic.get("ebpf_accessed_etc",            "False"))
       
        row["ebpf_privilege_escalation"]    = _str_bool(dynamic.get("ebpf_privilege_escalation",    "False"))
        row["ebpf_network_activity"]        = _str_bool(dynamic.get("ebpf_network_activity",        "False"))
        row["ebpf_spawned_process"]         = _str_bool(dynamic.get("ebpf_spawned_process",         "False"))
        row["ebpf_c2_port_suspected"]       = _str_bool(dynamic.get("ebpf_c2_port_suspected",       "False"))
       
        remote_ports_str = str(dynamic.get("ebpf_remote_ports", ""))
        try:
            detected_ports = set(int(p) for p in remote_ports_str.split("|") if p.strip().isdigit())
        except:
            detected_ports = set()
        row["c2_port_4444"]  = str(4444  in detected_ports)
        row["c2_port_1337"]  = str(1337  in detected_ports)
        row["c2_port_6667"]  = str(6667  in detected_ports)
        row["c2_port_31337"] = str(31337 in detected_ports)
        row["c2_port_9001"]  = str(9001  in detected_ports)
        row["c2_port_8080"]  = str(8080  in detected_ports)
        row["c2_port_2323"]  = str(2323  in detected_ports)
        row["c2_port_1234"]  = str(1234  in detected_ports)

        # NOTE: YARA and Semgrep already set from ml_log["static_analysis"] above

    else:
        # Fallback for old logs
        na           = behavioral_log.get("network_analysis", {})
        real_domains = na.get("real_domains", [])
        external_ips = na.get("external_ips", [])
        http_requests = behavioral_log.get("http_requests", [])
        http_methods  = list(set(r.get("method","") for r in http_requests if r.get("method")))
        accessed      = behavioral_log.get("accessed_files", [])
        sensitive_pats = ["/etc/passwd","/etc/shadow","/.ssh/","/.aws/","/.env","/.bashrc","/root/"]
        sensitive     = [f for f in accessed if any(p in f for p in sensitive_pats)]
        processes     = behavioral_log.get("processes", [])
        countries     = list(set(ip.get("country","") for ip in external_ips if ip.get("country")))

        row["contacted_external_domain"] = real_domains[0] if real_domains else "none"
        row["sensitive_file_read"]       = str(bool(sensitive))
        row["dns_query_to_external"]     = real_domains[0] if real_domains else "none"
        row["http_method"]               = http_methods[0] if http_methods else "none"
        row["spawned_shell"]             = str(any(re.search(r'\b(bash|sh|dash)\b', p) for p in processes))
        row["contacted_country"]         = countries[0] if countries else "none"

        # NOTE: YARA and Semgrep already set from ml_log["static_analysis"] above

    return row


def init_output_csv():
    os.makedirs(os.path.dirname(OUTPUT_CSV), exist_ok=True)

    needs_header = False
    if not os.path.exists(OUTPUT_CSV):
        needs_header = True
    else:
        # Check if first line is a valid header
        try:
            with open(OUTPUT_CSV, "r") as f:
                first_line = f.readline().strip()
            # Valid header must start with "Malicious" (first column)
            if not first_line.startswith("Malicious"):
                print(f"[!] CSV header missing or corrupt — rewriting with header")
                # Read existing data rows
                with open(OUTPUT_CSV, "r") as f:
                    existing = f.read()
                # Prepend header
                header_line = ",".join(ALL_COLUMNS)
                with open(OUTPUT_CSV, "w", newline="") as f:
                    f.write(header_line + "\n")
                    # Write back existing rows only if they look like data
                    for line in existing.split("\n"):
                        if line.strip() and not line.startswith("Malicious"):
                            f.write(line + "\n")
                print(f"[+] Header restored: {OUTPUT_CSV}")
                return
        except Exception as e:
            print(f"[!] Could not read CSV: {e}")
            needs_header = True

    if needs_header:
        with open(OUTPUT_CSV, "w", newline="") as f:
            csv.DictWriter(f, fieldnames=ALL_COLUMNS).writeheader()
        print(f"[+] Created: {OUTPUT_CSV}")


def append_row(row):
    with open(OUTPUT_CSV, "a", newline="") as f:
        csv.DictWriter(f, fieldnames=ALL_COLUMNS, extrasaction="ignore").writerow(row)


def run_once():
    processed  = load_processed()
    init_output_csv()
    all_latest = load_all_ml_logs()
    new_count  = 0

    for pkg_name, ml_log in all_latest.items():
        log_file = ml_log.get("_log_file", "")
        if log_file in processed:
            continue

        print(f"\n[>] {pkg_name}")
        row = extract_ml_row(ml_log)

        behavioral_log, source = find_behavioral_log(pkg_name)
        if behavioral_log:
            has_dyn = "dynamic_features" in behavioral_log
            print(f"  [{source}] verdict={behavioral_log.get('verdict')} "
                  f"score={behavioral_log.get('score')} "
                  f"dynamic={'yes' if has_dyn else 'old-format'}")
        else:
            print(f"  [no behavioral log] — defaults used")

        row.update(extract_cti(ml_log, behavioral_log))

        # ── Falco runtime features ──
        append_row(row)
        processed.add(log_file)
        new_count += 1
        print(f"  [✓] Appended")

    save_processed(processed)
    if new_count == 0:
        print("[=] No new logs.")
    else:
        print(f"\n[✓] {new_count} new rows added to {OUTPUT_CSV}")


def watch(interval=10):
    print(f"[*] Watching every {interval}s ...")
    while True:
        run_once()
        time.sleep(interval)


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "--watch":
        watch(interval=int(sys.argv[2]) if len(sys.argv) > 2 else 10)
    else:
        run_once()
