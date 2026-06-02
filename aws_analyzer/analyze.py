"""
AWS EC2 eBPF Analyzer
Watches for new packages and runs full kernel-level analysis.
Results saved locally — GitHub Actions copies them via SSH.
"""

import os
import re
import sys
import time
import json
import glob
import subprocess
import threading
import tempfile
import tarfile

REPO_DIR    = "/home/ubuntu/DanahCopy5"
WATCH_FILE  = ".ebpf_pending"
DECOY_DIR   = "decoy_logs/decoy_runs"
FLAG_DIR    = "decoy_logs"

PRIVATE_RANGES = [
    "127.", "10.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    "192.168.", "169.254.", "::1", "fe80"
]

def is_private_ip(ip):
    return any(ip.startswith(r) for r in PRIVATE_RANGES)


# ── Entry Point Detection ─────────────────────────────────────

def find_npm_entries(tmp_dir):
    """
    Find ALL entry points for an npm package.
    Returns list in priority order.
    """
    entries = []
    seen = set()

    def add(path):
        if path and os.path.exists(path) and path not in seen:
            seen.add(path)
            entries.append(path)

    # 1. index.js in root
    for f in glob.glob(f"{tmp_dir}/*/index.js"):
        add(f)

    # 2. main field in package.json
    for pj in glob.glob(f"{tmp_dir}/*/package.json"):
        try:
            with open(pj) as f:
                data = json.load(f)
            pkg_dir = os.path.dirname(pj)

            # scripts: preinstall, postinstall, install
            scripts = data.get("scripts", {})
            for script_name in ["preinstall", "install", "postinstall"]:
                script_val = scripts.get(script_name, "")
                if script_val.startswith("node "):
                    script_file = script_val.split("node ", 1)[1].split()[0]
                    add(os.path.join(pkg_dir, script_file))

            # main field
            main = data.get("main", "")
            if main:
                for ext in ["", ".js"]:
                    add(os.path.join(pkg_dir, main + ext))

            # bin field
            bin_field = data.get("bin", {})
            if isinstance(bin_field, str):
                add(os.path.join(pkg_dir, bin_field))
            elif isinstance(bin_field, dict):
                for v in bin_field.values():
                    add(os.path.join(pkg_dir, v))

        except:
            pass

    # 3. preinstall / postinstall / install js files
    for name in ["preinstall.js", "postinstall.js", "install.js", "binding.js"]:
        for f in glob.glob(f"{tmp_dir}/**/{name}", recursive=True):
            add(f)

    # 4. Any .js in package root
    for f in glob.glob(f"{tmp_dir}/*/*.js"):
        add(f)

    # 5. Any .js anywhere (limit to avoid too many files)
    for f in sorted(glob.glob(f"{tmp_dir}/**/*.js", recursive=True))[:10]:
        add(f)

    return entries


def find_pypi_entries(tmp_dir):
    """
    Find ALL entry points for a PyPI package.
    Returns list in priority order.
    """
    entries = []
    seen = set()

    def add(path):
        if path and os.path.exists(path) and path not in seen:
            seen.add(path)
            entries.append(path)

    # 1. setup.py — most common malicious trigger (runs on pip install)
    for f in glob.glob(f"{tmp_dir}/*/setup.py") + glob.glob(f"{tmp_dir}/setup.py"):
        add(f)

    # 2. __main__.py — runs with python -m package
    for f in glob.glob(f"{tmp_dir}/**/__main__.py", recursive=True):
        add(f)

    # 3. __init__.py — runs on import (first level priority)
    for f in glob.glob(f"{tmp_dir}/*/__init__.py"):
        add(f)
    for f in glob.glob(f"{tmp_dir}/*/*/__init__.py"):
        add(f)

    # 4. main.py
    for f in glob.glob(f"{tmp_dir}/*/main.py") + glob.glob(f"{tmp_dir}/main.py"):
        add(f)

    # 5. cli.py / app.py / core.py / run.py — common conventions
    for name in ["cli.py", "app.py", "core.py", "run.py", "start.py", "launch.py"]:
        for f in glob.glob(f"{tmp_dir}/**/{name}", recursive=True):
            add(f)

    # 6. Entry points from setup.cfg
    for sc in glob.glob(f"{tmp_dir}/*/setup.cfg") + glob.glob(f"{tmp_dir}/setup.cfg"):
        try:
            with open(sc) as f:
                content = f.read()
            pkg_dir = os.path.dirname(sc)
            for line in content.split('\n'):
                if '=' in line and ':' in line:
                    module = line.split('=')[-1].strip().split(':')[0].strip()
                    module_path = os.path.join(pkg_dir, module.replace('.', '/') + '.py')
                    add(module_path)
        except:
            pass

    # 7. Entry points from pyproject.toml
    for pt in glob.glob(f"{tmp_dir}/*/pyproject.toml") + glob.glob(f"{tmp_dir}/pyproject.toml"):
        try:
            with open(pt) as f:
                content = f.read()
            pkg_dir = os.path.dirname(pt)
            for line in content.split('\n'):
                if '=' in line and ':' in line and 'scripts' in content[:content.find(line)].lower():
                    module = line.split('=')[-1].strip().split(':')[0].strip().strip('"\'')
                    module_path = os.path.join(pkg_dir, module.replace('.', '/') + '.py')
                    add(module_path)
        except:
            pass

    # 8. src layout: src/packagename/__init__.py
    for f in glob.glob(f"{tmp_dir}/*/src/**/__init__.py", recursive=True):
        add(f)

    # 9. Any .py in package root
    for f in glob.glob(f"{tmp_dir}/*/*.py"):
        add(f)

    # 10. Any .py anywhere (limit to avoid too many)
    for f in sorted(glob.glob(f"{tmp_dir}/**/*.py", recursive=True))[:15]:
        add(f)

    return entries


# ── opensnoop parser ──────────────────────────────────────────

def parse_opensnoop(path, pid_filter=None):
    counts = {
        "root_dir_access": 0,
        "etc_dir_access": 0,
        "tmp_dir_access": 0,
        "home_dir_access": 0,
        "ssh_dir_access": 0,
        "other_dir_access": 0,
    }

    # Stores every observed access event without limiting the number.
    evidence = {
        "all_open_events": [],
        "root_access_values": [],
        "etc_access_values": [],
        "tmp_access_values": [],
        "home_access_values": [],
        "ssh_access_values": [],
        "other_access_values": [],
    }

    try:
        with open(path, "r", errors="ignore") as f:
            for line in f:
                raw_line = line.rstrip("\n")
                parts = raw_line.split()

                if len(parts) < 6:
                    continue

                if parts[0] == "TIME(s)":
                    continue

                try:
                    pid = parts[2]

                    # opensnoop output normally places PATH after the first columns.
                    # Joining preserves paths containing spaces.
                    path_val = " ".join(parts[5:])
                except Exception:
                    continue

                if pid_filter and pid != str(pid_filter):
                    continue

                # Check SSH first because /home/user/.ssh/... is also under /home/.
                if "/.ssh/" in path_val or "/root/.ssh/" in path_val:
                    category = "ssh"
                    counts["ssh_dir_access"] += 1
                    evidence["ssh_access_values"].append(path_val)

                elif "/root/" in path_val:
                    category = "root"
                    counts["root_dir_access"] += 1
                    evidence["root_access_values"].append(path_val)

                elif "/etc/" in path_val:
                    category = "etc"
                    counts["etc_dir_access"] += 1
                    evidence["etc_access_values"].append(path_val)

                elif "/tmp/" in path_val:
                    category = "tmp"
                    counts["tmp_dir_access"] += 1
                    evidence["tmp_access_values"].append(path_val)

                elif "/home/" in path_val:
                    category = "home"
                    counts["home_dir_access"] += 1
                    evidence["home_access_values"].append(path_val)

                else:
                    category = "other"
                    counts["other_dir_access"] += 1
                    evidence["other_access_values"].append(path_val)

                evidence["all_open_events"].append({
                    "pid": pid,
                    "category": category,
                    "path": path_val,
                    "raw_event": raw_line
                })

    except Exception as e:
        print(f"[opensnoop] parse error: {e}")

    features = {
        **counts,
        "ebpf_accessed_root": counts["root_dir_access"] > 0,
        "ebpf_accessed_ssh": counts["ssh_dir_access"] > 0,
        "ebpf_accessed_etc": counts["etc_dir_access"] > 5,
    }

    return features, evidence


# ── strace full output parser ─────────────────────────────────

def parse_strace_full(path):
    security_calls = {
        "setuid", "setgid", "chmod", "capset",
        "setreuid", "ptrace", "capget"
    }

    network_calls = {
        "socket", "connect", "accept", "listen",
        "sendto", "recvfrom", "bind", "recvmsg", "sendmsg"
    }

    process_calls = {
        "fork", "vfork", "clone", "clone3",
        "execve", "kill", "exit", "exit_group"
    }

    file_calls = {
        "open", "openat", "read", "write",
        "close", "unlink", "rename", "newfstatat"
    }

    suspicious_ports = {
        4444, 1337, 6667, 31337, 9001, 8080, 2323, 1234
    }

    counts = {
        "ebpf_security_ops": 0,
        "ebpf_network_ops": 0,
        "ebpf_process_ops": 0,
        "ebpf_file_ops": 0,
    }

    remote_ips = set()
    remote_ports = set()
    c2_suspected = False

    evidence = {
        "all_strace_events": [],
        "security_operation_values": [],
        "network_operation_values": [],
        "process_operation_values": [],
        "file_operation_values": [],
        "remote_connection_values": [],
        "c2_suspected_connection_values": [],
    }

    syscall_re = re.compile(r'^\d+\s+(\w+)\(')
    connect_re = re.compile(
        r'connect\(.*sin_port=htons\((\d+)\).*inet_addr\("([^"]+)"\)'
    )
    execve_security_re = re.compile(
        r'execve\(".*?(chmod|chown|chgrp|setuid|ptrace|capset|sudo|su)\b'
    )

    try:
        with open(path, "r", errors="ignore") as f:
            for line in f:
                raw_line = line.rstrip("\n")

                if not raw_line.strip():
                    continue

                # Preserve every raw strace line without a limit.
                evidence["all_strace_events"].append(raw_line)

                m = syscall_re.match(raw_line)
                if m:
                    name = m.group(1).lower()

                    if name in security_calls:
                        counts["ebpf_security_ops"] += 1
                        evidence["security_operation_values"].append(raw_line)

                    if name in network_calls:
                        counts["ebpf_network_ops"] += 1
                        evidence["network_operation_values"].append(raw_line)

                    if name in process_calls:
                        counts["ebpf_process_ops"] += 1
                        evidence["process_operation_values"].append(raw_line)

                    if name in file_calls:
                        counts["ebpf_file_ops"] += 1
                        evidence["file_operation_values"].append(raw_line)

                # Detect security-related commands executed through execve.
                es = execve_security_re.search(raw_line)
                if es:
                    counts["ebpf_security_ops"] += 1
                    evidence["security_operation_values"].append(raw_line)

                # Extract full remote connection evidence.
                cm = connect_re.search(raw_line)
                if cm:
                    port = int(cm.group(1))
                    ip = cm.group(2)

                    connection_event = {
                        "ip": ip,
                        "port": port,
                        "raw_event": raw_line
                    }

                    evidence["remote_connection_values"].append(connection_event)

                    if port > 0:
                        remote_ports.add(port)

                    if ip and not is_private_ip(ip):
                        remote_ips.add(ip)

                    if port in suspicious_ports:
                        c2_suspected = True
                        evidence["c2_suspected_connection_values"].append(
                            connection_event
                        )

    except Exception as e:
        print(f"[strace] parse error: {e}")

    features = {
        **counts,
        "ebpf_privilege_escalation": counts["ebpf_security_ops"] > 0,
        "ebpf_network_activity": counts["ebpf_network_ops"] > 0,
        "ebpf_spawned_process": counts["ebpf_process_ops"] > 2,
        "ebpf_remote_ips_count": len(remote_ips),
        "ebpf_remote_ips": "|".join(sorted(remote_ips)),
        "ebpf_remote_ports": "|".join(str(p) for p in sorted(remote_ports)),
        "ebpf_c2_port_suspected": c2_suspected,
    }

    return features, evidence


def extract_patterns(opensnoop_path, pid_filter=None):
    syscall_sequence = []
    try:
        with open(opensnoop_path) as f:
            for line in f:
                try:
                    obj = json.loads(line.strip())
                    if pid_filter and str(obj.get("PID", obj.get("pid", ""))) != str(pid_filter):
                        continue
                    sc = obj.get("syscall", "")
                    if sc:
                        syscall_sequence.append(sc.lower())
                except Exception:
                    pass
    except Exception:
        pass

    def has_sequence(seq):
        it = iter(syscall_sequence)
        return all(s in it for s in seq)

    enoent_count = sum(1 for s in syscall_sequence if "enoent" in s)
    return {
        "pattern_c2_communication":     has_sequence(["socket", "bind", "listen", "accept", "execve"]),
        "pattern_process_injection":    has_sequence(["mmap", "fork", "ptrace", "execve"]),
        "pattern_malicious_probing":    enoent_count > 50,
        "pattern_privilege_escalation": has_sequence(["ioctl", "setresuid", "setresgid", "execve"]),
        "pattern_file_locking":         has_sequence(["openat", "fstat", "fcntl"]),
    }


# ── Package Analysis ─────────────────────────────────────────

def analyze_package(pkg_name, run_number="0"):
    print(f"\n[analyzer] Starting analysis for: {pkg_name} (run={run_number})")

    pkg_path = os.path.join(REPO_DIR, pkg_name)
    if not os.path.exists(pkg_path):
        print(f"[analyzer] Package not found: {pkg_path}")
        return

    opensnoop_out = "/tmp/ebpf_opensnoop.txt"
    strace_out    = "/tmp/ebpf_strace_full.txt"

    for f in [opensnoop_out, strace_out]:
        if os.path.exists(f):
            os.remove(f)

    print("[analyzer] Starting eBPF monitors...")
    f_open = open(opensnoop_out, "w")
    mon_open = subprocess.Popen(
        ["sudo", "opensnoop-bpfcc", "-T"],
        stdout=f_open,
        stderr=subprocess.DEVNULL
    )
    time.sleep(2)

    print("[analyzer] Running package under strace...")
    sandbox_start = time.time()
    entry_points_run = []

    try:
        if pkg_name.endswith(".tgz") or pkg_name.endswith(".tar.gz"):
            tmp_dir = tempfile.mkdtemp()
            with tarfile.open(pkg_path) as tar:
                tar.extractall(tmp_dir)

            # Detect package type
            has_package_json = bool(glob.glob(f"{tmp_dir}/**/package.json", recursive=True))
            has_py_files     = bool(glob.glob(f"{tmp_dir}/**/*.py", recursive=True))

            if has_package_json and pkg_name.endswith(".tgz"):
                # NPM — run single entry point (already working well)
                entry = find_npm_entries(tmp_dir)
                entry = entry[0] if entry else None
                if entry:
                    print(f"[analyzer] NPM entry point: {os.path.basename(entry)}")
                    entry_points_run.append(entry)
                    try:
                        proc = subprocess.Popen(
                            ["strace", "-f", "-e", "trace=network,process,file",
                             "-o", strace_out, "node", entry],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL
                        )
                        try:
                            proc.wait(timeout=120)
                        except subprocess.TimeoutExpired:
                            proc.kill()
                    except Exception as e:
                        print(f"[analyzer] Error running {entry}: {e}")

            else:
                # PyPI — run ALL entry points and combine strace output
                entries = find_pypi_entries(tmp_dir)
                print(f"[analyzer] Found {len(entries)} PyPI entry point(s)")

                open(strace_out, "w").close()  # create empty file

                for entry in entries:
                    print(f"[analyzer] Running: {os.path.basename(entry)}")
                    entry_points_run.append(entry)
                    try:
                        proc = subprocess.Popen(
                            ["strace", "-f", "-e", "trace=network,process,file",
                             "-o", "/tmp/ebpf_strace_tmp.txt", "python3", entry],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL
                        )
                        try:
                            proc.wait(timeout=60)
                        except subprocess.TimeoutExpired:
                            proc.kill()

                        # Append to combined strace output
                        if os.path.exists("/tmp/ebpf_strace_tmp.txt"):
                            with open("/tmp/ebpf_strace_tmp.txt") as src, \
                                 open(strace_out, "a") as dst:
                                dst.write(src.read())

                    except Exception as e:
                        print(f"[analyzer] Error running {entry}: {e}")

    except Exception as e:
        print(f"[analyzer] Error extracting package: {e}")

    sandbox_end = time.time()
    print(f"[analyzer] Done. Duration: {int(sandbox_end - sandbox_start)}s")

    subprocess.run(["sudo", "kill", str(mon_open.pid)], capture_output=True)
    f_open.flush()
    f_open.close()
    time.sleep(2)

    print("[analyzer] Parsing results...")

    opensnoop_features, opensnoop_evidence = parse_opensnoop(opensnoop_out, None)
    strace_features, strace_evidence = parse_strace_full(strace_out)
    pattern_features = extract_patterns(opensnoop_out, None)

    all_features = {
        **opensnoop_features,
        **strace_features,
        **pattern_features,
    }

    raw_evidence = {
        "opensnoop_file_access_evidence": opensnoop_evidence,
        "strace_runtime_evidence": strace_evidence,
    }

    print(f"[analyzer] Features: {all_features}")

    pkg_stem = pkg_name.replace(".tgz", "").replace(".tar.gz", "")
    log_dir  = os.path.join(REPO_DIR, DECOY_DIR)
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, f"{pkg_stem}_run{run_number}_ebpf.json")

    with open(log_path, "w") as f:
        json.dump({
            "package": pkg_name,
            "analysis_type": "aws_ebpf",
            "run_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "sandbox_start": sandbox_start,
            "sandbox_end": sandbox_end,
            "entry_points_run": entry_points_run,

            # Summary numeric/boolean features.
            # These remain suitable for the ML pipeline and dashboard display.
            "ebpf_features": all_features,

            # Existing feature format preserved for the current pipeline.
            "dynamic_features": {k: str(v) for k, v in all_features.items()},

            # Full raw evidence retained only in the log.
            # No maximum number of captured values is applied here.
            "raw_evidence": raw_evidence,

        }, f, indent=2, ensure_ascii=False)

    print(f"[analyzer] Results saved at {log_path}")
    print(f"[analyzer] Done  {pkg_name}")


# ── Main Watch Loop ──────────────────────────────────────────

def main():
    print("[watcher] AWS EC2 Analyzer started")
    os.chdir(REPO_DIR)

    while True:
        print(f"[watcher] Waiting... {time.strftime('%H:%M:%S')}")
        pending = os.path.join(REPO_DIR, WATCH_FILE)
        if os.path.exists(pending):
            with open(pending) as f:
                content = f.read().strip()
            if ":" in content:
                pkg_name, run_number = content.split(":", 1)
            else:
                pkg_name, run_number = content, "0"
            if pkg_name:
                print(f"[watcher] New package detected: {pkg_name} (run={run_number})")
                os.remove(pending)
                analyze_package(pkg_name, run_number)
        time.sleep(5)


if __name__ == "__main__":
    main()
