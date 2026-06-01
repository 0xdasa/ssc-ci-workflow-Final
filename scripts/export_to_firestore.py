import json
import os
import re
import math
from pathlib import Path
from datetime import datetime, timezone, timedelta

import firebase_admin
from firebase_admin import credentials, firestore


def read_json(path, default=None):
    """
    Safely reads and parses a JSON file from the given path.
    Returns the parsed content as a dict or list.
    If the file does not exist or cannot be parsed, returns the
    provided default value (empty dict if no default is given).
    Used throughout this script to load ML logs, runtime logs,
    and eBPF logs without crashing on missing or corrupt files.
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default if default is not None else {}


def safe_id(value):
    """
    Converts any string value into a Firestore-safe document ID.
    Firestore document IDs cannot contain '/', '\\', or most special
    characters. This function replaces those characters with underscores
    and truncates the result to 140 characters to stay within Firestore
    limits. Used to construct run_id values from package filenames and
    GitHub run numbers.
    """
    value = str(value or "unknown")
    value = value.replace("/", "_").replace("\\", "_")
    value = re.sub(r"[^A-Za-z0-9_.-]", "_", value)
    return value[:140]


def strip_archive_ext(name):
    """
    Removes common archive file extensions from a package filename.
    Supports .tar.gz, .tgz, .whl, .zip, and .tar extensions.
    Returns just the package stem (e.g., 'requests-2.28.0' from
    'requests-2.28.0.tar.gz'). Used to match log filenames against
    the original package filename when searching for analysis results.
    """
    name = os.path.basename(str(name))
    for ext in [".tar.gz", ".tgz", ".whl", ".zip", ".tar"]:
        if name.endswith(ext):
            return name[:-len(ext)]
    return os.path.splitext(name)[0]


def find_latest_ml_log(package_file):
    """
    Searches decoy_logs/ml_logs/ for the most recent ML analysis log
    that corresponds to the given package file.

    Matching strategy:
      1. First tries to find logs where the package name matches exactly
         or the package stem appears in the log filename or log content.
      2. If no match is found, falls back to the most recently modified
         log file in the directory.

    Returns a tuple of (log_dict, log_path_string).
    Returns ({}, '') if no log is found.
    """
    pkg_stem = strip_archive_ext(package_file)
    ml_dir = Path("decoy_logs/ml_logs")
    candidates = []

    if ml_dir.exists():
        for p in ml_dir.glob("*.json"):
            data = read_json(p, {})
            data_pkg = os.path.basename(str(data.get("package", "")))
            if data_pkg == package_file or pkg_stem in p.name or pkg_stem in data_pkg:
                candidates.append((p.stat().st_mtime, p, data))

        # Fallback: return the most recently modified log if no match found
        if not candidates:
            for p in ml_dir.glob("*.json"):
                data = read_json(p, {})
                candidates.append((p.stat().st_mtime, p, data))

    if not candidates:
        return {}, ""

    candidates.sort(key=lambda x: x[0], reverse=True)
    return candidates[0][2], str(candidates[0][1])


def find_runtime_log(package_file, run_number):
    """
    Searches decoy_logs/decoy_runs/ for the Docker sandbox runtime log
    associated with the given package and GitHub Actions run number.

    The sandbox runner saves logs with the naming convention:
      <package_stem>_run<run_number>_sandbox.json

    Matching strategy:
      1. Tries the expected filename using both the safe_id and raw stem.
      2. Falls back to any sandbox log containing the package stem.
      3. As a last resort, reads decoy_logs/latest.json which always
         contains the most recently written sandbox result.

    Returns a tuple of (log_dict, log_path_string).
    """
    pkg_stem = strip_archive_ext(package_file)
    safe_stem = safe_id(pkg_stem)

    decoy_dir = Path("decoy_logs/decoy_runs")
    possible = [
        decoy_dir / f"{safe_stem}_run{run_number}_sandbox.json",
        decoy_dir / f"{pkg_stem}_run{run_number}_sandbox.json",
    ]

    for p in possible:
        data = read_json(p, {})
        if data:
            return data, str(p)

    candidates = []
    if decoy_dir.exists():
        for p in decoy_dir.glob("*_sandbox.json"):
            if safe_stem in p.name or pkg_stem in p.name:
                data = read_json(p, {})
                candidates.append((p.stat().st_mtime, p, data))

    if not candidates:
        latest = Path("decoy_logs/latest.json")
        data = read_json(latest, {})
        if data:
            return data, str(latest)
        return {}, ""

    candidates.sort(key=lambda x: x[0], reverse=True)
    return candidates[0][2], str(candidates[0][1])


def find_ebpf_log(package_file, run_number):
    """
    Searches decoy_logs/decoy_runs/ for the AWS EC2 eBPF analysis log
    associated with the given package and GitHub Actions run number.

    The eBPF analyzer saves logs with the naming convention:
      <package_stem>_run<run_number>_ebpf.json

    Matching strategy:
      1. Tries the expected filename using both the safe_id and raw stem.
      2. Falls back to any eBPF log containing the package stem.

    Returns a tuple of (log_dict, log_path_string).
    Returns ({}, '') if no eBPF log is found.
    """
    pkg_stem = strip_archive_ext(package_file)
    safe_stem = safe_id(pkg_stem)

    decoy_dir = Path("decoy_logs/decoy_runs")
    possible = [
        decoy_dir / f"{safe_stem}_run{run_number}_ebpf.json",
        decoy_dir / f"{pkg_stem}_run{run_number}_ebpf.json",
    ]

    for p in possible:
        data = read_json(p, {})
        if data:
            return data, str(p)

    candidates = []
    if decoy_dir.exists():
        for p in decoy_dir.glob("*_ebpf.json"):
            if safe_stem in p.name or pkg_stem in p.name:
                data = read_json(p, {})
                candidates.append((p.stat().st_mtime, p, data))

    if not candidates:
        return {}, ""

    candidates.sort(key=lambda x: x[0], reverse=True)
    return candidates[0][2], str(candidates[0][1])


def summarize_network(runtime_log, ebpf_log):
    """
    Builds a network activity summary from both the Docker sandbox
    runtime log and the AWS EC2 eBPF log.

    Extracts:
      - Count of external IPs contacted during execution
      - Count of unique external domains contacted
      - Count of DNS queries made
      - Count of outbound HTTP requests
      - Lists of unique countries, ISPs, and organizations from
        IP geolocation data collected via ip-api.com
      - eBPF-derived network activity flag and remote IP count

    The result is stored in the public Firestore document for
    dashboard visualization.
    """
    net = runtime_log.get("network_analysis", {}) or {}
    external_ips = net.get("external_ips", []) or []

    countries = []
    isps = []
    orgs = []

    for item in external_ips:
        if isinstance(item, dict):
            if item.get("country"):
                countries.append(item.get("country"))
            if item.get("isp"):
                isps.append(item.get("isp"))
            if item.get("org"):
                orgs.append(item.get("org"))

    ebpf_features = ebpf_log.get("ebpf_features", {}) or {}

    return {
        "external_ips_count": len(external_ips),
        "domains_count": len(net.get("real_domains", []) or []),
        "dns_queries_count": len(runtime_log.get("dns_queries", []) or runtime_log.get("dns", []) or []),
        "http_requests_count": len(runtime_log.get("http_requests", []) or []),
        "countries": sorted(set(countries)),
        "isps": sorted(set(isps)),
        "orgs": sorted(set(orgs)),
        "ebpf_network_activity": bool(ebpf_features.get("ebpf_network_activity", False)),
        "ebpf_remote_ips_count": ebpf_features.get("ebpf_remote_ips_count", 0),
    }


def ml_final_result(ml_log):
    """
    Determines the final classification verdict from the ML log.

    The XGBoost model outputs a binary prediction stored in the
    'prediction' field of the ML log:
      - prediction == 1  → MALICIOUS
      - prediction == 0  → BENIGN

    Also handles the legacy string format where prediction may be
    stored as the string "MALICIOUS" from earlier pipeline versions.

    Returns the string "MALICIOUS" or "BENIGN".
    """
    prediction = ml_log.get("prediction")

    if str(prediction).upper() == "MALICIOUS" or prediction == 1:
        return "MALICIOUS"

    return "BENIGN"


def risk_level(final_result, probability):
    """
    Maps the ML classification result and malicious probability score
    to a human-readable risk level for dashboard display.

    Rules:
      - BENIGN packages → LOW risk regardless of probability
      - MALICIOUS with probability >= 0.85 → CRITICAL
      - MALICIOUS with probability >= 0.65 → HIGH
      - MALICIOUS with probability < 0.65  → MEDIUM

    The probability thresholds were chosen to reflect the confidence
    of the XGBoost model's output score from predict_proba().
    """
    if final_result == "BENIGN":
        return "LOW"

    if probability >= 0.85:
        return "CRITICAL"

    if probability >= 0.65:
        return "HIGH"

    return "MEDIUM"


def trim_list(items, limit=50):
    """
    Truncates a list to the given limit to prevent Firestore documents
    from exceeding the 1 MB document size limit. Applied to runtime
    lists such as accessed files, processes, timeline events, and HTTP
    requests before they are written to restricted log collections.
    """
    if not isinstance(items, list):
        return []
    return items[:limit]


def sanitize_for_firestore(value, depth=0):
    """
    Recursively converts a Python value into a Firestore-safe structure.

    Firestore rejects certain Python types and structures:
      - NaN and Infinity floats are replaced with None
      - Nested arrays (arrays inside arrays) are not supported;
        inner arrays are wrapped in a dict with an 'items' key
      - Dict keys with '.', '/', or '\\' are sanitized to '_'
      - Depth is tracked to prevent infinite recursion on circular
        structures; values deeper than 20 levels are stringified

    This function is applied to every document before it is written
    to Firestore to prevent write failures caused by unsupported types.
    """
    if depth > 20:
        return str(value)

    if value is None:
        return None

    if isinstance(value, (str, bool, int)):
        return value

    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            return None
        return value

    if isinstance(value, datetime):
        return value

    if isinstance(value, dict):
        clean = {}
        for k, v in value.items():
            key = str(k).strip()
            if not key:
                key = "unknown_key"
            key = key.replace(".", "_").replace("/", "_").replace("\\", "_")
            clean[key] = sanitize_for_firestore(v, depth + 1)
        return clean

    if isinstance(value, (list, tuple, set)):
        clean_list = []
        for item in list(value)[:300]:
            # Firestore does not support arrays directly nested inside arrays.
            # Wrap inner arrays in a dict to maintain the data structure.
            if isinstance(item, (list, tuple, set)):
                clean_list.append({
                    "items": sanitize_for_firestore(list(item), depth + 1)
                })
            else:
                clean_list.append(sanitize_for_firestore(item, depth + 1))
        return clean_list

    return str(value)


def safe_list(value, limit=20):
    """
    Converts a value to a clean, deduplicated list of non-empty strings.

    Handles the following input types:
      - None or empty → returns []
      - A list → deduplicates, strips whitespace, removes None/empty items
      - Any other type → wraps the stringified value in a single-item list

    The limit parameter caps the output length to prevent Firestore
    documents from growing too large with noisy runtime data.
    """
    if not value:
        return []
    if isinstance(value, list):
        out = []
        for item in value:
            if item is None:
                continue
            s = str(item).strip()
            if s and s not in out:
                out.append(s)
        return out[:limit]
    s = str(value).strip()
    return [s] if s else []


def compact_dict(d):
    """
    Removes noise from a dict before writing to the public Firestore
    dashboard collection.

    Removes entries where the value is:
      - None
      - False (boolean)
      - 0 or 0.0 (numeric)
      - Empty string, or strings equal to 'none', 'null', 'false', etc.
      - Empty list or empty nested dict

    This keeps the public dashboard document small and meaningful,
    showing only features and indicators that actually fired during
    analysis. Nested dicts are recursively compacted.
    """
    if not isinstance(d, dict):
        return {}

    cleaned = {}
    for k, v in d.items():
        if v is None:
            continue

        if isinstance(v, bool):
            if v is True:
                cleaned[k] = v
            continue

        if isinstance(v, (int, float)):
            if v != 0:
                cleaned[k] = v
            continue

        if isinstance(v, str):
            s = v.strip()
            if s and s.lower() not in {"none", "null", "undefined", "false", "0", "—"}:
                cleaned[k] = s
            continue

        if isinstance(v, list):
            arr = safe_list(v)
            if arr:
                cleaned[k] = arr
            continue

        if isinstance(v, dict):
            nested = compact_dict(v)
            if nested:
                cleaned[k] = nested

    return cleaned


def extract_top_shap(raw_ml_doc, limit=10):
    """
    Extracts the top SHAP feature contributions from the ML log.

    SHAP (SHapley Additive exPlanations) values explain which features
    most influenced the model's malicious probability score for each
    package. The top features are shown on the dashboard to help the
    administrator understand why a package was classified as it was.

    The function handles multiple possible formats in which SHAP values
    may be stored across different pipeline versions:
      - List of (feature_name, shap_value) tuples
      - List of dicts with 'feature'/'name' and 'value'/'shap_value' keys
      - Plain dict mapping feature names to values
      - Nested under keys: top_shap, top_features, shap_values,
        shap_explanations, explanations, feature_importance,
        ml_explanation.top_features, ml_explanation.top_shap

    Returns a list of dicts sorted by absolute SHAP value descending,
    each with 'feature' (str) and 'value' (float) keys.
    Returns [] if no SHAP data is found.
    """
    raw_ml_doc = raw_ml_doc or {}

    if isinstance(raw_ml_doc, dict) and isinstance(raw_ml_doc.get("data"), dict):
        raw_ml_doc = raw_ml_doc.get("data") or {}

    candidates = [
        raw_ml_doc.get("top_shap"),
        raw_ml_doc.get("top_features"),
        raw_ml_doc.get("shap_values"),
        raw_ml_doc.get("shap_explanations"),
        raw_ml_doc.get("explanations"),
        raw_ml_doc.get("feature_importance"),
        raw_ml_doc.get("ml_explanation", {}).get("top_features") if isinstance(raw_ml_doc.get("ml_explanation"), dict) else None,
        raw_ml_doc.get("ml_explanation", {}).get("top_shap") if isinstance(raw_ml_doc.get("ml_explanation"), dict) else None,
    ]

    def to_number(value):
        # Safely converts a value to float; returns None if conversion fails.
        try:
            if value is None:
                return None
            return float(value)
        except Exception:
            return None

    def add_item(out, name, value):
        # Appends a validated (feature_name, shap_value) pair to the output
        # list. Silently skips entries where the name or value is missing.
        value = to_number(value)
        if name is None or value is None:
            return

        out.append({
            "feature": str(name),
            "value": value
        })

    for item in candidates:
        if not item:
            continue

        out = []

        if isinstance(item, list):
            for x in item:
                if isinstance(x, dict):
                    # Handle Firestore-wrapped nested arrays: {"items": [name, value]}
                    if "items" in x and isinstance(x.get("items"), list) and len(x.get("items")) >= 2:
                        add_item(out, x["items"][0], x["items"][1])
                        continue

                    # Handle dicts with named keys for feature and value
                    name = (
                        x.get("feature")
                        or x.get("name")
                        or x.get("key")
                        or x.get("feature_name")
                    )

                    value = (
                        x.get("value")
                        if x.get("value") is not None
                        else x.get("shap_value")
                        if x.get("shap_value") is not None
                        else x.get("impact")
                        if x.get("impact") is not None
                        else x.get("score")
                    )

                    add_item(out, name, value)

                elif isinstance(x, (list, tuple)) and len(x) >= 2:
                    # Handle plain (feature_name, shap_value) tuples or lists
                    add_item(out, x[0], x[1])

            if out:
                out.sort(key=lambda x: abs(x["value"]), reverse=True)
                return out[:limit]

        if isinstance(item, dict):
            # Handle plain dict mapping feature names directly to SHAP values
            for k, v in item.items():
                add_item(out, k, v)

            if out:
                out.sort(key=lambda x: abs(x["value"]), reverse=True)
                return out[:limit]

    return []


def extract_paths_matching(events, keywords, limit=20):
    """
    Scans a list of runtime timeline events for file paths that match
    any of the given keywords.

    Used to extract specific sensitive path categories from the sandbox
    behavioral timeline for the public dashboard, such as:
      - SSH credential paths (.ssh, authorized_keys, id_rsa)
      - Secret/environment file paths (.env, credentials, secrets)
      - System-sensitive paths (/etc/passwd, /etc/shadow)
      - Temporary directory accesses (/tmp)

    Extracts absolute paths using a regex pattern and returns only
    those paths whose text contains at least one keyword.
    Returns a deduplicated list capped at the given limit.
    """
    found = []
    keywords = [k.lower() for k in keywords]

    for item in events or []:
        text = item.get("event") if isinstance(item, dict) else str(item)
        text = str(text)

        if not any(k in text.lower() for k in keywords):
            continue

        matches = re.findall(r'(/[A-Za-z0-9._@%+=:,/~\-]+)', text)
        for m in matches:
            if any(k in m.lower() for k in keywords):
                if m not in found:
                    found.append(m)

    return found[:limit]


def extract_remote_ports(events, limit=30):
    """
    Extracts remote port numbers from sandbox runtime timeline events.

    Two extraction strategies are used:
      1. htons(<port>) pattern: matches socket connect() calls traced
         by strace where the port is encoded with htons().
      2. Known suspicious port numbers: directly matches a hardcoded
         set of well-known ports (21, 22, 23, 25, 53, 80, 443, 4444,
         5555, 6667, 8080, 9001) if they appear in the event text.

    Returns a deduplicated list of port strings capped at the limit.
    """
    found = []

    for item in events or []:
        text = item.get("event") if isinstance(item, dict) else str(item)
        text = str(text)

        for p in re.findall(r'htons\((\d+)\)', text):
            if p not in found:
                found.append(p)

        for p in re.findall(r'\b(21|22|23|25|53|80|443|4444|5555|6667|8080|9001)\b', text):
            if p not in found:
                found.append(p)

    return found[:limit]


def extract_ips_from_anything(obj, limit=30):
    """
    Extracts all IPv4 addresses from any object by converting it to
    a string and applying a regex pattern.

    Filters out loopback (127.x.x.x) and unspecified (0.0.0.0)
    addresses since these are not meaningful external indicators.
    Returns a deduplicated list of public IP address strings.

    Used as a fallback to capture IPs embedded anywhere in the
    runtime log structure when structured extraction misses them.
    """
    text = str(obj)
    ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)

    cleaned = []
    for ip in ips:
        if ip.startswith("127.") or ip == "0.0.0.0":
            continue
        if ip not in cleaned:
            cleaned.append(ip)

    return cleaned[:limit]


def extract_public_runtime_values(raw_runtime_doc):
    """
    Extracts a curated set of public-safe runtime observations from
    the Docker sandbox log for display on the dashboard.

    The full sandbox log stored in raw_runtime_logs contains detailed
    strace output, full memory strings, and complete behavioral timelines
    that should not be exposed publicly. This function extracts only the
    meaningful behavioral indicators:

      - accessed_files: file paths opened by the package
      - processes: child processes spawned during execution
      - ssh_paths_accessed: any SSH credential file paths accessed
      - secret_paths_accessed: .env, credentials, or secrets paths accessed
      - system_sensitive_paths_accessed: /etc/passwd or /etc/shadow accessed
      - tmp_paths_accessed: temporary directory accesses
      - remote_ips: external IP addresses contacted
      - remote_ports: outbound port numbers observed
      - dns_queries: domain names queried during execution
      - http_requests: outbound HTTP requests with method, path, and host

    The result is passed through compact_dict() to remove empty or
    zero-value entries before being written to dashboard_public.
    """
    raw_runtime_doc = raw_runtime_doc or {}

    timeline = raw_runtime_doc.get("timeline") or []
    accessed_files = safe_list(raw_runtime_doc.get("accessed_files"), 30)
    processes = safe_list(raw_runtime_doc.get("processes"), 20)
    http_requests = raw_runtime_doc.get("http_requests") or []
    dns = raw_runtime_doc.get("dns") or []
    network = raw_runtime_doc.get("network_analysis") or {}

    ssh_paths = extract_paths_matching(timeline, [".ssh", "authorized_keys", "id_rsa"])
    env_paths = extract_paths_matching(timeline, [".env", "credentials", "secrets"])
    passwd_paths = extract_paths_matching(timeline, ["/etc/passwd", "/etc/shadow"])
    tmp_paths = extract_paths_matching(timeline, ["/tmp"], limit=10)

    remote_ips = []
    if isinstance(network, dict):
        for item in network.get("external_ips", []) or []:
            if isinstance(item, dict) and item.get("ip"):
                remote_ips.append(str(item.get("ip")))
            elif item:
                remote_ips.append(str(item))

    remote_ips += extract_ips_from_anything(raw_runtime_doc)
    remote_ips = safe_list(remote_ips, 20)

    remote_ports = extract_remote_ports(timeline)

    public_runtime_values = {
        "accessed_files": accessed_files[:20],
        "processes": processes[:20],
        "ssh_paths_accessed": ssh_paths,
        "secret_paths_accessed": env_paths,
        "system_sensitive_paths_accessed": passwd_paths,
        "tmp_paths_accessed": tmp_paths,
        "remote_ips": remote_ips,
        "remote_ports": remote_ports,
        "dns_queries": safe_list(dns, 20),
        "http_requests": [
            {
                "method": r.get("method", "GET"),
                "path": r.get("path", ""),
                "host": r.get("host", ""),
            }
            for r in http_requests[:15]
            if isinstance(r, dict)
        ],
    }

    return compact_dict(public_runtime_values)


def extract_public_ebpf_values(raw_ebpf_doc):
    """
    Extracts a curated set of public-safe eBPF indicators from the
    AWS EC2 kernel-level analysis log for display on the dashboard.

    The full eBPF log stored in raw_ebpf_logs contains raw syscall
    counts, opensnoop output, and complete strace output that should
    not be exposed publicly. This function extracts only the high-level
    behavioral indicators:

      - cloud_remote_ips: remote IPs observed at kernel level
      - cloud_remote_ports: remote ports connected to
      - cloud_security_ops: count of security-related syscalls
        (setuid, chmod, ptrace, etc.)
      - cloud_network_ops: count of network syscalls
      - cloud_process_ops: count of process management syscalls
      - cloud_file_ops: count of file operation syscalls
      - root/home/etc/tmp/other directory access counts from opensnoop

    The result is passed through compact_dict() to remove zero-value
    entries before being written to dashboard_public.
    """
    raw_ebpf_doc = raw_ebpf_doc or {}

    features = (
        raw_ebpf_doc.get("dynamic_features")
        or raw_ebpf_doc.get("ebpf_features")
        or raw_ebpf_doc
        or {}
    )

    public_ebpf_values = {}

    if isinstance(features, dict):
        remote_ips = features.get("ebpf_remote_ips") or features.get("remote_ips")
        remote_ports = features.get("ebpf_remote_ports") or features.get("remote_ports")

        public_ebpf_values.update({
            "cloud_remote_ips": safe_list(remote_ips, 20),
            "cloud_remote_ports": safe_list(remote_ports, 20),
            "cloud_security_ops": features.get("ebpf_security_ops"),
            "cloud_network_ops": features.get("ebpf_network_ops"),
            "cloud_process_ops": features.get("ebpf_process_ops"),
            "cloud_file_ops": features.get("ebpf_file_ops"),
            "root_dir_access_count": features.get("root_dir_access"),
            "home_dir_access_count": features.get("home_dir_access"),
            "etc_dir_access_count": features.get("etc_dir_access"),
            "tmp_dir_access_count": features.get("tmp_dir_access"),
            "other_dir_access_count": features.get("other_dir_access"),
        })

    return compact_dict(public_ebpf_values)


# ============================================================


def init_firestore():
    """
    Initializes the Firebase Admin SDK and returns a Firestore client.

    The Firebase service account credentials are read from the
    FIREBASE_SERVICE_ACCOUNT_JSON environment variable, which is set
    as a GitHub Actions secret in the CI/CD pipeline. This ensures
    credentials are never hardcoded in the repository.

    If the Firebase app has already been initialized in a previous call
    (e.g., during testing), the existing app is reused to avoid the
    'app already exists' error from firebase_admin.

    Raises RuntimeError if the environment variable is missing.
    """
    service_json = os.environ.get("FIREBASE_SERVICE_ACCOUNT_JSON", "").strip()

    if not service_json:
        raise RuntimeError("FIREBASE_SERVICE_ACCOUNT_JSON secret is missing.")

    service_account = json.loads(service_json)

    if not firebase_admin._apps:
        cred = credentials.Certificate(service_account)
        firebase_admin.initialize_app(cred)

    return firestore.client()


def main():
    """
    Main entry point for the Firestore export script.

    This function is called at the end of each CI/CD pipeline run to
    export all analysis results to Firebase Firestore. It performs the
    following steps:

    1. Reads pipeline context from environment variables set by GitHub
       Actions (PACKAGE_FILE, GITHUB_RUN_ID, GITHUB_RUN_NUMBER, etc.)

    2. Locates the most recent ML log, sandbox runtime log, and eBPF
       log for the analyzed package from decoy_logs/.

    3. Constructs seven Firestore documents:
         - analysis_runs/<run_id>: summary metadata for this run
         - raw_logs/<run_id>: restricted metadata with log source paths
         - raw_ml_logs/<run_id>: full ML classification output
         - raw_runtime_logs/<run_id>: trimmed Docker sandbox runtime data
         - raw_ebpf_logs/<run_id>: full eBPF analysis output
         - dashboard_public_runs/<run_id>: public sanitized run record
         - dashboard_public/latest: always-updated latest result for dashboard

    4. Applies sanitize_for_firestore() to every document to ensure
       Firestore compatibility.

    5. Writes all seven documents atomically using a Firestore batch write.

    Retention policy:
       All documents include an expires_at field set to 365 days from
       the current timestamp, aligned with the Saudi NCA Essential
       Cybersecurity Controls (ECC-2:2024) requirement for retaining
       cybersecurity event logs for at least 12 months [33].
    """
    package_file = os.environ.get("PACKAGE_FILE", "").strip()
    github_run_id = os.environ.get("GITHUB_RUN_ID", "").strip()
    github_run_number = os.environ.get("GITHUB_RUN_NUMBER", "").strip()
    github_sha = os.environ.get("GITHUB_SHA", "").strip()
    github_ref = os.environ.get("GITHUB_REF_NAME", "").strip()

    if not package_file:
        raise RuntimeError("PACKAGE_FILE is missing.")

    db = init_firestore()

    now = datetime.now(timezone.utc)

    # ECC 2:2024 control 2.12.3.5 requires cybersecurity event logs
    # to be retained for at least 12 months.
    CYBERSECURITY_EVENT_LOG_RETENTION_DAYS = 365
    SUMMARY_RETENTION_DAYS = 365

    raw_expires = now + timedelta(days=CYBERSECURITY_EVENT_LOG_RETENTION_DAYS)
    summary_expires = now + timedelta(days=SUMMARY_RETENTION_DAYS)

    run_id = f"{safe_id(package_file)}_{github_run_number or safe_id(github_run_id) or int(now.timestamp())}"

    ml_log, ml_source = find_latest_ml_log(package_file)
    runtime_log, runtime_source = find_runtime_log(package_file, github_run_number)
    ebpf_log, ebpf_source = find_ebpf_log(package_file, github_run_number)

    top_shap_values = extract_top_shap(ml_log)

    final_result = ml_final_result(ml_log)
    probability = float(ml_log.get("risk_probability", 0) or 0)

    processes = runtime_log.get("processes", []) or []
    accessed_files = runtime_log.get("accessed_files", []) or []
    dynamic_features = runtime_log.get("dynamic_features", {}) or {}
    ebpf_features = ebpf_log.get("ebpf_features", {}) or {}

    # Extract public-safe values from restricted logs for dashboard display.
    # These contain only high-level behavioral indicators, not raw evidence.
    public_runtime_values = extract_public_runtime_values(runtime_log)
    public_ebpf_values = extract_public_ebpf_values(ebpf_log)

    # Count events per MITRE ATT&CK-inspired behavioral phase for dashboard display.
    behavioral_phases = runtime_log.get("behavioral_phases", {}) or {}
    behavior_phase_counts = {
        phase: len(events)
        for phase, events in behavioral_phases.items()
        if isinstance(events, list) and len(events) > 0
    }

    # ── Public document written to dashboard_public and dashboard_public_runs ──
    # Contains sanitized, visualization-ready data only.
    # Excludes raw logs, internal secrets, and detailed execution evidence.
    public_doc = {
        "run_id": run_id,
        "package": package_file,
        "package_stem": strip_archive_ext(package_file),
        "final_result": final_result,
        "is_malicious": final_result == "MALICIOUS",
        "risk_level": risk_level(final_result, probability),
        "risk_probability": probability,
        "ml_prediction": ml_log.get("prediction"),
        "processes_count": len(processes),
        "accessed_files_count": len(accessed_files),
        "network_summary": summarize_network(runtime_log, ebpf_log),
        "dynamic_features": compact_dict(dynamic_features),
        "ebpf_features": compact_dict(ebpf_features),
        "public_runtime_values": public_runtime_values,
        "public_ebpf_values": public_ebpf_values,
        "behavior_phase_counts": behavior_phase_counts,
        "sources": {
            "ml_log": ml_source,
            "runtime_log": runtime_source,
            "ebpf_log": ebpf_source,
        },
        "updated_at": now,
        "expires_at": summary_expires,
        "top_shap": top_shap_values,
    }

    # ── analysis_runs: summary metadata per run ──
    # Stores the package identifier, final verdict, probability, and
    # GitHub workflow context. Used for run history and audit purposes.
    analysis_doc = {
        "run_id": run_id,
        "package": package_file,
        "final_result": final_result,
        "risk_probability": probability,
        "github_run_id": github_run_id,
        "github_run_number": github_run_number,
        "github_sha": github_sha,
        "github_ref": github_ref,
        "created_at": now,
        "expires_at": summary_expires,
    }

    # ── raw_logs: restricted metadata document ──
    # Stores only source file paths and run context.
    # Does not contain raw analysis output.
    raw_meta_doc = {
        "run_id": run_id,
        "package": package_file,
        "github_run_id": github_run_id,
        "github_run_number": github_run_number,
        "github_sha": github_sha,
        "github_ref": github_ref,
        "final_result": final_result,
        "sources": {
            "ml_log": ml_source,
            "runtime_log": runtime_source,
            "ebpf_log": ebpf_source,
        },
        "created_at": now,
        "expires_at": raw_expires,
    }

    # ── raw_ml_logs: full ML classification output ──
    # Contains prediction, probability, SHAP values, and all features.
    # Restricted — not accessible from the public dashboard client.
    raw_ml_doc = {
        "run_id": run_id,
        "package": package_file,
        "source": ml_source,
        "data": ml_log,
        "created_at": now,
        "expires_at": raw_expires,
    }

    # ── raw_runtime_logs: trimmed Docker sandbox behavioral output ──
    # Contains processes, accessed files, network observations,
    # HTTP requests, DNS queries, dynamic features, and behavioral
    # timeline events. Lists are trimmed to avoid Firestore size limits.
    # Restricted — not accessible from the public dashboard client.
    raw_runtime_doc = {
        "run_id": run_id,
        "package": package_file,
        "source": runtime_source,
        "data": {
            "processes": trim_list(processes, 100),
            "accessed_files": trim_list(accessed_files, 100),
            "network_analysis": runtime_log.get("network_analysis", {}),
            "dns": trim_list(runtime_log.get("dns", []) or runtime_log.get("dns_queries", []), 100),
            "http_requests": trim_list(runtime_log.get("http_requests", []), 100),
            "dynamic_features": dynamic_features,
            "timeline": trim_list(runtime_log.get("timeline", []), 200),
        },
        "created_at": now,
        "expires_at": raw_expires,
    }

    # ── raw_ebpf_logs: full AWS EC2 eBPF analysis output ──
    # Contains kernel-level syscall counts, opensnoop directory access
    # counts, C2 port detection results, and behavioral pattern features.
    # Restricted — not accessible from the public dashboard client.
    raw_ebpf_doc = {
        "run_id": run_id,
        "package": package_file,
        "source": ebpf_source,
        "data": ebpf_log,
        "created_at": now,
        "expires_at": raw_expires,
    }

    # Sanitize all documents for Firestore compatibility before writing.
    # This converts NaN floats, nested arrays, and invalid key characters.
    analysis_doc = sanitize_for_firestore(analysis_doc)
    raw_meta_doc = sanitize_for_firestore(raw_meta_doc)
    raw_ml_doc = sanitize_for_firestore(raw_ml_doc)
    raw_runtime_doc = sanitize_for_firestore(raw_runtime_doc)
    raw_ebpf_doc = sanitize_for_firestore(raw_ebpf_doc)
    public_doc = sanitize_for_firestore(public_doc)

    # Write all seven documents atomically using a Firestore batch.
    # A batch write ensures either all documents are written or none are,
    # preventing partial exports on network failure or quota errors.
    batch = db.batch()

    batch.set(db.collection("analysis_runs").document(run_id), analysis_doc)

    batch.set(db.collection("raw_logs").document(run_id), raw_meta_doc)
    batch.set(db.collection("raw_ml_logs").document(run_id), raw_ml_doc)
    batch.set(db.collection("raw_runtime_logs").document(run_id), raw_runtime_doc)
    batch.set(db.collection("raw_ebpf_logs").document(run_id), raw_ebpf_doc)

    batch.set(db.collection("dashboard_public_runs").document(run_id), public_doc)
    batch.set(db.collection("dashboard_public").document("latest"), public_doc)

    batch.commit()

    print("Firestore export completed")
    print("run_id:", run_id)
    print("package:", package_file)
    print("final_result:", final_result)
    print("dashboard_public/latest updated")
    print("dashboard_public_runs/" + run_id + " created")
    print("restricted raw logs saved")
    print(f"top_shap extracted: {len(top_shap_values)} features")


if __name__ == "__main__":
    main()
