"""
Domain Enricher
---------------
Runs after both lightweight (benign) and decoy (malicious) analysis.
Reads the latest log, enriches all contacted external domains with:
  - VirusTotal malicious flag
Updates the log with domain enrichment features.
"""

import sys
import os
import json
import re
import time
import glob
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime, timezone

# ============================================================
# CONFIG — API Keys
# ============================================================
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")


# ============================================================
# VirusTotal — Malicious Flag
# ============================================================

def get_virustotal_malicious(domain: str) -> bool:
    """
    Returns True if VirusTotal flags the domain as malicious
    (3+ engines detect it).
    Returns False if no API key or lookup fails.
    """
    if not VIRUSTOTAL_API_KEY:
        return False
    try:
        url = f"https://www.virustotal.com/api/v3/domains/{urllib.parse.quote(domain)}"
        req = urllib.request.Request(url)
        req.add_header("x-apikey", VIRUSTOTAL_API_KEY)
        raw  = urllib.request.urlopen(req, timeout=8).read()
        data = json.loads(raw)
        stats     = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0))
        return malicious >= 3
    except Exception:
        return False


# ============================================================
# ENRICH ONE DOMAIN
# ============================================================

def enrich_domain(domain: str) -> dict:
    """
    Returns enrichment dict for a single domain.
    """
    print(f"  [enricher] Enriching: {domain}")
    vt_mali = get_virustotal_malicious(domain)

    return {
        "domain":                         domain,
        "feat_domain_is_known_malicious": vt_mali,
        "virustotal_malicious":           vt_mali,
    }


# ============================================================
# COMPUTE AGGREGATE DOMAIN FEATURES
# ============================================================

def compute_domain_features(enriched_list: list) -> dict:
    """
    Aggregate domain enrichment results into model features.
    Returns the worst-case values (most suspicious domain).
    """
    if not enriched_list:
        return {
            "feat_domain_is_known_malicious": "False",
        }

    any_malicious = any(e["feat_domain_is_known_malicious"] for e in enriched_list)

    return {
        "feat_domain_is_known_malicious": str(any_malicious),
    }


# ============================================================
# FIND AND UPDATE LATEST LOG
# ============================================================

def find_latest_log(pkg_name: str) -> tuple:
    """
    Find the latest log for this package in both
    benign_runs and decoy_runs directories.
    Returns (log_path, log_dict) or (None, None).
    """
    candidates = []
    for log_dir in ["decoy_logs/benign_runs", "decoy_logs/decoy_runs"]:
        for path in glob.glob(os.path.join(log_dir, "*.json")):
            basename = os.path.basename(path).replace(".json", "")
            if re.match(rf"^{re.escape(pkg_name)}_\d+$", basename):
                try:
                    ts = int(basename.split("_")[-1])
                    candidates.append((ts, path))
                except Exception:
                    continue

    if not candidates:
        return None, None

    candidates.sort(key=lambda x: x[0], reverse=True)
    latest_path = candidates[0][1]

    try:
        with open(latest_path) as f:
            log = json.load(f)
        return latest_path, log
    except Exception:
        return None, None


def update_log_with_enrichment(log_path: str, log: dict, domain_features: dict,
                                enriched_domains: list):
    """
    Update the log file with domain enrichment results.
    """
    log["domain_enrichment"] = enriched_domains
    df = log.get("dynamic_features", {})
    df.update(domain_features)
    log["dynamic_features"] = df

    with open(log_path, "w") as f:
        json.dump(log, f, indent=4)

    print(f"  [enricher] Updated log: {log_path}")


# ============================================================
# MAIN
# ============================================================

if len(sys.argv) < 2:
    print("Usage: python scripts/domain_enricher.py <package_name_stem>")
    sys.exit(0)

pkg_name = sys.argv[1]
for ext in (".tar.gz", ".tgz", ".tar"):
    if pkg_name.endswith(ext):
        pkg_name = pkg_name[:-len(ext)]

pkg_name = re.sub(r"[^\w.\-]", "_", pkg_name)

print(f"[enricher] Running domain enrichment for: {pkg_name}")

log_path, log = find_latest_log(pkg_name)

if not log:
    print(f"[enricher] No log found for {pkg_name} — skipping")
    sys.exit(0)

# Get contacted domains from log
dynamic = log.get("dynamic_features", {})

# Try multiple sources for domains
domains_raw = []

# From dynamic_features
contacted = dynamic.get("feat_contacted_external_domain", "none")
if contacted and contacted != "none":
    domains_raw.extend(contacted.split("|"))

# From network_analysis (decoy logs)
na = log.get("network_analysis", {})
domains_raw.extend(na.get("real_domains", []))

# From real_domains (benign logs)
domains_raw.extend(log.get("real_domains", []))

# Deduplicate and clean
domains = list(set(d.strip() for d in domains_raw if d.strip() and d.strip() != "none"))

if not domains:
    print(f"[enricher] No external domains to enrich for {pkg_name}")
    domain_features = compute_domain_features([])
    update_log_with_enrichment(log_path, log, domain_features, [])
    sys.exit(0)

print(f"[enricher] Found {len(domains)} domain(s) to enrich: {domains}")

# Enrich each domain
enriched_domains = []
for domain in domains[:5]:  # limit to 5 domains to avoid rate limits
    result = enrich_domain(domain)
    enriched_domains.append(result)
    time.sleep(0.5)  # rate limit protection

# Compute aggregate features
domain_features = compute_domain_features(enriched_domains)

print(f"[enricher] Domain features: {domain_features}")

# Update log
update_log_with_enrichment(log_path, log, domain_features, enriched_domains)

print(f"[enricher] Done.")
