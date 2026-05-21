from flask import Flask, request, jsonify
from datetime import datetime, timezone
import json
import base64
import os
import requests
import time
import uuid
import threading
import traceback
 
app = Flask(__name__)
 
# =====================================================
# CONFIG
 
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
GITHUB_REPO  = os.getenv("GITHUB_REPO")
 
# EXACT path in your repo — must match what exists in GitHub
STIX_FILE = "CTI_Storage/CTI_STIX.json"
 
ABUSE_API_KEY  = os.getenv("ABUSE_API_KEY")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
VT_API_KEY     = os.getenv("VT_API_KEY")
 
# =====================================================
# STARTUP CHECKS — printed in Render logs on boot
 
def startup_checks():
    print("=" * 60)
    print("[STARTUP] SSC Honeypot collector starting...")
    print(f"[STARTUP] GITHUB_TOKEN  : {'SET ✓' if GITHUB_TOKEN else 'MISSING ✗'}")
    print(f"[STARTUP] GITHUB_REPO   : {GITHUB_REPO or 'MISSING ✗'}")
    print(f"[STARTUP] ABUSE_API_KEY : {'SET ✓' if ABUSE_API_KEY else 'MISSING ✗'}")
    print(f"[STARTUP] SHODAN_API_KEY: {'SET ✓' if SHODAN_API_KEY else 'MISSING ✗'}")
    print(f"[STARTUP] VT_API_KEY    : {'SET ✓' if VT_API_KEY else 'MISSING ✗'}")
    print(f"[STARTUP] STIX_FILE     : {STIX_FILE}")
 
    # Test GitHub access immediately
    if GITHUB_TOKEN and GITHUB_REPO:
        try:
            r = requests.get(
                f"https://api.github.com/repos/{GITHUB_REPO}",
                headers={"Authorization": f"token {GITHUB_TOKEN}"},
                timeout=5
            )
            if r.status_code == 200:
                print(f"[STARTUP] GitHub repo access: OK ✓")
            else:
                print(f"[STARTUP] GitHub repo access: FAILED ✗ status={r.status_code} → {r.json().get('message')}")
        except Exception as e:
            print(f"[STARTUP] GitHub repo access: EXCEPTION ✗ → {e}")
    else:
        print("[STARTUP] Skipping GitHub test — token or repo missing")
    print("=" * 60)
 
# =====================================================
# CACHE
 
CACHE = {}
 
def cached_lookup(ip, func):
    if ip in CACHE and func.__name__ in CACHE[ip]:
        return CACHE[ip][func.__name__]
    data = func(ip)
    if ip not in CACHE:
        CACHE[ip] = {}
    CACHE[ip][func.__name__] = data
    return data
 
# =====================================================
# DEDUP
 
LAST_SEEN = {}
 
def is_duplicate(event):
    endpoint = event.get("ioc_endpoint", "unknown")
    ip       = event.get("ip", "unknown")
    key      = f"{ip}_{endpoint}"
    now      = time.time()
    if key in LAST_SEEN and now - LAST_SEEN[key] < 10:
        print(f"[DEDUP] Skipping duplicate: {key}")
        return True
    LAST_SEEN[key] = now
    return False
 
# =====================================================
# IP TRACKING
 
IP_TRACKER = {}
 
def track_ip(ip):
    if ip not in IP_TRACKER:
        IP_TRACKER[ip] = {"count": 1}
    else:
        IP_TRACKER[ip]["count"] += 1
    return IP_TRACKER[ip]
 
# =====================================================
# ENRICHMENT
 
def enrich_ip(ip):
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        data = r.json()
        print(f"[GEO] {ip} → {data.get('country', '?')}, {data.get('city', '?')}")
        return data
    except Exception as e:
        print(f"[GEO] FAILED for {ip}: {e}")
        return {}
 
def enrich_abuse(ip):
    if not ABUSE_API_KEY:
        print("[ABUSE] No API key — skipping")
        return {}
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSE_API_KEY},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
            timeout=5
        )
        data = r.json().get("data", {})
        print(f"[ABUSE] {ip} → score={data.get('abuseConfidenceScore', '?')}, tor={data.get('isTor', '?')}")
        return data
    except Exception as e:
        print(f"[ABUSE] FAILED for {ip}: {e}")
        return {}
 
 
def enrich_shodan(ip):
    if not SHODAN_API_KEY:
        print("[SHODAN] No API key — skipping")
        return {}
    try:
        r = requests.get(
            f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}",
            timeout=5
        )
        data = r.json()
        if "error" in data:
            print(f"[SHODAN] {ip} → error: {data['error']}")
        else:
            print(f"[SHODAN] {ip} → org={data.get('org', '?')}, ports={data.get('ports', [])}")
        return data
    except Exception as e:
        print(f"[SHODAN] FAILED for {ip}: {e}")
        return {}
 
def enrich_vt(ip):
    if not VT_API_KEY:
        print("[VT] No API key — skipping")
        return {}
    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": VT_API_KEY},
            timeout=5
        )
        data = r.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        print(f"[VT] {ip} → malicious={stats.get('malicious', '?')}, suspicious={stats.get('suspicious', '?')}")
        return data
    except Exception as e:
        print(f"[VT] FAILED for {ip}: {e}")
        return {}
 
# =====================================================
# HELPER — build raw event
 
def build_path_event(profile_name, privilege_level, endpoint_name):
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    ip = ip.split(",")[0].strip()
 
    print(f"\n[EVENT] Hit on {endpoint_name} from IP={ip}")
 
    ua          = request.headers.get("User-Agent", "")
    ip_data     = track_ip(ip)
    geo         = cached_lookup(ip, enrich_ip)
    abuse       = cached_lookup(ip, enrich_abuse)
    shodan      = cached_lookup(ip, enrich_shodan)
    vt          = cached_lookup(ip, enrich_vt)
 
    now             = datetime.utcnow()
    request_count   = ip_data["count"]
    burst_flag      = request_count > 5
    ua_lower        = ua.lower()
    automation_flag = any(x in ua_lower for x in ["curl","bot","python","scanner","wget"])
 
    return {
        "event_type":       "path_trigger",
        "token_profile":    profile_name,
        "privilege_level":  privilege_level,
        "ip":               ip,
        "country":          geo.get("country"),
        "city":             geo.get("city"),
        "isp":              geo.get("isp"),
        "asn":              geo.get("as"),
        "request_count":    request_count,
        "burst_flag":       burst_flag,
        "user_agent":       ua,
        "automation_flag":  automation_flag,
        "automation_score": int(automation_flag) * 80,
        "hour_of_day":      now.hour,
        "day_of_week":      now.strftime("%A"),
        "ioc_endpoint":     endpoint_name,
        "method":           request.method,
        "intel": {
            "geo":            geo,
            "abuseipdb":      abuse,
            "shodan":         shodan,
            "virustotal":     vt,
        },
        "timestamp": now.isoformat()
    }
 
# =====================================================
# FILTER — drop empty / error fields recursively
 
EMPTY_VALUES = {None, "", "N/A", "Premium required.", "Requires membership or higher to access"}

def filter_empty(obj):
    if isinstance(obj, dict):
        cleaned = {}
        for k, v in obj.items():
            v2 = filter_empty(v)

            if not isinstance(v2, (list, dict)) and v2 in EMPTY_VALUES:
                continue

            if isinstance(v2, dict) and not v2:
                continue
            if isinstance(v2, list) and not v2:
                continue

            cleaned[k] = v2
        return cleaned

    elif isinstance(obj, list):
        result = []
        for item in obj:
            item2 = filter_empty(item)

            if not isinstance(item2, (list, dict)) and item2 in EMPTY_VALUES:
                continue

            result.append(item2)
        return result

    else:
        return obj
 
# =====================================================
# STIX HELPERS
 
def stix_id(obj_type):
    return f"{obj_type}--{uuid.uuid4()}"
 
def now_stix():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
 
def ts_to_stix(ts_str):
    try:
        dt = datetime.fromisoformat(ts_str)
        return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    except:
        return now_stix()
 
# =====================================================
# STIX BUILDER
 
def build_stix_bundle(event):
    created_ts = ts_to_stix(event.get("timestamp", now_stix()))
    intel      = event.get("intel", {})
 
    geo_clean    = filter_empty(intel.get("geo", {}))
    abuse_clean  = filter_empty(intel.get("abuseipdb", {}))
    shodan_clean = filter_empty(intel.get("shodan", {}))
    vt_raw       = intel.get("virustotal", {})
 
    vt_attrs = filter_empty(vt_raw.get("data", {}).get("attributes", {}))
    for drop_key in ["whois", "rdap", "last_https_certificate"]:
        vt_attrs.pop(drop_key, None)
    vt_clean = vt_attrs
 
    abuse_score   = abuse_clean.get("abuseConfidenceScore", 0)
    is_tor        = abuse_clean.get("isTor", False)
    isp           = (event.get("isp") or "").lower()
    is_vpn        = any(x in isp for x in ["hosting", "cloud", "vpn", "proxy"]) 
    is_bot        = event.get("automation_flag", False)
    vt_stats      = vt_clean.get("last_analysis_stats", {})
    vt_malicious  = vt_stats.get("malicious", 0)
    vt_suspicious = vt_stats.get("suspicious", 0)
 
    high_confidence = (abuse_score >= 80 or vt_malicious >= 5)
 
    labels = ["honeytoken-hit"]
    if is_tor:       labels.append("tor-exit-node")
    if is_vpn:       labels.append("vpn")
    if is_bot:       labels.append("automated-scanner")
    if vt_malicious: labels.append("malicious-ip")
    if "config" in event.get("ioc_endpoint", ""):  labels.append("config-exposure")
    if "/s3/" in event.get("ioc_endpoint", ""):    labels.append("cloud-storage-probe")
 
    identity_id      = stix_id("identity")
    ip_id            = stix_id("ipv4-addr")
    net_traffic_id   = stix_id("network-traffic")
    indicator_id     = stix_id("indicator")
    observed_data_id = stix_id("observed-data")
    rel_ind_ip_id    = stix_id("relationship")
 
    objects = []
 
    # 1. Identity
    objects.append({
        "type":           "identity",
        "spec_version":   "2.1",
        "id":             identity_id,
        "created":        created_ts,
        "modified":       created_ts,
        "name":           "SSC Honeypot Collector",
        "identity_class": "system",
        "description":    "Honeytoken collector deployed in CI/CD workflow.",
        "labels":         ["honeypot", "threat-intelligence"]
    })
 
    # 2. IPv4
    ip_obj = {
        "type":         "ipv4-addr",
        "spec_version": "2.1",
        "id":           ip_id,
        "value":        event.get("ip"),
    }
    if event.get("country"): ip_obj["x_country"] = event["country"]
    if event.get("city"):    ip_obj["x_city"]    = event["city"]
    if event.get("isp"):     ip_obj["x_isp"]     = event["isp"]
    if event.get("asn"):     ip_obj["x_asn"]     = event["asn"]
    objects.append(ip_obj)
 
    # 3. Network traffic
    objects.append({
        "type":         "network-traffic",
        "spec_version": "2.1",
        "id":           net_traffic_id,
        "src_ref":      ip_id,
        "protocols":    ["http"],
        "start":        created_ts,
        "extensions": {
            "http-request-ext": {
                "request_method": event.get("method", "GET"),
                "request_value":  event.get("ioc_endpoint", ""),
                "request_header": {"User-Agent": event.get("user_agent", "")}
            }
        },
        "x_event_type":       event.get("event_type"),
        "x_token_profile":    event.get("token_profile"),
        "x_privilege_level":  event.get("privilege_level"),
        "x_automation_score": event.get("automation_score"),
        "x_burst_flag":       event.get("burst_flag"),
        "x_request_count":    event.get("request_count"),
        "x_hour_of_day":      event.get("hour_of_day"),
        "x_day_of_week":      event.get("day_of_week"),
    })
 
    # 4. Indicator
    endpoint = event.get("ioc_endpoint", "")
    objects.append({
        "type":            "indicator",
        "spec_version":    "2.1",
        "id":              indicator_id,
        "created":         created_ts,
        "modified":        created_ts,
        "created_by_ref":  identity_id,
        "name":            f"Honeytoken hit: {endpoint}",
        "description": (
            f"IP {event.get('ip')} hit '{endpoint}' via {event.get('method')} "
            f"from {event.get('country', 'unknown')}. "
            f"Profile: {event.get('token_profile')}, privilege {event.get('privilege_level')}."
        ),
        "indicator_types": ["malicious-activity", "anomalous-activity"],
        "pattern":         f"[ipv4-addr:value = '{event.get('ip')}']",
        "pattern_type":    "stix",
        "valid_from":      created_ts,
        "labels":          labels,
        "confidence":      85 if high_confidence else 55,
    })
 
    # 5. Observed-data
    objects.append({
        "type":            "observed-data",
        "spec_version":    "2.1",
        "id":              observed_data_id,
        "created":         created_ts,
        "modified":        created_ts,
        "created_by_ref":  identity_id,
        "first_observed":  created_ts,
        "last_observed":   created_ts,
        "number_observed": event.get("request_count", 1),
        "object_refs":     [ip_id, net_traffic_id],
        "labels":          labels,
    })
 
    # 6. Threat-actor (high confidence only)
    if high_confidence:
        ta_id = stix_id("threat-actor")
        objects.append({
            "type":            "threat-actor",
            "spec_version":    "2.1",
            "id":              ta_id,
            "created":         created_ts,
            "modified":        created_ts,
            "created_by_ref":  identity_id,
            "name":            f"Unattributed actor — {event.get('ip')}",
            "description": (
                f"From {event.get('country', 'unknown')}. "
                f"Infra: {'TOR' if is_tor else 'VPN/Proxy' if is_vpn else 'direct'}. "
                f"Abuse={abuse_score}/100, "
                f"VT malicious={vt_malicious}, suspicious={vt_suspicious}."
            ),
            "threat_actor_types": ["criminal"] if not is_tor else ["criminal", "activist"],
            "sophistication":  "intermediate" if is_bot else "minimal",
            "resource_level":  "individual",
            "labels":          labels,
        })
        objects.append({
            "type":               "relationship",
            "spec_version":       "2.1",
            "id":                 stix_id("relationship"),
            "created":            created_ts,
            "modified":           created_ts,
            "relationship_type":  "uses",
            "source_ref":         ta_id,
            "target_ref":         indicator_id,
        })
 
    # 7. Relationship: indicator → ipv4-addr
    objects.append({
        "type":               "relationship",
        "spec_version":       "2.1",
        "id":                 rel_ind_ip_id,
        "created":            created_ts,
        "modified":           created_ts,
        "relationship_type":  "indicates",
        "source_ref":         indicator_id,
        "target_ref":         ip_id,
    })
 
    # 8. Notes per intel source
    def make_note(source_name, data):
        if not data:
            return None
        return {
            "type":           "note",
            "spec_version":   "2.1",
            "id":             stix_id("note"),
            "created":        created_ts,
            "modified":       created_ts,
            "created_by_ref": identity_id,
            "abstract":       f"Intel from {source_name} for {event.get('ip')}",
            "content":        json.dumps(data, indent=2, ensure_ascii=False),
            "object_refs":    [ip_id, indicator_id],
            "labels":         [source_name.lower().replace(" ", "-"), "raw-intel"],
        }
 
    for src, data in [
        ("GeoIP-ip-api",   geo_clean),
        ("AbuseIPDB",      abuse_clean),
        ("Shodan",         shodan_clean),
        ("VirusTotal",     vt_clean),
    ]:
        note = make_note(src, data)
        if note:
            objects.append(note)
 
    bundle = {
        "type":         "bundle",
        "id":           stix_id("bundle"),
        "spec_version": "2.1",
        "objects":      objects,
    }
    print(f"[STIX] Bundle built: {bundle['id']} with {len(objects)} objects")
    return bundle
 
# =====================================================
# GITHUB SAVE — with full logging
 
def save_stix_to_github(bundle: dict):
    print(f"[GITHUB] Starting save → repo={GITHUB_REPO}, file={STIX_FILE}")
 
    if not GITHUB_TOKEN:
        print("[GITHUB] ERROR: GITHUB_TOKEN is not set — aborting save")
        return
    if not GITHUB_REPO:
        print("[GITHUB] ERROR: GITHUB_REPO is not set — aborting save")
        return
 
    url     = f"https://api.github.com/repos/{GITHUB_REPO}/contents/{STIX_FILE}"
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept":        "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }
 
    # Step 1: GET existing file
    try:
        r = requests.get(url, headers=headers, timeout=10)
        print(f"[GITHUB] GET status={r.status_code}")
    except Exception as e:
        print(f"[GITHUB] GET EXCEPTION: {e}")
        return
 
    if r.status_code == 200:
        meta = r.json()
        sha  = meta["sha"]
        try:
            raw      = base64.b64decode(meta["content"]).decode("utf-8")
            existing = json.loads(raw)
            if not isinstance(existing, list):
                existing = [existing]
            print(f"[GITHUB] Existing file has {len(existing)} bundles")
        except Exception as e:
            print(f"[GITHUB] Could not parse existing file: {e} — starting fresh")
            existing = []
    elif r.status_code == 404:
        print("[GITHUB] File does not exist yet — will create it")
        sha      = None
        existing = []
    else:
        print(f"[GITHUB] Unexpected GET response {r.status_code}: {r.text[:300]}")
        return
 
    # Step 2: Append and PUT
    existing.append(bundle)
 
    try:
        new_content = json.dumps(existing, indent=2, ensure_ascii=False)
        encoded     = base64.b64encode(new_content.encode("utf-8")).decode()
    except Exception as e:
        print(f"[GITHUB] JSON encode FAILED: {e}")
        return
 
    payload = {
        "message": f"stix: {bundle['id']}",
        "content": encoded,
        "branch":  "main"
    }
    if sha:
        payload["sha"] = sha
 
    try:
        put_r = requests.put(url, headers=headers, json=payload, timeout=15)
        print(f"[GITHUB] PUT status={put_r.status_code}")
        if put_r.status_code in (200, 201):
            print(f"[GITHUB] ✓ Saved successfully → {STIX_FILE}")
        else:
            print(f"[GITHUB] ✗ PUT failed: {put_r.text[:500]}")
    except Exception as e:
        print(f"[GITHUB] PUT EXCEPTION: {e}")
        traceback.print_exc()
 
# =====================================================
# PROCESS — background thread so response returns instantly
 
def process_event(event):
    if is_duplicate(event):
        return
    bundle = build_stix_bundle(event)
    t = threading.Thread(target=save_stix_to_github, args=(bundle,), daemon=True)
    t.start()
 
# =====================================================
# ROUTES
 
@app.route("/legacy_internal_config.yaml", methods=["GET"])
def scm():
    event = build_path_event("legacy_registry", 1, "/legacy_internal_config.yaml")
    process_event(event)
    yaml_content = """ci:
  provider: github-actions
  runner: self-hosted
  token: ghp_91kLmN8QxZ7aBcD3EfGhIjK4LmNoPqRsTuVwXyZ

registry:
  npm:
    url: https://registry.npmjs.org/
    token: npm_7f3a9c2b5d8e4a1f6b0c9d3e7f2a8b1c

  pypi:
    url: https://upload.pypi.org/legacy/
    username: __token__
    password: pypi-AgENdGVzdC5weXBpLm9yZwIkZjA5ZjY3YjItY2QxZC00Z

internal_registry:
  url: https://packages.internal.local
  auth_token: irt_6d9f2b1a4c7e8f0d3b5a9c2e1f4d6a7b

build:
  artifact_storage: s3://ci-artifacts-prod
  signing_key: -----BEGIN PRIVATE KEY-----
    MIIEvQIBADANBgkqhkiG9w0BAQEFAASCfakeKeyMaterialOnlyDoNotUse
    -----END PRIVATE KEY-----

docker:
  registry: registry.internal.local
  username: ci-bot
  password: D0ckerP@ss!2025

env:
  NODE_ENV: production
  DEBUG: false
"""
    return app.response_class(
        response=yaml_content,
        status=200,
        mimetype="text/plain"
    )
 
@app.route("/s3/<bucket>", methods=["GET", "POST", "PUT"])
def s3(bucket):
    event = build_path_event("s3", 3, f"/s3/{bucket}")
    process_event(event)
    return "denied", 403
 
@app.route("/api/v1/session", methods=["POST"])
def session():
    auth = request.headers.get("Authorization", "")
    token = auth.replace("Bearer ", "") if auth.startswith("Bearer ") else auth
    CREDENTIAL_STORE = {
        "repo_token": {"token": "ghp_pr0dRel3aseAdm1nAccess2026xYzAbC", "privilege_level": 3}
    }
    for name, data in CREDENTIAL_STORE.items():
        if token == data["token"]:
            event = build_path_event(name, data["privilege_level"], "/api/v1/session")
            event["event_type"] = "credential_misuse"
            process_event(event)
            return jsonify({
                "id": "sess_9f8a7c6b5d",
                "actor": "repo_admin",
                "scope": ["repo", "packages:write", "admin:repo_hook"],
                "token_last_used": "2026-05-02T22:36:14Z",
                "session_status": "active",
               "ip": request.headers.get("X-Forwarded-For", request.remote_addr) }), 200
    return jsonify({"error": "invalid"}), 403
 
@app.route("/health")
def health():
    return {"status": "ok"}
 
@app.route("/debug/env")
def debug_env():
    """Verify env vars are loaded — remove in production after confirming."""
    return jsonify({
        "GITHUB_TOKEN":  "SET" if GITHUB_TOKEN else "MISSING",
        "GITHUB_REPO":   GITHUB_REPO or "MISSING",
        "ABUSE_API_KEY": "SET" if ABUSE_API_KEY else "MISSING",
        "SHODAN_API_KEY":"SET" if SHODAN_API_KEY else "MISSING",
        "VT_API_KEY":    "SET" if VT_API_KEY else "MISSING",
        "STIX_FILE":     STIX_FILE,
    })
 
# =====================================================
 
startup_checks()
 
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
