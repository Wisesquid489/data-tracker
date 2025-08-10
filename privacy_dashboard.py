

import streamlit as st
import pandas as pd
import psutil
import requests
import time
from datetime import datetime, timedelta
import sqlite3
import hashlib
import os
from fpdf import FPDF
import socket
import threading
import subprocess
import json
import matplotlib.pyplot as plt
import networkx as nx
import pydeck as pdk
import smtplib
from email.message import EmailMessage
from typing import Set, Dict, Any, Optional

# --- Page config ---
st.set_page_config(
    page_title="Ultimate Security Dashboard v6",
    layout="wide",
    initial_sidebar_state="expanded",
    menu_items={"About": "Advanced defensive monitoring tool — v6 (VirusTotal integrated)"}
)

# --- Constants / Globals ---
DB_FILE = "pro_security_dashboard_v6.db"
DEFAULT_BLOCKLIST_URLS = [
    "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
]
SAFE_PROCESS_WHITELIST = {'chrome.exe', 'msedge.exe', 'svchost.exe', 'Code.exe', 'python.exe', 'explorer.exe'}
HIGH_RISK_COUNTRIES = {'Russia', 'China', 'North Korea', 'Iran', 'Pakistan'}  # heuristic list
SCAN_INTERVAL_SECONDS = 10
VT_LOOKUP_BACKOFF_BASE = 5  # seconds

# session state defaults
if 'virustotal_api_key' not in st.session_state:
    st.session_state.virustotal_api_key = ""
if 'scan_data' not in st.session_state:
    st.session_state.scan_data = pd.DataFrame()
if 'ip_blocklist' not in st.session_state:
    st.session_state.ip_blocklist = set()
if 'monitoring' not in st.session_state:
    st.session_state.monitoring = False
if 'scan_thread' not in st.session_state:
    st.session_state.scan_thread = None
if 'custom_blocklist_urls' not in st.session_state:
    st.session_state.custom_blocklist_urls = []
# VT lookup queue and status
if 'vt_queue' not in st.session_state:
    st.session_state.vt_queue = []  # list of dicts: {sha256, path, status}
if 'vt_worker' not in st.session_state:
    st.session_state.vt_worker = None
if 'vt_worker_running' not in st.session_state:
    st.session_state.vt_worker_running = False

# --- DB initialization & helpers ---
def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS connections (
            timestamp TEXT, pid INTEGER, process TEXT, remote_ip TEXT, domain TEXT,
            on_blocklist INTEGER, country TEXT, risk_score INTEGER
        )""")
        conn.execute("CREATE TABLE IF NOT EXISTS whitelist (item_type TEXT, item_value TEXT UNIQUE)")
        conn.execute("""
        CREATE TABLE IF NOT EXISTS geo_cache (
            ip TEXT PRIMARY KEY, country TEXT, domain TEXT, lat REAL, lon REAL, last_seen TEXT
        )""")
        conn.execute("""
        CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)
        """)
        conn.execute("""
        CREATE TABLE IF NOT EXISTS vt_cache (
            sha256 TEXT PRIMARY KEY,
            json TEXT,
            positives INTEGER,
            total INTEGER,
            last_checked TEXT
        )
        """)

# DAO helpers for geo cache & settings & vt_cache
def geo_cache_get(ip: str):
    with sqlite3.connect(DB_FILE) as conn:
        cur = conn.cursor()
        cur.execute("SELECT country, domain, lat, lon, last_seen FROM geo_cache WHERE ip=?", (ip,))
        row = cur.fetchone()
        if row:
            return {'country': row[0], 'domain': row[1], 'lat': row[2], 'lon': row[3], 'last_seen': row[4]}
    return None

def geo_cache_set(ip: str, country: str, domain: str, lat, lon):
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("""
            INSERT OR REPLACE INTO geo_cache (ip, country, domain, lat, lon, last_seen)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (ip, country, domain, lat, lon, datetime.utcnow().isoformat()))

def settings_set(key: str, value: str):
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value))

def settings_get(key: str, default=None):
    with sqlite3.connect(DB_FILE) as conn:
        cur = conn.cursor()
        cur.execute("SELECT value FROM settings WHERE key=?", (key,))
        row = cur.fetchone()
        return row[0] if row else default

def vt_cache_get(sha256: str) -> Optional[Dict[str, Any]]:
    with sqlite3.connect(DB_FILE) as conn:
        cur = conn.cursor()
        cur.execute("SELECT json, positives, total, last_checked FROM vt_cache WHERE sha256=?", (sha256,))
        row = cur.fetchone()
        if row:
            try:
                return {
                    "json": json.loads(row[0]) if row[0] else None,
                    "positives": row[1],
                    "total": row[2],
                    "last_checked": row[3]
                }
            except Exception:
                return None
    return None

def vt_cache_set(sha256: str, json_obj: Dict[str, Any], positives: int, total: int):
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("""
            INSERT OR REPLACE INTO vt_cache (sha256, json, positives, total, last_checked)
            VALUES (?, ?, ?, ?, ?)
        """, (sha256, json.dumps(json_obj), positives, total, datetime.utcnow().isoformat()))

# --- Blocklist fetching (unchanged) ---
@st.cache_data(ttl=3600)
def fetch_blocklists(urls: list):
    ips = set()
    for url in urls:
        try:
            r = requests.get(url, timeout=10)
            r.raise_for_status()
            for line in r.text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                token = line.split()[0]
                if token.count('.') == 3 or ':' in token:
                    ips.add(token)
        except Exception as e:
            st.warning(f"Could not fetch blocklist {url}: {e}")
    return ips

# --- GeoIP resolution with caching (unchanged) ---
@st.cache_data(ttl=86400)
def get_network_info(ip: str):
    info = {'country': 'N/A', 'domain': 'N/A', 'lat': None, 'lon': None}
    if not ip or ip.startswith(("127.", "192.168.", "10.", "172.")):
        info.update({'country': 'Private Network', 'domain': 'localhost'})
        return info
    cached = geo_cache_get(ip)
    if cached:
        last_seen = cached.get('last_seen')
        try:
            if last_seen and (datetime.fromisoformat(last_seen) < datetime.utcnow() - timedelta(days=7)):
                threading.Thread(target=_refresh_geo_cache, args=(ip,), daemon=True).start()
        except Exception:
            pass
        return {'country': cached['country'], 'domain': cached['domain'], 'lat': cached['lat'], 'lon': cached['lon']}
    try:
        domain = "No reverse DNS record"
        try:
            domain = socket.gethostbyaddr(ip)[0]
        except Exception:
            domain = "No reverse DNS record"
        resp = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,lat,lon,query", timeout=3)
        if resp.ok and resp.json().get('status') == 'success':
            data = resp.json()
            country = data.get('country', 'Unknown')
            lat = data.get('lat')
            lon = data.get('lon')
            geo_cache_set(ip, country, domain, lat, lon)
            return {'country': country, 'domain': domain, 'lat': lat, 'lon': lon}
    except Exception:
        pass
    return info

def _refresh_geo_cache(ip):
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,lat,lon,query", timeout=3)
        domain = "No reverse DNS record"
        try:
            domain = socket.gethostbyaddr(ip)[0]
        except Exception:
            pass
        if resp.ok and resp.json().get('status') == 'success':
            data = resp.json()
            geo_cache_set(ip, data.get('country', 'Unknown'), domain, data.get('lat'), data.get('lon'))
    except Exception:
        pass

# --- Whitelist management (unchanged) ---
def manage_whitelist(action, item_value=None, item_type=None):
    with sqlite3.connect(DB_FILE) as conn:
        if action == 'get':
            df = pd.read_sql_query("SELECT item_type, item_value FROM whitelist", conn)
            return set(df['item_value'])
        elif action == 'add' and item_value and item_type:
            try:
                conn.execute("INSERT INTO whitelist (item_type, item_value) VALUES (?, ?)", (item_type, item_value))
                st.toast(f"Added '{item_value}' to whitelist.", icon="✅")
            except sqlite3.IntegrityError:
                st.toast(f"'{item_value}' is already in the whitelist.", icon="⚠️")
        elif action == 'remove' and item_value:
            conn.execute("DELETE FROM whitelist WHERE item_value=?", (item_value,))
            st.toast(f"Removed '{item_value}' from whitelist.", icon="🗑️")

# --- VirusTotal integration (new) ---
def vt_request_file_info(sha256: str, api_key: str) -> Dict[str, Any]:
    """Make request to VirusTotal v3 files/{id} endpoint. Returns JSON or error dict."""
    headers = {"x-apikey": api_key}
    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    try:
        r = requests.get(url, headers=headers, timeout=15)
        if r.status_code == 200:
            return r.json()
        elif r.status_code == 404:
            return {"error": "Hash not found in VirusTotal database.", "status_code": 404}
        elif r.status_code == 401:
            return {"error": "Unauthorized - check API key.", "status_code": 401}
        elif r.status_code == 429:
            # rate limit
            return {"error": "Rate limit exceeded", "status_code": 429}
        else:
            return {"error": f"VT API error {r.status_code}", "status_code": r.status_code}
    except Exception as e:
        return {"error": str(e)}

def vt_parse_summary(vt_json: Dict[str, Any]) -> Dict[str, Any]:
    """Extract compact summary: positives/total, hashes, last_analysis_date, link, engine results dict."""
    out = {"positives": 0, "total": 0, "sha256": None, "md5": None, "sha1": None, "last_analysis_date": None, "vt_link": None, "engines": {}}
    if not vt_json or "error" in vt_json:
        return out
    data = vt_json.get("data", {})
    attrs = data.get("attributes", {})
    out["sha256"] = attrs.get("sha256")
    out["md5"] = attrs.get("md5")
    out["sha1"] = attrs.get("sha1")
    last_analysis_date = attrs.get("last_analysis_date")
    if last_analysis_date:
        try:
            out["last_analysis_date"] = datetime.utcfromtimestamp(int(last_analysis_date)).strftime("%Y-%m-%d %H:%M:%S UTC")
        except Exception:
            out["last_analysis_date"] = str(last_analysis_date)
    stats = attrs.get("last_analysis_stats", {})
    out["positives"] = stats.get("malicious", 0) + stats.get("suspicious", 0)
    out["total"] = sum([v for v in stats.values()]) if stats else 0
    # last_analysis_results contains engine-by-engine
    results = attrs.get("last_analysis_results", {}) or {}
    engines = {}
    for engine, info in results.items():
        engines[engine] = {
            "category": info.get("category"),
            "engine_name": engine,
            "result": info.get("result"),
            "method": info.get("method"),
            "engine_update": info.get("engine_update")
        }
    out["engines"] = engines
    # link to vt UI
    vt_id = data.get("id")
    if vt_id:
        out["vt_link"] = f"https://www.virustotal.com/gui/file/{vt_id}/detection"
    return out

def display_vt_ui(vt_json: Dict[str, Any], container: Optional[st.delta_generator] = None):
    """Render the VT summary + engines in a nice UI. If container provided, render inside it."""
    target = container if container else st
    if not vt_json:
        target.info("No VirusTotal data available.")
        return
    if "error" in vt_json:
        target.error(f"VirusTotal: {vt_json.get('error')}")
        return
    summary = vt_parse_summary(vt_json)
    positives = summary.get("positives", 0)
    total = summary.get("total", 0)
    ratio_text = f"{positives}/{total}" if total else "N/A"
    # summary header
    with target.container():
        cols = st.columns([3, 2, 2, 3])
        with cols[0]:
            st.markdown("#### 🔍 VirusTotal Summary")
            st.write(f"**SHA256:** {summary.get('sha256') or 'N/A'}")
            st.write(f"**MD5:** {summary.get('md5') or 'N/A'}")
            st.write(f"**Last Analysis:** {summary.get('last_analysis_date') or 'N/A'}")
        with cols[1]:
            st.metric("Detections", ratio_text, delta=None)
        with cols[2]:
            # show status color-coded
            if total and positives:
                st.error("Malicious", help="One or more engines detect this as suspicious or malicious.")
            elif total and not positives:
                st.success("Clean", help="No engines detect this sample as malicious (based on last analysis).")
            else:
                st.info("Unknown", help="No analysis results available.")
        with cols[3]:
            if summary.get("vt_link"):
                st.markdown(f"[Open full report on VirusTotal]({summary.get('vt_link')})")
            st.download_button("Export VT JSON", data=json.dumps(vt_json, indent=2), file_name=f"vt_{summary.get('sha256') or 'unknown'}.json")
        # engines table (collapsible)
        st.markdown("**Engine Results (sample)**")
        engines_df = pd.DataFrame.from_dict(summary.get("engines", {}), orient='index')
        if not engines_df.empty:
            # normalize columns and show result and category
            engines_df = engines_df.reset_index(drop=True)[["engine_name", "category", "result", "method", "engine_update"]]
            engines_df = engines_df.rename(columns={"engine_name": "Engine", "category": "Category", "result": "Result", "method": "Method", "engine_update": "Updated"})
            # color rows - use simple mapping
            def color_row(row):
                if row["Category"] == "malicious" or (isinstance(row["Result"], str) and row["Result"]):
                    return ["background-color: #ffdddd"]*len(row)
                elif row["Category"] == "suspicious":
                    return ["background-color: #fff2cc"]*len(row)
                else:
                    return [""]*len(row)
            try:
                st.dataframe(engines_df, use_container_width=True)
            except Exception:
                st.write(engines_df)
        else:
            st.write("No per-engine results available.")
        # raw JSON in expander
        with st.expander("Show raw VirusTotal JSON"):
            st.json(vt_json)

# --- VT background worker & queue management ---
def enqueue_vt_lookup(sha256: str, path: Optional[str] = None):
    """Add a lookup request to the queue if not already present."""
    queue = st.session_state.vt_queue
    for item in queue:
        if item.get("sha256") == sha256:
            return
    queue.append({"sha256": sha256, "path": path, "status": "queued", "queued_at": datetime.utcnow().isoformat()})
    st.session_state.vt_queue = queue

def vt_worker_loop():
    """Background worker that processes vt_queue items."""
    st.session_state.vt_worker_running = True
    try:
        while True:
            if not st.session_state.vt_queue:
                # sleep a bit then continue (worker stays alive)
                time.sleep(1)
                if not st.session_state.monitoring and not st.session_state.scan_thread:
                    # if no monitoring and no scan thread, we can keep worker alive but idle.
                    pass
                continue
            # pop first queued item
            item = st.session_state.vt_queue.pop(0)
            st.session_state.vt_queue = st.session_state.vt_queue  # persist
            sha256 = item.get("sha256")
            # mark in-progress status
            item["status"] = "in-progress"
            item["started_at"] = datetime.utcnow().isoformat()
            # check cache first
            cache = vt_cache_get(sha256)
            if cache and cache.get("json"):
                # already cached; nothing to do
                item["status"] = "done"
                item["cached"] = True
                item["completed_at"] = datetime.utcnow().isoformat()
                # continue to next item
                continue
            api_key = st.session_state.virustotal_api_key or settings_get('virustotal_api_key', '')
            if not api_key:
                item["status"] = "error"
                item["error"] = "VirusTotal API key not set."
                item["completed_at"] = datetime.utcnow().isoformat()
                continue
            backoff = VT_LOOKUP_BACKOFF_BASE
            while True:
                vt_resp = vt_request_file_info(sha256, api_key)
                if vt_resp and vt_resp.get("status_code") == 429:
                    # rate limited: sleep and retry with backoff
                    time.sleep(backoff)
                    backoff = min(backoff * 2, 300)
                    continue
                # if vt_resp contains "error" string and status_code 404 -> cache negative result but mark zeros
                if vt_resp and "error" in vt_resp:
                    # 404 means not found - cache minimal info with last_checked
                    if vt_resp.get("status_code") == 404:
                        vt_cache_set(sha256, {"error": "not_found"}, 0, 0)
                    # other errors do not get cached
                    item["status"] = "error"
                    item["error"] = vt_resp.get("error")
                    item["completed_at"] = datetime.utcnow().isoformat()
                    break
                # success
                try:
                    summary = vt_parse_summary(vt_resp)
                    vt_cache_set(sha256, vt_resp, summary.get("positives", 0), summary.get("total", 0))
                    item["status"] = "done"
                    item["completed_at"] = datetime.utcnow().isoformat()
                except Exception as ex:
                    item["status"] = "error"
                    item["error"] = str(ex)
                    item["completed_at"] = datetime.utcnow().isoformat()
                break
            # small sleep to avoid hammering
            time.sleep(0.5)
    except Exception:
        st.session_state.vt_worker_running = False

def start_vt_worker():
    if st.session_state.vt_worker and st.session_state.vt_worker.is_alive():
        return
    thread = threading.Thread(target=vt_worker_loop, daemon=True)
    st.session_state.vt_worker = thread
    thread.start()

# --- Reputation / Risk scoring (slightly adjusted, remove references to removed services) ---
def compute_risk_score(row, blocklist_set, hist_count_lookup):
    """Combine multiple signals into 0-100 risk score."""
    score = 0
    remote_ip = row.get('Remote IP')
    proc_name = row.get('Process')
    if remote_ip in blocklist_set:
        score += 50
    if proc_name not in SAFE_PROCESS_WHITELIST:
        score += 15
    country = row.get('Country', '')
    if country in HIGH_RISK_COUNTRIES:
        score += 10
    freq = hist_count_lookup.get(remote_ip, 0)
    if freq > 10:
        score += 10
    elif freq > 3:
        score += 5
    return min(100, score)

# --- Connection enumeration and data assembly (kept mostly same, small perf improvements) ---
def get_connections_data(whitelist: Set[str], blocklist: Set[str]):
    data = []
    # compute historical counts quickly
    hist = {}
    with sqlite3.connect(DB_FILE) as conn:
        cur = conn.cursor()
        try:
            cur.execute("SELECT remote_ip, COUNT(*) FROM connections GROUP BY remote_ip")
            for r in cur.fetchall():
                hist[r[0]] = r[1]
        except Exception:
            hist = {}
    # collect processes once
    for conn in psutil.net_connections(kind='inet'):
        if not conn.raddr or conn.status != psutil.CONN_ESTABLISHED:
            continue
        try:
            pid = conn.pid
            proc = None
            try:
                proc = psutil.Process(pid)
            except Exception:
                continue
            remote_ip = conn.raddr.ip
            if proc.name() in whitelist or remote_ip in whitelist:
                continue
            network_info = get_network_info(remote_ip)
            on_blocklist = remote_ip in blocklist
            row = {
                "PID": pid,
                "Process": proc.name(),
                "Remote IP": remote_ip,
                "Domain": network_info.get('domain'),
                "On Blocklist": on_blocklist,
                "Country": network_info.get('country'),
                "lat": network_info.get('lat'),
                "lon": network_info.get('lon'),
                "_proc_obj": proc
            }
            row['Risk Score'] = compute_risk_score(row, blocklist, hist)
            data.append(row)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    df = pd.DataFrame(data)
    return df

# --- Save & historical helpers (unchanged) ---
def save_scan_to_db(df: pd.DataFrame):
    if df.empty:
        return
    with sqlite3.connect(DB_FILE) as conn:
        df2 = df.copy()
        df2['timestamp'] = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        db_df = df2[['timestamp', 'PID', 'Process', 'Remote IP', 'Domain', 'On Blocklist', 'Country', 'Risk Score']].copy()
        db_df.columns = [c.lower().replace(' ', '_') for c in db_df.columns]
        db_df.to_sql('connections', conn, if_exists='append', index=False)

def get_historical_data(start_date: str, end_date: str):
    with sqlite3.connect(DB_FILE) as conn:
        query = f"SELECT * FROM connections WHERE timestamp BETWEEN '{start_date}' AND '{end_date}'"
        df = pd.read_sql_query(query, conn)
    if not df.empty:
        df['timestamp'] = pd.to_datetime(df['timestamp'])
    return df

# --- PDF report creation (unchanged) ---
def create_pdf_report(df: pd.DataFrame):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "Security Scan Report", 0, 1, "C")
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 5, f"Generated (UTC): {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}", 0, 1, "C")
    pdf.ln(10)
    pdf.set_font("Helvetica", "B", 8)
    headers = ["Process", "Remote IP", "Domain", "Country", "Risk"]
    col_widths = [50, 40, 50, 30, 20]
    for i, header in enumerate(headers):
        pdf.cell(col_widths[i], 10, header, 1, 0, "C")
    pdf.ln()
    pdf.set_font("Helvetica", "", 7)
    for _, row in df.head(50).iterrows():
        pdf.cell(col_widths[0], 10, str(row.get("Process", ""))[:28], 1)
        pdf.cell(col_widths[1], 10, str(row.get("Remote IP", "")), 1)
        pdf.cell(col_widths[2], 10, str(row.get("Domain", ""))[:30], 1)
        pdf.cell(col_widths[3], 10, str(row.get("Country", ""))[:20], 1)
        pdf.cell(col_widths[4], 10, str(row.get("Risk Score", "")), 1, 0, "C")
        pdf.ln()
    return bytes(pdf.output())

# --- Auto-block (unchanged) ---
def auto_block_ip(ip: str):
    allow = settings_get('allow_firewall_changes', 'false')
    if allow != 'true':
        st.warning("Auto-blocking is disabled in settings. Enable 'allow_firewall_changes' to use this feature.")
        return False, "Auto-block disabled"
    try:
        if os.name == 'nt':
            cmd = ["netsh", "advfirewall", "firewall", "add", "rule",
                   "name=BlockIP_"+ip, "dir=out", "action=block", f"remoteip={ip}"]
            subprocess.run(cmd, check=True)
            return True, "Blocked via netsh"
        else:
            cmd = ["sudo", "iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"]
            subprocess.run(cmd, check=True)
            return True, "Blocked via iptables"
    except Exception as e:
        return False, str(e)

# --- Alerts (unchanged) ---
def send_slack_alert(webhook_url: str, message: str):
    try:
        requests.post(webhook_url, json={"text": message}, timeout=5)
        return True
    except Exception:
        return False

def send_email_alert(smtp_server, smtp_port, username, password, to_email, subject, body):
    try:
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = username
        msg["To"] = to_email
        msg.set_content(body)
        with smtplib.SMTP(smtp_server, smtp_port, timeout=10) as s:
            s.starttls()
            s.login(username, password)
            s.send_message(msg)
        return True
    except Exception as e:
        print("Email send fail:", e)
        return False

# --- Background scanner thread management (unchanged) ---
def _background_scanner_loop(interval=SCAN_INTERVAL_SECONDS):
    while st.session_state.monitoring:
        try:
            whitelist = manage_whitelist('get')
            blocklist = st.session_state.ip_blocklist
            df = get_connections_data(whitelist, blocklist)
            st.session_state.scan_data = df
            if not df.empty:
                save_scan_to_db(df)
            alert_threshold = int(settings_get('alert_threshold', '70'))
            slack_url = settings_get('slack_webhook', '')
            if not df.empty and slack_url:
                high = df[df['Risk Score'] >= alert_threshold]
                if not high.empty:
                    msg = f"High-risk connections detected ({len(high)}). Top:\n"
                    for _, r in high.head(5).iterrows():
                        msg += f"{r['Process']} -> {r['Remote IP']} ({r['Risk Score']}%)\n"
                    send_slack_alert(slack_url, msg)
            time.sleep(interval)
        except Exception:
            time.sleep(interval)

def start_background_scanner():
    if st.session_state.scan_thread and st.session_state.scan_thread.is_alive():
        return
    st.session_state.monitoring = True
    thread = threading.Thread(target=_background_scanner_loop, daemon=True)
    st.session_state.scan_thread = thread
    thread.start()

def stop_background_scanner():
    st.session_state.monitoring = False

# --- Parent-child process tree visualization (unchanged) ---
def build_process_tree(proc_obj):
    G = nx.DiGraph()
    try:
        ancestors = []
        p = proc_obj
        while p:
            ancestors.append(p)
            if p.parent() is None:
                break
            p = p.parent()
        root = ancestors[-1]
        to_visit = [root]
        visited = set()
        while to_visit:
            p = to_visit.pop()
            if p.pid in visited:
                continue
            visited.add(p.pid)
            label = f"{p.name()} ({p.pid})"
            G.add_node(label)
            try:
                children = p.children()
                for c in children:
                    child_label = f"{c.name()} ({c.pid})"
                    G.add_node(child_label)
                    G.add_edge(label, child_label)
                    to_visit.append(c)
            except Exception:
                continue
    except Exception:
        pass
    return G

def draw_process_tree(proc_obj):
    G = build_process_tree(proc_obj)
    if len(G.nodes) == 0:
        st.info("Could not build process tree.")
        return
    plt.figure(figsize=(8, 6))
    pos = nx.spring_layout(G, k=0.5, iterations=20)
    nx.draw(G, pos, with_labels=True, node_size=700, font_size=8, arrows=True)
    st.pyplot(plt)

# --- UI: Sidebar & Pages (modified to use VT worker) ---
def draw_sidebar():
    with st.sidebar:
        st.title("🛡️ Ultimate Security Dashboard v6")
        st.markdown("---")
        page = st.radio("Navigation", ["Live Monitor", "Historical Analysis", "Settings & Reporting", "Threat Feeds & Custom URLs"])
        st.markdown("---")
        if not st.session_state.ip_blocklist:
            st.session_state.ip_blocklist = fetch_blocklists(DEFAULT_BLOCKLIST_URLS + st.session_state.custom_blocklist_urls)
        if st.button("🔄 Refresh Blocklists"):
            st.session_state.ip_blocklist = fetch_blocklists(DEFAULT_BLOCKLIST_URLS + st.session_state.custom_blocklist_urls)
            st.toast("Blocklists refreshed", icon="🔁")
        st.metric("Threat IPs in DB", f"{len(st.session_state.ip_blocklist):,}")
        st.markdown("---")
        # show small VT queue status
        if st.session_state.vt_queue:
            st.info(f"VirusTotal queue: {len(st.session_state.vt_queue)} item(s)")
        return page

def draw_live_monitor_page():
    st.title("🔴 Live Network Monitor")
    col1, col2 = st.columns([3, 1])
    with col1:
        if st.button("🔍 Run Manual Scan", help="Performs a one-time scan of all connections."):
            whitelist = manage_whitelist('get')
            st.session_state.scan_data = get_connections_data(whitelist, st.session_state.ip_blocklist)
            if not st.session_state.scan_data.empty:
                save_scan_to_db(st.session_state.scan_data)
                st.toast("Scan saved to history", icon="✅")
    with col2:
        if st.session_state.monitoring:
            if st.button("⏸ Stop Live Monitoring"):
                stop_background_scanner()
        else:
            if st.button("▶️ Start Live Monitoring"):
                start_background_scanner()
    # start VT worker if needed
    start_vt_worker()

    if st.session_state.scan_data.empty:
        st.info("No scan results yet. Run a manual scan or start live monitoring.")
        return

    df = st.session_state.scan_data.copy()
    tabs = st.tabs(["📊 Scan Results", "🕵️ Connection Inspector", "🗺️ Interactive Map", "📈 Risk Charts", "🔬 Process Forensics", "🦠 VT Queue"])
    with tabs[0]:
        st.subheader("Connection Overview")
        display_df = df[["PID", "Process", "Remote IP", "Domain", "Country", "On Blocklist", "Risk Score"]].copy()
        st.dataframe(display_df, use_container_width=True, hide_index=True)
        st.markdown("### Quick Actions")
        q1, q2, q3 = st.columns(3)
        with q1:
            if st.button("Export Last Scan (CSV)"):
                st.download_button("Download CSV", data=df.to_csv(index=False), file_name=f"scan_{datetime.utcnow().strftime('%Y%m%d')}.csv")
        with q2:
            if st.button("Export Last Scan (PDF)"):
                st.download_button("Download PDF", data=create_pdf_report(df), file_name=f"scan_{datetime.utcnow().strftime('%Y%m%d')}.pdf")
        with q3:
            if st.button("Top Risky IPs Summary"):
                top = df.sort_values('Risk Score', ascending=False).head(10)
                st.table(top[["Process", "Remote IP", "Country", "Risk Score"]])

    with tabs[1]:
        st.subheader("Detailed Inspection & Actions")
        idx = st.selectbox("Select a connection", options=df.index, format_func=lambda x: f"{df.loc[x,'Process']} ({df.loc[x,'PID']}) → {df.loc[x,'Remote IP']}")
        if idx is not None:
            row = df.loc[idx]
            proc_obj = row["_proc_obj"]
            st.markdown(f"**Process:** {row['Process']} (PID: {row['PID']})")
            st.markdown(f"**Destination:** {row['Remote IP']} ({row['Domain']})")
            if row['On Blocklist']:
                st.error(f"IP FOUND ON BLOCKLIST ({row['Country']})", icon="🚨")
            else:
                st.markdown(f"**Country:** {row['Country']}")
            st.progress(int(row['Risk Score']))
            with st.expander("Process Forensics"):
                try:
                    st.text(f"Path: {proc_obj.exe()}\nUser: {proc_obj.username()}\nParent: {proc_obj.parent().name() if proc_obj.parent() else 'N/A'}\nCreated: {datetime.fromtimestamp(proc_obj.create_time()).strftime('%Y-%m-%d %H:%M')}")
                except Exception as e:
                    st.warning(f"Could not fetch full process details: {e}")
            c1, c2, c3, c4 = st.columns(4)
            with c1:
                if st.button("Whitelist Process", key=f"wp_{row['PID']}"):
                    manage_whitelist('add', row['Process'], 'process')
            with c2:
                if st.button("Whitelist IP", key=f"wi_{row['PID']}"):
                    manage_whitelist('add', row['Remote IP'], 'ip')
            with c3:
                if st.button("Terminate Process", key=f"kill_{row['PID']}"):
                    try:
                        proc_obj.terminate()
                        st.success(f"Terminated PID {proc_obj.pid}.")
                        time.sleep(1)
                    except Exception as e:
                        st.error(f"Failed to terminate: {e}")

            # VirusTotal scan action (non-blocking): compute hash in background thread and enqueue
            vt_col1, vt_col2 = st.columns([2, 4])
            with vt_col1:
                if st.button("🦠 Scan Binary (VirusTotal)", key=f"vt_{row['PID']}"):
                    try:
                        path = proc_obj.exe()
                    except Exception as e:
                        st.error(f"Could not determine binary path: {e}")
                        path = None
                    if not path or not os.path.exists(path):
                        st.error("Binary path missing or inaccessible. Try running the app with elevated permissions.")
                    else:
                        # compute hash in background so UI doesn't freeze
                        def compute_hash_and_enqueue(pth, pid):
                            try:
                                h = hashlib.sha256()
                                with open(pth, "rb") as fh:
                                    for chunk in iter(lambda: fh.read(8192), b""):
                                        h.update(chunk)
                                sha = h.hexdigest()
                                enqueue_vt_lookup(sha, pth)
                                st.toast(f"Queued {os.path.basename(pth)} for VT lookup (sha256: {sha[:12]}...)", icon="✅")
                            except Exception as e:
                                st.session_state.vt_queue.append({"sha256": None, "path": pth, "status": "error", "error": str(e)})
                                st.error(f"Failed hashing/queueing: {e}")
                        threading.Thread(target=compute_hash_and_enqueue, args=(path, row['PID']), daemon=True).start()
            with vt_col2:
                st.caption("Queued VT lookups run in background. Check 'VT Queue' tab for status and results.")

            with c4:
                if st.button("Auto-Block IP (requires settings enable)"):
                    ok, msg = auto_block_ip(row['Remote IP'])
                    if ok:
                        st.success(f"Blocked {row['Remote IP']}: {msg}")
                    else:
                        st.error(f"Block failed / disabled: {msg}")

    with tabs[2]:
        st.subheader("Interactive Map (pydeck)")
        map_data = df[['lat', 'lon', 'Remote IP', 'Process', 'Risk Score']].dropna()
        if not map_data.empty:
            map_data = map_data.rename(columns={'lat': 'latitude', 'lon': 'longitude'})
            layer = pdk.Layer(
                "ScatterplotLayer",
                map_data,
                pickable=True,
                opacity=0.8,
                stroked=True,
                get_position='[longitude, latitude]',
                get_fill_color='[255, 100, Risk Score*2]',
                get_radius=20000,
            )
            view_state = pdk.ViewState(latitude=20, longitude=0, zoom=1)
            r = pdk.Deck(layers=[layer], initial_view_state=view_state, tooltip={"text": "{Process} → {Remote IP}\nRisk: {Risk Score}%"})
            st.pydeck_chart(r)
        else:
            st.info("No geolocated connections to display.")

    with tabs[3]:
        st.subheader("Risk Score Distribution & Countries")
        st.bar_chart(df['Risk Score'].value_counts())
        st.bar_chart(df['Country'][df['Country'] != 'Private Network'].value_counts())

    with tabs[4]:
        st.subheader("Process Forensics & Tree")
        idx2 = st.selectbox("Select a connection (for tree)", options=df.index, format_func=lambda x: f"{df.loc[x,'Process']} ({df.loc[x,'PID']}) → {df.loc[x,'Remote IP']}", key="tree_select")
        if idx2 is not None:
            row = df.loc[idx2]
            proc_obj = row["_proc_obj"]
            draw_process_tree(proc_obj)

    with tabs[5]:
        st.subheader("VirusTotal Queue & Results")
        # show queue items, their status, and allow selecting completed results to view
        queue = st.session_state.vt_queue
        if not queue:
            st.info("No VT lookups queued.")
        else:
            q_df = pd.DataFrame(queue)
            st.table(q_df[["sha256", "path", "status", "queued_at"]].fillna(""))

        # search by SHA256 to view cached result
        st.markdown("---")
        st.markdown("### Lookup cached VT result")
        sha_search = st.text_input("Enter SHA256 to view cached VT result (or paste from queue)")
        if st.button("Lookup SHA256"):
            if not sha_search:
                st.warning("Enter a SHA256 to lookup.")
            else:
                cached = vt_cache_get(sha_search.strip())
                if not cached or not cached.get("json"):
                    st.warning("No cached result found. You can add it to queue by clicking 'Queue SHA'.")
                    if st.button("Queue SHA"):
                        enqueue_vt_lookup(sha_search.strip(), None)
                else:
                    display_vt_ui(cached.get("json"))

def draw_historical_page():
    st.title("📈 Historical Analysis")
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=7)
    date_range = st.date_input("Select Date Range (UTC)", (start_date.date(), end_date.date()), key="history_date")
    if len(date_range) == 2:
        hist_df = get_historical_data(date_range[0].strftime('%Y-%m-%d %H:%M:%S'), (date_range[1] + timedelta(days=1)).strftime('%Y-%m-%d %H:%M:%S'))
        if not hist_df.empty:
            st.markdown("### Connections Per Day")
            daily_counts = hist_df.set_index('timestamp').resample('D').size()
            st.bar_chart(daily_counts)
            st.markdown("### Browse Historical Data")
            st.dataframe(hist_df, use_container_width=True)
        else:
            st.info("No data for selected range.")

def draw_settings_page():
    st.title("⚙️ Settings & Reporting")
    st.subheader("API Keys")
    vt = st.text_input("VirusTotal API Key", value=settings_get('virustotal_api_key', ''), type="password")
    slack = st.text_input("Slack Webhook URL (optional)", value=settings_get('slack_webhook', ''))
    if st.button("Save Keys"):
        settings_set('virustotal_api_key', vt)
        settings_set('slack_webhook', slack)
        st.session_state.virustotal_api_key = vt
        st.toast("Saved API keys/settings", icon="✅")
    st.markdown("---")
    st.subheader("Auto-block & Alerts")
    allow_block = st.checkbox("Allow firewall changes (Auto-block)", value=(settings_get('allow_firewall_changes', 'false') == 'true'))
    settings_set('allow_firewall_changes', 'true' if allow_block else 'false')
    alert_threshold = st.number_input("Alert threshold (risk score)", min_value=0, max_value=100, value=int(settings_get('alert_threshold', '70')))
    settings_set('alert_threshold', str(alert_threshold))
    st.markdown("---")
    st.subheader("Email Alert (optional)")
    smtp_server = st.text_input("SMTP Server", value=settings_get('smtp_server', 'smtp.gmail.com'))
    smtp_port = st.number_input("SMTP Port", value=int(settings_get('smtp_port', '587')))
    smtp_user = st.text_input("SMTP Username", value=settings_get('smtp_user', ''))
    smtp_pass = st.text_input("SMTP Password (app password recommended)", value=settings_get('smtp_pass', ''), type="password")
    alert_email = st.text_input("Alert recipient email", value=settings_get('alert_email', ''))
    if st.button("Save Email Settings"):
        settings_set('smtp_server', smtp_server)
        settings_set('smtp_port', str(smtp_port))
        settings_set('smtp_user', smtp_user)
        settings_set('smtp_pass', smtp_pass)
        settings_set('alert_email', alert_email)
        st.toast("Saved email settings", icon="✅")
    st.markdown("---")
    st.subheader("Whitelist Management")
    with st.container():
        current_whitelist = manage_whitelist('get')
        st.dataframe(pd.DataFrame(list(current_whitelist), columns=["Whitelisted Items"]), use_container_width=True)
        new_item = st.text_input("Add whitelist item (IP or process name)")
        item_type = st.radio("Type", ['ip', 'process'])
        if st.button("Add to whitelist"):
            if new_item:
                manage_whitelist('add', new_item.strip(), item_type)
    st.markdown("---")
    st.subheader("Export / Scheduled Reports")
    if st.button("Send Last Scan via Email"):
        if settings_get('smtp_user') and settings_get('smtp_pass') and settings_get('alert_email'):
            df = st.session_state.scan_data
            if df.empty:
                st.warning("No scan results to send.")
            else:
                pdfb = create_pdf_report(df)
                sent = send_email_alert(settings_get('smtp_server'), int(settings_get('smtp_port', '587')), settings_get('smtp_user'), settings_get('smtp_pass'), settings_get('alert_email'), "Security Scan Report", "Attached latest scan report.")
                if sent:
                    st.success("Email sent.")
                else:
                    st.error("Failed to send email.")
        else:
            st.error("Email settings incomplete.")
    st.markdown("---")
    st.markdown("**Note**: Auto-blocking will only run if you enable it above and run the specific 'Auto-Block IP' action in the inspector.")

def draw_threat_feeds_page():
    st.title("🧾 Threat Feeds & Custom URLs")
    st.subheader("Default Feeds")
    for u in DEFAULT_BLOCKLIST_URLS:
        st.write(u)
    st.markdown("---")
    st.subheader("Custom Blocklist URLs")
    new_url = st.text_input("Add custom blocklist URL")
    if st.button("Add URL"):
        if new_url:
            st.session_state.custom_blocklist_urls.append(new_url)
            st.session_state.ip_blocklist = fetch_blocklists(DEFAULT_BLOCKLIST_URLS + st.session_state.custom_blocklist_urls)
            st.toast("Added custom blocklist and refreshed", icon="✅")
    if st.session_state.custom_blocklist_urls:
        st.write("Your custom URLs:")
        for i, u in enumerate(st.session_state.custom_blocklist_urls):
            col1, col2 = st.columns([9,1])
            col1.write(u)
            if col2.button("Remove", key=f"rm_{i}"):
                st.session_state.custom_blocklist_urls.pop(i)
                st.session_state.ip_blocklist = fetch_blocklists(DEFAULT_BLOCKLIST_URLS + st.session_state.custom_blocklist_urls)
                st.experimental_rerun()

# --- Main app flow ---
def main():
    init_db()
    page = draw_sidebar()
    if page == "Live Monitor":
        draw_live_monitor_page()
    elif page == "Historical Analysis":
        draw_historical_page()
    elif page == "Settings & Reporting":
        draw_settings_page()
    elif page == "Threat Feeds & Custom URLs":
        draw_threat_feeds_page()
    # keep short-running scan loop to update if monitoring via background thread is not used
    if st.session_state.monitoring and (not st.session_state.scan_thread or not st.session_state.scan_thread.is_alive()):
        start_background_scanner()
    # ensure VT worker running
    start_vt_worker()

if __name__ == "__main__":
    main()