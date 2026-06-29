import streamlit as st
import requests
import time
from datetime import datetime
import concurrent.futures
import socket
import ssl
import pandas as pd
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS

st.set_page_config(page_title="SherlockLite v18.0", page_icon="🔱", layout="centered")

# ── Helpers ───────────────────────────────────────────────────────────────
def clean_to_pure_hostname(s):
    if not s: return ""
    s = s.strip().lower()
    s = s.replace("https://","").replace("http://","").replace("www.","")
    return s.split("/")[0].split(":")[0].split("?")[0]

def clean_to_root_domain(s):
    h = clean_to_pure_hostname(s)
    parts = h.split(".")
    if len(parts) > 2:
        if parts[-2] in ["com","co","org","net","gov","edu","ac","res"] and parts[-1] in ["in","uk","br","au","za","ru"]:
            return ".".join(parts[-3:])
        return ".".join(parts[-2:])
    return h

# ── Session State ─────────────────────────────────────────────────────────
if "scan_history" not in st.session_state:
    st.session_state["scan_history"] = []

# ── Sidebar ───────────────────────────────────────────────────────────────
MODULES = [
    "👤 Username Threat Scanner",
    "🌐 IP Intelligence Tracker",
    "🛡️ Tactical Port Scanner",
    "🛰️ DNS & Subdomain Mapper",
    "🧠 HTTP Header & Security Auditor",
    "📜 Domain Registry & Whois (RDAP)",
    "🔒 SSL/TLS Cryptographic Inspector",
    "📄 Metadata Threat Extractor",
]

st.sidebar.title("🔱 Sovereign Cyber Panel")
st.sidebar.markdown("**v18.0 Ironclad Production Suite**")
module_index = st.sidebar.radio(
    "Select Cyber OSINT Module:",
    range(len(MODULES)),
    format_func=lambda i: MODULES[i],
    key="module_radio",
)
st.sidebar.markdown("---")
st.sidebar.subheader("📜 System Intel Logs")
if st.sidebar.button("🧹 Clear Logs", key="clear_logs"):
    st.session_state["scan_history"] = []
    st.sidebar.success("Logs cleared!")
if st.session_state["scan_history"]:
    for t in reversed(st.session_state["scan_history"]):
        st.sidebar.markdown(f"🎯 `{t}`")
else:
    st.sidebar.info("No active logs registered.")

# =========================================================================
# MODULE FUNCTIONS — each is fully self-contained
# =========================================================================

def module_username():
    st.title("👤 Username Threat Scanner")
    st.markdown("> 📌 **Quick Intel:** Maps identical user handles across 18 major digital platforms in parallel.")
    target_user = st.text_input("🎯 Enter Target Username / Name:", placeholder="e.g., Cristiano Ronaldo", key="m1_username")
    enable_adv  = st.checkbox("🔥 Enable Advanced Search (Variations like _ff, _official, _real, _ig)", value=False, key="m1_adv")

    websites = {
        "GitHub":     {"url":"https://github.com/{}",                        "redirect":True},
        "GitLab":     {"url":"https://gitlab.com/{}",                        "redirect":True},
        "Dev.to":     {"url":"https://dev.to/{}",                            "redirect":True},
        "HackerRank": {"url":"https://www.hackerrank.com/profile/{}",        "redirect":True},
        "Medium":     {"url":"https://medium.com/@{}",                       "redirect":False},
        "Instagram":  {"url":"https://www.instagram.com/{}/",                "redirect":False},
        "X (Twitter)":{"url":"https://x.com/{}",                            "redirect":False},
        "LinkedIn":   {"url":"https://www.linkedin.com/in/{}",               "redirect":False},
        "Snapchat":   {"url":"https://www.snapchat.com/add/{}",              "redirect":True},
        "Pinterest":  {"url":"https://www.pinterest.com/{}/",                "redirect":True},
        "Twitch":     {"url":"https://www.twitch.tv/{}",                     "redirect":True},
        "Spotify":    {"url":"https://open.spotify.com/user/{}",             "redirect":True},
        "SoundCloud": {"url":"https://soundcloud.com/{}",                    "redirect":True},
        "Chess.com":  {"url":"https://www.chess.com/member/{}",              "redirect":True},
        "Wikipedia":  {"url":"https://en.wikipedia.org/wiki/User:{}",        "redirect":True},
        "Reddit":     {"url":"https://www.reddit.com/user/{}.json",          "redirect":True},
        "Bio.link":   {"url":"https://bio.link/{}",                          "redirect":True},
        "Linktree":   {"url":"https://linktr.ee/{}",                         "redirect":True},
    }

    def scan_site(site_name, config, username, delay=0):
        if delay > 0: time.sleep(delay)
        url = config["url"].format(username)
        try:
            r = requests.get(url, headers={"User-Agent":"Mozilla/5.0"}, timeout=5, allow_redirects=config["redirect"])
            if r.status_code == 200:
                if "reddit" in url and "error" in r.text:
                    return {"status":"not_found","site":site_name}
                return {"status":"found","site":site_name,"url":url}
            elif r.status_code in [429,999,403]:
                return {"status":"blocked","site":site_name,"url":url}
        except Exception:
            pass
        return {"status":"not_found","site":site_name}

    if st.button("⚡ Execute Turbo Fast Scan", key="m1_scan"):
        if not target_user.strip():
            st.error("Please enter a target username!")
            return
        raw = target_user.lower().strip()
        log = f"User: {target_user.strip()}"
        if log not in st.session_state["scan_history"]:
            st.session_state["scan_history"].append(log)
        if enable_adv:
            bases   = [raw.replace(" ",""), raw.replace(" ","-"), raw.replace(" ","_")]
            suffs   = ['','_ff','_official','_real','_ig','official']
            variations = {f"{b}{s}" for b in bases for s in suffs}
            delay, threads = 0.8, 3
        else:
            variations = {raw.replace(" ",""), raw.replace(" ","-"), raw.replace(" ","_")}
            delay, threads = 0, 10
        tasks = [(s,c,u) for u in variations for s,c in websites.items()]
        found, blocked = [], []
        bar  = st.progress(0)
        info = st.empty()
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
            futures = {ex.submit(scan_site, s, c, u, delay): s for s,c,u in tasks}
            for i, f in enumerate(concurrent.futures.as_completed(futures), 1):
                bar.progress(int(i/len(tasks)*100))
                info.text(f"⚡ Probing Nodes... ({int(i/len(tasks)*100)}%)")
                res = f.result()
                if res["status"]=="found":   found.append((res["site"],res["url"]))
                elif res["status"]=="blocked": blocked.append((res["site"],res["url"]))
        info.success("🎯 Digital footprint mapping complete!")
        c1,c2 = st.columns(2)
        c1.metric("🟢 Live Active Accounts", f"{len(found)} Hits")
        c2.metric("🟡 Guarded/Login Walls",  f"{len(blocked)} Nodes")
        t1,t2 = st.tabs(["🟢 Active Hits","🟨 Guarded / Restricted"])
        with t1:
            for s,u in sorted(found):    st.success(f"✅ **{s}** - [Launch Profile]({u})")
        with t2:
            for s,u in sorted(blocked):  st.warning(f"🟨 **{s}** - Auth Protected -> [Check Manually]({u})")
        st.markdown("---")
        st.markdown("### 📥 Export Intelligence Report")
        e1,e2 = st.columns(2)
        with e1:
            txt = f"SHERLOCKLITE SCAN\nTarget: {target_user}\nTime: {datetime.now()}\n\n"
            for s,u in sorted(found): txt += f"- {s}: {u}\n"
            st.download_button("🗎 Download Text Log", data=txt, file_name=f"osint_{target_user}.txt", mime="text/plain", key="m1_dl_txt")
        with e2:
            rows = [{"Platform":s,"URL":u,"Status":"🟢 Active"} for s,u in found]
            rows += [{"Platform":s,"URL":u,"Status":"🟡 Guarded"} for s,u in blocked]
            if rows:
                csv = pd.DataFrame(rows).to_csv(index=False).encode()
                st.download_button("📊 Download CSV", data=csv, file_name=f"osint_{target_user}.csv", mime="text/csv", key="m1_dl_csv")


def module_ip():
    st.title("🌐 IP Intelligence Tracker")
    st.markdown("> 📌 **Quick Intel:** Extracts geo, ISP, ASN, and coordinates from any public IP or domain.")
    ip_input = st.text_input("📡 Enter Target IP Address or Domain Name:", placeholder="e.g., 8.8.8.8 or google.com", key="m2_ip")
    if st.button("🔍 Trace IP Address", key="m2_trace"):
        if not ip_input.strip():
            st.error("Please provide an IP address or domain!")
            return
        with st.spinner("Resolving and querying geolocation nodes..."):
            try:
                clean = clean_to_pure_hostname(ip_input)
                try:    resolved = socket.gethostbyname(clean)
                except: resolved = clean
                r = requests.get(f"https://ip-api.com/json/{resolved}", timeout=6).json()
                if r.get("status") == "success":
                    ip = r.get("query","?")
                    log = f"IP: {ip}"
                    if log not in st.session_state["scan_history"]:
                        st.session_state["scan_history"].append(log)
                    st.success(f"🎯 Target Acquired: {ip} ({clean})")
                    c1,c2 = st.columns(2)
                    with c1:
                        st.markdown(f"**🌍 Country:** {r.get('country')} ({r.get('countryCode')})")
                        st.markdown(f"**🏙️ Region:** {r.get('regionName')}")
                        st.markdown(f"**📍 City:** {r.get('city')}")
                    with c2:
                        st.markdown(f"**🏢 ISP:** {r.get('isp')}")
                        st.markdown(f"**📡 Timezone:** {r.get('timezone')}")
                        st.markdown(f"**🛰️ Coordinates:** `{r.get('lat')}, {r.get('lon')}`")
                    data = f"IP Intel:\nInput: {ip_input}\nIP: {ip}\nLocation: {r.get('city')}, {r.get('country')}\nISP: {r.get('isp')}"
                    st.download_button("📥 Download IP Log", data=data, file_name=f"ip_{ip}.txt", key="m2_dl")
                else:
                    st.error(f"🛑 Failed: {r.get('message','Unknown error')}")
            except Exception as e:
                st.error(f"Network error: {e}")


def module_ports():
    st.title("🛡️ Tactical Port Scanner")
    st.markdown("> 📌 **Quick Intel:** Probes critical ports to detect open communication channels.")
    target = st.text_input("💻 Enter Target Domain / Host IP:", placeholder="e.g., scanme.nmap.org", key="m3_host")
    PORTS  = {21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",80:"HTTP",110:"POP3",443:"HTTPS",3306:"MySQL",8080:"HTTP-Alt"}

    def check(host, port, svc):
        try:
            s = socket.socket(); s.settimeout(1.5)
            r = s.connect_ex((host, port)); s.close()
            return {"port":port,"status":"OPEN" if r==0 else "CLOSED","service":svc}
        except:
            return {"port":port,"status":"CLOSED","service":svc}

    if st.button("⚡ Trigger Stealth Port Audit", key="m3_audit"):
        if not target.strip():
            st.error("Please enter a valid target hostname!")
            return
        host = clean_to_pure_hostname(target)
        log  = f"Ports: {host}"
        if log not in st.session_state["scan_history"]:
            st.session_state["scan_history"].append(log)
        opened, closed = [], []
        with st.spinner("Probing network sockets..."):
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
                for f in concurrent.futures.as_completed([ex.submit(check, host, p, s) for p,s in PORTS.items()]):
                    res = f.result()
                    (opened if res["status"]=="OPEN" else closed).append(res)
        t1,t2 = st.tabs(["🟢 Open Ports","🔴 Closed / Blocked"])
        with t1:
            if opened:
                for i in opened: st.error(f"🔓 **Port {i['port']}** OPEN → `{i['service']}`")
            else:
                st.success("No open ports detected.")
        with t2:
            for i in closed: st.text(f"🔒 Port {i['port']} ({i['service']}) — Closed.")
        txt = f"PORT SCAN: {host}\nTime: {datetime.now()}\n\n"
        for i in opened: txt += f"Port {i['port']} ({i['service']}): OPEN\n"
        st.download_button("📥 Download Report", data=txt, file_name=f"ports_{host}.txt", key="m3_dl")


def module_dns():
    st.title("🛰️ DNS & Subdomain Mapper")
    st.markdown("> 📌 **Quick Intel:** Enumerates common subdomains to locate active sub-assets.")
    domain = st.text_input("🌐 Enter Base Domain Name:", placeholder="e.g., google.com", key="m4_domain")
    SUBS   = ["www","mail","ftp","admin","dev","staging","api","blog","secure","vpn"]

    def resolve(base, sub):
        full = f"{sub}.{base}"
        try:    return {"subdomain":full,"status":"ALIVE","ip":socket.gethostbyname(full)}
        except: return {"subdomain":full,"status":"DEAD"}

    if st.button("🚀 Map Target Subdomains", key="m4_map"):
        if not domain.strip():
            st.error("Please supply a valid domain name!")
            return
        root = clean_to_root_domain(domain)
        log  = f"DNS: {root}"
        if log not in st.session_state["scan_history"]:
            st.session_state["scan_history"].append(log)
        alive, dead = [], []
        with st.spinner("Querying DNS zones..."):
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
                for f in concurrent.futures.as_completed([ex.submit(resolve, root, s) for s in SUBS]):
                    res = f.result()
                    (alive if res["status"]=="ALIVE" else dead).append(res)
        t1,t2 = st.tabs(["🟢 Active Subdomains","🔴 Non-Responsive"])
        with t1:
            if alive:
                for i in alive: st.markdown(f"🌐 **{i['subdomain']}** → IP: `{i['ip']}`")
            else:
                st.warning("No subdomains resolved.")
        with t2:
            for i in dead: st.caption(f"❌ {i['subdomain']}")
        txt = f"DNS MAP: {root}\n\n"
        for i in alive: txt += f"{i['subdomain']} -> {i['ip']}\n"
        st.download_button("📥 Download DNS Report", data=txt, file_name=f"dns_{root}.txt", key="m4_dl")


def module_headers():
    st.title("🧠 HTTP Header & Security Auditor")
    st.markdown("> 📌 **Quick Intel:** Audits security headers and detects missing policy configurations.")
    url_input = st.text_input("🔗 Enter Target Website URL:", placeholder="e.g., https://google.com", key="m5_url")
    if st.button("🛡️ Audit Web Security Headers", key="m5_audit"):
        if not url_input.strip():
            st.error("Please enter a URL!")
            return
        host = clean_to_pure_hostname(url_input)
        url  = ("http://" if url_input.strip().lower().startswith("http://") else "https://") + host
        try:
            log = f"Headers: {url}"
            if log not in st.session_state["scan_history"]:
                st.session_state["scan_history"].append(log)
            with st.spinner("Fetching headers..."):
                r = requests.get(url, timeout=6, headers={"User-Agent":"Mozilla/5.0"}, allow_redirects=True)
            hdrs = r.headers
            st.success("🎯 Headers captured!")
            checks = {
                "Strict-Transport-Security": "Forces HTTPS.",
                "Content-Security-Policy":   "Blocks XSS.",
                "X-Frame-Options":           "Clickjacking protection.",
                "X-Content-Type-Options":    "Blocks MIME sniffing.",
            }
            log_txt = f"HTTP Security Audit: {url}\n\n"
            for key, desc in checks.items():
                match = next((k for k in hdrs if k.lower()==key.lower()), None)
                if match:
                    st.success(f"🟢 **{key}** ACTIVE → `{hdrs[match]}`")
                    log_txt += f"[OK] {key}: {hdrs[match]}\n"
                else:
                    st.error(f"🔴 **{key}** MISSING → {desc}")
                    log_txt += f"[VULN] {key} absent\n"
            st.download_button("📥 Download Audit Log", data=log_txt, file_name=f"headers_{host}.txt", key="m5_dl")
        except Exception as e:
            st.error(f"Request failed: {e}")


def module_whois():
    st.title("📜 Domain Registry & Whois (RDAP)")
    st.markdown("> 📌 **Quick Intel:** RDAP query to extract official domain registrar records.")
    domain = st.text_input("📝 Enter Target Domain Name:", placeholder="e.g., google.com", key="m6_domain")
    if st.button("🔍 Pull Registry Metadata", key="m6_pull"):
        if not domain.strip():
            st.error("Please enter a domain name!")
            return
        root = clean_to_root_domain(domain)
        log  = f"Whois: {root}"
        if log not in st.session_state["scan_history"]:
            st.session_state["scan_history"].append(log)
        try:
            with st.spinner("Querying RDAP registries..."):
                r = requests.get(f"https://rdap.org/domain/{root}", timeout=10)
            if r.status_code == 200:
                data = r.json()
                created, expires = "Hidden", "Hidden"
                for ev in data.get("events",[]):
                    if ev.get("eventAction")=="registration": created = ev.get("eventDate","").split("T")[0]
                    elif ev.get("eventAction")=="expiration":  expires = ev.get("eventDate","").split("T")[0]
                c1,c2 = st.columns(2)
                with c1: st.info(f"🌐 **Domain:** `{root}`\n\n📅 **Created:** `{created}`")
                with c2: st.warning(f"⏳ **Expires:** `{expires}`")
                txt = f"RDAP WHOIS:\nDomain: {root}\nCreated: {created}\nExpires: {expires}"
                st.download_button("📥 Download Logs", data=txt, file_name=f"whois_{root}.txt", key="m6_dl")
            else:
                st.error("RDAP registry returned no data.")
        except Exception as e:
            st.error(f"Registry error: {e}")


def module_ssl():
    st.title("🔒 SSL/TLS Cryptographic Inspector")
    domain = st.text_input("🛡️ Enter Domain Name for SSL Handshake:", placeholder="e.g., google.com", key="m7_ssl")
    if st.button("🔒 Trigger Cryptographic Verification", key="m7_verify"):
        if not domain.strip():
            st.error("Please insert a domain!")
            return
        host = clean_to_pure_hostname(domain)
        log  = f"SSL: {host}"
        if log not in st.session_state["scan_history"]:
            st.session_state["scan_history"].append(log)
        with st.status("Initiating TLS Connection...", expanded=True) as status:
            try:
                sock  = socket.create_connection((host,443), timeout=6)
                ctx   = ssl.create_default_context()
                ctx.set_alpn_protocols(['http/1.1','h2'])
                ssock = ctx.wrap_socket(sock, server_hostname=host)
                cert  = ssock.getpeercert()
                ssock.close(); sock.close()
                if cert:
                    status.update(label="✅ Handshake Complete!", state="complete")
                    iss = {}
                    for item in cert.get('issuer',[]):
                        for t in item:
                            if len(t)==2: iss[t[0]]=t[1]
                    issuer = f"{iss.get('organizationName','')} ({iss.get('commonName','')})".strip(" ()")
                    exp    = cert.get('notAfter','N/A')
                    c1,c2  = st.columns(2)
                    with c1: st.success(f"🤝 **Issuer CA:**\n\n`{issuer}`")
                    with c2: st.error(f"🚨 **Expiration:**\n\n`{exp}`")
                else:
                    st.warning("Certificate data unreadable.")
            except Exception as e:
                st.error(f"Handshake aborted: {e}")


def module_metadata():
    st.title("📄 Image Metadata (EXIF) Leaks Extractor")

    def safe_float(v):
        try:
            if hasattr(v,'numerator') and hasattr(v,'denominator'):
                return float(v.numerator)/float(v.denominator) if v.denominator!=0 else 0.0
            return float(v)
        except: return 0.0

    def gps_coords(gps):
        try:
            lat_t, lat_r = gps.get(2), gps.get(1)
            lon_t, lon_r = gps.get(4), gps.get(3)
            if not (lat_t and lat_r and lon_t and lon_r): return None
            lat = safe_float(lat_t[0]) + safe_float(lat_t[1])/60 + safe_float(lat_t[2])/3600
            if lat_r!='N': lat=-lat
            lon = safe_float(lon_t[0]) + safe_float(lon_t[1])/60 + safe_float(lon_t[2])/3600
            if lon_r!='E': lon=-lon
            return lat, lon
        except: return None

    img_file = st.file_uploader("📤 Upload Target Image File (JPEG/PNG):", type=["jpg","jpeg","png"], key="m8_upload")
    if img_file is None: return

    img = Image.open(img_file)
    st.image(img, caption="Loaded Target Payload Preview", width=320)

    with st.spinner("Analyzing EXIF metadata..."):
        try:    exif = img.getexif()
        except: exif = getattr(img,'_getexif',lambda:None)()

    if not exif:
        st.warning("⚠️ No EXIF data found in this image.")
        return

    parsed  = {}
    gps_raw = {}
    for tag_id, val in exif.items():
        tag = TAGS.get(tag_id, str(tag_id))
        if tag_id == 34853:
            gps_raw = exif.get_ifd(34853)
            parsed[tag] = "GPS Data (see Geo-Tracking section)"
            continue
        if isinstance(val, bytes):
            parsed[tag] = val.decode('utf-8', errors='ignore').strip('\x00')
        elif tag in ['DateTime','DateTimeOriginal','DateTimeDigitized']:
            parsed[tag] = str(val).replace(':','-',2)
        elif hasattr(val,'numerator'):
            parsed[tag] = str(safe_float(val))
        else:
            try:    parsed[tag] = str(val)
            except: parsed[tag] = "<unreadable>"

    # Camera clock integrity check
    detected_year = None
    for k in ['DateTime','DateTimeOriginal','DateTimeDigitized']:
        if k in parsed:
            try: detected_year = int(parsed[k][:4]); break
            except: pass
    if detected_year:
        diff = datetime.now().year - detected_year
        if diff >= 2:
            st.warning(
                f"⚠️ **Camera Clock Integrity Warning**\n\n"
                f"EXIF timestamp shows **{detected_year}**, current year is **{datetime.now().year}** "
                f"({diff} years difference).\n\n"
                f"**Likely Cause:** Camera CMOS battery dead or clock was never set — defaulted to factory date.\n\n"
                f"**Fix:** Camera Settings → `Date/Time` → set correct date manually."
            )
        elif diff < 0:
            st.warning(f"⚠️ **Timestamp Anomaly:** EXIF shows future date ({detected_year}). Check camera clock.")

    c1,c2 = st.columns(2)
    with c1:
        st.markdown("### 📱 Device Info")
        st.json(parsed)
    with c2:
        st.markdown("### 🌐 Geo-Tracking Coordinates")
        coords = gps_coords(gps_raw) if gps_raw else None
        if coords:
            lat,lon = coords
            st.success(f"📍 GPS: `{lat:.6f}, {lon:.6f}`")
            st.map(pd.DataFrame({'lat':[lat],'lon':[lon]}))
        else:
            st.info("❌ No Geotags Embedded.")
    csv = pd.DataFrame(list(parsed.items()), columns=["EXIF Tag","Value"]).to_csv(index=False).encode()
    st.download_button("📊 Export Report (.CSV)", data=csv, file_name=f"meta_{img_file.name}.csv", mime="text/csv", key="m8_dl")


# =========================================================================
# DISPATCH — one clean lookup, zero if/elif chains
# =========================================================================
DISPATCH = [
    module_username,
    module_ip,
    module_ports,
    module_dns,
    module_headers,
    module_whois,
    module_ssl,
    module_metadata,
]

DISPATCH[module_index]()
