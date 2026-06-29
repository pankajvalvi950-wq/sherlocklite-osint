import streamlit as st
import requests
import time
import random
from datetime import datetime
import concurrent.futures
import socket
import ssl
import pandas as pd
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS

# Page Configuration
st.set_page_config(page_title="SherlockLite v18.0", page_icon="🔱", layout="centered")

# =========================================================================
# GLOBAL FAIL-SAFE INPUT UTILITIES
# =========================================================================
def clean_to_pure_hostname(input_str):
    """Cleans any dirty URL or path input into a pure clean domain/hostname"""
    if not input_str:
        return ""
    clean = input_str.strip().lower()
    clean = clean.replace("https://", "").replace("http://", "").replace("www.", "")
    clean = clean.split("/")[0].split(":")[0].split("?")[0]
    return clean

def clean_to_root_domain(input_str):
    """Extracts the base root domain from subdomains for registry validation"""
    hostname = clean_to_pure_hostname(input_str)
    parts = hostname.split(".")
    if len(parts) > 2:
        if parts[-2] in ["com", "co", "org", "net", "gov", "edu", "ac", "res"] and parts[-1] in ["in", "uk", "br", "au", "za", "ru"]:
            return ".".join(parts[-3:])
        return ".".join(parts[-2:])
    return hostname

# Initialize Session State
if "scan_history" not in st.session_state:
    st.session_state["scan_history"] = []

# FIX: Track active module in session_state so Streamlit Cloud
# doesn't mix up two modules' UI on first render / rerun
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
if "active_module" not in st.session_state:
    st.session_state["active_module"] = MODULES[0]

# Sidebar Panel Layout
st.sidebar.title("🔱 Sovereign Cyber Panel")
st.sidebar.markdown("**v18.0 Ironclad Production Suite**")

selected = st.sidebar.radio(
    "Select Cyber OSINT Module:",
    MODULES,
    index=MODULES.index(st.session_state["active_module"]),
)
# Persist selection — prevents ghost UI on cloud rerun
if selected != st.session_state["active_module"]:
    st.session_state["active_module"] = selected
    st.rerun()

module_choice = st.session_state["active_module"]

st.sidebar.markdown("---")
st.sidebar.subheader("📜 System Intel Logs")
if st.sidebar.button("🧹 Clear Logs"):
    st.session_state["scan_history"] = []
    st.sidebar.success("Logs cleared!")

if st.session_state["scan_history"]:
    for past_target in reversed(st.session_state["scan_history"]):
        st.sidebar.markdown(f"🎯 `{past_target}`")
else:
    st.sidebar.info("No active logs registered.")

# =========================================================================
# MODULE 1: USERNAME THREAT SCANNER
# =========================================================================
# FIX 1: Removed duplicate `import time` inside this block (already imported at top)
if module_choice == "👤 Username Threat Scanner":
    st.title("👤 Username Threat Scanner")
    st.markdown("> 📌 **Quick Intel:** Maps identical user handles across 18 major digital platforms in parallel.")

    target_user = st.text_input("🎯 Enter Target Username / Name:", placeholder="e.g., Cristiano Ronaldo")
    enable_adv = st.checkbox("🔥 Enable Advanced Search (Scan Shadow Accounts & Variations like _ff, _official, _real, _ig)", value=False)

    websites = {
        "GitHub": {"url": "https://github.com/{}", "redirect": True},
        "GitLab": {"url": "https://gitlab.com/{}", "redirect": True},
        "Dev.to": {"url": "https://dev.to/{}", "redirect": True},
        "HackerRank": {"url": "https://www.hackerrank.com/profile/{}", "redirect": True},
        "Medium": {"url": "https://medium.com/@{}", "redirect": False},
        "Instagram": {"url": "https://www.instagram.com/{}/", "redirect": False},   
        "X (Twitter)": {"url": "https://x.com/{}", "redirect": False},
        "LinkedIn": {"url": "https://www.linkedin.com/in/{}", "redirect": False},
        "Snapchat": {"url": "https://www.snapchat.com/add/{}", "redirect": True},    
        "Pinterest": {"url": "https://www.pinterest.com/{}/", "redirect": True},     
        "Twitch": {"url": "https://www.twitch.tv/{}", "redirect": True},
        "Spotify": {"url": "https://open.spotify.com/user/{}", "redirect": True},
        "SoundCloud": {"url": "https://soundcloud.com/{}", "redirect": True},
        "Chess.com": {"url": "https://www.chess.com/member/{}", "redirect": True},
        "Wikipedia": {"url": "https://en.wikipedia.org/wiki/User:{}", "redirect": True},
        "Reddit": {"url": "https://www.reddit.com/user/{}.json", "redirect": True}, 
        "Bio.link": {"url": "https://bio.link/{}", "redirect": True},
        "Linktree": {"url": "https://linktr.ee/{}", "redirect": True}
    }

    def scan_single_site(site_name, config, username, delay=0):
        # FIX 2: Only sleep if delay > 0, avoids unnecessary time.sleep(0) calls
        if delay > 0:
            time.sleep(delay)
        target_url = config["url"].format(username)
        current_headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        try:
            response = requests.get(target_url, headers=current_headers, timeout=5, allow_redirects=config["redirect"])
            if response.status_code == 200:
                if "reddit" in target_url and "error" in response.text:
                    return {"status": "not_found", "site": site_name}
                return {"status": "found", "site": site_name, "url": target_url}
            elif response.status_code in [429, 999, 403]:
                return {"status": "blocked", "site": site_name, "url": target_url}
            return {"status": "not_found", "site": site_name}
        except Exception:
            return {"status": "not_found", "site": site_name}

    if st.button("⚡ Execute Turbo Fast Scan"):
        if target_user.strip():
            raw_input = target_user.lower().strip()
            log_entry = f"User: {target_user.strip()}"
            if log_entry not in st.session_state["scan_history"]:
                st.session_state["scan_history"].append(log_entry)
            
            if enable_adv:
                base_vars = [raw_input.replace(" ", ""), raw_input.replace(" ", "-"), raw_input.replace(" ", "_")]
                suffixes = ['', '_ff', '_official', '_real', '_ig', 'official']
                advanced_vars = set()
                for bv in base_vars:
                    for suff in suffixes:
                        advanced_vars.add(f"{bv}{suff}")
                username_variations = advanced_vars
                delay_per_request = 0.8  
                max_threads = 3          
            else:
                username_variations = set([raw_input.replace(" ", ""), raw_input.replace(" ", "-"), raw_input.replace(" ", "_")])
                delay_per_request = 0    
                max_threads = 10         
            
            found_profiles, blocked_profiles = [], []
            scan_tasks = [(site, cfg, user) for user in username_variations for site, cfg in websites.items()]
            
            progress_bar = st.progress(0)
            status_text = st.empty()
            total_steps, current_step = len(scan_tasks), 0
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
                futures = {executor.submit(scan_single_site, s, c, u, delay_per_request): s for s, c, u in scan_tasks}
                for future in concurrent.futures.as_completed(futures):
                    current_step += 1
                    percent = int((current_step / total_steps) * 100)
                    progress_bar.progress(percent)
                    status_text.text(f"⚡ Probing Nodes... ({percent}%)")
                    
                    res = future.result()
                    if res["status"] == "found": found_profiles.append((res["site"], res["url"]))
                    elif res["status"] == "blocked": blocked_profiles.append((res["site"], res["url"]))
                    
            status_text.success("🎯 Digital footprint mapping pipeline complete!")
            
            m_col1, m_col2 = st.columns(2)
            m_col1.metric("🟢 Live Active Accounts", f"{len(found_profiles)} Hits")
            m_col2.metric("🟡 Guarded/Login Walls", f"{len(blocked_profiles)} Nodes")
            
            tab1, tab2 = st.tabs(["🟢 Active Hits", "🟨 Guarded / Restricted"])
            with tab1:
                for site, url in sorted(found_profiles): st.success(f"✅ **{site}** - [Launch Profile]({url})")
            with tab2:
                for site, url in sorted(blocked_profiles): st.warning(f"🟨 **{site}** - Auth Protected -> [Check Manually]({url})")
            
            st.markdown("---")
            st.markdown("💡 **Result Intel:** Active hits confirm registered digital accounts with matching identity handles.")
            
            st.markdown("### 📥 Export Intelligence Report")
            exp_col1, exp_col2 = st.columns(2)
            with exp_col1:
                report_text = f"--- SHERLOCKLITE OSINT SCAN REPORT ---\nTarget Username: {target_user}\nScan Time: {datetime.now()}\n\n[Active Hits]\n"
                for site, url in sorted(found_profiles): report_text += f"- {site}: {url}\n"
                st.download_button(label="🗎 Download Notepad Text Log", data=report_text, file_name=f"osint_report_{target_user}.txt", mime="text/plain")
                
            with exp_col2:
                sheet_data = []
                for site, url in found_profiles: sheet_data.append({"Platform": site, "Profile URL": url, "Status": "🟢 Active Hit"})
                for site, url in blocked_profiles: sheet_data.append({"Platform": site, "Profile URL": url, "Status": "🟡 Auth Guarded"})
                if sheet_data:
                    df = pd.DataFrame(sheet_data)
                    csv_data = df.to_csv(index=False).encode('utf-8')
                    st.download_button(label="📊 Download Excel / CSV Sheet", data=csv_data, file_name=f"osint_report_{target_user}.csv", mime="text/csv")
                else:
                    st.info("No data available to export in sheet.")
        else:
            st.error("Please enter a target username!")

# =========================================================================
# MODULE 2: LIVE IP INTELLIGENCE TRACKER
# =========================================================================
elif module_choice == "🌐 IP Intelligence Tracker":
    st.title("🌐 IP Intelligence Tracker")
    st.markdown("> 📌 **Quick Intel:** Extracts geographical location, ISP data, ASN routes, and coordinates from any public IP or domain.")

    ip_input = st.text_input("📡 Enter Target IP Address or Domain Name:", placeholder="e.g., 8.8.8.8 or google.com")

    if st.button("🔍 Trace IP Address"):
        if ip_input.strip():
            with st.spinner("Resolving destination routes and querying global geolocation nodes..."):
                try:
                    clean_target = clean_to_pure_hostname(ip_input)
                    try:
                        resolved_ip = socket.gethostbyname(clean_target)
                    except socket.gaierror:
                        resolved_ip = clean_target

                    # FIX 3: Use HTTPS endpoint for ip-api to avoid mixed content / network blocks
                    api_url = f"https://ip-api.com/json/{resolved_ip}"
                    response = requests.get(api_url, timeout=6).json()
                    
                    if response.get("status") == "success":
                        target_ip = response.get("query", "Unknown IP")
                        log_entry = f"IP: {target_ip}"
                        if log_entry not in st.session_state["scan_history"]:
                            st.session_state["scan_history"].append(log_entry)
                        
                        st.success(f"🎯 Target Acquired: {target_ip} ({clean_target})")
                        col1, col2 = st.columns(2)
                        with col1:
                            st.markdown(f"**🌍 Country:** {response.get('country')} ({response.get('countryCode')})")
                            st.markdown(f"**🏙️ Region:** {response.get('regionName')}")
                            st.markdown(f"**📍 City Name:** {response.get('city')}")
                        with col2:
                            st.markdown(f"**🏢 ISP / Provider:** {response.get('isp')}")
                            st.markdown(f"**📡 Timezone:** {response.get('timezone')}")
                            st.markdown(f"**🛰️ Coordinates:** `{response.get('lat')}, {response.get('lon')}`")
                        
                        st.markdown("---")
                        report_data = f"IP Intelligence Audit:\nTarget Input: {ip_input}\nResolved IP: {target_ip}\nLocation: {response.get('city')}, {response.get('country')}\nISP: {response.get('isp')}"
                        st.download_button("📥 Download IP Intelligence Log", data=report_data, file_name=f"ip_intel_{target_ip}.txt")
                    else:
                        st.error(f"🛑 Scan Failed: {response.get('message', 'Unknown Node Error')}")
                except Exception as e:
                    st.error(f"Network processing error: {e}")
        else:
            st.error("Please provide an IP address or domain!")

# =========================================================================
# MODULE 3: TACTICAL PORT SCANNER
# =========================================================================
elif module_choice == "🛡️ Tactical Port Scanner":
    st.title("🛡️ Tactical Port Scanner")
    st.markdown("> 📌 **Quick Intel:** Probes critical ports to detect open communication channels.")

    target_host = st.text_input("💻 Enter Target Domain / Host IP:", placeholder="e.g., scanme.nmap.org")
    common_ports = {21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3", 443: "HTTPS", 3306: "MySQL", 8080: "HTTP-Alt"}

    def check_port(host, port, service_name):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.5)
            result = s.connect_ex((host, port))
            s.close()
            return {"port": port, "status": "OPEN" if result == 0 else "CLOSED", "service": service_name}
        except Exception:
            return {"port": port, "status": "CLOSED", "service": service_name}

    if st.button("⚡ Trigger Stealth Port Audit"):
        if target_host.strip():
            clean_host = clean_to_pure_hostname(target_host)
            log_entry = f"Ports: {clean_host}"
            if log_entry not in st.session_state["scan_history"]:
                st.session_state["scan_history"].append(log_entry)
            open_ports, closed_ports = [], []
            with st.spinner("Executing network socket pipeline probes..."):
                with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                    futures = {executor.submit(check_port, clean_host, port, svc): port for port, svc in common_ports.items()}
                    for future in concurrent.futures.as_completed(futures):
                        res = future.result()
                        if res["status"] == "OPEN": open_ports.append(res)
                        else: closed_ports.append(res)
            
            p_tab1, p_tab2 = st.tabs(["🟢 Open Ports", "🔴 Closed / Blocked"])
            with p_tab1:
                if open_ports:
                    for item in open_ports: st.error(f"🔓 **Port {item['port']}** is OPEN -> Running `{item['service']}`")
                else: st.success("Excellent: No open core communication ports exposed directly.")
            with p_tab2:
                for item in closed_ports: st.text(f"🔒 Port {item['port']} ({item['service']}) - Closed / Safe.")
            
            report_text = f"--- INFRASTRUCTURE PORT SCAN REPORT ---\nTarget Host: {clean_host}\nTime: {datetime.now()}\n\n"
            for item in open_ports: report_text += f"Port {item['port']} ({item['service']}): OPEN\n"
            st.download_button("📥 Download Network Audit Report", data=report_text, file_name=f"port_audit_{clean_host}.txt")
        else:
            st.error("Please enter a valid target hostname!")

# =========================================================================
# MODULE 4: DNS & SUBDOMAIN MAPPER
# =========================================================================
elif module_choice == "🛰️ DNS & Subdomain Mapper":
    st.title("🛰️ DNS & Subdomain Mapper")
    st.markdown("> 📌 **Quick Intel:** Enumerates common host prefix vectors to locate active corporate sub-assets.")

    target_domain = st.text_input("🌐 Enter Base Domain Name:", placeholder="e.g., google.com")
    subdomain_wordlist = ["www", "mail", "ftp", "admin", "dev", "staging", "api", "blog", "secure", "vpn"]

    def resolve_subdomain(base_domain, sub):
        full_target = f"{sub}.{base_domain}"
        try:
            resolved_ip = socket.gethostbyname(full_target)
            return {"subdomain": full_target, "status": "ALIVE", "ip": resolved_ip}
        except socket.gaierror:
            return {"subdomain": full_target, "status": "DEAD"}

    if st.button("🚀 Mapping Target Subdomains"):
        if target_domain.strip():
            clean_domain = clean_to_root_domain(target_domain)
            log_entry = f"DNS: {clean_domain}"
            if log_entry not in st.session_state["scan_history"]:
                st.session_state["scan_history"].append(log_entry)
            alive_subs, dead_subs = [], []
            with st.spinner("Querying authoritative zone maps..."):
                with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                    futures = {executor.submit(resolve_subdomain, clean_domain, s): s for s in subdomain_wordlist}
                    for future in concurrent.futures.as_completed(futures):
                        res = future.result()
                        if res["status"] == "ALIVE": alive_subs.append(res)
                        else: dead_subs.append(res)

            d_tab1, d_tab2 = st.tabs(["🟢 Active Subdomains", "🔴 Non-Responsive"])
            with d_tab1:
                if alive_subs:
                    for item in alive_subs: st.markdown(f"🌐 **{item['subdomain']}** -> IP: `{item['ip']}`")
                else: st.warning("No standard organizational subdomains resolved.")
            with d_tab2:
                for item in dead_subs: st.caption(f"❌ {item['subdomain']}")
            
            dns_report = f"DNS Subdomain Map for Root Scope: {clean_domain}\n\n[Active Records]\n"
            for item in alive_subs: dns_report += f"{item['subdomain']} -> {item['ip']}\n"
            st.download_button("📥 Download DNS Map Report", data=dns_report, file_name=f"dns_map_{clean_domain}.txt")
        else:
            st.error("Please supply a valid domain name!")

# =========================================================================
# MODULE 5: HTTP HEADER & SECURITY AUDITOR
# =========================================================================
elif module_choice == "🧠 HTTP Header & Security Auditor":
    st.title("🧠 HTTP Header & Security Auditor")
    st.markdown("> 📌 **Quick Intel:** Extracts server framework banners and audits missing security policy configurations.")

    target_url = st.text_input("🔗 Enter Target Website URL:", placeholder="e.g., https://google.com")

    if st.button("🛡️ Audit Web Security Headers"):
        if target_url.strip():
            clean_host = clean_to_pure_hostname(target_url)
            # FIX 4: Preserve original scheme if user entered http://, else default to https://
            if target_url.strip().lower().startswith("http://"):
                url = "http://" + clean_host
            else:
                url = "https://" + clean_host
            try:
                log_entry = f"Headers: {url}"
                if log_entry not in st.session_state["scan_history"]:
                    st.session_state["scan_history"].append(log_entry)
                with st.spinner("Capturing transmission response headers..."):
                    browser_headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
                    response = requests.get(url, timeout=6, headers=browser_headers, allow_redirects=True)
                
                headers = response.headers
                st.success("🎯 Metatag connection signatures cataloged!")
                security_checks = {
                    "Strict-Transport-Security": "Forces HTTPS.",
                    "Content-Security-Policy": "Blocks XSS.",
                    "X-Frame-Options": "Clickjacking protection.",
                    "X-Content-Type-Options": "Blocks sniffing."
                }

                audit_log = f"HTTP Security Audit Summary for {url}\n\n"
                for key, description in security_checks.items():
                    matched = next((k for k in headers if k.lower() == key.lower()), None)
                    if matched: 
                        st.success(f"🟢 **{key}** is ACTIVE!\n* Value: `{headers[matched]}`")
                        audit_log += f"[OK] {key}: {headers[matched]}\n"
                    else: 
                        st.error(f"🔴 **{key}** is MISSING!\n* Impact: {description}")
                        audit_log += f"[VULN] {key} is absent\n"
                st.download_button("📥 Download Audit Log", data=audit_log, file_name=f"header_audit_{clean_host}.txt")
            except Exception as e:
                st.error(f"Web server rejected query: {e}")

# =========================================================================
# MODULE 6: DOMAIN REGISTRY & WHOIS (RDAP)
# =========================================================================
elif module_choice == "📜 Domain Registry & Whois (RDAP)":
    st.title("📜 Domain Registry & Whois (RDAP)")
    st.markdown("> 📌 **Quick Intel:** Direct RDAP query mechanism to extract official registrar logs.")

    input_domain = st.text_input("📝 Enter Target Domain Name:", placeholder="e.g., google.com")

    if st.button("🔍 Pull Registry Metadata"):
        if input_domain.strip():
            root_domain = clean_to_root_domain(input_domain)
            log_entry = f"Whois: {root_domain}"
            if log_entry not in st.session_state["scan_history"]:
                st.session_state["scan_history"].append(log_entry)
            try:
                with st.spinner("Querying global registries..."):
                    response = requests.get(f"https://rdap.org/domain/{root_domain}", timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    creation_date, expiration_date = "Hidden", "Hidden"
                    for event in data.get("events", []):
                        if event.get("eventAction") == "registration":
                            creation_date = event.get("eventDate", "").split("T")[0]
                        elif event.get("eventAction") == "expiration":
                            expiration_date = event.get("eventDate", "").split("T")[0]
                    col1, col2 = st.columns(2)
                    with col1: st.info(f"🌐 **Domain:** `{root_domain}`\n\n📅 **Created:** `{creation_date}`")
                    with col2: st.warning(f"⏳ **Expires:** `{expiration_date}`")
                    rdap_report = f"RDAP WHOIS Dump:\nDomain: {root_domain}\nCreated: {creation_date}\nExpires: {expiration_date}"
                    st.download_button("📥 Download Logs", data=rdap_report, file_name=f"whois_{root_domain}.txt")
                else:
                    st.error("RDAP root registrar missing target response.")
            except Exception as e:
                st.error(f"Registry connection error: {e}")

# =========================================================================
# MODULE 7: SSL/TLS CRYPTOGRAPHIC INSPECTOR
# =========================================================================
elif module_choice == "🔒 SSL/TLS Cryptographic Inspector":
    st.title("🔒 SSL/TLS Cryptographic Inspector")
    ssl_domain = st.text_input("🛡️ Enter Domain Name for SSL Handshake:", placeholder="e.g., google.com")

    if st.button("🔒 Trigger Cryptographic Verification"):
        if ssl_domain.strip():
            clean_ssl = clean_to_pure_hostname(ssl_domain)
            log_entry = f"SSL: {clean_ssl}"
            if log_entry not in st.session_state["scan_history"]:
                st.session_state["scan_history"].append(log_entry)
            with st.status("Initiating TLS Connection...", expanded=True) as status_block:
                try:
                    sock = socket.create_connection((clean_ssl, 443), timeout=6)
                    ctx = ssl.create_default_context()
                    ctx.set_alpn_protocols(['http/1.1', 'h2'])
                    ssock = ctx.wrap_socket(sock, server_hostname=clean_ssl)
                    cert = ssock.getpeercert()
                    ssock.close()
                    sock.close()
                    
                    if cert:
                        status_block.update(label="✅ Handshake Complete!", state="complete")
                        issuer_map = {}
                        for item in cert.get('issuer', []):
                            for sub_tuple in item:
                                if len(sub_tuple) == 2:
                                    issuer_map[sub_tuple[0]] = sub_tuple[1]
                        issuer_string = f"{issuer_map.get('organizationName', '')} ({issuer_map.get('commonName', '')})".strip(" ()")
                        valid_till = cert.get('notAfter', 'N/A')
                        col1, col2 = st.columns(2)
                        with col1: st.success(f"🤝 **Issuer CA:**\n\n`{issuer_string}`")
                        with col2: st.error(f"🚨 **Expiration:**\n\n`{valid_till}`")
                    else:
                        st.warning("Cert data payload is unreadable.")
                except Exception as e:
                    st.error(f"Handshake aborted: {e}")
        else:
            st.error("Please insert a domain!")

# =========================================================================
# MODULE 8: METADATA THREAT EXTRACTOR (FULLY FIXED)
# =========================================================================
elif module_choice == "📄 Metadata Threat Extractor":
    st.title("📄 Image Metadata (EXIF) Leaks Extractor")

    def safe_float(value):
        """
        FIX 5: Safely convert IFDRational, tuple, or numeric types to float.
        PIL returns GPS coordinates as IFDRational objects which need explicit conversion.
        """
        try:
            if hasattr(value, 'numerator') and hasattr(value, 'denominator'):
                # IFDRational object
                return float(value.numerator) / float(value.denominator) if value.denominator != 0 else 0.0
            return float(value)
        except Exception:
            return 0.0

    def get_decimal_coordinates(gps_info):
        """
        FIX 6: Robust GPS extraction handling IFDRational tuples from PIL.
        gps_info is a dict keyed by GPS tag IDs (integers).
        """
        try:
            gps_latitude     = gps_info.get(2)   # tuple of 3 IFDRationals: (deg, min, sec)
            gps_latitude_ref = gps_info.get(1)   # 'N' or 'S'
            gps_longitude    = gps_info.get(4)   # tuple of 3 IFDRationals
            gps_longitude_ref = gps_info.get(3)  # 'E' or 'W'

            if not (gps_latitude and gps_latitude_ref and gps_longitude and gps_longitude_ref):
                return None

            lat = safe_float(gps_latitude[0]) + safe_float(gps_latitude[1]) / 60.0 + safe_float(gps_latitude[2]) / 3600.0
            if gps_latitude_ref != 'N':
                lat = -lat

            lon = safe_float(gps_longitude[0]) + safe_float(gps_longitude[1]) / 60.0 + safe_float(gps_longitude[2]) / 3600.0
            if gps_longitude_ref != 'E':
                lon = -lon

            return lat, lon
        except Exception:
            return None

    uploaded_image = st.file_uploader("📤 Upload Target Image File (JPEG/PNG):", type=["jpg", "jpeg", "png"], key="meta_uploader")
    
    if uploaded_image is not None:
        img = Image.open(uploaded_image)
        st.image(img, caption="Loaded Target Payload Preview", width=320)
        
        with st.spinner("Analyzing image..."):
            # FIX 7: Use public .getexif() instead of deprecated private ._getexif()
            # ._getexif() crashes on PNG files and is removed in newer Pillow versions
            try:
                exif_data = img.getexif()
            except AttributeError:
                # Fallback for very old Pillow versions
                exif_data = img._getexif() if hasattr(img, '_getexif') else None

            if not exif_data:
                st.warning("⚠️ No EXIF data found in this image.")
            else:
                human_readable_exif = {}
                gps_raw = {}

                for tag_id, value in exif_data.items():
                    tag_name = TAGS.get(tag_id, str(tag_id))

                    # FIX 8: Capture GPS IFD sub-data (tag 34853) separately for coordinate extraction
                    if tag_id == 34853:
                        # On newer Pillow, getexif() returns the GPS IFD as a nested dict via get_ifd()
                        gps_raw = exif_data.get_ifd(34853)
                        human_readable_exif[tag_name] = "GPS Data (see Geo-Tracking section)"
                        continue

                    # FIX 9: Safe serialization — handle bytes and IFDRational objects
                    if isinstance(value, bytes):
                        human_readable_exif[tag_name] = value.decode('utf-8', errors='ignore').strip('\x00')
                    elif tag_name in ['DateTime', 'DateTimeOriginal', 'DateTimeDigitized']:
                        human_readable_exif[tag_name] = str(value).replace(':', '-', 2)
                    elif hasattr(value, 'numerator'):
                        # IFDRational → show as decimal
                        human_readable_exif[tag_name] = str(safe_float(value))
                    else:
                        try:
                            human_readable_exif[tag_name] = str(value)
                        except Exception:
                            human_readable_exif[tag_name] = "<unreadable>"

                # ── Camera Clock Integrity Check ──────────────────────────────
                # If DateTime is 2+ years older than current year, warn the user
                # that the camera's internal clock was likely never set or reset.
                detected_year = None
                for dt_key in ['DateTime', 'DateTimeOriginal', 'DateTimeDigitized']:
                    if dt_key in human_readable_exif:
                        try:
                            detected_year = int(human_readable_exif[dt_key][:4])
                            break
                        except (ValueError, TypeError):
                            pass

                current_year = datetime.now().year
                if detected_year is not None:
                    year_diff = current_year - detected_year
                    if year_diff >= 2:
                        st.warning(
                            f"⚠️ **Camera Clock Integrity Warning**\n\n"
                            f"EXIF timestamp shows **{detected_year}**, but current year is **{current_year}** "
                            f"({year_diff} year{'s' if year_diff > 1 else ''} difference detected).\n\n"
                            f"**Likely Cause:** Camera's internal CMOS clock battery is dead or was never set. "
                            f"The device defaulted to its factory date on power-up.\n\n"
                            f"**Fix:** Go to camera settings → `Date/Time` → set correct date manually."
                        )
                    elif year_diff < 0:
                        st.warning(
                            f"⚠️ **Timestamp Anomaly Detected**\n\n"
                            f"EXIF timestamp shows a **future date ({detected_year})**. "
                            f"Camera clock may be incorrectly configured.\n\n"
                            f"**Fix:** Go to camera settings → `Date/Time` → set correct date manually."
                        )
                # ─────────────────────────────────────────────────────────────

                # UI Display
                col1, col2 = st.columns(2)
                with col1:
                    st.markdown("### 📱 Device Info")
                    st.json(human_readable_exif)
                    
                with col2:
                    st.markdown("### 🌐 Geo-Tracking Coordinates")
                    # FIX 10: Use the properly extracted gps_raw IFD dict
                    coordinates = get_decimal_coordinates(gps_raw) if gps_raw else None
                    if coordinates:
                        lat, lon = coordinates
                        st.success(f"📍 GPS: `{lat:.6f}, {lon:.6f}`")
                        st.map(pd.DataFrame({'lat': [lat], 'lon': [lon]}))
                    else:
                        st.info("❌ No Geotags Embedded.")
                
                # Export
                raw_meta_df = pd.DataFrame(list(human_readable_exif.items()), columns=["EXIF Tag", "Value"])
                csv_meta = raw_meta_df.to_csv(index=False).encode('utf-8')
                st.download_button(
                    "📊 Export Report (.CSV)",
                    data=csv_meta,
                    file_name=f"meta_{uploaded_image.name}.csv",
                    mime="text/csv"
                )
