import streamlit as st
import requests
import time
import random
from datetime import datetime
import concurrent.futures
import socket
import ssl

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

# Initialize Session State for Sidebar Logs as a dictionary for each module
if "scan_history" not in st.session_state:
    st.session_state["scan_history"] = {
        "👤 Username Threat Scanner": [],
        "🌐 IP Intelligence Tracker": [],
        "🛡️ Tactical Port Scanner": [],
        "🛰️ DNS & Subdomain Mapper": [],
        "🧠 HTTP Header & Security Auditor": [],
        "📜 Domain Registry & Whois (RDAP)": [],
        "🔒 SSL/TLS Cryptographic Inspector": []
    }

# Sidebar Panel Layout
st.sidebar.title("🔱 Sovereign Cyber Panel")
st.sidebar.markdown("**v18.0 Ironclad Production Suite**")

module_choice = st.sidebar.radio(
    "Select Cyber OSINT Module:", 
    [
        "👤 Username Threat Scanner", 
        "🌐 IP Intelligence Tracker", 
        "🛡️ Tactical Port Scanner",
        "🛰️ DNS & Subdomain Mapper",
        "🧠 HTTP Header & Security Auditor",
        "📜 Domain Registry & Whois (RDAP)",
        "🔒 SSL/TLS Cryptographic Inspector"
    ]
)

st.sidebar.markdown("---")
st.sidebar.subheader("📜 System Intel Logs")
if st.sidebar.button("🧹 Clear Logs"):
    st.session_state["scan_history"][module_choice] = []
    st.sidebar.success("Logs cleared!")

current_logs = st.session_state["scan_history"].get(module_choice, [])
if current_logs:
    for past_target in reversed(current_logs):
        st.sidebar.markdown(f"🎯 `{past_target}`")
else:
    st.sidebar.info("No active logs registered for this module.")

# =========================================================================
# MODULE 1: USERNAME THREAT SCANNER
# =========================================================================
if module_choice == "👤 Username Threat Scanner":
    st.title("👤 Username Threat Scanner")
    st.markdown("> 📌 **Quick Intel:** Maps identical user handles across 18 major digital platforms in parallel.")

    target_user = st.text_input("🎯 Enter Target Username / Name:", placeholder="e.g., pankajvalvi")
    enable_adv = st.checkbox("🔥 Enable Advanced Search (Scan Shadow Accounts & Variations)", value=False)

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
            if log_entry not in st.session_state["scan_history"][module_choice]:
                st.session_state["scan_history"][module_choice].append(log_entry)
            
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
            st.markdown("💡 **Result Intel:** Active hits confirm registered digital accounts.")
            
            report_text = f"--- SHERLOCKLITE OSINT SCAN REPORT ---\nTarget Username: {target_user}\n\n[Active Hits]\n"
            for site, url in sorted(found_profiles): report_text += f"- {site}: {url}\n"
            st.download_button("📥 Download Encrypted OSINT Log Report", data=report_text, file_name=f"osint_report_{target_user}.txt")
        else:
            st.error("Please enter a target username!")

# =========================================================================
# MODULE 2: LIVE IP INTELLIGENCE TRACKER
# =========================================================================
elif module_choice == "🌐 IP Intelligence Tracker":
    st.title("🌐 IP Intelligence Tracker")
    st.markdown("> 📌 **Quick Intel:** Extracts geographical location, ISP data, and coordinates.")

    ip_input = st.text_input("📡 Enter Target IP Address or Domain Name:", placeholder="e.g., 8.8.8.8")

    if st.button("🔍 Trace IP Address"):
        if ip_input.strip():
            with st.spinner("Resolving routes..."):
                try:
                    clean_target = clean_to_pure_hostname(ip_input)
                    try: resolved_ip = socket.gethostbyname(clean_target)
                    except socket.gaierror: resolved_ip = clean_target

                    api_url = f"http://ip-api.com/json/{resolved_ip}"
                    response = requests.get(api_url, timeout=6).json()
                    
                    if response.get("status") == "success":
                        target_ip = response.get("query", "Unknown IP")
                        log_entry = f"IP: {target_ip}"
                        if log_entry not in st.session_state["scan_history"][module_choice]:
                            st.session_state["scan_history"][module_choice].append(log_entry)
                        
                        st.success(f"🎯 Target Acquired: {target_ip}")
                        st.markdown(f"**🌍 Country:** {response.get('country')}")
                        st.markdown(f"**🏢 ISP:** {response.get('isp')}")
                    else:
                        st.error("🛑 Scan Failed.")
                except Exception as e:
                    st.error(f"Error: {e}")

# =========================================================================
# MODULE 3: TACTICAL PORT SCANNER
# =========================================================================
elif module_choice == "🛡️ Tactical Port Scanner":
    st.title("🛡️ Tactical Port Scanner")
    st.markdown("> 📌 **Quick Intel:** Probes critical ports to detect open communication channels.")

    target_host = st.text_input("💻 Enter Target Domain / Host IP:", placeholder="e.g., scanme.nmap.org")
    common_ports = {21: "FTP", 22: "SSH", 80: "HTTP", 443: "HTTPS"}

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
            if log_entry not in st.session_state["scan_history"][module_choice]:
                st.session_state["scan_history"][module_choice].append(log_entry)
                
            open_ports, closed_ports = [], []
            with st.spinner("Probing sockets..."):
                with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                    futures = {executor.submit(check_port, clean_host, p, s): p for p, s in common_ports.items()}
                    for future in concurrent.futures.as_completed(futures):
                        res = future.result()
                        if res["status"] == "OPEN": open_ports.append(res)
                        else: closed_ports.append(res)
            
            if open_ports:
                for item in open_ports: st.error(f"🔓 **Port {item['port']}** is OPEN (`{item['service']}`)")
            else: st.success("No core ports exposed.")

# =========================================================================
# MODULE 4: DNS & SUBDOMAIN MAPPER
# =========================================================================
elif module_choice == "🛰️ DNS & Subdomain Mapper":
    st.title("🛰️ DNS & Subdomain Mapper")
    target_domain = st.text_input("🌐 Enter Base Domain Name:", placeholder="google.com")
    subdomain_wordlist = ["www", "mail", "api", "dev"]

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
            if log_entry not in st.session_state["scan_history"][module_choice]:
                st.session_state["scan_history"][module_choice].append(log_entry)
            
            with st.spinner("Mapping..."):
                with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
                    futures = {executor.submit(resolve_subdomain, clean_domain, s): s for s in subdomain_wordlist}
                    for future in concurrent.futures.as_completed(futures):
                        res = future.result()
                        if res["status"] == "ALIVE": st.success(f"🌐 **{res['subdomain']}** -> {res['ip']}")

# =========================================================================
# MODULE 5: HTTP HEADER & SECURITY AUDITOR
# =========================================================================
elif module_choice == "🧠 HTTP Header & Security Auditor":
    st.title("🧠 HTTP Header & Security Auditor")
    target_url = st.text_input("🔗 Enter Target Website URL:", placeholder="https://google.com")

    if st.button("🛡️ Audit Web Security Headers"):
        if target_url.strip():
            clean_host = clean_to_pure_hostname(target_url)
            url = "https://" + clean_host
            try:
                log_entry = f"Headers: {url}"
                if log_entry not in st.session_state["scan_history"][module_choice]:
                    st.session_state["scan_history"][module_choice].append(log_entry)

                response = requests.get(url, timeout=6, allow_redirects=True)
                st.write(dict(response.headers))
            except Exception as e:
                st.error(f"Error: {e}")

# =========================================================================
# MODULE 6: DOMAIN REGISTRY & WHOIS (RDAP)
# =========================================================================
elif module_choice == "📜 Domain Registry & Whois (RDAP)":
    st.title("📜 Domain Registry & Whois (RDAP)")
    input_domain = st.text_input("📝 Enter Target Domain Name:", placeholder="netlify.app")

    if st.button("🔍 Pull Registry Metadata"):
        if input_domain.strip():
            root_domain = clean_to_root_domain(input_domain)
            log_entry = f"Whois: {root_domain}"
            if log_entry not in st.session_state["scan_history"][module_choice]:
                st.session_state["scan_history"][module_choice].append(log_entry)

            try:
                rdap_endpoint = f"https://rdap.org/domain/{root_domain}"
                res = requests.get(rdap_endpoint, timeout=10).json()
                st.json(res)
            except Exception as e:
                st.error(f"Error: {e}")

# =========================================================================
# MODULE 7: SSL/TLS CRYPTOGRAPHIC INSPECTOR
# =========================================================================
elif module_choice == "🔒 SSL/TLS Cryptographic Inspector":
    st.title("🔒 SSL/TLS Cryptographic Inspector")
    ssl_domain = st.text_input("🛡️ Enter Domain Name for SSL Handshake:", placeholder="google.com")

    if st.button("🔒 Trigger Cryptographic Verification"):
        if ssl_domain.strip():
            clean_ssl = clean_to_pure_hostname(ssl_domain)
            log_entry = f"SSL: {clean_ssl}"
            if log_entry not in st.session_state["scan_history"][module_choice]:
                st.session_state["scan_history"][module_choice].append(log_entry)

            try:
                sock = socket.create_connection((clean_ssl, 443), timeout=5)
                ctx = ssl.create_default_context()
                ssock = ctx.wrap_socket(sock, server_hostname=clean_ssl)
                cert = ssock.getpeercert()
                st.write(cert)
            except Exception as e:
                st.error(f"Handshake failed: {e}")
