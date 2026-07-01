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
    # Remove paths, query strings, or port numbers
    clean = clean.split("/")[0].split(":")[0].split("?")[0]
    return clean

def clean_to_root_domain(input_str):
    """Extracts the base root domain from subdomains for registry validation"""
    hostname = clean_to_pure_hostname(input_str)
    parts = hostname.split(".")
    if len(parts) > 2:
        # Handling common second-level domains (e.g., co.uk, com.in)
        if parts[-2] in ["com", "co", "org", "net", "gov", "edu", "ac", "res"] and parts[-1] in ["in", "uk", "br", "au", "za", "ru"]:
            return ".".join(parts[-3:])
        return ".".join(parts[-2:])
    return hostname

# Initialize Session State for Sidebar Logs
if "scan_history" not in st.session_state:
    st.session_state["scan_history"] = []

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
if st.sidebar.button("🧹 Clear Logs", key="clear_logs_sidebar_btn"):
    st.session_state["scan_history"] = []
    st.sidebar.success("Logs cleared!")

if st.session_state["scan_history"]:
    for past_target in reversed(st.session_state["scan_history"]):
        st.sidebar.markdown(f"🎯 `{past_target}`")
else:
    st.sidebar.info("No active logs registered.")

# --- Module 1 के स्टार्टिंग में Session State इनिशियलाइज़ करें ---
if "osint_results" not in st.session_state:
    st.session_state["osint_results"] = None

if module_choice == "👤 Username Threat Scanner":
    st.title("👤 Username Threat Scanner")
    st.markdown("> 📌 **Quick Intel:** Maps identical user handles across 18 major digital platforms in parallel.")

    target_user = st.text_input("🎯 Enter Target Username / Name:", placeholder="e.g., pankajvalvi")

    # ... (बाकी websites dict और scan_single_site function सेम रहेगा) ...

    if st.button("⚡ Execute Turbo Fast Scan"):
        if target_user.strip():
            raw_input = target_user.lower().strip()
            if target_user.strip() not in st.session_state["scan_history"]:
                st.session_state["scan_history"].append(f"User: {target_user.strip()}")
            
            username_variations = set([raw_input.replace(" ", ""), raw_input.replace(" ", "-"), raw_input.replace(" ", "_")])
            found_profiles, blocked_profiles = [], []
            
            scan_tasks = [(site, cfg, user) for user in username_variations for site, cfg in websites.items()]
            
            progress_bar = st.progress(0)
            status_text = st.empty()
            total_steps, current_step = len(scan_tasks), 0
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                futures = {executor.submit(scan_single_site, s, c, u): s for s, c, u in scan_tasks}
                for future in concurrent.futures.as_completed(futures):
                    current_step += 1
                    percent = int((current_step / total_steps) * 100)
                    progress_bar.progress(percent)
                    status_text.text(f"⚡ Probing Nodes... ({percent}%)")
                    
                    res = future.result()
                    if res["status"] == "found": found_profiles.append((res["site"], res["url"]))
                    elif res["status"] == "blocked": blocked_profiles.append((res["site"], res["url"]))
            
            # 🟢 बदलाव यहाँ है: रिज़ल्ट को session_state में सेव करें
            st.session_state["osint_results"] = {
                "found": found_profiles,
                "blocked": blocked_profiles,
                "user": target_user
            }
            status_text.success("🎯 Digital footprint mapping pipeline complete!")
        else:
            st.error("Please enter a target username!")

    # 🟢 बटन के बाहर रिज़ल्ट्स को रेंडर करें ताकि क्लिक करने पर गायब न हों
    if st.session_state["osint_results"] is not None:
        res_data = st.session_state["osint_results"]
        found_profiles = res_data["found"]
        blocked_profiles = res_data["blocked"]
        target_user = res_data["user"]

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
        
        report_text = f"--- SHERLOCKLITE OSINT SCAN REPORT ---\nTarget Username: {target_user}\nScan Time: {datetime.now()}\n\n[Active Hits]\n"
        for site, url in sorted(found_profiles): report_text += f"- {site}: {url}\n"
        
        # अब यह डाउनलोड बटन मक्खन की तरह काम करेगा!
        st.download_button("📥 Download Encrypted OSINT Log Report", data=report_text, file_name=f"osint_report_{target_user}.txt")

# --- Module 2 के स्टार्टिंग में Session State इनिशियलाइज़ करें ---
if "ip_results" not in st.session_state:
    st.session_state["ip_results"] = None

elif module_choice == "🌐 IP Intelligence Tracker":
    st.title("🌐 IP Intelligence Tracker")
    st.markdown("> 📌 **Quick Intel:** Extracts geographical location, ISP data, ASN routes, and coordinates from any public IP or domain.")

    ip_input = st.text_input("📡 Enter Target IP Address or Domain Name:", placeholder="e.g., 8.8.8.8 or netlify.app")

    if st.button("🔍 Trace IP Address"):
        if ip_input.strip():
            with st.spinner("Resolving destination routes..."):
                try:
                    clean_target = clean_to_pure_hostname(ip_input)
                    try:
                        resolved_ip = socket.gethostbyname(clean_target)
                    except socket.gaierror:
                        resolved_ip = clean_target

                    api_url = f"http://ip-api.com/json/{resolved_ip}"
                    response = requests.get(api_url, timeout=6).json()
                    
                    if response.get("status") == "success":
                        target_ip = response.get("query", "Unknown IP")
                        if f"IP: {target_ip}" not in st.session_state["scan_history"]:
                            st.session_state["scan_history"].append(f"IP: {target_ip}")
                        
                        # 🟢 रिज़ल्ट को state में सेव करें
                        st.session_state["ip_results"] = {
                            "response": response,
                            "target_ip": target_ip,
                            "clean_target": clean_target,
                            "ip_input": ip_input
                        }
                    else:
                        st.error(f"🛑 Scan Failed: {response.get('message', 'Unknown Node Error')}")
                except Exception as e:
                    st.error(f"Network processing error: {e}")
        else:
            st.error("Please provide an IP address or domain!")

    # 🟢 रिज़ल्ट डिस्प्ले बटन के बाहर होगा
    if st.session_state["ip_results"] is not None:
        ip_data = st.session_state["ip_results"]
        resp = ip_data["response"]
        
        st.success(f"🎯 Target Acquired: {ip_data['target_ip']} ({ip_data['clean_target']})")
        col1, col2 = st.columns(2)
        with col1:
            st.markdown(f"**🌍 Country:** {resp.get('country')} ({resp.get('countryCode')})")
            st.markdown(f"**🏙️ Region:** {resp.get('regionName')}")
            st.markdown(f"**📍 City Name:** {resp.get('city')}")
        with col2:
            st.markdown(f"**🏢 ISP / Provider:** {resp.get('isp')}")
            st.markdown(f"**📡 Timezone:** {resp.get('timezone')}")
            st.markdown(f"**🛰️ Coordinates:** `{resp.get('lat')}, {resp.get('lon')}`")
        
        st.markdown("---")
        report_data = f"IP Intelligence Audit:\nTarget Input: {ip_data['ip_input']}\nResolved IP: {ip_data['target_ip']}\nLocation: {resp.get('city')}, {resp.get('country')}\nISP: {resp.get('isp')}"
        st.download_button("📥 Download IP Intelligence Log", data=report_data, file_name=f"ip_intel_{ip_data['target_ip']}.txt")

# =========================================================================
# MODULE 3: TACTICAL PORT SCANNER
# =========================================================================
elif module_choice == "🛡️ Tactical Port Scanner":
    st.title("🛡️ Tactical Port Scanner")
    st.markdown("> 📌 **Quick Intel:** Probes critical ports to detect open communication channels and active service signatures.")

    if "m3_results" not in st.session_state:
        st.session_state["m3_results"] = None

    target_host = st.text_input("💻 Enter Target Domain / Host IP:", placeholder="e.g., scanme.nmap.org", key="m3_host_input")

    common_ports = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
        110: "POP3", 443: "HTTPS", 3306: "MySQL", 8080: "HTTP-Alt"
    }

    def check_port(host, port, service_name):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.5)
            result = s.connect_ex((host, port))
            s.close()
            return {"port": port, "status": "OPEN" if result == 0 else "CLOSED", "service": service_name}
        except Exception:
            return {"port": port, "status": "CLOSED", "service": service_name}

    m3_col_b1, m3_col_b2 = st.columns(2)
    with m3_col_b1:
        scan_clicked = st.button("⚡ Trigger Stealth Port Audit", key="m3_port_audit_btn", use_container_width=True)
    with m3_col_b2:
        clear_clicked = st.button("🗑️ Clear Results", key="m3_clear_btn", use_container_width=True)

    if clear_clicked:
        st.session_state["m3_results"] = None
        st.rerun()

    if scan_clicked:
        if target_host.strip():
            clean_host = clean_to_pure_hostname(target_host)
            if f"Ports: {clean_host}" not in st.session_state["scan_history"]:
                st.session_state["scan_history"].append(f"Ports: {clean_host}")
                
            open_ports, closed_ports = [], []
            with st.spinner("Executing network socket pipeline probes..."):
                with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                    futures = {executor.submit(check_port, clean_host, port, svc): port for port, svc in common_ports.items()}
                    for future in concurrent.futures.as_completed(futures):
                        res = future.result()
                        if res["status"] == "OPEN": open_ports.append(res)
                        else: closed_ports.append(res)
            st.session_state["m3_results"] = {"open": open_ports, "closed": closed_ports, "clean_host": clean_host}
        else:
            st.error("Please enter a valid target hostname!")

    if st.session_state["m3_results"]:
        res = st.session_state["m3_results"]
        p_tab1, p_tab2 = st.tabs(["🟢 Open Ports", "🔴 Closed / Blocked"])
        with p_tab1:
            if res["open"]:
                for item in res["open"]: st.error(f"🔓 **Port {item['port']}** is OPEN -> Running `{item['service']}`")
            else: st.success("Excellent: No open core communication ports exposed directly.")
        with p_tab2:
            for item in res["closed"]: st.text(f"🔒 Port {item['port']} ({item['service']}) - Closed / Safe.")
        
        st.markdown("---")
        st.markdown("💡 **Result Intel:** Exposed open entry points represent listening listeners. Unused ports should remain CLOSED or hidden behind firewall protocols to block lateral movement threats.")
        report_text = f"--- INFRASTRUCTURE PORT SCAN REPORT ---\nTarget Host: {res['clean_host']}\nTime: {datetime.now()}\n\n"
        for item in res["open"]: report_text += f"Port {item['port']} ({item['service']}): OPEN\n"
        st.download_button("📥 Download Network Audit Report", data=report_text, file_name=f"port_audit_{res['clean_host']}.txt", key="m3_download_report_btn")

# =========================================================================
# MODULE 4: DNS & SUBDOMAIN MAPPER
# =========================================================================
elif module_choice == "🛰️ DNS & Subdomain Mapper":
    st.title("🛰️ DNS & Subdomain Mapper")
    st.markdown("> 📌 **Quick Intel:** Enumerates common host prefix vectors to locate active corporate sub-assets and microservices.")

    if "m4_results" not in st.session_state:
        st.session_state["m4_results"] = None

    target_domain = st.text_input("🌐 Enter Base Domain Name:", placeholder="e.g., google.com", key="m4_domain_input")
    subdomain_wordlist = ["www", "mail", "ftp", "admin", "dev", "staging", "api", "blog", "secure", "vpn"]

    def resolve_subdomain(base_domain, sub):
        full_target = f"{sub}.{base_domain}"
        try:
            resolved_ip = socket.gethostbyname(full_target)
            return {"subdomain": full_target, "status": "ALIVE", "ip": resolved_ip}
        except socket.gaierror:
            return {"subdomain": full_target, "status": "DEAD"}

    m4_col_b1, m4_col_b2 = st.columns(2)
    with m4_col_b1:
        map_clicked = st.button("🚀 Mapping Target Subdomains", key="m4_dns_mapping_btn", use_container_width=True)
    with m4_col_b2:
        clear_clicked = st.button("🗑️ Clear Results", key="m4_clear_btn", use_container_width=True)

    if clear_clicked:
        st.session_state["m4_results"] = None
        st.rerun()

    if map_clicked:
        if target_domain.strip():
            clean_domain = clean_to_root_domain(target_domain)
            st.info(f"⚙️ Target Mapping optimized on Root Asset: `{clean_domain}`")
            
            if f"DNS: {clean_domain}" not in st.session_state["scan_history"]:
                st.session_state["scan_history"].append(f"DNS: {clean_domain}")
            
            alive_subs, dead_subs = [], []
            with st.spinner("Querying authoritative zone maps..."):
                with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                    futures = {executor.submit(resolve_subdomain, clean_domain, s): s for s in subdomain_wordlist}
                    for future in concurrent.futures.as_completed(futures):
                        res = future.result()
                        if res["status"] == "ALIVE": alive_subs.append(res)
                        else: dead_subs.append(res)
            st.session_state["m4_results"] = {"alive": alive_subs, "dead": dead_subs, "clean_domain": clean_domain}
        else:
            st.error("Please supply a valid domain name!")

    if st.session_state["m4_results"]:
        res = st.session_state["m4_results"]
        d_tab1, d_tab2 = st.tabs(["🟢 Active Subdomains", "🔴 Non-Responsive"])
        with d_tab1:
            if res["alive"]:
                for item in res["alive"]: st.markdown(f"🌐 **{item['subdomain']}** -> IP: `{item['ip']}`")
            else: st.warning("No standard organizational subdomains resolved for this scope.")
        with d_tab2:
            for item in res["dead"]: st.caption(f"❌ {item['subdomain']}")
        
        st.markdown("---")
        st.markdown("💡 **Result Intel:** Discovering active subdomains maps out an entity's internal attack surface, unmasking hidden staging boxes or API entry points.")
        dns_report = f"DNS Subdomain Map for Root Scope: {res['clean_domain']}\n\n[Active Records]\n"
        for item in res["alive"]: dns_report += f"{item['subdomain']} -> {item['ip']}\n"
        st.download_button("📥 Download DNS Map Report", data=dns_report, file_name=f"dns_map_{res['clean_domain']}.txt", key="m4_download_report_btn")

# =========================================================================
# MODULE 5: HTTP HEADER & SECURITY AUDITOR
# =========================================================================
elif module_choice == "🧠 HTTP Header & Security Auditor":
    st.title("🧠 HTTP Header & Security Auditor")
    st.markdown("> 📌 **Quick Intel:** Extracts server framework banners and audits missing security policy configurations (CSP, HSTS, X-Frame).")

    if "m5_results" not in st.session_state:
        st.session_state["m5_results"] = None

    target_url = st.text_input("🔗 Enter Target Website URL:", placeholder="e.g., https://google.com", key="m5_url_input")

    m5_col_b1, m5_col_b2 = st.columns(2)
    with m5_col_b1:
        audit_clicked = st.button("🛡️ Audit Web Security Headers", key="m5_header_audit_btn", use_container_width=True)
    with m5_col_b2:
        clear_clicked = st.button("🗑️ Clear Results", key="m5_clear_btn", use_container_width=True)

    if clear_clicked:
        st.session_state["m5_results"] = None
        st.rerun()

    if audit_clicked:
        if target_url.strip():
            clean_host = clean_to_pure_hostname(target_url)
            url = "https://" + clean_host
            try:
                if f"Headers: {url}" not in st.session_state["scan_history"]:
                    st.session_state["scan_history"].append(f"Headers: {url}")

                with st.spinner("Capturing transmission response headers..."):
                    browser_headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
                    response = requests.get(url, timeout=6, headers=browser_headers, allow_redirects=True)
                
                st.session_state["m5_results"] = {"headers": dict(response.headers), "url": url, "clean_host": clean_host}
            except Exception as e:
                st.error(f"Web server pipeline rejected query: {e}")
        else:
            st.error("Please enter a target website URL!")

    if st.session_state["m5_results"]:
        res = st.session_state["m5_results"]
        st.success("🎯 Metatag connection signatures cataloged!")
        security_checks = {
            "Strict-Transport-Security": "Forces secure HTTPS tunnels.",
            "Content-Security-Policy": "Mitigates XSS injections.",
            "X-Frame-Options": "Defends against Clickjacking structures.",
            "X-Content-Type-Options": "Blocks unauthorized MIME type sniffing."
        }
        audit_log = f"HTTP Security Audit Summary for {res['url']}\nEvaluated at: {datetime.now()}\n\n"
        for key, description in security_checks.items():
            matched = next((k for k in res["headers"] if k.lower() == key.lower()), None)
            if matched: 
                st.success(f"🟢 **{key}** is ACTIVE!\n* Value: `{res['headers'][matched]}`")
                audit_log += f"[OK] {key}: {res['headers'][matched]}\n"
            else: 
                st.error(f"🔴 **{key}** is MISSING!\n* Impact: {description}")
                audit_log += f"[VULNERABILITY] {key} is absent -> {description}\n"
        
        st.markdown("---")
        st.markdown("💡 **Result Intel:** Missing HTTP security policy headers leave web browsers unprotected against common automated client-side injection vectors.")
        st.download_button("📥 Download Security Header Audit Log", data=audit_log, file_name=f"header_audit_{res['clean_host']}.txt", key="m5_download_report_btn")

# =========================================================================
# MODULE 6: DOMAIN REGISTRY & WHOIS (RDAP)
# =========================================================================
elif module_choice == "📜 Domain Registry & Whois (RDAP)":
    st.title("📜 Domain Registry & Whois (RDAP)")
    st.markdown("> 📌 **Quick Intel:** Direct RDAP query mechanism to extract official registrar logs, registration dates, and expiry checkpoints.")

    if "m6_results" not in st.session_state:
        st.session_state["m6_results"] = None

    input_domain = st.text_input("📝 Enter Target Domain Name:", placeholder="e.g., netlify.app", key="m6_domain_input")

    m6_col_b1, m6_col_b2 = st.columns(2)
    with m6_col_b1:
        pull_clicked = st.button("🔍 Pull Registry Metadata", key="m6_rdap_pull_btn", use_container_width=True)
    with m6_col_b2:
        clear_clicked = st.button("🗑️ Clear Results", key="m6_clear_btn", use_container_width=True)

    if clear_clicked:
        st.session_state["m6_results"] = None
        st.rerun()

    if pull_clicked:
        if input_domain.strip():
            root_domain = clean_to_root_domain(input_domain)
            st.info(f"⚙️ Target auto-cleaned down to Registry Root Domain: `{root_domain}`")
            
            if f"Whois: {root_domain}" not in st.session_state["scan_history"]:
                st.session_state["scan_history"].append(f"Whois: {root_domain}")

            try:
                with st.spinner("Querying centralized root registry node gateways..."):
                    rdap_endpoint = f"https://rdap.org/domain/{root_domain}"
                    response = requests.get(rdap_endpoint, timeout=10)
                
                if response.status_code == 200:
                    st.session_state["m6_results"] = {"data": response.json(), "root_domain": root_domain}
                else:
                    st.error(f"RDAP root registrar missing target response (Code: {response.status_code}). Base root domain verification required.")
            except Exception as e:
                st.error(f"Registry connection pipeline error: {e}")
        else:
            st.error("Please provide a valid domain string!")

    if st.session_state["m6_results"]:
        res = st.session_state["m6_results"]
        creation_date, expiration_date = "Hidden/Unlisted", "Hidden/Unlisted"
        for event in res["data"].get("events", []):
            if event.get("eventAction") == "registration": creation_date = event.get("eventDate", "").split("T")[0]
            elif event.get("eventAction") == "expiration": expiration_date = event.get("eventDate", "").split("T")[0]

        col1, col2 = st.columns(2)
        with col1: st.info(f"🌐 **Base Domain:** `{res['root_domain']}`\n\n📅 **Created On:** `{creation_date}`")
        with col2: st.warning(f"⏳ **Expires On:** `{expiration_date}`")
        
        st.markdown("---")
        st.markdown("💡 **Result Intel:** Official registry databases map root asset lifecycles.")
        rdap_report = f"RDAP WHOIS Database Dump:\nRoot Asset Name: {res['root_domain']}\nCreated on: {creation_date}\nExpires on: {expiration_date}"
        st.download_button("📥 Download Official Registry Logs", data=rdap_report, file_name=f"whois_report_{res['root_domain']}.txt", key="m6_download_report_btn")

# =========================================================================
# MODULE 7: SSL/TLS CRYPTOGRAPHIC INSPECTOR
# =========================================================================
elif module_choice == "🔒 SSL/TLS Cryptographic Inspector":
    st.title("🔒 SSL/TLS Cryptographic Inspector")
    st.markdown("> 📌 **Quick Intel:** Connects directly over port 443 to parse certificate validity cycles and validating authorities.")

    if "m7_results" not in st.session_state:
        st.session_state["m7_results"] = None

    ssl_domain = st.text_input("🛡️ Enter Domain Name for SSL Handshake:", placeholder="e.g., netlify.app", key="m7_ssl_input")

    m7_col_b1, m7_col_b2 = st.columns(2)
    with m7_col_b1:
        verify_clicked = st.button("🔒 Trigger Cryptographic Verification", key="m7_ssl_verify_btn", use_container_width=True)
    with m7_col_b2:
        clear_clicked = st.button("🗑️ Clear Results", key="m7_clear_btn", use_container_width=True)

    if clear_clicked:
        st.session_state["m7_results"] = None
        st.rerun()

    if verify_clicked:
        if ssl_domain.strip():
            clean_ssl = clean_to_pure_hostname(ssl_domain)
            if f"SSL: {clean_ssl}" not in st.session_state["scan_history"]:
                st.session_state["scan_history"].append(f"SSL: {clean_ssl}")

            with st.status("Initiating Advanced TLS Connection...", expanded=True) as status_block:
                try:
                    status_block.write(f"🔌 Building TCP Socket channel onto `{clean_ssl}:443`...")
                    sock = socket.create_connection((clean_ssl, 443), timeout=6)
                    ctx = ssl.create_default_context()
                    ctx.set_alpn_protocols(['http/1.1', 'h2'])
                    ssock = ctx.wrap_socket(sock, server_hostname=clean_ssl)
                    cert = ssock.getpeercert()
                    ssock.close()
                    sock.close()
                    
                    if cert:
                        status_block.update(label="✅ Handshake Complete & Verified!", state="complete")
                        st.session_state["m7_results"] = {"cert": cert, "clean_ssl": clean_ssl}
                    else:
                        status_block.update(label="⚠️ Cert data payload is unreadable.", state="error")
                except Exception as e:
                    status_block.update(label="❌ Handshake Interrupted / Aborted!", state="error")
                    st.error(f"Secure handshake protocol aborted: {e}")
        else:
            st.error("Please insert a target host domain!")

    if st.session_state["m7_results"]:
        res = st.session_state["m7_results"]
        issuer_map = {}
        try:
            for item in res["cert"].get('issuer', []):
                for sub_tuple in item:
                    if len(sub_tuple) == 2: issuer_map[sub_tuple[0]] = sub_tuple[1]
        except Exception: pass
                        
        issuer_string = f"{issuer_map.get('organizationName', '')} ({issuer_map.get('commonName', '')})".strip(" ()")
        if not issuer_string: issuer_string = str(res["cert"].get('issuer', 'Unknown Authority'))
        valid_till = res["cert"].get('notAfter', 'N/A')
        
        col1, col2 = st.columns(2)
        with col1: st.success(f"🤝 **Verified Issuer CA:**\n\n`{issuer_string}`")
        with col2: st.error(f"🚨 **Expiration Deadline:**\n\n`{valid_till}`")
        
        st.markdown("---")
        ssl_report = f"SSL/TLS Cert Audit for {res['clean_ssl']}\nIssuer CA Signature: {issuer_string}\nExpiration Deadline: {valid_till}"
        st.download_button("📥 Download Cryptographic Audit Report", data=ssl_report, file_name=f"ssl_audit_{res['clean_ssl']}.txt", key="m7_download_report_btn")
