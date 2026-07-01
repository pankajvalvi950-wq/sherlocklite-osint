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
if module_choice == "👤 Username Threat Scanner":
    st.title("👤 Username Threat Scanner")
    st.markdown("> 📌 **Quick Intel:** Maps identical user handles across 18 major digital platforms in parallel.")

    target_user = st.text_input("🎯 Enter Target Username / Name:", placeholder="e.g., pankajvalvi")

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

    def scan_single_site(site_name, config, username):
        target_url = config["url"].format(username)
        current_headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}
        try:
            response = requests.get(target_url, headers=current_headers, timeout=5, allow_redirects=config["redirect"])
            if response.status_code == 200:
                if "reddit" in target_url and "error" in response.text:
                    return {"status": "not_found", "site": site_name}
                return {"status": "found", "site": site_name, "url": target_url}
            # YAHAN BADLAV KIYA HAI: 301, 302 aur 401 ko add kiya hai taki Instagram redirect hone par sahi se catch ho sake
            elif response.status_code in [301, 302, 401, 403, 429, 999]:
                return {"status": "blocked", "site": site_name, "url": target_url}
            return {"status": "not_found", "site": site_name}
        except Exception:
            return {"status": "not_found", "site": site_name}

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
            st.markdown("💡 **Result Intel:** Active hits confirm registered digital accounts with matching identity handles. Guarded networks mean user accounts might exist but are hidden behind strict authorization headers.")
            
            report_text = f"--- SHERLOCKLITE OSINT SCAN REPORT ---\nTarget Username: {target_user}\nScan Time: {datetime.now()}\n\n[Active Hits]\n"
            for site, url in sorted(found_profiles): report_text += f"- {site}: {url}\n"
            st.download_button("📥 Download Encrypted OSINT Log Report", data=report_text, file_name=f"osint_report_{target_user}.txt")
        else:
            st.error("Please enter a target username!")

# =========================================================================
# MODULE 2: LIVE IP INTELLIGENCE TRACKER
# =========================================================================
elif module_choice == "🌐 IP Intelligence Tracker":
    st.title("🌐 IP Intelligence Tracker")
    st.markdown("> 📌 **Quick Intel:** Extracts geographical location, ISP data, ASN routes, and coordinates from any public IP or domain.")

    ip_input = st.text_input("📡 Enter Target IP Address or Domain Name:", placeholder="e.g., 8.8.8.8 or netlify.app")

    if st.button("🔍 Trace IP Address"):
        if ip_input.strip():
            with st.spinner("Resolving destination routes and querying global geolocation nodes..."):
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
                        st.markdown("💡 **Result Intel:** Geolocation values show routing checkpoints assigned by regional Internet Service Providers (ISPs), pinpointing network origin coordinates.")
                        
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
    st.markdown("> 📌 **Quick Intel:** Probes critical ports to detect open communication channels and active service signatures.")

    target_host = st.text_input("💻 Enter Target Domain / Host IP:", placeholder="e.g., scanme.nmap.org")

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

    if st.button("⚡ Trigger Stealth Port Audit"):
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
            
            p_tab1, p_tab2 = st.tabs(["🟢 Open Ports", "🔴 Closed / Blocked"])
            with p_tab1:
                if open_ports:
                    for item in open_ports: st.error(f"🔓 **Port {item['port']}** is OPEN -> Running `{item['service']}`")
                else: st.success("Excellent: No open core communication ports exposed directly.")
            with p_tab2:
                for item in closed_ports: st.text(f"🔒 Port {item['port']} ({item['service']}) - Closed / Safe.")
            
            st.markdown("---")
            st.markdown("💡 **Result Intel:** Exposed open entry points represent listening listeners. Unused ports should remain CLOSED or hidden behind firewall protocols to block lateral movement threats.")
            
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
    st.markdown("> 📌 **Quick Intel:** Enumerates common host prefix vectors to locate active corporate sub-assets and microservices.")

    target_domain = st.text_input("🌐 Enter Base Domain Name:", placeholder="e.g., google.com (Use root domains for accurate maps)")
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

            d_tab1, d_tab2 = st.tabs(["🟢 Active Subdomains", "🔴 Non-Responsive"])
            with d_tab1:
                if alive_subs:
                    for item in alive_subs: st.markdown(f"🌐 **{item['subdomain']}** -> IP: `{item['ip']}`")
                else: st.warning("No standard organizational subdomains resolved for this scope.")
            with d_tab2:
                for item in dead_subs: st.caption(f"❌ {item['subdomain']}")
            
            st.markdown("---")
            st.markdown("💡 **Result Intel:** Discovering active subdomains maps out an entity's internal attack surface, unmasking hidden staging boxes or API entry points.")
            
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
    st.markdown("> 📌 **Quick Intel:** Extracts server framework banners and audits missing security policy configurations (CSP, HSTS, X-Frame).")

    target_url = st.text_input("🔗 Enter Target Website URL:", placeholder="e.g., https://google.com")

    if st.button("🛡️ Audit Web Security Headers"):
        if target_url.strip():
            clean_host = clean_to_pure_hostname(target_url)
            url = "https://" + clean_host
            try:
                if f"Headers: {url}" not in st.session_state["scan_history"]:
                    st.session_state["scan_history"].append(f"Headers: {url}")

                with st.spinner("Capturing transmission response headers..."):
                    browser_headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
                    response = requests.get(url, timeout=6, headers=browser_headers, allow_redirects=True)
                
                headers = response.headers
                st.success("🎯 Metatag connection signatures cataloged!")

                security_checks = {
                    "Strict-Transport-Security": "Forces secure HTTPS tunnels.",
                    "Content-Security-Policy": "Mitigates XSS injections.",
                    "X-Frame-Options": "Defends against Clickjacking structures.",
                    "X-Content-Type-Options": "Blocks unauthorized MIME type sniffing."
                }

                audit_log = f"HTTP Security Audit Summary for {url}\nEvaluated at: {datetime.now()}\n\n"
                for key, description in security_checks.items():
                    matched = next((k for k in headers if k.lower() == key.lower()), None)
                    if matched: 
                        st.success(f"🟢 **{key}** is ACTIVE!\n* Value: `{headers[matched]}`")
                        audit_log += f"[OK] {key}: {headers[matched]}\n"
                    else: 
                        st.error(f"🔴 **{key}** is MISSING!\n* Impact: {description}")
                        audit_log += f"[VULNERABILITY] {key} is absent -> {description}\n"
                
                st.markdown("---")
                st.markdown("💡 **Result Intel:** Missing HTTP security policy headers leave web browsers unprotected against common automated client-side injection vectors.")
                st.download_button("📥 Download Security Header Audit Log", data=audit_log, file_name=f"header_audit_{clean_host}.txt")
            except Exception as e:
                st.error(f"Web server pipeline rejected query: {e}")

# =========================================================================
# MODULE 6: DOMAIN REGISTRY & WHOIS (RDAP)
# =========================================================================
elif module_choice == "📜 Domain Registry & Whois (RDAP)":
    st.title("📜 Domain Registry & Whois (RDAP)")
    st.markdown("> 📌 **Quick Intel:** Direct RDAP query mechanism to extract official registrar logs, registration dates, and expiry checkpoints.")

    input_domain = st.text_input("📝 Enter Target Domain Name:", placeholder="e.g., netlify.app")

    if st.button("🔍 Pull Registry Metadata"):
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
                    data = response.json()
                    
                    creation_date, expiration_date = "Hidden/Unlisted", "Hidden/Unlisted"
                    for event in data.get("events", []):
                        if event.get("eventAction") == "registration": creation_date = event.get("eventDate", "").split("T")[0]
                        elif event.get("eventAction") == "expiration": expiration_date = event.get("eventDate", "").split("T")[0]

                    col1, col2 = st.columns(2)
                    with col1: st.info(f"🌐 **Base Domain:** `{root_domain}`\n\n📅 **Created On:** `{creation_date}`")
                    with col2: st.warning(f"⏳ **Expires On:** `{expiration_date}`")
                    
                    st.markdown("---")
                    st.markdown("💡 **Result Intel:** Official registry databases map root asset lifecycles. Subdomains (like *.netlify.app) do not have independent registry papers because they belong under the main provider domain.")
                    
                    rdap_report = f"RDAP WHOIS Database Dump:\nRoot Asset Name: {root_domain}\nCreated on: {creation_date}\nExpires on: {expiration_date}"
                    st.download_button("📥 Download Official Registry Logs", data=rdap_report, file_name=f"whois_report_{root_domain}.txt")
                else:
                    st.error(f"RDAP root registrar missing target response (Code: {response.status_code}). Base root domain verification required.")
            except requests.exceptions.Timeout:
                st.error("🚨 Public RDAP registry gatekeeper timed out. Network queues are congested. Try again in a few moments.")
            except Exception as e:
                st.error(f"Registry connection pipeline error: {e}")
        else:
            st.error("Please provide a valid domain string!")

# =========================================================================
# MODULE 7: SSL/TLS CRYPTOGRAPHIC INSPECTOR
# =========================================================================
elif module_choice == "🔒 SSL/TLS Cryptographic Inspector":
    st.title("🔒 SSL/TLS Cryptographic Inspector")
    st.markdown("> 📌 **Quick Intel:** Connects directly over port 443 to parse certificate validity cycles and validating authorities.")

    ssl_domain = st.text_input("🛡️ Enter Domain Name for SSL Handshake:", placeholder="e.g., free-gst-invoice.netlify.app")

    if st.button("🔒 Trigger Cryptographic Verification"):
        if ssl_domain.strip():
            clean_ssl = clean_to_pure_hostname(ssl_domain)
            
            if f"SSL: {clean_ssl}" not in st.session_state["scan_history"]:
                st.session_state["scan_history"].append(f"SSL: {clean_ssl}")

            with st.status("Initiating Advanced TLS Connection...", expanded=True) as status_block:
                try:
                    status_block.write(f"🔌 Building TCP Socket channel onto `{clean_ssl}:443`...")
                    sock = socket.create_connection((clean_ssl, 443), timeout=6)
                    
                    status_block.write("🔒 Preparing security engine configuration with modern SNI/ALPN context blocks...")
                    ctx = ssl.create_default_context()
                    ctx.set_alpn_protocols(['http/1.1', 'h2']) 
                    
                    status_block.write("🤝 Negotiating secure cryptographic wrapper keys...")
                    ssock = ctx.wrap_socket(sock, server_hostname=clean_ssl)
                    
                    status_block.write("📜 Parsing active certificate mapping records...")
                    cert = ssock.getpeercert()
                    ssock.close()
                    sock.close()
                    
                    if cert:
                        status_block.update(label="✅ Handshake Complete & Verified!", state="complete")
                        
                        issuer_map = {}
                        try:
                            for item in cert.get('issuer', []):
                                for sub_tuple in item:
                                    if len(sub_tuple) == 2:
                                        issuer_map[sub_tuple[0]] = sub_tuple[1]
                        except Exception:
                            pass
                                    
                        issuer_org = issuer_map.get('organizationName', '')
                        issuer_cn = issuer_map.get('commonName', '')
                        
                        if not issuer_org and not issuer_cn:
                            issuer_string = str(cert.get('issuer', 'Unknown Issuer Certificate Authority'))
                        else:
                            issuer_string = f"{issuer_org} ({issuer_cn})".strip(" ()")
                            
                        valid_till = cert.get('notAfter', 'N/A')
                        
                        col1, col2 = st.columns(2)
                        with col1: 
                            st.success(f"🤝 **Verified Issuer CA:**\n\n`{issuer_string}`")
                        with col2: 
                            st.error(f"🚨 **Expiration Deadline:**\n\n`{valid_till}`")
                            
                        st.markdown("---")
                        st.markdown("💡 **Result Intel:** Validates active encryption infrastructure keys. Expired keys trigger system browser blocks for incoming client traffic.")
                        
                        ssl_report = f"SSL/TLS Cert Audit for {clean_ssl}\nIssuer CA Signature: {issuer_string}\nExpiration Deadline: {valid_till}"
                        st.download_button("📥 Download Cryptographic Audit Report", data=ssl_report, file_name=f"ssl_audit_{clean_ssl}.txt")
                    else:
                        status_block.update(label="⚠️ Handshake complete, but cert data payload is unreadable.", state="error")
                        st.warning("Handshake complete, but verification payload was unreadable.")
                        
                except Exception as e:
                    status_block.update(label="❌ Handshake Interrupted / Aborted!", state="error")
                    st.error(f"Secure handshake protocol aborted: {e}")
                    st.info("💡 **Cyber Context Note:** Modern proxies (like local tunnels or invalid host inputs) might reject external raw TCP handshakes. Ensure the host is publicly addressable on Port 443.")
        else:
            st.error("Please insert a target host domain!")
