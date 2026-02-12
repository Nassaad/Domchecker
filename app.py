import streamlit as st
import pandas as pd
import dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed
import socket
import time

# -------------------------
# Page Setup
# -------------------------
st.set_page_config(page_title="Security Dashboard", layout="wide")

# -------------------------
# Sidebar Navigation
# -------------------------
page = st.sidebar.radio("Navigate to:", ["Welcome", "Domain Checks", "IP Checks"])

# -------------------------
# Resolver for DNS
# -------------------------
resolver = dns.resolver.Resolver()
resolver.nameservers = ["8.8.8.8", "1.1.1.1"]

# -------------------------
# Welcome Page
# -------------------------
if page == "Welcome":
    st.title("🛡️ Welcome to Security Dashboard")
    st.markdown("""
    Use the sidebar to navigate between **Domain Checks** and **IP Checks**.
    
    ### Instructions:
    - Upload a TXT file with domains or IPs (one per line) on the respective page.
    - Use the filters to refine results.
    - Click links in the table to open MXToolbox or Talos checks in a new tab.
    """)

# -------------------------
# Domain Checks Page
# -------------------------
elif page == "Domain Checks":
    st.title("📄 Domain Security & Reputation Checks")

    uploaded_file = st.file_uploader("Upload TXT file with domains (one per line)", type=["txt"])

    @st.cache_data
    def read_domains(file):
        content = file.read().decode("utf-8").splitlines()
        return [d.strip().lower() for d in content if d.strip()]

    def get_spf(domain):
        try:
            answers = resolver.resolve(domain, "TXT", lifetime=5)
            for rdata in answers:
                txt = "".join([part.decode() for part in rdata.strings])
                if txt.lower().startswith("v=spf1"):
                    return txt
        except:
            return None

    def get_dmarc(domain):
        try:
            answers = resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=5)
            for rdata in answers:
                txt = "".join([part.decode() for part in rdata.strings])
                if txt.lower().startswith("v=dmarc"):
                    return txt
        except:
            return None

    def process_domain(domain):
        spf = get_spf(domain)
        dmarc = get_dmarc(domain)
        spf_plus = "Yes" if spf and "+all" in spf.lower() else "No"
        spf_qmark = "Yes" if spf and "?all" in spf.lower() else "No"
        return {
            "Domain": domain,
            "DMARC": "Yes" if dmarc else "No",
            "SPF": "Yes" if spf else "No",
            "SPF +all": spf_plus,
            "SPF ?all": spf_qmark,
            "MXToolbox": f"https://mxtoolbox.com/SuperTool.aspx?action=mx%3a{domain}",
            "Talos": f"https://talosintelligence.com/reputation_center/lookup?search={domain}",
            "Blacklist": f"https://mxtoolbox.com/SuperTool.aspx?action=blacklist%3a{domain}&run=toolpage"
        }

    if uploaded_file:
        domains = read_domains(uploaded_file)
        progress_bar = st.progress(0)
        results = []

        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(process_domain, d): d for d in domains}
            for i, future in enumerate(as_completed(futures)):
                results.append(future.result())
                progress_bar.progress((i + 1)/len(domains))

        df = pd.DataFrame(results)

        # -------------------------
        # Sidebar Filters
        # -------------------------
        st.sidebar.header("Filters")
        dmarc_filter = st.sidebar.selectbox("DMARC", ["All", "Yes", "No"])
        spf_filter = st.sidebar.selectbox("SPF", ["All", "Yes", "No"])
        plusall_filter = st.sidebar.selectbox("SPF +all", ["All", "Yes", "No"])
        qmark_filter = st.sidebar.selectbox("SPF ?all", ["All", "Yes", "No"])
        blacklist_filter = st.sidebar.selectbox("Blacklist", ["All", "Yes", "No"])

        df_filtered = df.copy()
        if dmarc_filter != "All":
            df_filtered = df_filtered[df_filtered["DMARC"] == dmarc_filter]
        if spf_filter != "All":
            df_filtered = df_filtered[df_filtered["SPF"] == spf_filter]
        if plusall_filter != "All":
            df_filtered = df_filtered[df_filtered["SPF +all"] == plusall_filter]
        if qmark_filter != "All":
            df_filtered = df_filtered[df_filtered["SPF ?all"] == qmark_filter]
        if blacklist_filter != "All":
            df_filtered = df_filtered[df_filtered["Blacklist"] == blacklist_filter]

        # -------------------------
        # Render Table
        # -------------------------
        def render_table(df):
            html = """
            <div style="overflow-x:auto; max-height:600px; border-radius:8px; box-shadow: 0 4px 8px rgba(0,0,0,0.3);">
            <table style="border-collapse: collapse; width:100%; font-family: Arial, sans-serif; border-radius:8px; overflow:hidden;">
            <thead style="position: sticky; top: 0; background-color:#121212; color:white; z-index:1;">
            <tr>
            """
            for col in df.columns:
                html += f'<th style="padding:10px; text-align:center; color:white">{col}</th>'
            html += "</tr></thead><tbody>"

            for _, row in df.iterrows():
                html += f'<tr style="background-color:#1e1e1e; color:white;">'
                for col in df.columns:
                    if col in ["MXToolbox", "Talos", "Blacklist"]:
                        html += f'<td style="text-align:center; padding:8px;"><a href="{row[col]}" target="_blank" style="color:#4fc3f7; text-decoration:none;">Open</a></td>'
                    else:
                        html += f'<td style="text-align:center; padding:8px; color:white">{row[col]}</td>'
                html += "</tr>"
            html += "</tbody></table></div>"
            return html

        st.subheader("Domain Results")
        st.markdown(render_table(df_filtered), unsafe_allow_html=True)

        st.download_button(
            "Download results as CSV",
            df_filtered.drop(columns=["MXToolbox", "Talos", "Blacklist"]).to_csv(index=False),
            "domain_results.csv",
            "text/csv"
        )

# -------------------------
# IP Checks Page
# -------------------------
elif page == "IP Checks":
    st.title("🌐 IP Checks Dashboard")

    uploaded_file = st.file_uploader("Upload TXT file with IPs (one per line, max 50 per run)", type=["txt"])

    def read_ips(file):
        content = file.read().decode("utf-8").splitlines()
        return [ip.strip() for ip in content if ip.strip()]

    def reverse_dns(ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return None

    def spamhaus_blacklist(ip):
        try:
            reversed_ip = ".".join(ip.split(".")[::-1])
            query = f"{reversed_ip}.zen.spamhaus.org"
            resolver.resolve(query, "A", lifetime=3)
            return "Yes"
        except dns.resolver.NXDOMAIN:
            return "No"
        except:
            return "Unknown"

    if uploaded_file:
        ips = read_ips(uploaded_file)

        if len(ips) > 50:
            st.warning("⚠️ You can check a maximum of 50 IPs per run. Truncating list.")
            ips = ips[:50]

        progress_bar = st.progress(0)
        results = []

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(lambda ip: {
                "IP": ip,
                "Reverse DNS": reverse_dns(ip),
                "Spamhaus Blacklist": spamhaus_blacklist(ip),
                "MXToolbox Blacklist": f"https://mxtoolbox.com/SuperTool.aspx?action=blacklist%3a{ip}&run=toolpage"
            }, ip): ip for ip in ips}

            for i, future in enumerate(as_completed(futures)):
                results.append(future.result())
                progress_bar.progress((i + 1)/len(ips))

        df = pd.DataFrame(results)

        # -------------------------
        # Sidebar Filters for IPs
        # -------------------------
        st.sidebar.header("Filters")
        reverse_filter = st.sidebar.selectbox("Reverse DNS Exists", ["All", "Yes", "No"])
        spamhaus_filter = st.sidebar.selectbox("Spamhaus Blacklist", ["All", "Yes", "No", "Unknown"])

        df_filtered = df.copy()
        if reverse_filter != "All":
            df_filtered = df_filtered[df_filtered["Reverse DNS"].notnull() if reverse_filter == "Yes" else df_filtered["Reverse DNS"].isnull()]
        if spamhaus_filter != "All":
            df_filtered = df_filtered[df_filtered["Spamhaus Blacklist"] == spamhaus_filter]

        # -------------------------
        # Render modern dark table
        # -------------------------
        def render_table(df):
            html = """
            <div style="overflow-x:auto; max-height:600px; border-radius:8px; box-shadow: 0 4px 8px rgba(0,0,0,0.3);">
            <table style="border-collapse: collapse; width:100%; font-family: Arial, sans-serif; border-radius:8px; overflow:hidden;">
            <thead style="position: sticky; top: 0; background-color:#121212; color:white; z-index:1;">
            <tr>
            """
            for col in df.columns:
                html += f'<th style="padding:10px; text-align:center; color:white">{col}</th>'
            html += "</tr></thead><tbody>"

            for _, row in df.iterrows():
                html += f'<tr style="background-color:#1e1e1e; color:white;">'
                for col in df.columns:
                    if col in ["MXToolbox Blacklist"]:
                        html += f'<td style="text-align:center; padding:8px;"><a href="{row[col]}" target="_blank" style="color:#4fc3f7; text-decoration:none;">Open</a></td>'
                    else:
                        html += f'<td style="text-align:center; padding:8px; color:white">{row[col]}</td>'
                html += "</tr>"
            html += "</tbody></table></div>"
            return html

        st.subheader("IP Results")
        st.markdown(render_table(df_filtered), unsafe_allow_html=True)

        st.download_button(
            "Download results as CSV",
            df_filtered.drop(columns=["MXToolbox Blacklist"]).to_csv(index=False),
            "ip_results.csv",
            "text/csv"
        )
