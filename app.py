import streamlit as st
import dns.resolver
import pandas as pd
from concurrent.futures import ThreadPoolExecutor, as_completed

st.set_page_config(page_title="Domain Security Checker", layout="wide")
st.title("Domain Security & Reputation Checker")

uploaded_file = st.file_uploader("Upload TXT file with domains (one per line)", type=["txt"])

DNSBLS = [
    "zen.spamhaus.org",
    "bl.spamcop.net",
]

def get_spf(domain):
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        for rdata in answers:
            txt = "".join([part.decode() for part in rdata.strings])
            if txt.lower().startswith("v=spf1"):
                return txt
    except:
        return None
    return None

def get_dmarc(domain):
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        for rdata in answers:
            txt = "".join([part.decode() for part in rdata.strings])
            if txt.lower().startswith("v=dmarc"):
                return txt
    except:
        return None
    return None

def check_dnsbl(domain):
    listed = []
    for bl in DNSBLS:
        try:
            query = ".".join(reversed(domain.split("."))) + "." + bl
            dns.resolver.resolve(query, "A")
            listed.append(bl)
        except:
            pass
    return listed

def process_domain(domain):
    spf = get_spf(domain)
    dmarc = get_dmarc(domain)
    dnsbls = check_dnsbl(domain)

    return {
        "Domain": domain,
        "DMARC": "Yes" if dmarc else "No",
        "SPF": "Yes" if spf else "No",
        "SPF +all": "Yes" if spf and "+all" in spf.lower() else "No",
        "DNSBL Listed": "Yes" if dnsbls else "No",
        "DNSBL Sources": ", ".join(dnsbls) if dnsbls else "—",
        "MXToolbox": f'<a href="https://mxtoolbox.com/SuperTool.aspx?action=mx%3a{domain}" target="_blank">Open</a>',
        "Talos": f'<a href="https://talosintelligence.com/reputation_center/lookup?search={domain}" target="_blank">Open</a>',
    }

if uploaded_file:
    domains = uploaded_file.read().decode("utf-8").splitlines()
    domains = [d.strip().lower() for d in domains if d.strip()]

    results = []

    with st.spinner("Checking domains..."):
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(process_domain, d) for d in domains]

            for future in as_completed(futures):
                results.append(future.result())

    df = pd.DataFrame(results)

    # Render clickable table
    st.markdown(
        df.to_html(escape=False, index=False),
        unsafe_allow_html=True
    )

    st.download_button(
        "Download results as CSV",
        df.drop(columns=["MXToolbox", "Talos"])
          .to_csv(index=False),
        "domain_results.csv",
        "text/csv"
    )