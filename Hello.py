import csv
import requests
import pandas as pd
import dns.resolver
import ssl
import socket
import streamlit as st
from datetime import datetime
import whois
from streamlit.logger import get_logger
from bs4 import BeautifulSoup

LOGGER = get_logger(__name__)


def fetch_subdomains(domain):
    # Construct the URL for querying crt.sh
    url = f"https://crt.sh/?q=%.{domain}&output=json"

    # Send the request
    try:
        response = requests.get(url)
        if response.status_code == 200:
            # Parse the JSON response
            json_data = response.json()
            # Extract sub-domains
            subdomains = set()
            for entry in json_data:
                # Extract the name_value field, which contains the domain names
                name_value = entry.get('name_value')
                if not name_value:
                    continue
                # Some entries might contain multiple names separated by '\n'
                for name in name_value.split('\n'):
                    # Basic validation to exclude wildcard entries and ensure it belongs to the domain
                    if '*' not in name and domain in name:
                        subdomains.add(name)
            return list(subdomains)
        else:
            LOGGER.error(f"Failed to fetch data for {domain}. Status code: {response.status_code}")
            return []
    except Exception as e:
        LOGGER.error(f"An error occurred: {e}")
        return []


def fetch_whois_info(domain):
    try:
        w = whois.whois(domain)
        # Extracting specific fields; adjust these as needed
        whois_data = {
            "registrar": w.registrar,
            "creation_date": w.creation_date,
            "expiration_date": w.expiration_date,
            "emails": w.emails
        }
        return whois_data
    except Exception as e:
        return {"error": f"Failed to fetch WHOIS info for {domain}: {e}"}

def fetch_dns_records(domain):
    records = {}
    record_types = ['A', 'MX', 'NS', 'TXT', 'CNAME']
    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            records[record_type] = "; ".join([rdata.to_text() for rdata in answers])
        except Exception as e:
            records[record_type] = f"Error: {str(e)}"
    return records

def get_ssl_certificate(domain):
    try:
        # Connect to the domain over port 443 (SSL)
        context = ssl.create_default_context()
        conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain)
        conn.settimeout(10.0)  # Set timeout to 10 seconds
        conn.connect((domain, 443))
        ssl_info = conn.getpeercert()
        exp_date = ssl_info['notAfter']
        exp_date = datetime.strptime(exp_date, '%b %d %H:%M:%S %Y %Z')

        # Normalize the issuer data
        issuer = ssl_info.get('issuer')
        issuer_str = ', '.join([str(i[0][1]) for i in issuer]) if issuer else "N/A"

        return {"domain": domain, "expiry_date": exp_date, "issuer": issuer_str}
    except Exception as e:
        return {"domain": domain, "error": str(e), "issuer": "Error fetching issuer"}

def is_url_live(url):
    try:
        response = requests.get(url, timeout=10, allow_redirects=True)
        if 200 <= response.status_code < 400:
            live = True
            status_code = response.status_code
            redirect_url = response.url if response.url != url else None
        else:
            live = False
            status_code = response.status_code
            redirect_url = None
    except requests.RequestException as e:
        live = False
        status_code = str(e)
        redirect_url = None
    
    # Ensure this function always returns a tuple of three values
    return live, status_code, redirect_url

def subdomains_to_dataframe(subdomains):
    df_rows = []
    for domain, subs in subdomains.items():
        for sub in subs:
            ssl_info = get_ssl_certificate(sub)
            dns_records = fetch_dns_records(sub)
            whois_info = fetch_whois_info(sub)
            live, status, redirect_url = is_url_live(f"http://{sub}")
            
            row = {
                "Parent Domain": domain,
                "Subdomain": sub,
                "SSL Expiry Date": ssl_info.get("expiry_date", "N/A"),
                "SSL Issuer": ssl_info.get("issuer", "N/A"),
                "SSL Error": ssl_info.get("error", ""),
                "Registrar": whois_info.get("registrar", "N/A"),
                "Creation Date": whois_info.get("creation_date", "N/A"),
                "Expiration Date": whois_info.get("expiration_date", "N/A"),
                "WHOIS Emails": whois_info.get("emails", "N/A"),
                "WHOIS Error": whois_info.get("error", ""),
                "URL Live": live,
                "Status Code": status,
                "Redirect URL": redirect_url if redirect_url else "No Redirect"
            }
            for record_type, record_string in dns_records.items():
                row[f"{record_type} Records"] = record_string
            df_rows.append(row)
    df = pd.DataFrame(df_rows)
    # Ensure consistent data types
    df['SSL Issuer'] = df['SSL Issuer'].astype(str)
    return df

st.set_page_config(
    page_title="Domain Info Fetcher",
    page_icon="🌐",
)

st.title('Domain Info Fetcher')

# Option to enter domains directly
domains_input = st.text_area("Enter domains (one per line):")

# Option to upload a CSV file of domains
uploaded_file = st.file_uploader("Or upload a CSV file with domains:", type=['csv'])

domains = []
if domains_input:
    domains = domains_input.split('\n')  # Process direct input

if uploaded_file is not None:
    try:
        # Process uploaded file
        domains_df = pd.read_csv(uploaded_file)
        domains.extend(domains_df.iloc[:, 0].tolist())  # Assuming domains are in the first column
    except Exception as e:
        st.error(f"Error reading uploaded file: {e}")

# Button to start processing
if st.button('Fetch Domain Information'):
    if domains:
        all_subdomains = {}
        for domain in domains:
            subdomains = fetch_subdomains(domain)
            if subdomains:
                all_subdomains[domain] = subdomains
            else:
                all_subdomains[domain] = ["No subdomains found"]

        # Create DataFrame and display
        df_subdomains = subdomains_to_dataframe(all_subdomains)
        st.dataframe(df_subdomains)

        # Optional: Allow downloading of the DataFrame as CSV
        csv = df_subdomains.to_csv(index=False).encode('utf-8')
        st.download_button(
            label="Download data as CSV",
            data=csv,
            file_name='domain_info.csv',
            mime='text/csv',
        )
    else:
        st.error('Please enter domain(s) or upload a CSV file.')
