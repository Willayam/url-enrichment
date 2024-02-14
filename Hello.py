import csv
import pandas as pd
import dns.resolver
import logging
import requests
import ssl
import socket
import streamlit as st
import time
from datetime import datetime
import whois
from streamlit.logger import get_logger
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed

LOGGER = get_logger(__name__)

# Setup basic logging configuration
logging.basicConfig(level=logging.INFO)

def log_function_time(func):
    """Decorator to log the execution time of a function."""
    def wrapper(*args, **kwargs):
        start = time.time()
        result = func(*args, **kwargs)
        end = time.time()
        logging.info(f"{func.__name__} executed in {end - start:.4f} seconds")
        return result
    return wrapper

@log_function_time
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

@log_function_time
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

@log_function_time
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

@log_function_time
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

@log_function_time
def is_url_live(url):
    try:
        response = requests.get(url, timeout=3, allow_redirects=True)
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

@log_function_time
def parallel_fetch_subdomains(domains):
    subdomains_aggregated = {}
    with ThreadPoolExecutor(max_workers=20) as executor:
        future_to_domain = {executor.submit(fetch_subdomains, domain): domain for domain in domains}
        
        for future in as_completed(future_to_domain):
            domain = future_to_domain[future]
            try:
                subdomains_aggregated[domain] = future.result()
            except Exception as exc:
                logging.error(f"{domain} generated an exception: {exc}")
                subdomains_aggregated[domain] = []

    return subdomains_aggregated

@log_function_time
def parallel_fetch_details_for_subdomains(subdomains_aggregated):
    # Flatten the list of subdomains for parallel processing
    all_subdomains = [sub for sublist in subdomains_aggregated.values() for sub in sublist]

    # Dictionary to hold fetched details for each subdomain
    subdomain_details = {}
    with ThreadPoolExecutor(max_workers=20) as executor:
        future_to_subdomain = {}
        for subdomain in all_subdomains:
            future_to_subdomain[executor.submit(fetch_whois_info, subdomain)] = (subdomain, 'whois')
            future_to_subdomain[executor.submit(fetch_dns_records, subdomain)] = (subdomain, 'dns')
            future_to_subdomain[executor.submit(get_ssl_certificate, subdomain)] = (subdomain, 'ssl')
            future_to_subdomain[executor.submit(is_url_live, f"http://{subdomain}")] = (subdomain, 'live')

        for future in as_completed(future_to_subdomain):
            subdomain, info_type = future_to_subdomain[future]
            if subdomain not in subdomain_details:
                subdomain_details[subdomain] = {}
            try:
                subdomain_details[subdomain][info_type] = future.result()
            except Exception as exc:
                logging.error(f"{subdomain} generated an exception: {exc}")
                subdomain_details[subdomain][info_type] = None

    return subdomain_details

@log_function_time
def parallel_fetch_info(domains):
    # Dictionary to hold all fetched data
    domain_info = {}

    with ThreadPoolExecutor(max_workers=20) as executor:
        # Initialize an empty dictionary to hold future tasks
        future_to_domain = {}
        
        # Loop over domains to populate the dictionary with future tasks
        for domain in domains:
            future_to_domain[executor.submit(fetch_subdomains, domain)] = (domain, 'subdomains')
            future_to_domain[executor.submit(fetch_whois_info, domain)] = (domain, 'whois')
            future_to_domain[executor.submit(fetch_dns_records, domain)] = (domain, 'dns')
            future_to_domain[executor.submit(get_ssl_certificate, domain)] = (domain, 'ssl')
            future_to_domain[executor.submit(is_url_live, f"http://{domain}")] = (domain, 'live')

        # Process completed futures as they complete
        for future in as_completed(future_to_domain):
            domain, info_type = future_to_domain[future]
            try:
                data = future.result()
                if domain not in domain_info:
                    domain_info[domain] = {}
                domain_info[domain][info_type] = data
            except Exception as exc:
                logging.error(f"{domain} generated an exception: {exc}")
    
    return domain_info


@log_function_time
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
        # Phase 1: Fetch all subdomains for each domain in parallel with feedback
        with st.spinner('Fetching subdomains...'):
            subdomains_aggregated = parallel_fetch_subdomains(domains)

        # Phase 2: Fetch details for each subdomain in parallel with feedback
        with st.spinner('Fetching domain info...'):
            subdomain_details = parallel_fetch_details_for_subdomains(subdomains_aggregated)
        
        # Initialize an empty list for DataFrame rows
        df_rows = []
        for domain, subdomains in subdomains_aggregated.items():
            for sub in subdomains:
                # Fetch detailed info for the subdomain from the aggregated details
                details = subdomain_details.get(sub, {})
                ssl_info = details.get('ssl', {})
                dns_records = details.get('dns', {})
                whois_info = details.get('whois', {})
                live_info = details.get('live', (False, 'N/A', 'No Redirect'))

                # Construct the row for each subdomain
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
                    "URL Live": live_info[0],
                    "Status Code": live_info[1],
                    "Redirect URL": live_info[2]
                }
                # For DNS records, iterate over each record type you're interested in
                for record_type in ['A', 'MX', 'NS', 'TXT', 'CNAME']:
                    row[f"{record_type} Records"] = dns_records.get(record_type, "N/A")

                df_rows.append(row)

        # Convert the list of rows into a DataFrame
        df_subdomains = pd.DataFrame(df_rows)
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