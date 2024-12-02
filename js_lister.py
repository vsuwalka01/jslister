import os
import re
import requests
import subprocess
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("js_lister.log")
    ]
)

# Tool Introduction
def print_intro():
    print("=" * 50)
    print("    JS Lister - A Tool to Extract and Analyze JavaScript Files")
    print("    Created by: Vishal Suwalka")
    print("=" * 50)

# Comprehensive regex patterns for sensitive data
regex_patterns = {
    "API Key": r"(?:[\'\"]?)([A-Za-z0-9_-]{32,45})(?:[\'\"]?)",
    "JWT Token": r"eyJ[a-zA-Z0-9_-]+?\.[a-zA-Z0-9_-]+?\.[a-zA-Z0-9_-]+",
    "AWS Access Key ID": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Access Key": r"(?:aws|AWS)?[-]?SECRET[-]?ACCESS[_-]?KEY[\"\']?\s*[:=][\"\']?([A-Za-z0-9/+=]{40})",
    "Google API Key": r"AIza[0-9A-Za-z-_]{35}",
    "Slack Token": r"xox[baprs]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}",
    "OAuth Token": r"[a-zA-Z0-9-_]{20,200}",
    "Stripe API Key": r"(?:sk_live|sk_test)_[0-9a-zA-Z]{24}",
    "Private RSA Key": r"-----BEGIN PRIVATE KEY-----[\s\S]+?-----END PRIVATE KEY-----",
    "SSH Private Key": r"-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]+?-----END OPENSSH PRIVATE KEY-----",
    "GitHub Token": r"ghp_[A-Za-z0-9]{36}",
    "Database Connection Strings": r"(?:jdbc|mongodb|mysql|postgres|oracle):\/\/(?:[^:\/\s]+)(?::([^@\/\s]+))?@(?:[^\s]+)",
    "Firebase Database URL": r"https:\/\/[a-z0-9-]+\.firebaseio\.com",
    "Slack Webhook URLs": r"https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9\/]+",
    "Microsoft Teams Webhook URL": r"https:\/\/[a-zA-Z0-9-]+\.webhook\.office\.com\/webhookb2\/[a-zA-Z0-9-]+",
    "Google OAuth 2.0 Client ID": r"[0-9]+-[a-zA-Z0-9]+\.apps\.googleusercontent\.com",
    "Discord Bot Token": r"mfa\.[a-zA-Z0-9_-]{84}",
    "Facebook Access Token": r"EAACEdEose0cBA[0-9A-Za-z]+",
    "Twilio API Key": r"SK[0-9a-fA-F]{32}",
}

# Function to read subdomains from a file
def read_subdomains(file_path):
    if not os.path.exists(file_path):
        logging.error(f"Subdomain file {file_path} not found!")
        return []
    with open(file_path, 'r') as file:
        subdomains = file.readlines()
    return [subdomain.strip() for subdomain in subdomains]

# Function to run Waybackurls and extract JavaScript file URLs
def run_waybackurls(subdomain):
    try:
        result = subprocess.run(["waybackurls", subdomain], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode != 0:
            logging.error(f"Error running Waybackurls for {subdomain}: {result.stderr}")
            return []
        # Filter for .js files
        js_files = [url for url in result.stdout.splitlines() if url.endswith(".js")]
        return list(set(js_files))  # Remove duplicates
    except FileNotFoundError:
        logging.error("'waybackurls' is not installed or not in your PATH.")
        return []

# Function to extract sensitive data using regex
def extract_sensitive_data(js_content):
    sensitive_data = {}
    for data_type, pattern in regex_patterns.items():
        matches = re.findall(pattern, js_content)
        if matches:
            sensitive_data[data_type] = matches
    return sensitive_data

# Function to save extracted sensitive data
def save_sensitive_data(subdomain, js_file, data):
    if data:
        subdomain_name = subdomain.replace('https://', '').replace('http://', '').replace('/', '_')
        file_path = f"sensitive_data_{subdomain_name}.txt"
        with open(file_path, 'a') as file:
            file.write(f"\nSensitive data found in JS file: {js_file}\n")
            for data_type, matches in data.items():
                file.write(f"  {data_type}:\n")
                for match in matches:
                    file.write(f"    {match}\n")
        logging.info(f"Sensitive data saved to {file_path}")
    else:
        logging.info(f"No sensitive data found in {js_file}")

# Function to process each subdomain
def process_subdomains(subdomains):
    for subdomain in subdomains:
        logging.info(f"Processing subdomain: {subdomain}")
        if not subdomain.startswith(("http://", "https://")):
            subdomain = f"http://{subdomain}"

        # Run Waybackurls to get JS file links
        js_files = run_waybackurls(subdomain)
        if not js_files:
            logging.info(f"No JavaScript files found for {subdomain}.")
            continue

        logging.info(f"Found {len(js_files)} unique JS files for {subdomain}.")
        for js_file in js_files:
            try:
                logging.info(f"Checking JS file: {js_file}")
                response = requests.get(js_file, timeout=10)
                if response.status_code == 200:
                    sensitive_data = extract_sensitive_data(response.text)
                    save_sensitive_data(subdomain, js_file, sensitive_data)
                else:
                    logging.warning(f"Failed to fetch JS file {js_file}, status code: {response.status_code}")
            except requests.exceptions.RequestException as e:
                logging.error(f"Error fetching JS file {js_file}: {e}")

# Main function to execute the tool
def main():
    print_intro()
    subdomain_file = "subdomains.txt"  # Path to your subdomain list
    subdomains = read_subdomains(subdomain_file)
    if not subdomains:
        logging.error("No subdomains to process. Exiting.")
        return
    process_subdomains(subdomains)

if __name__ == "__main__":
    main()

