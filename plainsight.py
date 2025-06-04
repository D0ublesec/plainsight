import argparse
import dns.resolver
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import os
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from datetime import datetime
import logging
from urllib.parse import urlparse
import time
import json
import sys
import re
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from colorama import init, Fore, Back, Style
import threading
import queue
import csv
import base64
from bs4 import BeautifulSoup
import warnings
import select

# Import msvcrt only on Windows
if os.name == 'nt':
    import msvcrt

# Disable SSL warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Initialize colorama and rich
init()
console = Console()

# Define color codes for terminal output
class Colors:
    GREEN = Fore.GREEN
    RED = Fore.RED
    ORANGE = Fore.YELLOW
    CYAN = Fore.CYAN
    YELLOW = Fore.YELLOW
    BLUE = Fore.BLUE
    PINK = Fore.MAGENTA
    RESET = Style.RESET_ALL
    BOLD = Style.BRIGHT

def validate_domain(domain):
    """Validate if the provided string is a valid domain."""
    # Basic domain validation regex
    pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain))

def setup_logging(output_dir, verbose_level):
    """Setup logging configuration."""
    # Only create log file if verbose level is set
    if verbose_level > 0:
        log_file = os.path.join(output_dir, f'scan_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')
        
        # Set logging level based on verbose level
        if verbose_level == 2:
            log_level = logging.DEBUG
        else:
            log_level = logging.INFO
        
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )
    else:
        # If not verbose, only log to console
        logging.basicConfig(
            level=logging.WARNING,
            format='%(message)s',
            handlers=[logging.StreamHandler(sys.stdout)]
        )
    return logging.getLogger(__name__)

def print_banner():
    """Print an ASCII banner."""
    banner = """
    _ (`-.              ('-.                  .-') _   .-')                         ('-. .-. .-') _
   ( (OO  )            ( OO ).-.             ( OO ) ) ( OO ).                      ( OO )  /(  OO) )
  _.`     \ ,--.       / . --. /  ,-.-') ,--./ ,--,' (_)---\_)  ,-.-')   ,----.    ,--. ,--./     '._
 (__...--'' |  |.-')   | \-.  \   |  |OO)|   \ |  |\ /    _ |   |  |OO) '  .-./-') |  | |  ||'--...__)
  |  /  | | |  | OO ).-'-'  |  |  |  |  \|    \|  | )\  :` `.   |  |  \ |  |_( O- )|   .|  |'--.  .--'
  |  |_.' | |  |`-' | \| |_.'  |  |  |(_/|  .     |/  '..`''.)  |  |(_/ |  | .--, \|       |   |  |
  |  .___.'(|  '---.'  |  .-.  | ,|  |_.'|  |\    |  .-._)   \ ,|  |_.'(|  | '. (_/|  .-.  |   |  |
  |  |      |      |   |  | |  |(_|  |   |  | \   |  \       /(_|  |    |  '--'  | |  | |  |   |  |
  `--'      `------'   `--' `--'  `--'   `--'  `--'   `-----'   `--'     `------'  `--' `--'   `--'    
    """
    print(f"{Colors.CYAN}{banner}{Colors.RESET}")

def save_results_to_csv(results, output_dir, domain):
    """Save results to CSV format."""
    # Replace dots with underscores in domain name for filename
    safe_domain = domain.replace('.', '_')
    csv_path = os.path.join(output_dir, f"services.csv")
    
    # Prepare CSV data
    csv_data = []
    for service in results['services']:
        csv_data.append({
            'domain': domain,
            'service_url': service['url'],
            'status_code': service['status'],
            'redirect_url': service.get('redirect_url', ''),
            'html_path': service['html_path'],
            'screenshot_path': service['screenshot_path'],
            'logo_url': service.get('logo', {}).get('url', '') if service.get('logo') else ''
        })
    
    # Write CSV file
    if csv_data:
        with open(csv_path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=csv_data[0].keys())
            writer.writeheader()
            writer.writerows(csv_data)

def print_dns_results(dns_results, pretty_output=True):
    """Print DNS results to stdout."""
    if pretty_output:
        print(f"\n{Colors.BOLD}DNS Records:{Colors.RESET}")
        for record_type, records in dns_results.items():
            if records:
                print(f"\n{Colors.CYAN}{record_type} Records:{Colors.RESET}")
                for record in records:
                    print(f"{Colors.GREEN}- {record}{Colors.RESET}")
    else:
        print("\nDNS Records:")
        for record_type, records in dns_results.items():
            if records:
                print(f"\n{record_type} Records:")
                for record in records:
                    print(f"- {record}")

def save_dns_results(dns_results, output_dir, domain):
    """Save DNS results to a text file."""
    dns_path = os.path.join(output_dir, f"dns_records.txt")
    with open(dns_path, 'w') as f:
        f.write(f"DNS Records for {domain}\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        for record_type, records in dns_results.items():
            if records:
                f.write(f"{record_type} Records:\n")
                for record in records:
                    f.write(f"- {record}\n")
                f.write("\n")

def get_script_dir():
    """Get the directory where the script is located."""
    return os.path.dirname(os.path.abspath(__file__))

def get_definitions_path(filename):
    """Get the full path to a definitions file."""
    script_dir = get_script_dir()
    return os.path.join(script_dir, 'definitions', filename)

def load_definitions():
    """Load all definition files."""
    definitions = {
        'services': [],
        'dns_strings': []
    }
    
    # Load public services
    services_path = get_definitions_path('public_services.txt')
    if os.path.exists(services_path):
        with open(services_path, 'r') as f:
            definitions['services'] = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    
    # Load DNS TXT strings
    dns_strings_path = get_definitions_path('dns_txt_strings.txt')
    if os.path.exists(dns_strings_path):
        with open(dns_strings_path, 'r') as f:
            definitions['dns_strings'] = [line.strip() for line in f if line.strip()]
    
    return definitions

def setup_webdriver():
    """Setup and return a configured Chrome WebDriver."""
    chrome_options = Options()
    chrome_options.add_argument('--headless')
    chrome_options.add_argument('--no-sandbox')
    chrome_options.add_argument('--disable-dev-shm-usage')
    chrome_options.add_argument('--window-size=1920,1080')
    return webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=chrome_options)

def take_screenshot(driver, url, output_dir, filename):
    """Take a screenshot of the webpage."""
    try:
        driver.get(url)
        time.sleep(2)  # Wait for page to load
        screenshot_path = os.path.join(output_dir, f"{filename}.png")
        driver.save_screenshot(screenshot_path)
        return screenshot_path
    except Exception as e:
        logging.error(f"Failed to take screenshot of {url}: {str(e)}")
        return None

def extract_logo(url, driver, output_dir):
    """Extract company logo from the website or Clearbit."""
    try:
        # First try Clearbit
        domain = urlparse(url).netloc
        clearbit_url = f"https://logo.clearbit.com/{domain}"
        response = requests.get(clearbit_url, timeout=10)
        
        if response.status_code == 200:
            # Save logo to file
            logo_path = os.path.join(output_dir, 'logo.png')
            with open(logo_path, 'wb') as f:
                f.write(response.content)
            
            return {
                'url': clearbit_url,
                'base64': base64.b64encode(response.content).decode('utf-8'),
                'source': 'clearbit',
                'file_path': logo_path
            }
        
        # If Clearbit fails, try website
        driver.get(url)
        time.sleep(2)  # Wait for page to load
        
        # Try to find logo in common locations
        logo_selectors = [
            'link[rel="icon"]',
            'link[rel="shortcut icon"]',
            'link[rel="apple-touch-icon"]',
            'meta[property="og:image"]',
            'img[alt*="logo" i]',
            'img[src*="logo" i]',
            'img[class*="logo" i]',
            'img[id*="logo" i]'
        ]
        
        for selector in logo_selectors:
            elements = driver.find_elements_by_css_selector(selector)
            for element in elements:
                if selector.startswith('meta'):
                    logo_url = element.get_attribute('content')
                else:
                    logo_url = element.get_attribute('href') or element.get_attribute('src')
                
                if logo_url:
                    # Handle relative URLs
                    if not logo_url.startswith(('http://', 'https://')):
                        logo_url = urljoin(url, logo_url)
                    
                    # Download and save logo
                    response = requests.get(logo_url, verify=False, timeout=10)
                    if response.status_code == 200:
                        # Determine file extension from content type or URL
                        content_type = response.headers.get('content-type', '')
                        if 'png' in content_type or logo_url.endswith('.png'):
                            ext = '.png'
                        elif 'jpeg' in content_type or 'jpg' in content_type or logo_url.endswith(('.jpg', '.jpeg')):
                            ext = '.jpg'
                        elif 'svg' in content_type or logo_url.endswith('.svg'):
                            ext = '.svg'
                        else:
                            ext = '.png'  # default to png
                        
                        logo_path = os.path.join(output_dir, f'logo{ext}')
                        with open(logo_path, 'wb') as f:
                            f.write(response.content)
                        
                        return {
                            'url': logo_url,
                            'base64': base64.b64encode(response.content).decode('utf-8'),
                            'source': 'website',
                            'file_path': logo_path
                        }
    except Exception as e:
        logging.debug(f"Error extracting logo: {str(e)}")
    return None

def check_dns_records(domain, logger, verbose_level, pretty_output=True):
    """Check various DNS records for a domain."""
    dns_results = {
        'A': [],
        'AAAA': [],
        'MX': [],
        'TXT': [],
        'SPF': [],
        'DMARC': [],
        'CNAME': []
    }
    
    record_types = ['A', 'AAAA', 'MX', 'TXT', 'CNAME']
    
    for record_type in record_types:
        try:
            if verbose_level >= 1 and pretty_output:
                print(f"{Colors.ORANGE}[*] Checking {record_type} records for {domain}{Colors.RESET}")
            
            answers = dns.resolver.resolve(domain, record_type)
            records = [str(answer) for answer in answers]
            dns_results[record_type] = records
            
            if verbose_level >= 1 and pretty_output:
                for record in records:
                    print(f"{Colors.CYAN}[~] {record_type} Record: {record}{Colors.RESET}")
                    
        except dns.resolver.NoAnswer:
            if verbose_level >= 1 and pretty_output:
                print(f"{Colors.YELLOW}[!] No {record_type} records found for {domain}{Colors.RESET}")
        except Exception as e:
            if verbose_level >= 1 and pretty_output:
                print(f"{Colors.RED}[-] Error checking {record_type} records: {str(e)}{Colors.RESET}")
    
    # Check SPF record
    try:
        spf_records = dns.resolver.resolve(domain, 'TXT')
        for record in spf_records:
            if 'v=spf1' in str(record):
                dns_results['SPF'].append(str(record))
                if verbose_level >= 1 and pretty_output:
                    print(f"{Colors.CYAN}[~] SPF Record: {record}{Colors.RESET}")
    except Exception:
        pass
    
    # Check DMARC record
    try:
        dmarc_domain = f'_dmarc.{domain}'
        dmarc_records = dns.resolver.resolve(dmarc_domain, 'TXT')
        for record in dmarc_records:
            if 'v=DMARC1' in str(record):
                dns_results['DMARC'].append(str(record))
                if verbose_level >= 1 and pretty_output:
                    print(f"{Colors.CYAN}[~] DMARC Record: {record}{Colors.RESET}")
    except Exception:
        pass
    
    return dns_results

def check_dns_txt(domain, dns_strings, logger, verbose_level, pretty_output=True):
    """Check DNS TXT records for known service indicators."""
    try:
        if verbose_level >= 1 and pretty_output:
            print(f"{Colors.ORANGE}[*] Checking DNS TXT records for service indicators{Colors.RESET}")
        
        answers = dns.resolver.resolve(domain, 'TXT')
        txt_records = [str(txt.to_text()) for txt in answers]
        found_services = []
        
        for record in txt_records:
            if verbose_level >= 2 and pretty_output:
                print(f"{Colors.CYAN}[~] TXT Record: {record}{Colors.RESET}")
            
            for service in dns_strings:
                if service.lower() in record.lower():
                    found_services.append({
                        'service': service,
                        'record': record
                    })
                    logger.info(f"Found service indicator in DNS TXT: {service} - {record}")
                    if verbose_level >= 1 and pretty_output:
                        print(f"{Colors.GREEN}[+] Found service indicator: {service} in TXT record{Colors.RESET}")
        
        return found_services
    except Exception as e:
        logger.debug(f"Error checking DNS TXT records for {domain}: {str(e)}")
        return []

def check_for_enter():
    """Check if Enter key is pressed."""
    if os.name == 'nt':  # Windows
        return msvcrt.kbhit() and msvcrt.getch() == b'\r'
    else:  # Unix-like
        rlist, _, _ = select.select([sys.stdin], [], [], 0.1)
        if rlist:
            line = sys.stdin.readline()
            return line.strip() == ''
        return False

def is_same_domain(url1, url2):
    """Check if two URLs have the same domain."""
    try:
        domain1 = urlparse(url1).netloc
        domain2 = urlparse(url2).netloc
        return domain1 == domain2
    except:
        return False

def check_service(domain, service, output_dir, driver, logger, verbose_level, pretty_output=True):
    """Check if a service is accessible and save evidence."""
    company_name = domain.split('.')[0]
    url = f"https://{company_name}.{service}"
    
    if verbose_level >= 1 and pretty_output:
        print(f"{Colors.ORANGE}[*] Checking service: {url}{Colors.RESET}")
    
    # Use a common user agent
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
        'Sec-Fetch-User': '?1',
        'Cache-Control': 'max-age=0'
    }
    
    try:
        response = requests.get(url, timeout=10, allow_redirects=True, headers=headers)
        
        if verbose_level >= 2 and pretty_output:
            print(f"{Colors.CYAN}[~] Request Headers: {dict(response.request.headers)}{Colors.RESET}")
            print(f"{Colors.CYAN}[~] Response Headers: {dict(response.headers)}{Colors.RESET}")
            print(f"{Colors.CYAN}[~] Response Status: {response.status_code}{Colors.RESET}")
        
        if response.status_code in [200, 301, 302]:
            logger.info(f"Found service: {url} (Status: {response.status_code})")
            
            # Check for redirects
            redirect_url = None
            if response.history:
                redirect_url = response.url
                if pretty_output:
                    if is_same_domain(url, redirect_url):
                        print(f"{Colors.GREEN}[+] Found service: {url} -> {redirect_url}{Colors.RESET}")
                    else:
                        print(f"{Colors.YELLOW}[!] Redirect detected: {url} -> {redirect_url}{Colors.RESET}")
            elif verbose_level >= 1 and pretty_output:
                print(f"{Colors.GREEN}[+] Found service: {url} (Status: {response.status_code}){Colors.RESET}")
            
            # Create service-specific directory
            service_name = service.replace('.', '_')
            safe_domain = domain.replace('.', '_')
            service_dir = os.path.join(output_dir, service_name)
            os.makedirs(service_dir, exist_ok=True)
            
            # Save HTML with domain and service name
            html_path = os.path.join(service_dir, f"index_{safe_domain}_{service_name}.html")
            with open(html_path, 'w', encoding='utf-8') as f:
                f.write(response.text)
            
            # Take screenshot with domain and service name
            screenshot_path = take_screenshot(driver, url, service_dir, f"screenshot_{safe_domain}_{service_name}")
            
            return {
                'url': url,
                'status': response.status_code,
                'html_path': html_path,
                'screenshot_path': screenshot_path,
                'headers': dict(response.headers),
                'redirect_url': redirect_url
            }
    except requests.RequestException as e:
        if verbose_level >= 1 and pretty_output:
            print(f"{Colors.RED}[-] Service not accessible: {url} - {str(e)}{Colors.RESET}")
        logger.debug(f"Service not accessible: {url} - {str(e)}")
    
    return None

def print_status(status_queue, progress=None):
    """Print status messages from the queue."""
    while True:
        try:
            message = status_queue.get_nowait()
            if message == "DONE":
                break
            if progress:
                console.print(f"[cyan][*] {message}[/cyan]")
            else:
                print(f"{Colors.CYAN}[*] {message}{Colors.RESET}")
        except queue.Empty:
            time.sleep(0.1)

def save_current_results(all_results, output_dir, pretty_output=True):
    """Save current results to files."""
    if pretty_output:
        console.print("\n[yellow][!] Saving current results...[/yellow]")
    
    # Save individual domain results
    for result in all_results:
        domain = result['domain']
        domain_dir = os.path.join(output_dir, domain)
        
        # Save domain results as JSON
        summary_path = os.path.join(domain_dir, 'summary.json')
        with open(summary_path, 'w') as f:
            json.dump(result, f, indent=2)
        
        # Save domain results as CSV
        save_results_to_csv(result, domain_dir, domain)
    
    if pretty_output:
        console.print(f"[green][+] Results saved to {output_dir}[/green]")

def check_dns_security(domain, logger, verbose_level, pretty_output=True):
    """Check DNS security features and potential issues."""
    security_results = {
        'dnssec': False,
        'dnssec_errors': [],
        'dns_takeover_risks': [],
        'dns_misconfigurations': [],
        'email_security': {
            'spf': {'exists': False, 'record': None, 'issues': []},
            'dkim': {'exists': False, 'record': None, 'issues': []},
            'dmarc': {'exists': False, 'record': None, 'issues': []},
            'email_providers': []
        }
    }

    try:
        # Check DNSSEC
        try:
            dnssec = dns.resolver.resolve(domain, 'DNSKEY')
            security_results['dnssec'] = True
            if verbose_level >= 1 and pretty_output:
                print(f"{Colors.GREEN}[+] DNSSEC is enabled for {domain}{Colors.RESET}")
        except Exception as e:
            security_results['dnssec_errors'].append(str(e))
            if verbose_level >= 1 and pretty_output:
                print(f"{Colors.YELLOW}[!] DNSSEC is not enabled for {domain}{Colors.RESET}")

        # Check for DNS takeover opportunities
        try:
            cname_records = dns.resolver.resolve(domain, 'CNAME')
            for record in cname_records:
                target = str(record.target)
                if any(provider in target.lower() for provider in ['github.io', 'herokuapp.com', 'azurewebsites.net', 'cloudfront.net']):
                    security_results['dns_takeover_risks'].append({
                        'type': 'CNAME',
                        'target': target,
                        'risk': 'Potential DNS takeover via CNAME'
                    })
                    if verbose_level >= 1 and pretty_output:
                        print(f"{Colors.RED}[-] Potential DNS takeover risk: CNAME pointing to {target}{Colors.RESET}")
        except Exception:
            pass

        # Check SPF record
        try:
            txt_records = dns.resolver.resolve(domain, 'TXT')
            spf_found = False
            for record in txt_records:
                record_str = str(record)
                if 'v=spf1' in record_str:
                    spf_found = True
                    security_results['email_security']['spf']['exists'] = True
                    security_results['email_security']['spf']['record'] = record_str
                    
                    # Analyze SPF record
                    if 'all' not in record_str:
                        security_results['email_security']['spf']['issues'].append('Missing "all" mechanism')
                    if '~all' in record_str:
                        security_results['email_security']['spf']['issues'].append('Using soft fail (~all) instead of hard fail (-all)')
                    
                    if verbose_level >= 1 and pretty_output:
                        print(f"{Colors.GREEN}[+] SPF record found: {record_str}{Colors.RESET}")
                        for issue in security_results['email_security']['spf']['issues']:
                            print(f"{Colors.YELLOW}[!] SPF issue: {issue}{Colors.RESET}")
                    break
            
            if not spf_found and verbose_level >= 1 and pretty_output:
                print(f"{Colors.RED}[-] No SPF record found{Colors.RESET}")
        except Exception as e:
            if verbose_level >= 1 and pretty_output:
                print(f"{Colors.RED}[-] Error checking SPF record: {str(e)}{Colors.RESET}")

        # Check DKIM record
        try:
            dkim_domain = f'default._domainkey.{domain}'
            dkim_records = dns.resolver.resolve(dkim_domain, 'TXT')
            for record in dkim_records:
                if 'v=DKIM1' in str(record):
                    security_results['email_security']['dkim']['exists'] = True
                    security_results['email_security']['dkim']['record'] = str(record)
                    if verbose_level >= 1 and pretty_output:
                        print(f"{Colors.GREEN}[+] DKIM record found: {record}{Colors.RESET}")
        except Exception:
            if verbose_level >= 1 and pretty_output:
                print(f"{Colors.RED}[-] No DKIM record found{Colors.RESET}")

        # Check DMARC record
        try:
            dmarc_domain = f'_dmarc.{domain}'
            dmarc_records = dns.resolver.resolve(dmarc_domain, 'TXT')
            for record in dmarc_records:
                if 'v=DMARC1' in str(record):
                    security_results['email_security']['dmarc']['exists'] = True
                    security_results['email_security']['dmarc']['record'] = str(record)
                    
                    # Analyze DMARC record
                    dmarc_str = str(record)
                    if 'p=none' in dmarc_str:
                        security_results['email_security']['dmarc']['issues'].append('Using monitor mode (p=none)')
                    if 'p=quarantine' in dmarc_str:
                        security_results['email_security']['dmarc']['issues'].append('Using quarantine mode (p=quarantine)')
                    if 'pct=100' not in dmarc_str:
                        security_results['email_security']['dmarc']['issues'].append('Not enforcing policy on all emails (pct<100)')
                    
                    if verbose_level >= 1 and pretty_output:
                        print(f"{Colors.GREEN}[+] DMARC record found: {record}{Colors.RESET}")
                        for issue in security_results['email_security']['dmarc']['issues']:
                            print(f"{Colors.YELLOW}[!] DMARC issue: {issue}{Colors.RESET}")
        except Exception:
            if verbose_level >= 1 and pretty_output:
                print(f"{Colors.RED}[-] No DMARC record found{Colors.RESET}")

        # Check for email service providers
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            for record in mx_records:
                mx_target = str(record.exchange).lower()
                security_results['email_security']['email_providers'].append(mx_target)
                
                # Identify common email providers
                provider = None
                if 'google' in mx_target:
                    provider = 'Google Workspace'
                elif 'outlook' in mx_target or 'microsoft' in mx_target:
                    provider = 'Microsoft 365'
                elif 'zoho' in mx_target:
                    provider = 'Zoho Mail'
                elif 'amazonses' in mx_target:
                    provider = 'Amazon SES'
                elif 'sendgrid' in mx_target:
                    provider = 'SendGrid'
                elif 'mailgun' in mx_target:
                    provider = 'Mailgun'
                
                if provider and verbose_level >= 1 and pretty_output:
                    print(f"{Colors.GREEN}[+] Email provider detected: {provider}{Colors.RESET}")
        except Exception as e:
            if verbose_level >= 1 and pretty_output:
                print(f"{Colors.RED}[-] No MX records found{Colors.RESET}")

        # Check for DNS misconfigurations
        try:
            # Check for dangling CNAME records
            cname_records = dns.resolver.resolve(domain, 'CNAME')
            for record in cname_records:
                target = str(record.target)
                try:
                    dns.resolver.resolve(target, 'A')
                except Exception:
                    security_results['dns_misconfigurations'].append({
                        'type': 'CNAME',
                        'issue': f'Dangling CNAME record pointing to {target}'
                    })
                    if verbose_level >= 1 and pretty_output:
                        print(f"{Colors.RED}[-] DNS misconfiguration: Dangling CNAME record pointing to {target}{Colors.RESET}")
        except Exception:
            pass

        # Check for conflicting records
        try:
            a_records = dns.resolver.resolve(domain, 'A')
            cname_records = dns.resolver.resolve(domain, 'CNAME')
            if len(a_records) > 0 and len(cname_records) > 0:
                security_results['dns_misconfigurations'].append({
                    'type': 'Record Conflict',
                    'issue': 'Domain has both A and CNAME records'
                })
                if verbose_level >= 1 and pretty_output:
                    print(f"{Colors.RED}[-] DNS misconfiguration: Domain has both A and CNAME records{Colors.RESET}")
        except Exception:
            pass

    except Exception as e:
        logger.error(f"Error in DNS security check: {str(e)}")
        if verbose_level >= 1 and pretty_output:
            print(f"{Colors.RED}[-] Error checking DNS security: {str(e)}{Colors.RESET}")

    return security_results

def get_company_logo(domain, output_dir, pretty_output=True):
    """Get the main company logo from Clearbit."""
    try:
        clearbit_url = f"https://logo.clearbit.com/{domain}"
        response = requests.get(clearbit_url, timeout=10)
        
        if response.status_code == 200:
            # Save logo to file
            logo_path = os.path.join(output_dir, 'company_logo.png')
            with open(logo_path, 'wb') as f:
                f.write(response.content)
            
            if pretty_output:
                print(f"{Colors.GREEN}[+] Found company logo for {domain}{Colors.RESET}")
            
            return {
                'url': clearbit_url,
                'base64': base64.b64encode(response.content).decode('utf-8'),
                'source': 'clearbit',
                'file_path': logo_path
            }
    except Exception as e:
        if pretty_output:
            print(f"{Colors.YELLOW}[!] Could not fetch company logo: {str(e)}{Colors.RESET}")
    return None

def save_dns_security_to_csv(security_results, output_dir, domain):
    """Save DNS security results to CSV format."""
    csv_path = os.path.join(output_dir, f"dns_security.csv")
    
    # Prepare CSV data
    csv_data = []
    
    # DNSSEC status
    csv_data.append({
        'category': 'DNSSEC',
        'feature': 'DNSSEC',
        'status': 'Enabled' if security_results['dnssec'] else 'Disabled',
        'details': '',
        'issues': '; '.join(security_results['dnssec_errors']) if security_results['dnssec_errors'] else ''
    })
    
    # DNS takeover risks
    for risk in security_results['dns_takeover_risks']:
        csv_data.append({
            'category': 'DNS Takeover',
            'feature': risk['type'],
            'status': 'Risk',
            'details': f"Target: {risk['target']}",
            'issues': risk['risk']
        })
    
    # DNS misconfigurations
    for misconfig in security_results['dns_misconfigurations']:
        csv_data.append({
            'category': 'DNS Misconfiguration',
            'feature': misconfig['type'],
            'status': 'Issue',
            'details': '',
            'issues': misconfig['issue']
        })
    
    # Email security - SPF
    spf = security_results['email_security']['spf']
    csv_data.append({
        'category': 'Email Security',
        'feature': 'SPF',
        'status': 'Enabled' if spf['exists'] else 'Disabled',
        'details': spf['record'] if spf['exists'] else 'No SPF record found',
        'issues': '; '.join(spf['issues']) if spf['issues'] else ''
    })
    
    # Email security - DKIM
    dkim = security_results['email_security']['dkim']
    csv_data.append({
        'category': 'Email Security',
        'feature': 'DKIM',
        'status': 'Enabled' if dkim['exists'] else 'Disabled',
        'details': dkim['record'] if dkim['exists'] else 'No DKIM record found',
        'issues': ''
    })
    
    # Email security - DMARC
    dmarc = security_results['email_security']['dmarc']
    csv_data.append({
        'category': 'Email Security',
        'feature': 'DMARC',
        'status': 'Enabled' if dmarc['exists'] else 'Disabled',
        'details': dmarc['record'] if dmarc['exists'] else 'No DMARC record found',
        'issues': '; '.join(dmarc['issues']) if dmarc['issues'] else ''
    })
    
    # Email providers
    for provider in security_results['email_security']['email_providers']:
        csv_data.append({
            'category': 'Email Security',
            'feature': 'Email Provider',
            'status': 'Detected',
            'details': provider,
            'issues': ''
        })
    
    # Write CSV file
    if csv_data:
        with open(csv_path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['category', 'feature', 'status', 'details', 'issues'])
            writer.writeheader()
            writer.writerows(csv_data)
            
        # Print issues to stdout
        print(f"\n{Colors.BOLD}DNS Security Issues for {domain}:{Colors.RESET}")
        for row in csv_data:
            if row['issues']:
                print(f"{Colors.YELLOW}[!] {row['category']} - {row['feature']}: {row['issues']}{Colors.RESET}")

def check_domain_takeover(domain, services, logger, verbose_level, pretty_output=True):
    """Check for domain takeover opportunities after service discovery."""
    takeover_risks = []
    
    # Check each found service for potential takeover
    for service in services:
        url = service['url']
        try:
            # Check if the service is using a CNAME
            cname_records = dns.resolver.resolve(urlparse(url).netloc, 'CNAME')
            for record in cname_records:
                target = str(record.target)
                
                # Check for known vulnerable services
                if any(provider in target.lower() for provider in [
                    'github.io', 'herokuapp.com', 'azurewebsites.net', 'cloudfront.net',
                    's3.amazonaws.com', 'cloudfront.net', 'fastly.net', 'netlify.app',
                    'vercel.app', 'firebaseapp.com', 'appspot.com', 'herokuapp.com',
                    'azurewebsites.net', 'cloudapp.net', 'elasticbeanstalk.com',
                    'appengine.google.com', 'pages.github.io', 'ghost.io', 'wordpress.com',
                    'tumblr.com', 'shopify.com', 'myshopify.com', 'squarespace.com',
                    'wix.com', 'weebly.com', 'blogspot.com', 'medium.com'
                ]):
                    takeover_risks.append({
                        'type': 'CNAME',
                        'service': url,
                        'target': target,
                        'risk': 'Potential DNS takeover via CNAME',
                        'details': f'Service {url} is using a CNAME record pointing to {target} which could be vulnerable to takeover'
                    })
                    if verbose_level >= 1 and pretty_output:
                        print(f"{Colors.RED}[-] Potential takeover risk for {url}: CNAME pointing to {target}{Colors.RESET}")
                
                # Check if the target domain is available for registration
                try:
                    # Try to resolve the target domain
                    dns.resolver.resolve(target, 'A')
                except dns.resolver.NXDOMAIN:
                    takeover_risks.append({
                        'type': 'Dangling CNAME',
                        'service': url,
                        'target': target,
                        'risk': 'Dangling CNAME record',
                        'details': f'Service {url} has a dangling CNAME record pointing to {target} which could be registered'
                    })
                    if verbose_level >= 1 and pretty_output:
                        print(f"{Colors.RED}[-] Dangling CNAME risk for {url}: Target {target} is not registered{Colors.RESET}")
                
        except dns.resolver.NoAnswer:
            # No CNAME records found, which is good
            pass
        except Exception as e:
            logger.debug(f"Error checking takeover for {url}: {str(e)}")
    
    return takeover_risks

def main():
    parser = argparse.ArgumentParser(description="OSINT tool for detecting 3rd party services used by companies.")
    parser.add_argument('domains', nargs='*', help='List of domains to process.')
    parser.add_argument('-f', '--file', type=str, help='File containing domains (one per line).')
    parser.add_argument('-v', '--verbose', action='count', default=0, help='Enable verbose output. Use -vv for extra verbose.')
    parser.add_argument('-o', '--output', type=str, help='Output directory for results.')
    parser.add_argument('--no-banner', action='store_true', help='Disable the ASCII banner.')
    parser.add_argument('--no-pretty', action='store_true', help='Disable pretty output formatting.')
    parser.add_argument('--dns-security', action='store_true', help='Enable enhanced DNS security checks.')

    args = parser.parse_args()

    if not args.domains and not args.file:
        parser.error("Please provide either domains or a file")

    # Validate domains
    invalid_domains = []
    domains = args.domains
    if args.file:
        with open(args.file, 'r') as f:
            domains.extend(line.strip() for line in f)
    
    for domain in domains:
        if not validate_domain(domain):
            invalid_domains.append(domain)
    
    if invalid_domains:
        print(f"{Colors.RED}[-] Invalid domains found:{Colors.RESET}")
        for domain in invalid_domains:
            print(f"{Colors.RED}    - {domain}{Colors.RESET}")
        parser.error("Please provide valid domains")

    # Setup output directory - use plainsight_results in current directory if not specified
    base_output_dir = args.output or os.path.join(os.getcwd(), 'plainsight_results')
    os.makedirs(base_output_dir, exist_ok=True)

    # Setup logging
    logger = setup_logging(base_output_dir, args.verbose)

    # Print banner
    if not args.no_banner:
        print_banner()

    # Load definitions
    definitions = load_definitions()
    if not definitions['services']:
        logger.error("No services found in definitions/public_services.txt")
        return

    # Setup WebDriver
    driver = setup_webdriver()

    # Store all results for combined output
    all_results = []

    try:
        print(f"\n{Colors.YELLOW}[!] Press Enter at any time to cancel the scan and save current results{Colors.RESET}\n")

        for domain in domains:
            logger.info(f"Processing domain: {domain}")
            # Replace dots with underscores in domain name for directory
            safe_domain = domain.replace('.', '_')
            domain_dir = os.path.join(base_output_dir, safe_domain)
            os.makedirs(domain_dir, exist_ok=True)

            # Get company logo first
            company_logo = get_company_logo(domain, domain_dir, not args.no_pretty)

            results = {
                'domain': domain,
                'scan_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'dns_records': {},
                'services': [],
                'dns_txt_findings': [],
                'dns_security': {},
                'company_logo': company_logo,
                'takeover_risks': []
            }

            # Setup status queue and thread
            status_queue = queue.Queue()
            
            # Create progress display if needed
            progress = None
            if not args.verbose and not args.no_pretty:
                progress = Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                    TextColumn("[progress.completed]{task.completed}/{task.total}"),
                    TimeElapsedColumn(),
                    console=console
                )
                progress.start()
                task = progress.add_task("Checking services", total=len(definitions['services']))
            
            # Start status thread
            status_thread = threading.Thread(target=print_status, args=(status_queue, progress))
            status_thread.start()

            # Check DNS records
            status_queue.put(f"Checking DNS records for {domain}")
            results['dns_records'] = check_dns_records(domain, logger, args.verbose, not args.no_pretty)
            
            # Enhanced DNS security checks
            if args.dns_security:
                status_queue.put(f"Performing enhanced DNS security checks for {domain}")
                results['dns_security'] = check_dns_security(domain, logger, args.verbose, not args.no_pretty)
                # Save DNS security results to CSV
                save_dns_security_to_csv(results['dns_security'], domain_dir, domain)
            
            # Print DNS results
            if progress:
                console.print()  # Add newline before DNS results
            print_dns_results(results['dns_records'], not args.no_pretty)
            
            # Save DNS results
            save_dns_results(results['dns_records'], domain_dir, domain)

            # Check DNS TXT records for service indicators
            status_queue.put(f"Checking DNS TXT records for service indicators")
            dns_findings = check_dns_txt(domain, definitions['dns_strings'], logger, args.verbose, not args.no_pretty)
            results['dns_txt_findings'] = dns_findings

            # Check services
            status_queue.put(f"Checking services for {domain}")
            for service in definitions['services']:
                # Check for Enter key press
                if check_for_enter():
                    if not args.no_pretty:
                        console.print(f"\n[yellow][!] Scan cancelled by user[/yellow]")
                    save_current_results(all_results, base_output_dir, not args.no_pretty)
                    if progress:
                        progress.stop()
                    status_queue.put("DONE")
                    status_thread.join()
                    return

                result = check_service(domain, service, domain_dir, driver, logger, args.verbose, not args.no_pretty)
                if result:
                    results['services'].append(result)
                    if progress and not result.get('redirect_url'):
                        console.print(f"[green][+] Found service: {result['url']}[/green]")
                if progress:
                    progress.update(task, advance=1)

            # Check for domain takeover opportunities after finding all services
            if args.dns_security:
                status_queue.put(f"Checking for domain takeover opportunities")
                results['takeover_risks'] = check_domain_takeover(domain, results['services'], logger, args.verbose, not args.no_pretty)

            # Stop progress display if it exists
            if progress:
                progress.stop()
                console.print()  # Add newline after progress bar

            # Save individual domain results
            summary_path = os.path.join(domain_dir, 'summary.json')
            with open(summary_path, 'w') as f:
                json.dump(results, f, indent=2)

            # Save individual domain results as CSV
            save_results_to_csv(results, domain_dir, domain)

            # Add to all results
            all_results.append(results)

            status_queue.put(f"Completed scanning {domain}")
            status_queue.put("DONE")
            status_thread.join()

        # Save final results
        save_current_results(all_results, base_output_dir, not args.no_pretty)

    except KeyboardInterrupt:
        if not args.no_pretty:
            print(f"\n{Colors.YELLOW}[!] Scan interrupted by user{Colors.RESET}")
        save_current_results(all_results, base_output_dir, not args.no_pretty)
    finally:
        driver.quit()

if __name__ == '__main__':
    main()
