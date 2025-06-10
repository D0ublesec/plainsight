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
    csv_path = os.path.join(output_dir, f"services_{safe_domain}.csv")
    
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
    safe_domain = domain.replace('.', '_')
    dns_path = os.path.join(output_dir, f"dns_records_{safe_domain}.txt")
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

def check_dns_txt(domain, definitions, logger, verbose_level, pretty_output=True):
    """Check DNS TXT records for service indicators."""
    if verbose_level >= 1 and pretty_output:
        print(f"{Colors.ORANGE}[*] Checking DNS TXT records for service indicators{Colors.RESET}")
    
    try:
        # Get all TXT records
        txt_records = dns.resolver.resolve(domain, 'TXT')
        
        if verbose_level >= 1 and pretty_output:
            print(f"{Colors.CYAN}[~] Found {len(txt_records)} TXT records{Colors.RESET}")
            for record in txt_records:
                print(f"{Colors.CYAN}[~] TXT Record: {record}{Colors.RESET}")
        
        # Check each record for service indicators
        found_services = []
        for record in txt_records:
            record_str = str(record)
            # Handle both list and dictionary formats
            if isinstance(definitions['dns_strings'], dict):
                for service, indicator in definitions['dns_strings'].items():
                    if indicator.lower() in record_str.lower():
                        found_services.append(service)
                        if verbose_level >= 1 and pretty_output:
                            print(f"{Colors.GREEN}[+] Found {service} indicator in TXT record{Colors.RESET}")
            else:  # Handle list format
                for indicator in definitions['dns_strings']:
                    if indicator.lower() in record_str.lower():
                        found_services.append(indicator)
                        if verbose_level >= 1 and pretty_output:
                            print(f"{Colors.GREEN}[+] Found {indicator} in TXT record{Colors.RESET}")
        
        if found_services:
            if verbose_level >= 1 and pretty_output:
                print(f"{Colors.GREEN}[+] Found service indicators for: {', '.join(found_services)}{Colors.RESET}")
            return found_services
        else:
            if verbose_level >= 1 and pretty_output:
                print(f"{Colors.YELLOW}[!] No service indicators found in TXT records{Colors.RESET}")
            return []
            
    except dns.resolver.NoAnswer:
        if verbose_level >= 1 and pretty_output:
            print(f"{Colors.YELLOW}[!] No TXT records found for {domain}{Colors.RESET}")
        return []
    except dns.resolver.NXDOMAIN:
        if verbose_level >= 1 and pretty_output:
            print(f"{Colors.RED}[-] Domain {domain} does not exist{Colors.RESET}")
        return []
    except Exception as e:
        if verbose_level >= 1 and pretty_output:
            print(f"{Colors.RED}[-] Error checking TXT records: {str(e)}{Colors.RESET}")
        logger.error(f"Error checking TXT records: {str(e)}")
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
        
        # Check for specific domain redirects and content
        if response.status_code in [200, 301, 302]:
            redirect_url = response.url if response.history else None
            
            # Auth0 check
            if service == 'auth0.com' and redirect_url and 'auth0.com' in redirect_url:
                if verbose_level >= 1 and pretty_output:
                    print(f"{Colors.YELLOW}[!] Auth0 redirect detected, marking as not found{Colors.RESET}")
                return None
            
            # Box check
            if service == 'box.com' and redirect_url and 'account.box.com' in redirect_url:
                if verbose_level >= 1 and pretty_output:
                    print(f"{Colors.YELLOW}[!] Box account redirect detected, marking as not found{Colors.RESET}")
                return None
            
            # SharePoint redirect check - mark as found when redirected to Microsoft login
            if service == 'sharepoint' and 'login.microsoftonline.com' in redirect_url:
                if pretty_output:
                    print(f"{Colors.GREEN}[+] Found {service} service{Colors.RESET}")
                return {
                    'url': url,
                    'status': response.status_code,
                    'headers': dict(response.headers),
                    'screenshot_path': take_screenshot(driver, url, output_dir, f"screenshot_{domain}_{service}") if redirect_url else None,
                    'redirect_url': redirect_url
                }
            
            # Nethunt check
            if service == 'nethunt.com' and redirect_url and 'nethunt.com' in redirect_url:
                if verbose_level >= 1 and pretty_output:
                    print(f"{Colors.YELLOW}[!] Nethunt redirect detected, marking as not found{Colors.RESET}")
                return None
            
            # AgileCRM check
            if service == 'agilecrm.com' and redirect_url and 'my.agilecrm.com' in redirect_url:
                if verbose_level >= 1 and pretty_output:
                    print(f"{Colors.YELLOW}[!] AgileCRM redirect detected, marking as not found{Colors.RESET}")
                return None
            
            # Vtiger check
            if service == 'vtiger.com' and redirect_url and 'www.vtiger.com' in redirect_url:
                if verbose_level >= 1 and pretty_output:
                    print(f"{Colors.YELLOW}[!] Vtiger redirect detected, marking as not found{Colors.RESET}")
                return None
            
            # Workable check
            if service == 'workable.com' and redirect_url and 'apply.workable.com/oops' in redirect_url:
                if verbose_level >= 1 and pretty_output:
                    print(f"{Colors.YELLOW}[!] Workable oops page detected, marking as not found{Colors.RESET}")
                return None
            
            # Zendesk check
            if service == 'zendesk.com':
                if redirect_url and 'www.zendesk.com' in redirect_url:
                    if verbose_level >= 1 and pretty_output:
                        print(f"{Colors.YELLOW}[!] Zendesk redirect detected, marking as not found{Colors.RESET}")
                    return None
                elif redirect_url and 'www.zendesk.co.uk' in redirect_url:
                    if 'Oops! This help centre no longer exists' in response.text:
                        if verbose_level >= 1 and pretty_output:
                            print(f"{Colors.YELLOW}[!] Zendesk help centre not found{Colors.RESET}")
                        return None
            
            # Zammad check
            if service == 'zammad.com' and 'Requested system was not found.' in response.text:
                if verbose_level >= 1 and pretty_output:
                    print(f"{Colors.YELLOW}[!] Zammad system not found{Colors.RESET}")
                return None
            
            # TalentLMS check
            if service == 'talentlms.com' and redirect_url and 'www.talentlms.com' in redirect_url:
                if verbose_level >= 1 and pretty_output:
                    print(f"{Colors.YELLOW}[!] TalentLMS redirect detected, marking as not found{Colors.RESET}")
                return None
            
            # LearnWorlds check
            if service == 'learnworlds.com' and redirect_url and 'www.learnworlds.com' in redirect_url:
                if verbose_level >= 1 and pretty_output:
                    print(f"{Colors.YELLOW}[!] LearnWorlds redirect detected, marking as not found{Colors.RESET}")
                return None
            
            # Monday.com check
            if service == 'monday.com' and redirect_url and 'auth.monday.com/slug_not_found' in redirect_url:
                if verbose_level >= 1 and pretty_output:
                    print(f"{Colors.YELLOW}[!] Monday.com slug not found, marking as not found{Colors.RESET}")
                return None
            
            # BambooHR check
            if service == 'bamboohr.com' and redirect_url and 'www.bamboohr.com' in redirect_url:
                if verbose_level >= 1 and pretty_output:
                    print(f"{Colors.YELLOW}[!] BambooHR redirect detected, marking as not found{Colors.RESET}")
                return None
            
            logger.info(f"Found service: {url} (Status: {response.status_code})")
            
            # Check for redirects
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
        safe_domain = domain.replace('.', '_')
        domain_dir = os.path.join(output_dir, safe_domain)
        
        # Create domain directory if it doesn't exist
        os.makedirs(domain_dir, exist_ok=True)
        
        # Save domain results as JSON
        summary_path = os.path.join(domain_dir, f'summary_{safe_domain}.json')
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
            safe_domain = domain.replace('.', '_')
            logo_path = os.path.join(output_dir, f'company_logo_{safe_domain}.png')
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
    safe_domain = domain.replace('.', '_')
    csv_path = os.path.join(output_dir, f"dns_security_{safe_domain}.csv")
    
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

def generate_html_report(results, output_dir, pretty_output=True):
    """Generate an HTML report similar to Aquatone's output."""
    def get_ordinal(n):
        if 10 <= n % 100 <= 20:
            suffix = 'th'
        else:
            suffix = {1: 'st', 2: 'nd', 3: 'rd'}.get(n % 10, 'th')
        return suffix
    
    def format_date(date_str):
        try:
            # Parse the date string
            dt = datetime.strptime(date_str, '%Y-%m-%d %H:%M:%S')
            
            # Get the day directly from the datetime object
            day = dt.day
            
            # Format the date with proper ordinal and local timezone
            formatted_date = f"{day}{get_ordinal(day)} {dt.strftime('%B %Y at %H:%M:%S')} {dt.astimezone().strftime('%Z')}"
            
            return formatted_date
        except Exception as e:
            return date_str

    if pretty_output:
        print(f"{Colors.YELLOW}[!] Generating HTML report...{Colors.RESET}")

    # Create domain-specific directory for the report
    domain = results[0]['domain']
    safe_domain = domain.replace('.', '_')
    report_dir = os.path.join(output_dir, safe_domain)
    os.makedirs(report_dir, exist_ok=True)

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Plainsight Scan Results - {domain}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, 'Open Sans', 'Helvetica Neue', sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background: #f5f5f5;
            color: #333;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        .header {{
            background: #fff;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }}
        .domain-section {{
            background: #fff;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }}
        .domain-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 1px solid #eee;
        }}
        .services-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 20px;
        }}
        .services-grid.cols-1 {{
            grid-template-columns: 1fr;
        }}
        .services-grid.cols-2 {{
            grid-template-columns: repeat(2, 1fr);
        }}
        .services-grid.cols-3 {{
            grid-template-columns: repeat(3, 1fr);
        }}
        .service-card {{
            background: #fff;
            border: 1px solid #ddd;
            border-radius: 8px;
            padding: 15px;
            cursor: pointer;
            transition: all 0.3s ease;
            position: relative;
        }}
        .service-card:hover {{
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0,0,0,0.1);
        }}
        .service-card h3 {{
            margin: 0 0 10px 0;
            color: #2c3e50;
        }}
        .service-card p {{
            margin: 5px 0;
            color: #666;
        }}
        .service-card .status {{
            position: absolute;
            top: 10px;
            right: 10px;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8em;
        }}
        .status-found {{
            background: #d4edda;
            color: #155724;
        }}
        .status-not-found {{
            background: #f8d7da;
            color: #721c24;
        }}
        .screenshot {{
            width: 100%;
            height: auto;
            max-height: 200px;
            object-fit: contain;
            border-radius: 4px;
            margin-top: 10px;
        }}
        .modal {{
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.9);
            z-index: 1000;
        }}
        .modal-content {{
            position: relative;
            background: #fff;
            margin: 2% auto;
            padding: 20px;
            width: 90%;
            max-width: 1200px;
            border-radius: 8px;
            max-height: 96vh;
            overflow-y: auto;
        }}
        .close-button {{
            position: absolute;
            right: 20px;
            top: 20px;
            font-size: 24px;
            cursor: pointer;
            color: #666;
            z-index: 1001;
        }}
        .tabs {{
            display: flex;
            margin-bottom: 20px;
            border-bottom: 1px solid #ddd;
            position: sticky;
            top: 0;
            background: #fff;
            padding: 10px 0;
            z-index: 1;
        }}
        .tab {{
            padding: 10px 20px;
            cursor: pointer;
            border: 1px solid transparent;
            border-bottom: none;
            margin-right: 5px;
            border-radius: 4px 4px 0 0;
        }}
        .tab.active {{
            background: #fff;
            border-color: #ddd;
            border-bottom-color: #fff;
            margin-bottom: -1px;
        }}
        .tab-content {{
            display: none;
            padding: 20px;
            background: #fff;
            border-radius: 0 0 4px 4px;
        }}
        .tab-content.active {{
            display: block;
        }}
        .request-details, .response-details {{
            white-space: pre-wrap;
            font-family: monospace;
            font-size: 14px;
            line-height: 1.4;
            background: #f8f9fa;
            padding: 15px;
            border-radius: 4px;
            overflow-x: auto;
        }}
        .screenshot-modal {{
            max-width: 100%;
            height: auto;
            border-radius: 4px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .timestamp {{
            color: #666;
            font-size: 0.9em;
        }}
        .headers-section {{
            margin-top: 15px;
            padding-top: 15px;
            border-top: 1px solid #eee;
        }}
        .headers-section h4 {{
            margin: 0 0 10px 0;
            color: #2c3e50;
        }}
        .display-controls {{
            position: fixed;
            bottom: 20px;
            right: 20px;
            background: #fff;
            padding: 10px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            z-index: 100;
        }}
        .display-controls button {{
            padding: 5px 10px;
            margin: 0 5px;
            border: 1px solid #ddd;
            border-radius: 4px;
            background: #fff;
            cursor: pointer;
        }}
        .display-controls button:hover {{
            background: #f8f9fa;
        }}
        .display-controls button.active {{
            background: #007bff;
            color: #fff;
            border-color: #007bff;
        }}
        .redirect-label {{
            background: #fff3cd;
            color: #856404;
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 0.8em;
            margin-left: 8px;
        }}
        .redirect-section {{
            margin-top: 15px;
            padding: 10px;
            background: #f8f9fa;
            border-left: 4px solid #ffc107;
            border-radius: 4px;
        }}
        .redirect-section h4 {{
            margin: 0 0 10px 0;
            color: #856404;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Plainsight Scan Results - {domain}</h1>
            <p>Scan Date: {format_date(results[0]['scan_date'])}</p>
        </div>
"""

    for result in results:
        domain = result['domain']
        services = result['services']
        
        html_content += f"""
        <div class="domain-section">
            <div class="domain-header">
                <h2>{domain}</h2>
                <span class="timestamp">Scanned: {format_date(result['scan_date'])}</span>
            </div>
            <div class="services-grid cols-3">
"""
        
        # Convert services list to dictionary if it's not already
        if isinstance(services, list):
            services_dict = {service['url'].split('://')[-1].split('/')[0]: service for service in services if service}
        else:
            services_dict = services
        
        for service_name, service_data in services_dict.items():
            if service_data:
                status_class = "status-found"
                status_text = "Found"
                if service_data.get('redirect_url'):
                    status_text += " <span class='redirect-label'>Redirect</span>"
            else:
                status_class = "status-not-found"
                status_text = "Not Found"
            
            # Convert service_data to JSON string for data attribute, properly escaping quotes
            service_data_json = json.dumps(service_data).replace('"', '&quot;') if service_data else 'null'
            
            html_content += f"""
                <div class="service-card" data-service="{service_data_json}">
                    <h3>{service_name}</h3>
                    <span class="status {status_class}">{status_text}</span>
"""
            
            if service_data:
                html_content += f"""
                    <p>URL: {service_data['url']}</p>
                    <p>Status: {service_data['status']}</p>
"""
                if service_data.get('screenshot_path'):
                    screenshot_path = os.path.relpath(service_data['screenshot_path'], report_dir)
                    html_content += f"""
                    <img src="{screenshot_path}" alt="Screenshot" class="screenshot">
"""
            
            html_content += """
                </div>
"""
        
        html_content += """
            </div>
        </div>
"""
    
    html_content += """
    </div>
    
    <div class="display-controls">
        <button onclick="changeLayout(1)" class="active">1 Column</button>
        <button onclick="changeLayout(2)">2 Columns</button>
        <button onclick="changeLayout(3)">3 Columns</button>
    </div>
    
    <div id="detailsModal" class="modal">
        <div class="modal-content">
            <span class="close-button" onclick="closeModal()">&times;</span>
            <div class="tabs">
                <div class="tab active" onclick="switchTab('screenshot')">Screenshot</div>
                <div class="tab" onclick="switchTab('request')">Request</div>
                <div class="tab" onclick="switchTab('response')">Response</div>
                <div class="tab" onclick="switchTab('redirectRequest')">Redirect Request</div>
                <div class="tab" onclick="switchTab('redirectResponse')">Redirect Response</div>
            </div>
            <div id="screenshotTab" class="tab-content active">
                <img id="modalScreenshot" class="screenshot-modal" src="" alt="Screenshot">
            </div>
            <div id="requestTab" class="tab-content">
                <div id="requestDetails" class="request-details"></div>
            </div>
            <div id="responseTab" class="tab-content">
                <div id="responseDetails" class="response-details"></div>
            </div>
            <div id="redirectRequestTab" class="tab-content">
                <div id="redirectRequestDetails" class="request-details"></div>
            </div>
            <div id="redirectResponseTab" class="tab-content">
                <div id="redirectResponseDetails" class="response-details"></div>
            </div>
        </div>
    </div>

    <script>
        // Add click event listeners to all service cards
        document.addEventListener('DOMContentLoaded', function() {
            document.querySelectorAll('.service-card').forEach(card => {
                card.addEventListener('click', function() {
                    try {
                        const serviceData = JSON.parse(this.getAttribute('data-service'));
                        const serviceName = this.querySelector('h3').textContent;
                        const screenshot = this.querySelector('.screenshot');
                        
                        // Show modal
                        const modal = document.getElementById('detailsModal');
                        modal.style.display = 'block';
                        
                        // Set screenshot
                        if (screenshot) {
                            document.getElementById('modalScreenshot').src = screenshot.src;
                        }
                        
                        // Set request details
                        if (serviceData) {
                            // Original request details
                            const requestDetails = `URL: ${serviceData.url}
Method: GET
Status: ${serviceData.status}

Request Headers:
${Object.entries(serviceData.headers || {}).map(([key, value]) => `${key}: ${value}`).join('\\n')}`;
                            
                            document.getElementById('requestDetails').textContent = requestDetails;
                            
                            // Original response details
                            const responseDetails = `Status: ${serviceData.status}
URL: ${serviceData.url}

Response Headers:
${Object.entries(serviceData.headers || {}).map(([key, value]) => `${key}: ${value}`).join('\\n')}`;
                            
                            document.getElementById('responseDetails').textContent = responseDetails;
                            
                            // Redirect information if present
                            if (serviceData.redirect_url) {
                                const redirectRequestDetails = `Original URL: ${serviceData.url}
Redirect URL: ${serviceData.redirect_url}
Status: ${serviceData.status}

Request Headers:
${Object.entries(serviceData.headers || {}).map(([key, value]) => `${key}: ${value}`).join('\\n')}`;
                                
                                const redirectResponseDetails = `Status: ${serviceData.status}
Redirect URL: ${serviceData.redirect_url}

Response Headers:
${Object.entries(serviceData.headers || {}).map(([key, value]) => `${key}: ${value}`).join('\\n')}`;
                                
                                document.getElementById('redirectRequestDetails').textContent = redirectRequestDetails;
                                document.getElementById('redirectResponseDetails').textContent = redirectResponseDetails;
                                
                                // Show redirect tabs
                                document.querySelectorAll('.tab').forEach(tab => {
                                    if (tab.textContent.includes('Redirect')) {
                                        tab.style.display = 'block';
                                    }
                                });
                            } else {
                                // Hide redirect tabs if no redirect
                                document.querySelectorAll('.tab').forEach(tab => {
                                    if (tab.textContent.includes('Redirect')) {
                                        tab.style.display = 'none';
                                    }
                                });
                            }
                        } else {
                            document.getElementById('requestDetails').textContent = 'No request details available';
                            document.getElementById('responseDetails').textContent = 'No response details available';
                            document.getElementById('redirectRequestDetails').textContent = 'No redirect request details available';
                            document.getElementById('redirectResponseDetails').textContent = 'No redirect response details available';
                        }
                    } catch (error) {
                        console.error('Error parsing service data:', error);
                    }
                });
            });
        });
        
        function closeModal() {
            document.getElementById('detailsModal').style.display = 'none';
        }
        
        function switchTab(tabName) {
            // Hide all tabs
            document.querySelectorAll('.tab-content').forEach(tab => {
                tab.classList.remove('active');
            });
            document.querySelectorAll('.tab').forEach(tab => {
                tab.classList.remove('active');
            });
            
            // Show selected tab
            document.getElementById(tabName + 'Tab').classList.add('active');
            document.querySelector(`.tab[onclick="switchTab('${tabName}')"]`).classList.add('active');
        }
        
        function changeLayout(columns) {
            const grid = document.querySelector('.services-grid');
            grid.className = 'services-grid cols-' + columns;
            
            // Update active button
            document.querySelectorAll('.display-controls button').forEach(btn => {
                btn.classList.remove('active');
            });
            event.target.classList.add('active');
        }
        
        // Close modal when clicking outside
        window.onclick = function(event) {
            const modal = document.getElementById('detailsModal');
            if (event.target == modal) {
                closeModal();
            }
        }
    </script>
</body>
</html>
"""

    # Update the report filename to include the target domain
    report_path = os.path.join(report_dir, f'report_{safe_domain}.html')
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    if pretty_output:
        print(f"{Colors.GREEN}[+] Generated HTML report: {report_path}{Colors.RESET}")
    
    return report_path

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
    """Main function."""
    parser = argparse.ArgumentParser(description="OSINT tool for detecting 3rd party services used by companies.")
    parser.add_argument('domains', nargs='*', help='List of domains to process.')
    parser.add_argument('-f', '--file', type=str, help='File containing domains (one per line).')
    parser.add_argument('-v', '--verbose', action='count', default=0, help='Enable verbose output. Use -vv for extra verbose.')
    parser.add_argument('-o', '--output', type=str, help='Output directory for results.')
    parser.add_argument('--no-banner', action='store_true', help='Disable the ASCII banner.')
    parser.add_argument('--no-pretty', action='store_true', help='Disable pretty output formatting.')
    parser.add_argument('-t', '--threads', type=int, default=5, help='Number of threads for scanning (default: 5)')
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
            print(f"{Colors.RED}[-] Invalid domain: {domain}{Colors.RESET}")
            continue

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
            if not args.no_pretty:
                console.print(f"\n[bold cyan]╔════════════════════════════════════════════════════════════════════════════╗[/bold cyan]")
                console.print(f"[bold cyan]║[/bold cyan] [bold yellow]Scanning Domain:[/bold yellow] {domain:<50} [bold cyan]║[/bold cyan]")
                console.print(f"[bold cyan]╚════════════════════════════════════════════════════════════════════════════╝[/bold cyan]\n")
            else:
                print(f"\n[*] Scanning domain: {domain}")
            
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
            
            # Enhanced DNS security checks - now always enabled
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
            dns_findings = check_dns_txt(domain, definitions, logger, args.verbose, not args.no_pretty)
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
            status_queue.put(f"Checking for domain takeover opportunities")
            results['takeover_risks'] = check_domain_takeover(domain, results['services'], logger, args.verbose, not args.no_pretty)

            # Stop progress display if it exists
            if progress:
                progress.stop()
                console.print()  # Add newline after progress bar

            # Save individual domain results
            summary_path = os.path.join(domain_dir, f'summary_{safe_domain}.json')
            with open(summary_path, 'w') as f:
                json.dump(results, f, indent=2)

            # Save individual domain results as CSV
            save_results_to_csv(results, domain_dir, domain)

            # Add to all results
            all_results.append(results)

            status_queue.put(f"Completed scanning {domain}")
            status_queue.put("DONE")
            status_thread.join()

            # Save current results after each domain
            save_current_results(all_results, base_output_dir, not args.no_pretty)
            
            # Generate HTML report for the current domain
            if not args.no_pretty:
                generate_html_report([result for result in all_results if result['domain'] == domain], base_output_dir, not args.no_pretty)

        # Save final results
        save_current_results(all_results, base_output_dir, not args.no_pretty)
    except KeyboardInterrupt:
        if not args.no_pretty:
            print(f"\n{Colors.YELLOW}[!] Scan interrupted by user{Colors.RESET}")
        sys.exit(1)
    finally:
        driver.quit()

if __name__ == '__main__':
    main()
