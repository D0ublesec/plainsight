# Plainsight

Plainsight is an OSINT tool for detecting 3rd party services used by companies.

## Features

- DNS record checking (A, AAAA, MX, TXT, SPF, DMARC, CNAME)
- Service detection by checking common subdomain patterns
- DNS security analysis (DNSSEC, email security)
- Domain takeover risk detection
- HTML report generation with dark mode support
- CSV export functionality
- Multi-threaded scanning
- Screenshot capture (requires Chrome/Chromium)
- **Full content encoding support** (gzip, Brotli/br, deflate)
- Logo/favicon fetching using Google's favicon service


## Installation

1. Ensure Go 1.21+ is installed
2. Install dependencies:
   ```bash
   go mod tidy
   ```
3. Build:
   ```bash
   go build -o plainsight
   ```

## Usage

```bash
# Scan a single domain
./plainsight example.com

# Scan multiple domains
./plainsight example.com example2.com

# Scan domains from a file
./plainsight -f domains.txt

# Specify output directory
./plainsight -o /path/to/output example.com

# Enable verbose output
./plainsight -v example.com

# Set number of threads
./plainsight -t 10 example.com

# Disable pretty output
./plainsight --no-pretty example.com
```

## Command Line Options

- `-f, --file`: File containing domains (one per line)
- `-v`: Enable verbose output (use `-vv` for extra verbose)
- `-o, --output`: Output directory for results (default: `./plainsight_results`)
- `--no-banner`: Disable the ASCII banner
- `--no-pretty`: Disable pretty output formatting
- `-t, --threads`: Number of threads for scanning (default: 5)

## Output

Results are saved in the output directory with the following structure:

```
plainsight_results/
├── example_com/
│   ├── summary_example_com.json
│   ├── services_example_com.csv
│   ├── dns_records_example_com.txt
│   ├── dns_email_security_example_com.csv
│   ├── company_logo_example_com.png
│   ├── index.html (HTML report)
│   └── [service_name]/
│       └── index_example_com_[service_name].html
```

## Dependencies

- `github.com/fatih/color` - Colored terminal output
- `github.com/miekg/dns` - DNS query functionality
- `github.com/chromedp/chromedp` - Screenshot capture (optional)
- `github.com/andybalholm/brotli` - Brotli decompression support

## Content Encoding Support

Plainsight automatically handles all common HTTP content encodings:
- **gzip** - Standard gzip compression
- **br (Brotli)** - Modern Brotli compression
- **deflate** - Deflate compression
- **Multiple encodings** - Handles comma-separated encodings (e.g., "br, gzip")

The tool automatically decompresses response bodies based on the `Content-Encoding` header.

## Notes

- The tool requires internet access to query DNS and check services
- Some services may have rate limiting or blocking mechanisms
- Results are saved incrementally, so you can interrupt the scan and resume later
- Screenshots require Chrome/Chromium to be installed (optional feature)
- The tool gracefully handles missing Chrome installation and continues without screenshots
