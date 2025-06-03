# plainsight

OSINT tool for:
- Detecting 3rd party services used by companies.
- Checking DNS security
- Checking if domains are vulnerable to domain takeover

``` bash
positional arguments:
  domains               List of domains to process.

options:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  File containing domains (one per line).
  -v, --verbose         Enable verbose output. Use -vv for extra verbose.
  -o OUTPUT, --output OUTPUT
                        Output directory for results.
  --no-banner           Disable the ASCII banner.
  --no-pretty           Disable pretty output formatting.
  --dns-security        Enable enhanced DNS security checks.
```
