# plainsight

OSINT tool for:
- Detecting 3rd party services used by companies.
- Checking DNS security
- Checking if domains are vulnerable to domain takeover

It will save the results to the "./plainsight_results" directory if nothing is defined.

A HTML report is generated that you can view locally to quickly review the discovered sites.

``` bash
usage: plainsight.py [-h] [-f FILE] [-v] [-o OUTPUT] [--no-banner] [--no-pretty] [-t THREADS] [domains ...]

OSINT tool for detecting 3rd party services used by companies.

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
  -t THREADS, --threads THREADS
                        Number of threads for scanning (default: 5)
```
