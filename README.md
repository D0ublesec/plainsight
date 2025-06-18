# plainsight
## Overview
OSINT tool for:
- Detecting 3rd party services used by companies.
- Checking DNS security
- Checking if domains are vulnerable to domain takeover

## CLI Output Example
![plainsight_cli_hd](https://github.com/user-attachments/assets/d919778c-81bf-4e63-965f-62f3f0964854)

## HTML Report Example
A HTML report is generated that you can view locally to quickly review the discovered sites.

![plainsight_web_report_hd](https://github.com/user-attachments/assets/e7c47b84-4e06-4993-a648-2f0c4381feae)

## Install
1. Clone Repo
   ```
   git clone https://github.com/D0ublesec/plainsight.git
   ```
3. Install python requirements with pip
   ```
   pip install -r ./plainsight/requirements.txt
   ```
4. On Kali, ensure Chromium and its driver are installed
   ```
   sudo apt install chromium chromium-driver
   ```

## Help
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
