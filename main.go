package main

import (
	"bufio"
	"compress/flate"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/chromedp/chromedp"
	"github.com/fatih/color"
	"github.com/miekg/dns"
)

// Colors for terminal output
var (
	green   = color.New(color.FgGreen)
	red     = color.New(color.FgRed)
	yellow  = color.New(color.FgYellow)
	cyan    = color.New(color.FgCyan)
	blue    = color.New(color.FgBlue)
	magenta = color.New(color.FgMagenta)
	bold    = color.New(color.Bold)
)

// errorFilterWriter filters out harmless chromedp error messages
type errorFilterWriter struct {
	original io.Writer
}

func (w *errorFilterWriter) Write(p []byte) (n int, err error) {
	msg := string(p)
	// Filter out known harmless chromedp errors
	if strings.Contains(msg, "could not unmarshal event") &&
		(strings.Contains(msg, "cookiePart") ||
			strings.Contains(msg, "PrivateNetworkRequestPolicy") ||
			strings.Contains(msg, "parse error") ||
			strings.Contains(msg, "unknown PrivateNetworkRequestPolicy")) {
		// Suppress these errors by returning success but not writing
		return len(p), nil
	}
	// Write all other messages to original stderr
	return w.original.Write(p)
}

// Definitions structure
type Definitions struct {
	Services   []string
	DNSStrings []string
}

// DNSResults structure
type DNSResults struct {
	A     []string `json:"A"`
	AAAA  []string `json:"AAAA"`
	MX    []string `json:"MX"`
	TXT   []string `json:"TXT"`
	SPF   []string `json:"SPF"`
	DMARC []string `json:"DMARC"`
	CNAME []string `json:"CNAME"`
}

// LogoInfo structure
type LogoInfo struct {
	URL      string `json:"url"`
	Base64   string `json:"base64"`
	Source   string `json:"source"`
	FilePath string `json:"file_path"`
}

// ServiceResult structure
type ServiceResult struct {
	URL            string            `json:"url"`
	Status         int               `json:"status"`
	HTMLPath       string            `json:"html_path"`
	ScreenshotPath string            `json:"screenshot_path,omitempty"`
	Headers        map[string]string `json:"headers"`
	RequestHeaders map[string]string `json:"request_headers,omitempty"`
	RedirectURL    string            `json:"redirect_url,omitempty"`
	ResponseBody   string            `json:"response_body,omitempty"`
	Logo           *LogoInfo         `json:"logo,omitempty"`
}

// ScanResult structure
type ScanResult struct {
	Domain         string                 `json:"domain"`
	ScanDate       string                 `json:"scan_date"`
	DNSRecords     DNSResults             `json:"dns_records"`
	Services       []ServiceResult        `json:"services"`
	DNSTxtFindings []string               `json:"dns_txt_findings"`
	DNSSecurity    map[string]interface{} `json:"dns_security"`
	CompanyLogo    *LogoInfo              `json:"company_logo"`
	TakeoverRisks  []interface{}          `json:"takeover_risks"`
}

// Config structure
type Config struct {
	Domains  []string
	File     string
	Verbose  int
	Output   string
	NoBanner bool
	NoPretty bool
	Threads  int
}

var userInterrupted bool
var interruptMutex sync.Mutex

func main() {
	config := parseArgs()

	if len(config.Domains) == 0 && config.File == "" {
		fmt.Fprintf(os.Stderr, "Error: Please provide either domains or a file\n")
		os.Exit(1)
	}

	// Load domains from file if specified
	if config.File != "" {
		domains, err := loadDomainsFromFile(config.File)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
			os.Exit(1)
		}
		config.Domains = append(config.Domains, domains...)
	}

	// Validate domains
	var validDomains []string
	for _, domain := range config.Domains {
		if validateDomain(domain) {
			validDomains = append(validDomains, domain)
		} else {
			red.Printf("[-] Invalid domain: %s\n", domain)
		}
	}

	if len(validDomains) == 0 {
		fmt.Fprintf(os.Stderr, "Error: No valid domains provided\n")
		os.Exit(1)
	}

	// Setup output directory
	baseOutputDir := config.Output
	if baseOutputDir == "" {
		cwd, _ := os.Getwd()
		baseOutputDir = filepath.Join(cwd, "plainsight_results")
	}
	os.MkdirAll(baseOutputDir, 0755)

	// Print banner
	if !config.NoBanner {
		printBanner()
	}

	// Load definitions
	definitions, err := loadDefinitions()
	if err != nil {
		red.Printf("[-] Error loading definitions: %v\n", err)
		os.Exit(1)
	}

	if len(definitions.Services) == 0 {
		red.Printf("[-] No services found in definitions/public_services.txt\n")
		os.Exit(1)
	}

	// Setup ChromeDP allocator for screenshots (optional, will fail gracefully if Chrome not available)
	var allocCtx context.Context
	var allocCancel context.CancelFunc
	chromeAvailable := false

	// Suppress chromedp's internal logging (those parse errors are harmless)
	// These are Chrome DevTools Protocol parsing errors that don't affect functionality
	originalLogOutput := log.Writer()
	log.SetOutput(io.Discard)

	// Try to setup ChromeDP allocator
	// Redirect stderr to suppress Chrome's error output
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.WindowSize(1920, 1080),
		chromedp.DisableGPU,
		chromedp.Flag("disable-logging", true),
		chromedp.Flag("log-level", "3"), // Only show fatal errors
	)

	allocCtx, allocCancel = chromedp.NewExecAllocator(context.Background(), opts...)

	// Custom logger that filters out harmless chromedp parse errors
	filteredLogger := func(format string, v ...interface{}) {
		msg := fmt.Sprintf(format, v...)
		// Filter out known harmless chromedp errors
		if strings.Contains(msg, "could not unmarshal event") &&
			(strings.Contains(msg, "cookiePart") ||
				strings.Contains(msg, "PrivateNetworkRequestPolicy") ||
				strings.Contains(msg, "parse error")) {
			return // Suppress these harmless errors
		}
		// Only log if verbose mode is enabled
		if config.Verbose >= 2 {
			log.Printf(msg)
		}
	}

	// Redirect stderr to filter Chrome errors during initialization
	originalStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w
	filteredWriter := &errorFilterWriter{original: originalStderr}

	// Start goroutine to filter stderr output
	done := make(chan struct{})
	go func() {
		defer close(done)
		scanner := bufio.NewScanner(r)
		for scanner.Scan() {
			line := scanner.Bytes()
			filteredWriter.Write(append(line, '\n'))
		}
	}()

	// Test if Chrome is available by creating a test context
	// Use WithLogf to filter out harmless chromedp parse errors
	testCtx, testCancel := chromedp.NewContext(allocCtx, chromedp.WithLogf(filteredLogger))
	testTimeoutCtx, testTimeoutCancel := context.WithTimeout(testCtx, 5*time.Second)
	testErr := chromedp.Run(testTimeoutCtx)
	testTimeoutCancel()
	testCancel()

	// Restore log output and stderr after Chrome setup
	log.SetOutput(originalLogOutput)
	w.Close()
	os.Stderr = originalStderr
	r.Close()
	<-done

	if testErr == nil {
		chromeAvailable = true
		if !config.NoPretty {
			green.Println("[+] Chrome/Chromium detected - screenshots enabled")
		}
	} else {
		if !config.NoPretty {
			yellow.Printf("[!] Chrome/Chromium not available - screenshots disabled: %v\n", testErr)
		}
		allocCancel()
		allocCtx = nil
	}

	// Defer cleanup
	defer func() {
		if allocCancel != nil {
			allocCancel()
		}
	}()

	// Store all results
	var allResults []ScanResult

	// Process each domain
	for _, domain := range validDomains {
		if checkInterrupted() {
			if !config.NoPretty {
				yellow.Println("\n[!] Scan cancelled by user")
			}
			saveCurrentResults(allResults, baseOutputDir, !config.NoPretty)
			return
		}

		if !config.NoPretty {
			cyan.Println("\n╔════════════════════════════════════════════════════════════════════════════╗")
			cyan.Printf("║ Scanning Domain: %-50s ║\n", domain)
			cyan.Println("╚════════════════════════════════════════════════════════════════════════════╝\n")
		} else {
			fmt.Printf("\n[*] Scanning domain: %s\n", domain)
		}

		// Create domain directory
		safeDomain := strings.ReplaceAll(domain, ".", "_")
		domainDir := filepath.Join(baseOutputDir, safeDomain)
		os.MkdirAll(domainDir, 0755)

		// Get company logo
		companyLogo := getCompanyLogo(domain, domainDir, !config.NoPretty)

		// Initialize result
		result := ScanResult{
			Domain:         domain,
			ScanDate:       time.Now().Format("2006-01-02 15:04:05"),
			DNSRecords:     DNSResults{},
			Services:       []ServiceResult{},
			DNSTxtFindings: []string{},
			DNSSecurity:    make(map[string]interface{}),
			CompanyLogo:    companyLogo,
			TakeoverRisks:  []interface{}{},
		}

		// Check DNS records
		if !config.NoPretty {
			cyan.Printf("[*] Checking DNS records for %s\n", domain)
		}
		result.DNSRecords = checkDNSRecords(domain, config.Verbose, !config.NoPretty)

		// Check DNS security
		if !config.NoPretty {
			cyan.Printf("[*] Performing enhanced DNS security checks for %s\n", domain)
		}
		result.DNSSecurity = checkDNSSecurity(domain, config.Verbose, !config.NoPretty)
		saveDNSSecurityToCSV(result.DNSSecurity, domainDir, domain)

		// Print DNS results
		printDNSResults(result.DNSRecords, !config.NoPretty)
		saveDNSResults(result.DNSRecords, domainDir, domain)

		// Check DNS TXT records
		if !config.NoPretty {
			cyan.Println("[*] Checking DNS TXT records for service indicators")
		}
		result.DNSTxtFindings = checkDNSTxt(domain, definitions, config.Verbose, !config.NoPretty)

		// Check services
		if !config.NoPretty {
			cyan.Printf("[*] Checking services for %s\n", domain)
		}

		// Use worker pool for service checking
		serviceChan := make(chan string, len(definitions.Services))
		resultChan := make(chan *ServiceResult, len(definitions.Services))

		// Send all services to channel
		for _, service := range definitions.Services {
			serviceChan <- service
		}
		close(serviceChan)

		// Start workers
		var wg sync.WaitGroup
		for i := 0; i < config.Threads; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for service := range serviceChan {
					if checkInterrupted() {
						return
					}
					// Pass the allocator context - takeScreenshot will create its own browser context
					serviceResult := checkService(domain, service, domainDir, allocCtx, chromeAvailable, config.Verbose, !config.NoPretty)
					if serviceResult != nil {
						resultChan <- serviceResult
					}
				}
			}()
		}

		// Wait for all workers to finish
		go func() {
			wg.Wait()
			close(resultChan)
		}()

		// Collect results
		for serviceResult := range resultChan {
			result.Services = append(result.Services, *serviceResult)
		}

		// Check for domain takeover opportunities
		if !config.NoPretty {
			cyan.Println("[*] Checking for domain takeover opportunities")
		}
		result.TakeoverRisks = checkDomainTakeover(domain, result.Services, config.Verbose, !config.NoPretty)

		// Save individual domain results
		saveDomainResults(result, domainDir, safeDomain)

		// Add to all results
		allResults = append(allResults, result)

		// Save current results
		saveCurrentResults(allResults, baseOutputDir, !config.NoPretty)

		// Generate HTML report
		if !config.NoPretty {
			generateHTMLReport([]ScanResult{result}, domainDir, !config.NoPretty)
		}
	}

	// Save final results
	saveCurrentResults(allResults, baseOutputDir, !config.NoPretty)
}

func parseArgs() *Config {
	config := &Config{}

	// Pre-process args to handle -v 1 syntax (convert to -v=1)
	args := make([]string, 0, len(os.Args)-1)
	domains := make([]string, 0)

	for i := 1; i < len(os.Args); i++ {
		arg := os.Args[i]

		// Handle -v 1 syntax
		if arg == "-v" && i+1 < len(os.Args) && len(os.Args[i+1]) > 0 && os.Args[i+1][0] != '-' {
			// Convert "-v 1" to "-v=1"
			args = append(args, "-v="+os.Args[i+1])
			i++ // Skip the next argument since we've combined it
		} else if len(arg) > 0 && arg[0] == '-' {
			// It's a flag, add to args
			args = append(args, arg)
		} else {
			// It's a domain, collect separately
			domains = append(domains, arg)
		}
	}

	flag.StringVar(&config.File, "f", "", "File containing domains (one per line)")
	flag.StringVar(&config.File, "file", "", "File containing domains (one per line)")
	flag.IntVar(&config.Verbose, "v", 0, "Verbose level (0=none, 1=verbose, 2=extra verbose)")
	flag.StringVar(&config.Output, "o", "", "Output directory for results")
	flag.StringVar(&config.Output, "output", "", "Output directory for results")
	noBanner := flag.Bool("no-banner", false, "Disable the ASCII banner")
	noPretty := flag.Bool("no-pretty", false, "Disable pretty output formatting")
	flag.IntVar(&config.Threads, "t", 5, "Number of threads for scanning (default: 5)")
	flag.IntVar(&config.Threads, "threads", 5, "Number of threads for scanning (default: 5)")

	// Parse flags
	flag.CommandLine.Parse(args)

	// Add any domains from flag.Args() (in case flags came first)
	config.Domains = append(domains, flag.Args()...)
	config.NoBanner = *noBanner
	config.NoPretty = *noPretty

	return config
}

func validateDomain(domain string) bool {
	pattern := `^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`
	matched, _ := regexp.MatchString(pattern, domain)
	return matched
}

func printBanner() {
	// Ghost banner - keeping the original style
	banner := `    _ (` + "`" + `-.              ('-.                  .-') _   .-')                         ('-. .-. .-') _
   ( (OO  )            ( OO ).-.             ( OO ) ) ( OO ).                      ( OO )  /(  OO) )
  _.` + "`" + `     \ ,--.       / . --. /  ,-.-') ,--./ ,--,' (_)---\_)  ,-.-')   ,----.    ,--. ,--./     '._
 (__...--'' |  |.-')   | \-.  \   |  |OO)|   \ |  |\ /    _ |   |  |OO) '  .-./-') |  | |  ||'--...__)
  |  /  | | |  | OO ).-'-'  |  |  |  |  \|    \|  | )\  :` + "`" + ` ` + "`" + `.   |  |  \ |  |_( O- )|   .|  |'--.  .--'
  |  |_.' | |  |` + "`" + `-' | \| |_.'  |  |  |(_/|  .     |/  '..` + "`" + `''.)  |  |(_/ |  | .--, \|       |   |  |
  |  .___.'(|  '---.'  |  .-.  | ,|  |_.'|  |\    |  .-._)   \ ,|  |_.'(|  | '. (_/|  .-.  |   |  |
  |  |      |      |   |  | |  |(_|  |   |  | \   |  \       /(_|  |    |  '--'  | |  | |  |   |  |
  ` + "`" + `--'      ` + "`" + `------'   ` + "`" + `--' ` + "`" + `--'  ` + "`" + `--'   ` + "`" + `--'  ` + "`" + `-----'   ` + "`" + `--'     ` + "`" + `------'  ` + "`" + `--' ` + "`" + `--'   ` + "`" + `--'    
`
	cyan.Println(banner)
}

func loadDomainsFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var domains []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			domains = append(domains, line)
		}
	}
	return domains, scanner.Err()
}

func getDefinitionsPath(filename string) string {
	// Get the directory where the executable is located
	exePath, err := os.Executable()
	if err != nil {
		// Fallback to current directory
		return filepath.Join("definitions", filename)
	}
	exeDir := filepath.Dir(exePath)
	return filepath.Join(exeDir, "definitions", filename)
}

func loadDefinitions() (*Definitions, error) {
	definitions := &Definitions{
		Services:   []string{},
		DNSStrings: []string{},
	}

	// Load public services
	servicesPath := getDefinitionsPath("public_services.txt")
	file, err := os.Open(servicesPath)
	if err == nil {
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				definitions.Services = append(definitions.Services, line)
			}
		}
	}

	// Load DNS TXT strings
	dnsStringsPath := getDefinitionsPath("dns_txt_strings.txt")
	file, err = os.Open(dnsStringsPath)
	if err == nil {
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				definitions.DNSStrings = append(definitions.DNSStrings, line)
			}
		}
	}

	return definitions, nil
}

func checkInterrupted() bool {
	interruptMutex.Lock()
	defer interruptMutex.Unlock()
	return userInterrupted
}

func setInterrupted() {
	interruptMutex.Lock()
	defer interruptMutex.Unlock()
	userInterrupted = true
}

// getCompanyLogo fetches company logo using Google's favicon service instead of Clearbit
func getCompanyLogo(domain, outputDir string, prettyOutput bool) *LogoInfo {
	// Use Google's favicon service as Clearbit is no longer reliable
	// Google's service: https://www.google.com/s2/favicons?domain=example.com&sz=128
	logoURL := fmt.Sprintf("https://www.google.com/s2/favicons?domain=%s&sz=128", domain)

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Get(logoURL)
	if err != nil {
		if prettyOutput {
			yellow.Printf("[!] Could not fetch company logo: %v\n", err)
		}
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		if prettyOutput {
			yellow.Printf("[!] Could not fetch company logo: HTTP %d\n", resp.StatusCode)
		}
		return nil
	}

	// Read logo data
	logoData, err := io.ReadAll(resp.Body)
	if err != nil {
		if prettyOutput {
			yellow.Printf("[!] Could not read logo data: %v\n", err)
		}
		return nil
	}

	// Save logo to file
	safeDomain := strings.ReplaceAll(domain, ".", "_")
	logoPath := filepath.Join(outputDir, fmt.Sprintf("company_logo_%s.png", safeDomain))

	err = os.WriteFile(logoPath, logoData, 0644)
	if err != nil {
		if prettyOutput {
			yellow.Printf("[!] Could not save logo: %v\n", err)
		}
		return nil
	}

	if prettyOutput {
		green.Printf("[+] Found company logo for %s\n", domain)
	}

	return &LogoInfo{
		URL:      logoURL,
		Base64:   base64.StdEncoding.EncodeToString(logoData),
		Source:   "google_favicon",
		FilePath: logoPath,
	}
}

func checkDNSRecords(domain string, verboseLevel int, prettyOutput bool) DNSResults {
	results := DNSResults{
		A:     []string{},
		AAAA:  []string{},
		MX:    []string{},
		TXT:   []string{},
		SPF:   []string{},
		DMARC: []string{},
		CNAME: []string{},
	}

	// Create DNS client with timeout
	client := &dns.Client{
		Timeout: 2 * time.Second,
	}

	// Configure resolver
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeA)

	recordTypes := []struct {
		Type  uint16
		Name  string
		Store *[]string
	}{
		{dns.TypeA, "A", &results.A},
		{dns.TypeAAAA, "AAAA", &results.AAAA},
		{dns.TypeMX, "MX", &results.MX},
		{dns.TypeTXT, "TXT", &results.TXT},
		{dns.TypeCNAME, "CNAME", &results.CNAME},
	}

	for _, rt := range recordTypes {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(domain), rt.Type)

		r, _, err := client.Exchange(m, "8.8.8.8:53")
		if err != nil {
			if verboseLevel >= 1 && prettyOutput {
				yellow.Printf("[!] Error checking %s records: %v\n", rt.Name, err)
			}
			continue
		}

		if r.Rcode != dns.RcodeSuccess {
			if verboseLevel >= 1 && prettyOutput {
				yellow.Printf("[!] No %s records found for %s\n", rt.Name, domain)
			}
			continue
		}

		for _, answer := range r.Answer {
			switch rt.Type {
			case dns.TypeA:
				if a, ok := answer.(*dns.A); ok {
					*rt.Store = append(*rt.Store, a.A.String())
					if verboseLevel >= 1 && prettyOutput {
						cyan.Printf("[~] %s Record: %s\n", rt.Name, a.A.String())
					}
				}
			case dns.TypeAAAA:
				if aaaa, ok := answer.(*dns.AAAA); ok {
					*rt.Store = append(*rt.Store, aaaa.AAAA.String())
					if verboseLevel >= 1 && prettyOutput {
						cyan.Printf("[~] %s Record: %s\n", rt.Name, aaaa.AAAA.String())
					}
				}
			case dns.TypeMX:
				if mx, ok := answer.(*dns.MX); ok {
					*rt.Store = append(*rt.Store, fmt.Sprintf("%d %s", mx.Preference, mx.Mx))
					if verboseLevel >= 1 && prettyOutput {
						cyan.Printf("[~] %s Record: %d %s\n", rt.Name, mx.Preference, mx.Mx)
					}
				}
			case dns.TypeTXT:
				if txt, ok := answer.(*dns.TXT); ok {
					txtStr := strings.Join(txt.Txt, "")
					*rt.Store = append(*rt.Store, txtStr)
					if verboseLevel >= 1 && prettyOutput {
						cyan.Printf("[~] %s Record: %s\n", rt.Name, txtStr)
					}
					// Check for SPF (case-insensitive, handle whitespace and quotes)
					txtStrClean := strings.Trim(strings.TrimSpace(txtStr), `"'`)
					txtStrLower := strings.ToLower(txtStrClean)
					if strings.HasPrefix(txtStrLower, "v=spf1") {
						results.SPF = append(results.SPF, txtStrClean)
					} else if strings.Contains(txtStrLower, "v=spf1") {
						// SPF might be embedded in the record
						idx := strings.Index(txtStrLower, "v=spf1")
						if idx >= 0 {
							potentialSPF := txtStrClean[idx:]
							// Validate it looks like an SPF record
							if strings.Contains(strings.ToLower(potentialSPF), "include:") ||
								strings.Contains(strings.ToLower(potentialSPF), "mx") ||
								strings.Contains(strings.ToLower(potentialSPF), "all") {
								results.SPF = append(results.SPF, potentialSPF)
							}
						}
					}
				}
			case dns.TypeCNAME:
				if cname, ok := answer.(*dns.CNAME); ok {
					*rt.Store = append(*rt.Store, cname.Target)
					if verboseLevel >= 1 && prettyOutput {
						cyan.Printf("[~] %s Record: %s\n", rt.Name, cname.Target)
					}
				}
			}
		}
	}

	// Check DMARC
	dmarcDomain := fmt.Sprintf("_dmarc.%s", domain)
	m = new(dns.Msg)
	m.SetQuestion(dns.Fqdn(dmarcDomain), dns.TypeTXT)

	r, _, err := client.Exchange(m, "8.8.8.8:53")
	if err == nil && r.Rcode == dns.RcodeSuccess {
		for _, answer := range r.Answer {
			if txt, ok := answer.(*dns.TXT); ok {
				txtStr := strings.Join(txt.Txt, "")
				if strings.Contains(txtStr, "v=DMARC1") {
					results.DMARC = append(results.DMARC, txtStr)
					if verboseLevel >= 1 && prettyOutput {
						cyan.Printf("[~] DMARC Record: %s\n", txtStr)
					}
				}
			}
		}
	}

	return results
}

func checkDNSTxt(domain string, definitions *Definitions, verboseLevel int, prettyOutput bool) []string {
	if verboseLevel >= 1 && prettyOutput {
		cyan.Println("[*] Checking DNS TXT records for service indicators")
	}

	client := &dns.Client{
		Timeout: 2 * time.Second,
	}

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeTXT)

	r, _, err := client.Exchange(m, "8.8.8.8:53")
	if err != nil {
		if verboseLevel >= 1 && prettyOutput {
			red.Printf("[-] Error checking TXT records: %v\n", err)
		}
		return []string{}
	}

	if r.Rcode != dns.RcodeSuccess {
		if verboseLevel >= 1 && prettyOutput {
			yellow.Printf("[!] No TXT records found for %s\n", domain)
		}
		return []string{}
	}

	var foundServices []string

	for _, answer := range r.Answer {
		if txt, ok := answer.(*dns.TXT); ok {
			txtStr := strings.Join(txt.Txt, "")
			if verboseLevel >= 1 && prettyOutput {
				cyan.Printf("[~] TXT Record: %s\n", txtStr)
			}

			// Check for service indicators
			for _, indicator := range definitions.DNSStrings {
				if strings.Contains(strings.ToLower(txtStr), strings.ToLower(indicator)) {
					foundServices = append(foundServices, indicator)
					if verboseLevel >= 1 && prettyOutput {
						green.Printf("[+] Found %s in TXT record\n", indicator)
					}
				}
			}
		}
	}

	if len(foundServices) > 0 && verboseLevel >= 1 && prettyOutput {
		green.Printf("[+] Found service indicators for: %s\n", strings.Join(foundServices, ", "))
	}

	return foundServices
}

func takeScreenshot(allocCtx context.Context, url, outputPath string) string {
	if allocCtx == nil {
		return ""
	}

	// Suppress chromedp's internal logging during screenshot operations
	originalLogOutput := log.Writer()
	originalStderr := os.Stderr
	log.SetOutput(io.Discard)

	// Redirect stderr to filter out Chrome's error messages
	// Create a pipe to intercept stderr output
	r, w, _ := os.Pipe()
	os.Stderr = w
	filteredWriter := &errorFilterWriter{original: originalStderr}

	// Start goroutine to filter stderr output
	done := make(chan struct{})
	go func() {
		defer close(done)
		scanner := bufio.NewScanner(r)
		for scanner.Scan() {
			line := scanner.Bytes()
			filteredWriter.Write(append(line, '\n'))
		}
	}()

	defer func() {
		log.SetOutput(originalLogOutput)
		w.Close()
		os.Stderr = originalStderr
		r.Close()
		<-done
	}()

	// Custom logger that filters out harmless chromedp parse errors
	filteredLogger := func(format string, v ...interface{}) {
		msg := fmt.Sprintf(format, v...)
		// Filter out known harmless chromedp errors
		if strings.Contains(msg, "could not unmarshal event") &&
			(strings.Contains(msg, "cookiePart") ||
				strings.Contains(msg, "PrivateNetworkRequestPolicy") ||
				strings.Contains(msg, "parse error")) {
			return // Suppress these harmless errors
		}
		// Don't log chromedp messages during screenshots
	}

	// Create a new browser context from the allocator for this screenshot
	// Each screenshot needs its own browser context (cannot share across goroutines)
	// Use WithLogf to filter out harmless chromedp parse errors
	screenshotCtx, cancel := chromedp.NewContext(allocCtx, chromedp.WithLogf(filteredLogger))
	defer cancel()

	timeoutCtx, timeoutCancel := context.WithTimeout(screenshotCtx, 15*time.Second)
	defer timeoutCancel()

	var buf []byte
	err := chromedp.Run(timeoutCtx,
		chromedp.Navigate(url),
		chromedp.Sleep(2*time.Second),
		chromedp.CaptureScreenshot(&buf),
	)

	if err != nil {
		// Error will be logged by caller if verbose
		return ""
	}

	if len(buf) == 0 {
		return ""
	}

	// Ensure directory exists
	dir := filepath.Dir(outputPath)
	os.MkdirAll(dir, 0755)

	err = os.WriteFile(outputPath, buf, 0644)
	if err != nil {
		return ""
	}

	// Verify file was written
	if info, err := os.Stat(outputPath); err != nil || info.Size() == 0 {
		return ""
	}

	return outputPath
}

// getDecompressedReader returns a reader that decompresses the response body
// based on the Content-Encoding header. Supports gzip, br (Brotli), deflate,
// and multiple encodings (decoded in reverse order).
func getDecompressedReader(resp *http.Response) (io.Reader, error) {
	contentEncoding := resp.Header.Get("Content-Encoding")
	if contentEncoding == "" {
		return resp.Body, nil
	}

	// Parse encodings (can be comma-separated, e.g., "br, gzip")
	encodings := strings.Split(contentEncoding, ",")
	// Reverse the order since encodings are applied last-first
	for i, j := 0, len(encodings)-1; i < j; i, j = i+1, j-1 {
		encodings[i], encodings[j] = encodings[j], encodings[i]
	}

	var reader io.Reader = resp.Body
	var err error

	for _, encoding := range encodings {
		encoding = strings.TrimSpace(strings.ToLower(encoding))
		switch encoding {
		case "gzip":
			reader, err = gzip.NewReader(reader)
			if err != nil {
				return resp.Body, fmt.Errorf("gzip decompression failed: %w", err)
			}
		case "br":
			reader = brotli.NewReader(reader)
		case "deflate":
			reader = flate.NewReader(reader)
		case "identity", "":
			// No-op, already decompressed or no encoding
		default:
			// Unknown encoding, return original body
			return resp.Body, fmt.Errorf("unsupported encoding: %s", encoding)
		}
	}

	return reader, nil
}

func checkService(domain, service, outputDir string, allocCtx context.Context, chromeAvailable bool, verboseLevel int, prettyOutput bool) *ServiceResult {
	companyName := strings.Split(domain, ".")[0]
	serviceURL := fmt.Sprintf("https://%s.%s", companyName, service)

	if verboseLevel >= 1 && prettyOutput {
		cyan.Printf("[*] Checking service: %s\n", serviceURL)
	}

	req, err := http.NewRequest("GET", serviceURL, nil)
	if err != nil {
		return nil
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Cache-Control", "max-age=0")

	// Capture request headers
	requestHeaders := make(map[string]string)
	for k, v := range req.Header {
		if len(v) > 0 {
			requestHeaders[k] = v[0]
		}
	}

	// Create a client that follows redirects and captures them
	var redirectURL string
	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Capture redirect URL
			if len(via) > 0 {
				redirectURL = req.URL.String()
			}
			return nil
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		if verboseLevel >= 1 && prettyOutput {
			red.Printf("[-] Service not accessible: %s - %v\n", serviceURL, err)
		}
		return nil
	}
	defer resp.Body.Close()

	// If redirect happened, capture final URL
	if redirectURL == "" && resp.Request != nil && resp.Request.URL != nil {
		finalURL := resp.Request.URL.String()
		if finalURL != serviceURL {
			redirectURL = finalURL
		}
	}

	// Check for specific service filters
	if shouldFilterService(service, serviceURL, redirectURL, resp) {
		return nil
	}

	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		// Create service directory
		serviceName := strings.ReplaceAll(service, ".", "_")
		safeDomain := strings.ReplaceAll(domain, ".", "_")
		serviceDir := filepath.Join(outputDir, serviceName)
		os.MkdirAll(serviceDir, 0755)

		// Read response body - handle all common content encodings
		bodyReader, err := getDecompressedReader(resp)
		if err != nil {
			if verboseLevel >= 1 && prettyOutput {
				yellow.Printf("[!] Warning: Could not decompress response body: %v\n", err)
			}
			bodyReader = resp.Body
		}

		body, err := io.ReadAll(bodyReader)
		if err != nil {
			body = []byte{}
		}

		// Save HTML (save decompressed version)
		htmlPath := filepath.Join(serviceDir, fmt.Sprintf("index_%s_%s.html", safeDomain, serviceName))
		os.WriteFile(htmlPath, body, 0644)

		// Extract headers
		headers := make(map[string]string)
		for k, v := range resp.Header {
			if len(v) > 0 {
				headers[k] = v[0]
			}
		}

		// Limit response body size for JSON storage
		responseBody := string(body)
		if len(responseBody) > 5000 {
			responseBody = responseBody[:5000]
		}

		// Take screenshot if Chrome is available
		var screenshotPath string
		if chromeAvailable && allocCtx != nil {
			screenshotFilename := fmt.Sprintf("screenshot_%s_%s.png", safeDomain, serviceName)
			fullScreenshotPath := filepath.Join(serviceDir, screenshotFilename)
			if verboseLevel >= 1 && prettyOutput {
				cyan.Printf("[~] Taking screenshot: %s\n", serviceURL)
			}
			takenPath := takeScreenshot(allocCtx, serviceURL, fullScreenshotPath)
			if takenPath != "" {
				// Calculate relative path from reportDir (where index.html is) to screenshot
				// reportDir is the domain directory (outputDir), serviceDir is outputDir/serviceName
				// So relative path is: serviceName/screenshotFilename
				relPath, err := filepath.Rel(outputDir, fullScreenshotPath)
				if err == nil {
					screenshotPath = relPath
					// Normalize path separators for web
					screenshotPath = strings.ReplaceAll(screenshotPath, "\\", "/")
					if verboseLevel >= 1 && prettyOutput {
						green.Printf("[+] Screenshot saved: %s\n", screenshotPath)
					}
				} else {
					// Fallback: use serviceName/screenshotFilename
					screenshotPath = filepath.Join(serviceName, screenshotFilename)
					screenshotPath = strings.ReplaceAll(screenshotPath, "\\", "/")
					if verboseLevel >= 1 && prettyOutput {
						yellow.Printf("[!] Using fallback screenshot path: %s\n", screenshotPath)
					}
				}
			} else {
				screenshotPath = ""
				if verboseLevel >= 1 && prettyOutput {
					yellow.Printf("[!] Screenshot failed for %s\n", serviceURL)
				}
			}
		}

		if prettyOutput {
			if redirectURL != "" {
				yellow.Printf("[!] Redirect detected: %s -> %s\n", serviceURL, redirectURL)
			} else {
				green.Printf("[+] Found service: %s (Status: %d)\n", serviceURL, resp.StatusCode)
			}
		}

		return &ServiceResult{
			URL:            serviceURL,
			Status:         resp.StatusCode,
			HTMLPath:       htmlPath,
			ScreenshotPath: screenshotPath,
			Headers:        headers,
			RequestHeaders: requestHeaders,
			RedirectURL:    redirectURL,
			ResponseBody:   responseBody,
		}
	}

	return nil
}

func shouldFilterService(service, serviceURL, redirectURL string, resp *http.Response) bool {
	// Auth0 check
	if service == "auth0.com" && strings.Contains(redirectURL, "auth0.com") {
		return true
	}

	// Box check
	if service == "box.com" && strings.Contains(redirectURL, "account.box.com") {
		return true
	}

	// Other service-specific filters can be added here
	return false
}

func checkDNSSecurity(domain string, verboseLevel int, prettyOutput bool) map[string]interface{} {
	securityResults := map[string]interface{}{
		"dnssec":                false,
		"dnssec_errors":         []string{},
		"dns_takeover_risks":    []interface{}{},
		"dns_misconfigurations": []interface{}{},
		"email_security": map[string]interface{}{
			"spf": map[string]interface{}{
				"exists":        false,
				"record":        nil,
				"issues":        []string{},
				"third_parties": []string{},
			},
			"dkim": map[string]interface{}{
				"exists": false,
				"record": nil,
				"issues": []string{},
			},
			"dmarc": map[string]interface{}{
				"exists": false,
				"record": nil,
				"issues": []string{},
			},
			"email_providers": []string{},
		},
	}

	client := &dns.Client{
		Timeout: 2 * time.Second,
	}

	// Check DNSSEC
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeDNSKEY)

	r, _, err := client.Exchange(m, "8.8.8.8:53")
	if err == nil && r.Rcode == dns.RcodeSuccess && len(r.Answer) > 0 {
		securityResults["dnssec"] = true
		if verboseLevel >= 1 && prettyOutput {
			green.Printf("[+] DNSSEC is enabled for %s\n", domain)
		}
	} else {
		if verboseLevel >= 1 && prettyOutput {
			yellow.Printf("[!] DNSSEC is not enabled for %s\n", domain)
		}
	}

	// Check SPF record - check domain's TXT records and parent domains
	m = new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeTXT)
	// Enable EDNS0 to handle larger DNS responses (SPF records can be long)
	m.SetEdns0(4096, true)

	r, _, err = client.Exchange(m, "8.8.8.8:53")
	spfFound := false
	var spfRecord string
	var allTxtRecords []string
	
	// Check if response was truncated
	if err == nil && r.Truncated {
		if verboseLevel >= 1 && prettyOutput {
			yellow.Printf("[!] DNS response was truncated, retrying with TCP\n")
		}
		// Retry with TCP for truncated responses
		clientTCP := &dns.Client{Net: "tcp", Timeout: 5 * time.Second}
		r, _, err = clientTCP.Exchange(m, "8.8.8.8:53")
	}
	
	if err == nil && r.Rcode == dns.RcodeSuccess {
		if verboseLevel >= 1 && prettyOutput {
			cyan.Printf("[~] Checking TXT records for SPF on %s (found %d answer(s))\n", domain, len(r.Answer))
		}
		// Collect all TXT records first, then check for SPF
		// SPF records can span multiple TXT record entries in DNS
		var allTxtStrings []string
		for i, answer := range r.Answer {
			if txt, ok := answer.(*dns.TXT); ok {
				// Join all TXT record parts (SPF records can be split across multiple strings within one TXT record)
				txtStr := strings.Join(txt.Txt, "")
				txtStrTrimmed := strings.TrimSpace(txtStr)
				allTxtStrings = append(allTxtStrings, txtStrTrimmed)
				allTxtRecords = append(allTxtRecords, txtStrTrimmed)
				
				if verboseLevel >= 1 && prettyOutput {
					cyan.Printf("[~] TXT record[%d]: %s\n", i+1, txtStrTrimmed)
				}
			}
		}
		
		if verboseLevel >= 1 && prettyOutput {
			cyan.Printf("[~] Total TXT records found: %d\n", len(allTxtStrings))
		}
		
		// Check each TXT record for SPF
		for i, txtStrTrimmed := range allTxtStrings {
			// Remove quotes if present (some DNS responses include quotes)
			txtStrClean := strings.Trim(txtStrTrimmed, `"'`)
			// Normalize whitespace
			txtStrClean = strings.TrimSpace(txtStrClean)
			txtStrLower := strings.ToLower(txtStrClean)
			
			if verboseLevel >= 2 && prettyOutput {
				preview := txtStrClean
				if len(preview) > 80 {
					preview = preview[:80] + "..."
				}
				cyan.Printf("[~] Checking TXT[%d] for SPF: %s\n", i+1, preview)
			}
			
			// Check for SPF records that start with v=spf1 (case-insensitive)
			if strings.HasPrefix(txtStrLower, "v=spf1") {
				spfFound = true
				spfRecord = txtStrClean
				if verboseLevel >= 1 && prettyOutput {
					green.Printf("[+] Found SPF record in TXT[%d]: %s\n", i+1, spfRecord)
				}
				break
			}
			
			// Also check if "v=spf1" appears anywhere in the record (in case of formatting issues)
			if strings.Contains(txtStrLower, "v=spf1") {
				// Extract the SPF part - find where v=spf1 starts
				idx := strings.Index(txtStrLower, "v=spf1")
				if idx >= 0 {
					// Try to extract the full SPF record
					// SPF records typically end with "all" or similar, but can be long
					// For now, take from v=spf1 to the end, or until we hit a non-SPF character pattern
					potentialSPF := txtStrClean[idx:]
					// Check if it looks like a valid SPF record
					if strings.Contains(strings.ToLower(potentialSPF), "include:") ||
						strings.Contains(strings.ToLower(potentialSPF), "mx") ||
						strings.Contains(strings.ToLower(potentialSPF), "a:") ||
						strings.Contains(strings.ToLower(potentialSPF), "ip4:") ||
						strings.Contains(strings.ToLower(potentialSPF), "ip6:") ||
						strings.Contains(strings.ToLower(potentialSPF), "all") {
						spfFound = true
						spfRecord = potentialSPF
						if verboseLevel >= 1 && prettyOutput {
							green.Printf("[+] Found SPF record (embedded in TXT[%d]): %s\n", i+1, spfRecord)
						}
						break
					}
				}
			}
		}
		
		// If still not found, try combining all TXT records (SPF might span multiple TXT records)
		if !spfFound && len(allTxtStrings) > 1 {
			combinedTxt := strings.Join(allTxtStrings, "")
			combinedLower := strings.ToLower(combinedTxt)
			if strings.Contains(combinedLower, "v=spf1") {
				idx := strings.Index(combinedLower, "v=spf1")
				potentialSPF := combinedTxt[idx:]
				// Validate it's a real SPF record
				if strings.Contains(combinedLower[idx:], "include:") ||
					strings.Contains(combinedLower[idx:], "mx") ||
					strings.Contains(combinedLower[idx:], "all") {
					spfFound = true
					spfRecord = potentialSPF
					if verboseLevel >= 1 && prettyOutput {
						green.Printf("[+] Found SPF record (spanning multiple TXT records): %s\n", spfRecord)
					}
				}
			}
		}
	} else if err != nil {
		if verboseLevel >= 1 && prettyOutput {
			yellow.Printf("[!] Error querying TXT records for SPF: %v\n", err)
		}
	}

	// If no SPF found on domain, check parent domain (some domains inherit SPF from parent)
	if !spfFound {
		parts := strings.Split(domain, ".")
		if len(parts) > 2 {
			parentDomain := strings.Join(parts[1:], ".")
			if verboseLevel >= 2 && prettyOutput {
				cyan.Printf("[~] No SPF found on %s, checking parent domain %s\n", domain, parentDomain)
			}
			
			m = new(dns.Msg)
			m.SetQuestion(dns.Fqdn(parentDomain), dns.TypeTXT)
			r, _, err = client.Exchange(m, "8.8.8.8:53")
			if err == nil && r.Rcode == dns.RcodeSuccess {
				for _, answer := range r.Answer {
					if txt, ok := answer.(*dns.TXT); ok {
						txtStr := strings.Join(txt.Txt, "")
						txtStrTrimmed := strings.TrimSpace(txtStr)
						txtStrLower := strings.ToLower(txtStrTrimmed)
						
						if strings.HasPrefix(txtStrLower, "v=spf1") {
							spfFound = true
							spfRecord = txtStrTrimmed
							if verboseLevel >= 1 && prettyOutput {
								green.Printf("[+] Found SPF record on parent domain %s: %s\n", parentDomain, spfRecord)
							}
							break
						}
					}
				}
			}
		}
	}

	// If still no SPF found, check if MX records point to email providers
	// Some tools (like mxtoolbox) may infer SPF protection from MX records pointing to email providers
	if !spfFound {
		mxMsg := new(dns.Msg)
		mxMsg.SetQuestion(dns.Fqdn(domain), dns.TypeMX)
		mxResp, _, mxErr := client.Exchange(mxMsg, "8.8.8.8:53")
		if mxErr == nil && mxResp.Rcode == dns.RcodeSuccess && len(mxResp.Answer) > 0 {
			// Check if MX records point to known email providers
			emailProvidersWithSPF := map[string]string{
				"google.com":      "Google Workspace",
				"googlemail.com":  "Google Workspace",
				"outlook.com":     "Microsoft 365",
				"office365.com":   "Microsoft 365",
				"microsoft.com":   "Microsoft 365",
				"zoho.com":        "Zoho Mail",
				"amazonses.com":   "Amazon SES",
				"sendgrid.net":    "SendGrid",
				"mailgun.org":     "Mailgun",
				"mailgun.com":     "Mailgun",
				"postmarkapp.com": "Postmark",
				"sparkpostmail.com": "SparkPost",
			}
			
			var detectedProviders []string
			for _, answer := range mxResp.Answer {
				if mx, ok := answer.(*dns.MX); ok {
					mxHost := strings.ToLower(mx.Mx)
					for providerKey, providerName := range emailProvidersWithSPF {
						if strings.Contains(mxHost, providerKey) {
							detectedProviders = append(detectedProviders, providerName)
							break
						}
					}
				}
			}
			
			if len(detectedProviders) > 0 {
				spfMap := securityResults["email_security"].(map[string]interface{})["spf"].(map[string]interface{})
				spfMap["note"] = fmt.Sprintf("No explicit SPF TXT record found, but MX records point to: %s. Some tools may infer SPF protection from email provider infrastructure.", strings.Join(detectedProviders, ", "))
				if verboseLevel >= 1 && prettyOutput {
					yellow.Printf("[!] No SPF TXT record found, but MX records point to: %s\n", strings.Join(detectedProviders, ", "))
					yellow.Printf("[!] Note: Some tools (like mxtoolbox) may show SPF as 'enabled' based on email provider,\n")
					yellow.Printf("[!]       but RFC 7208 requires an explicit SPF TXT record for proper SPF protection.\n")
				}
			}
		}
	}

	// Log all TXT records found for debugging (already logged above, but summarize here)
	if verboseLevel >= 2 && prettyOutput && len(allTxtRecords) > 0 {
		cyan.Printf("[~] Summary: Found %d TXT record(s) for %s\n", len(allTxtRecords), domain)
		for i, txt := range allTxtRecords {
			// Truncate very long records for summary
			displayTxt := txt
			if len(displayTxt) > 100 {
				displayTxt = displayTxt[:100] + "..."
			}
			cyan.Printf("[~]   TXT[%d]: %s\n", i+1, displayTxt)
		}
	}

	// If SPF record found, analyze it
	if spfFound && spfRecord != "" {
		spfMap := securityResults["email_security"].(map[string]interface{})["spf"].(map[string]interface{})
		spfMap["exists"] = true
		spfMap["record"] = spfRecord

		// Analyze SPF record
		issues := []string{}
		thirdParties := []string{}

		spfRecordLower := strings.ToLower(spfRecord)
		if !strings.Contains(spfRecordLower, "all") && !strings.Contains(spfRecordLower, "redirect=") {
			issues = append(issues, "Missing \"all\" mechanism or redirect")
		}
		if strings.Contains(spfRecordLower, "~all") {
			issues = append(issues, "Using soft fail (~all) instead of hard fail (-all)")
		}

		// Extract third-party references (case-insensitive)
		spfParts := strings.Fields(spfRecord)
		for _, part := range spfParts {
			partLower := strings.ToLower(part)
			if strings.HasPrefix(partLower, "include:") {
				thirdParty := strings.TrimPrefix(part, "include:")
				thirdParty = strings.TrimPrefix(thirdParty, "Include:")
				thirdParty = strings.TrimPrefix(thirdParty, "INCLUDE:")
				thirdParties = append(thirdParties, strings.TrimSpace(thirdParty))
			} else if strings.HasPrefix(partLower, "redirect=") {
				thirdParty := strings.TrimPrefix(part, "redirect=")
				thirdParty = strings.TrimPrefix(thirdParty, "Redirect=")
				thirdParty = strings.TrimPrefix(thirdParty, "REDIRECT=")
				thirdParties = append(thirdParties, strings.TrimSpace(thirdParty))
			}
		}

		spfMap["issues"] = issues
		spfMap["third_parties"] = thirdParties

		if verboseLevel >= 1 && prettyOutput {
			green.Printf("[+] SPF record found: %s\n", spfRecord)
			if len(issues) > 0 {
				for _, issue := range issues {
					yellow.Printf("[!] SPF issue: %s\n", issue)
				}
			}
			if len(thirdParties) > 0 {
				cyan.Printf("[~] SPF third-party references: %s\n", strings.Join(thirdParties, ", "))
			}
		}
	}
	if !spfFound {
		// Explicitly set exists to false if not found
		spfMap := securityResults["email_security"].(map[string]interface{})["spf"].(map[string]interface{})
		spfMap["exists"] = false
		if verboseLevel >= 1 && prettyOutput {
			if len(allTxtRecords) > 0 {
				red.Printf("[-] No SPF record found in TXT records (found %d TXT record(s) but none contain 'v=spf1')\n", len(allTxtRecords))
				yellow.Printf("[!] Note: RFC 7208 requires an explicit SPF TXT record starting with 'v=spf1'\n")
				yellow.Printf("[!]       If mxtoolbox shows SPF as enabled, it may be inferring protection from:\n")
				yellow.Printf("[!]       1. MX records pointing to email providers (Google, Microsoft, etc.)\n")
				yellow.Printf("[!]       2. Cached or historical SPF records\n")
				yellow.Printf("[!]       3. Email provider infrastructure (not a valid SPF implementation)\n")
				if verboseLevel >= 2 {
					yellow.Printf("[!]       To properly enable SPF, add a TXT record: v=spf1 ... ~all\n")
				}
			} else {
				red.Printf("[-] No SPF record found (no TXT records found)\n")
			}
		}
	}

	// Check DKIM record
	dkimDomain := fmt.Sprintf("default._domainkey.%s", domain)
	m = new(dns.Msg)
	m.SetQuestion(dns.Fqdn(dkimDomain), dns.TypeTXT)

	r, _, err = client.Exchange(m, "8.8.8.8:53")
	if err == nil && r.Rcode == dns.RcodeSuccess {
		for _, answer := range r.Answer {
			if txt, ok := answer.(*dns.TXT); ok {
				txtStr := strings.Join(txt.Txt, "")
				if strings.Contains(txtStr, "v=DKIM1") {
					dkimMap := securityResults["email_security"].(map[string]interface{})["dkim"].(map[string]interface{})
					dkimMap["exists"] = true
					dkimMap["record"] = txtStr
					if verboseLevel >= 1 && prettyOutput {
						green.Printf("[+] DKIM record found: %s\n", txtStr)
					}
					break
				}
			}
		}
	}
	dkimMap := securityResults["email_security"].(map[string]interface{})["dkim"].(map[string]interface{})
	if exists, ok := dkimMap["exists"].(bool); !ok || !exists {
		if verboseLevel >= 1 && prettyOutput {
			red.Printf("[-] No DKIM record found\n")
		}
	}

	// Check DMARC record
	dmarcDomain := fmt.Sprintf("_dmarc.%s", domain)
	m = new(dns.Msg)
	m.SetQuestion(dns.Fqdn(dmarcDomain), dns.TypeTXT)

	r, _, err = client.Exchange(m, "8.8.8.8:53")
	if err == nil && r.Rcode == dns.RcodeSuccess {
		for _, answer := range r.Answer {
			if txt, ok := answer.(*dns.TXT); ok {
				txtStr := strings.Join(txt.Txt, "")
				if strings.Contains(txtStr, "v=DMARC1") {
					dmarcMap := securityResults["email_security"].(map[string]interface{})["dmarc"].(map[string]interface{})
					dmarcMap["exists"] = true
					dmarcMap["record"] = txtStr

					// Analyze DMARC record
					issues := []string{}
					if strings.Contains(txtStr, "p=none") {
						issues = append(issues, "Using monitor mode (p=none)")
					}
					if strings.Contains(txtStr, "p=quarantine") {
						issues = append(issues, "Using quarantine mode (p=quarantine)")
					}
					if !strings.Contains(txtStr, "pct=100") {
						issues = append(issues, "Not enforcing policy on all emails (pct<100)")
					}
					dmarcMap["issues"] = issues

					if verboseLevel >= 1 && prettyOutput {
						green.Printf("[+] DMARC record found: %s\n", txtStr)
						if len(issues) > 0 {
							for _, issue := range issues {
								yellow.Printf("[!] DMARC issue: %s\n", issue)
							}
						}
					}
					break
				}
			}
		}
	}
	dmarcMap := securityResults["email_security"].(map[string]interface{})["dmarc"].(map[string]interface{})
	if existsVal, existsOk := dmarcMap["exists"]; existsOk {
		if exists, ok := existsVal.(bool); !ok || !exists {
			if verboseLevel >= 1 && prettyOutput {
				red.Printf("[-] No DMARC record found\n")
			}
		}
	} else {
		if verboseLevel >= 1 && prettyOutput {
			red.Printf("[-] No DMARC record found\n")
		}
	}

	// Check for email service providers
	m = new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeMX)

	r, _, err = client.Exchange(m, "8.8.8.8:53")
	if err == nil && r.Rcode == dns.RcodeSuccess {
		emailProviders := []string{}
		for _, answer := range r.Answer {
			if mx, ok := answer.(*dns.MX); ok {
				mxTarget := strings.ToLower(mx.Mx)
				emailProviders = append(emailProviders, mxTarget)

				// Identify common email providers
				var provider string
				if strings.Contains(mxTarget, "google") {
					provider = "Google Workspace"
				} else if strings.Contains(mxTarget, "outlook") || strings.Contains(mxTarget, "microsoft") {
					provider = "Microsoft 365"
				} else if strings.Contains(mxTarget, "zoho") {
					provider = "Zoho Mail"
				} else if strings.Contains(mxTarget, "amazonses") {
					provider = "Amazon SES"
				} else if strings.Contains(mxTarget, "sendgrid") {
					provider = "SendGrid"
				} else if strings.Contains(mxTarget, "mailgun") {
					provider = "Mailgun"
				}

				if provider != "" && verboseLevel >= 1 && prettyOutput {
					green.Printf("[+] Email provider detected: %s\n", provider)
				}
			}
		}
		emailSec := securityResults["email_security"].(map[string]interface{})
		emailSec["email_providers"] = emailProviders
	}

	return securityResults
}

func checkDomainTakeover(domain string, services []ServiceResult, verboseLevel int, prettyOutput bool) []interface{} {
	var takeoverRisks []interface{}

	// Check CNAME records for takeover opportunities
	client := &dns.Client{
		Timeout: 2 * time.Second,
	}

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeCNAME)

	r, _, err := client.Exchange(m, "8.8.8.8:53")
	if err == nil && r.Rcode == dns.RcodeSuccess {
		for _, answer := range r.Answer {
			if cname, ok := answer.(*dns.CNAME); ok {
				target := cname.Target
				// Check if target is a known takeover target
				takeoverProviders := []string{"github.io", "herokuapp.com", "azurewebsites.net", "cloudfront.net"}
				for _, provider := range takeoverProviders {
					if strings.Contains(strings.ToLower(target), provider) {
						risk := map[string]interface{}{
							"service": domain,
							"target":  target,
							"risk":    fmt.Sprintf("Dangling CNAME record pointing to %s which could be registered", target),
						}
						takeoverRisks = append(takeoverRisks, risk)
						if verboseLevel >= 1 && prettyOutput {
							red.Printf("[-] Dangling CNAME risk: Target %s is not registered\n", target)
						}
					}
				}
			}
		}
	}

	return takeoverRisks
}

func printDNSResults(results DNSResults, prettyOutput bool) {
	if prettyOutput {
		bold.Println("\nDNS Records:")
		if len(results.A) > 0 {
			cyan.Println("\nA Records:")
			for _, record := range results.A {
				green.Printf("- %s\n", record)
			}
		}
		if len(results.AAAA) > 0 {
			cyan.Println("\nAAAA Records:")
			for _, record := range results.AAAA {
				green.Printf("- %s\n", record)
			}
		}
		if len(results.MX) > 0 {
			cyan.Println("\nMX Records:")
			for _, record := range results.MX {
				green.Printf("- %s\n", record)
			}
		}
		if len(results.TXT) > 0 {
			cyan.Println("\nTXT Records:")
			for _, record := range results.TXT {
				green.Printf("- %s\n", record)
			}
		}
		if len(results.SPF) > 0 {
			cyan.Println("\nSPF Records:")
			for _, record := range results.SPF {
				green.Printf("- %s\n", record)
			}
		}
		if len(results.DMARC) > 0 {
			cyan.Println("\nDMARC Records:")
			for _, record := range results.DMARC {
				green.Printf("- %s\n", record)
			}
		}
		if len(results.CNAME) > 0 {
			cyan.Println("\nCNAME Records:")
			for _, record := range results.CNAME {
				green.Printf("- %s\n", record)
			}
		}
	} else {
		fmt.Println("\nDNS Records:")
		if len(results.A) > 0 {
			fmt.Println("\nA Records:")
			for _, record := range results.A {
				fmt.Printf("- %s\n", record)
			}
		}
		// Similar for other record types...
	}
}

func saveDNSResults(results DNSResults, outputDir, domain string) {
	safeDomain := strings.ReplaceAll(domain, ".", "_")
	dnsPath := filepath.Join(outputDir, fmt.Sprintf("dns_records_%s.txt", safeDomain))

	file, err := os.Create(dnsPath)
	if err != nil {
		return
	}
	defer file.Close()

	fmt.Fprintf(file, "DNS Records for %s\n", domain)
	fmt.Fprintf(file, "Generated: %s\n\n", time.Now().Format("2006-01-02 15:04:05"))

	if len(results.A) > 0 {
		fmt.Fprintf(file, "A Records:\n")
		for _, record := range results.A {
			fmt.Fprintf(file, "- %s\n", record)
		}
		fmt.Fprintf(file, "\n")
	}
	// Similar for other record types...
}

func saveDNSSecurityToCSV(securityResults map[string]interface{}, outputDir, domain string) {
	safeDomain := strings.ReplaceAll(domain, ".", "_")
	csvPath := filepath.Join(outputDir, fmt.Sprintf("dns_email_security_%s.csv", safeDomain))

	file, err := os.Create(csvPath)
	if err != nil {
		return
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	writer.Write([]string{"category", "feature", "status", "details", "issues"})

	// Write DNSSEC status
	dnssec := securityResults["dnssec"].(bool)
	status := "Disabled"
	if dnssec {
		status = "Enabled"
	}
	writer.Write([]string{"DNSSEC", "DNSSEC", status, "", ""})

	// Write other security information...
}

func saveDomainResults(result ScanResult, domainDir, safeDomain string) {
	summaryPath := filepath.Join(domainDir, fmt.Sprintf("summary_%s.json", safeDomain))
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return
	}
	os.WriteFile(summaryPath, data, 0644)

	// Save CSV
	saveResultsToCSV(result, domainDir)
}

func saveResultsToCSV(result ScanResult, domainDir string) {
	safeDomain := strings.ReplaceAll(result.Domain, ".", "_")
	csvPath := filepath.Join(domainDir, fmt.Sprintf("services_%s.csv", safeDomain))

	file, err := os.Create(csvPath)
	if err != nil {
		return
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	writer.Write([]string{"domain", "service_url", "status_code", "redirect_url", "html_path", "screenshot_path", "logo_url"})

	for _, service := range result.Services {
		logoURL := ""
		if service.Logo != nil {
			logoURL = service.Logo.URL
		}
		writer.Write([]string{
			result.Domain,
			service.URL,
			fmt.Sprintf("%d", service.Status),
			service.RedirectURL,
			service.HTMLPath,
			service.ScreenshotPath,
			logoURL,
		})
	}
}

func saveCurrentResults(allResults []ScanResult, outputDir string, prettyOutput bool) {
	if prettyOutput {
		yellow.Println("\n[!] Saving current results...")
	}

	for _, result := range allResults {
		safeDomain := strings.ReplaceAll(result.Domain, ".", "_")
		domainDir := filepath.Join(outputDir, safeDomain)
		os.MkdirAll(domainDir, 0755)

		saveDomainResults(result, domainDir, safeDomain)
	}

	if prettyOutput {
		green.Printf("[+] Results saved to %s\n", outputDir)
	}
}

func htmlEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, `"`, "&quot;")
	s = strings.ReplaceAll(s, "'", "&#39;")
	return s
}

func generateHTMLReport(results []ScanResult, reportDir string, prettyOutput bool) {
	if prettyOutput {
		yellow.Println("[!] Generating HTML report...")
	}

	for _, result := range results {
		htmlPath := filepath.Join(reportDir, "index.html")

		html := generateHTMLContent(result, reportDir)
		os.WriteFile(htmlPath, []byte(html), 0644)

		if prettyOutput {
			green.Printf("[+] Generated HTML report: %s\n", htmlPath)
		}
	}
}

func generateHTMLContent(result ScanResult, reportDir string) string {
	safeDomain := strings.ReplaceAll(result.Domain, ".", "_")

	// Format date with ordinal
	formattedDate, timezoneTimes := formatDate(result.ScanDate)

	// Build HTML template
	html := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>👀 Plainsight Scan Results - ` + result.Domain + ` 👀</title>
    <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>👀</text></svg>">
    <style>
        :root {
            --bg-color: #ffffff;
            --text-color: #000000;
            --border-color: #ddd;
            --header-bg: #f4f4f4;
            --modal-bg: #ffffff;
            --input-bg: #ffffff;
            --button-bg: #ff6b00;
            --button-hover: #e65c00;
            --comment-bg: #f9f9f9;
        }

        [data-theme="dark"] {
            --bg-color: #0a192f;
            --text-color: #ffffff;
            --border-color: #1e3a5f;
            --header-bg: #112240;
            --modal-bg: #112240;
            --input-bg: #1e3a5f;
            --button-bg: #ff6b00;
            --button-hover: #e65c00;
            --comment-bg: #112240;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, 'Open Sans', 'Helvetica Neue', sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: var(--bg-color);
            color: var(--text-color);
            transition: background-color 0.3s ease, color 0.3s ease;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
        }

        .header {
            background: var(--header-bg);
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 20px;
            border: 1px solid var(--border-color);
            transition: background-color 0.3s ease, border-color 0.3s ease;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .header-content {
            flex: 1;
        }

        .header h1 {
            margin: 0 0 10px 0;
            color: var(--text-color);
        }

        .header p {
            margin: 0;
            color: var(--text-color);
            opacity: 0.8;
        }

        .company-logo {
            width: 100px;
            height: 100px;
            object-fit: contain;
            margin-left: 20px;
            border-radius: 8px;
            background: var(--bg-color);
            padding: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }

        .domain-section {
            background: var(--header-bg);
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 20px;
            border: 1px solid var(--border-color);
            transition: background-color 0.3s ease, border-color 0.3s ease;
        }

        .domain-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 20px;
            padding: 20px;
            background: var(--header-bg);
            border-radius: 12px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }

        .domain-info {
            flex: 1;
        }

        .domain-info h2 {
            margin: 0 0 10px 0;
            font-size: 1.8em;
            color: var(--text-color);
        }

        .timezone-grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 12px;
            margin-left: 30px;
            padding: 15px;
            background: var(--bg-color);
            border-radius: 8px;
            font-size: 0.85em;
            box-shadow: inset 0 2px 4px rgba(0,0,0,0.05);
        }

        .timezone-item {
            padding: 8px 12px;
            background: var(--header-bg);
            border-radius: 6px;
            font-weight: 500;
            color: var(--text-color);
            transition: transform 0.2s ease;
        }

        .timezone-item:hover {
            transform: translateY(-1px);
        }

        .timestamp {
            color: var(--text-color);
            font-size: 0.9em;
            opacity: 0.8;
        }

        .services-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 20px;
        }

        .services-grid.cols-1 {
            grid-template-columns: 1fr;
        }

        .services-grid.cols-2 {
            grid-template-columns: repeat(2, minmax(0, 1fr));
        }

        .services-grid.cols-3 {
            grid-template-columns: repeat(3, minmax(0, 1fr));
        }

        .service-card {
            background: var(--bg-color);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 15px;
            cursor: pointer;
            transition: all 0.3s ease;
            position: relative;
            padding-top: 40px;
            min-width: 0;
            word-wrap: break-word;
            overflow-wrap: break-word;
        }

        .service-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0,0,0,0.1);
        }

        .service-card h3 {
            margin: 0 0 10px 0;
            color: var(--text-color);
            padding-right: 80px;
        }

        .service-card p {
            margin: 5px 0;
            color: var(--text-color);
        }

        .service-card .status {
            position: absolute;
            top: 10px;
            right: 10px;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            z-index: 1;
        }

        .status-found {
            background: #d4edda;
            color: #155724;
        }

        .status-not-found {
            background: #f8d7da;
            color: #721c24;
        }

        .screenshot {
            width: 100%;
            height: auto;
            max-height: 200px;
            object-fit: contain;
            border-radius: 4px;
            margin-top: 10px;
        }

        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.9);
            z-index: 1000;
        }

        .modal-content {
            background: var(--modal-bg);
            margin: 2% auto;
            padding: 25px;
            width: 90%;
            max-width: 1200px;
            border-radius: 12px;
            max-height: 96vh;
            overflow-y: auto;
            color: var(--text-color);
            border: none;
            box-shadow: 0 4px 20px rgba(0,0,0,0.15);
        }

        .close-button {
            position: absolute;
            right: 20px;
            top: 20px;
            font-size: 24px;
            cursor: pointer;
            color: var(--text-color);
            z-index: 1001;
        }

        .tabs {
            display: flex;
            margin: -25px -25px 20px -25px;
            padding: 20px 25px;
            background: var(--header-bg);
            border-radius: 12px 12px 0 0;
            position: sticky;
            top: 0;
            z-index: 1;
        }

        .tab {
            padding: 10px 20px;
            cursor: pointer;
            border: none;
            margin-right: 10px;
            border-radius: 6px;
            color: var(--text-color);
            font-weight: 500;
            transition: all 0.3s ease;
        }

        .tab:hover {
            background: var(--bg-color);
        }

        .tab.active {
            background: var(--button-bg);
            color: #fff;
        }

        .request-details, .response-details {
            background: var(--input-bg);
            color: var(--text-color);
            border: 1px solid var(--border-color);
            padding: 20px;
            border-radius: 8px;
            font-family: 'Consolas', 'Monaco', monospace;
            white-space: pre-wrap;
            word-wrap: break-word;
            max-height: 400px;
            overflow-y: auto;
            transition: all 0.3s ease;
        }

        .request-details .header, .response-details .header {
            font-size: 1.2em;
            font-weight: 600;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 2px solid var(--border-color);
            color: var(--text-color);
        }

        .request-details .section, .response-details .section {
            margin: 15px 0;
            padding: 12px;
            background: var(--header-bg);
            border-radius: 6px;
        }

        .request-details .section-title, .response-details .section-title {
            font-weight: 600;
            color: var(--button-bg);
            margin: 0 0 8px 0;
            font-size: 1.1em;
        }

        .request-details .header-item, .response-details .header-item {
            margin: 4px 0;
            padding: 6px 10px;
            background: var(--bg-color);
            border-radius: 4px;
            font-size: 0.9em;
            border-left: 3px solid var(--button-bg);
        }

        .screenshot-modal {
            max-width: 100%;
            height: auto;
            border-radius: 4px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }

        .display-controls {
            position: fixed;
            bottom: 20px;
            right: 20px;
            background: var(--header-bg);
            padding: 10px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            z-index: 100;
            border: 1px solid var(--border-color);
            transition: background-color 0.3s ease, border-color 0.3s ease;
        }

        .display-controls button {
            padding: 5px 10px;
            margin: 0 5px;
            border: 1px solid var(--border-color);
            border-radius: 4px;
            background: var(--bg-color);
            cursor: pointer;
            color: var(--text-color);
            transition: background-color 0.3s ease, color 0.3s ease, border-color 0.3s ease;
        }

        .display-controls button:hover {
            background: var(--input-bg);
        }

        .display-controls button.active {
            background: var(--button-bg);
            color: #fff;
            border-color: var(--button-bg);
        }

        .redirect-label {
            background: #fff3cd;
            color: #856404;
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 0.8em;
            margin-left: 8px;
        }

        .theme-switch-wrapper {
            position: fixed;
            top: 20px;
            right: 20px;
            display: flex;
            align-items: center;
            z-index: 1000;
        }

        .theme-switch {
            display: inline-block;
            width: 60px;
            height: 32px;
            position: relative;
        }

        .theme-switch input {
            opacity: 0;
            width: 0;
            height: 0;
        }

        .slider {
            position: absolute;
            cursor: pointer;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: var(--border-color);
            border-radius: 32px;
            transition: background 0.3s;
        }

        .slider:before {
            position: absolute;
            content: '';
            height: 24px;
            width: 24px;
            left: 4px;
            top: 4px;
            background: var(--bg-color);
            border-radius: 50%;
            transition: transform 0.3s;
            box-shadow: 0 2px 6px rgba(0,0,0,0.15);
        }

        .theme-switch input:checked + .slider:before {
            transform: translateX(28px);
        }

        .slider:after {
            content: '☀';
            position: absolute;
            left: 8px;
            top: 4px;
            font-size: 16px;
            transition: opacity 0.3s;
            color: #ffd700;
        }

        .theme-switch input:checked + .slider:after {
            content: '☾';
            left: 36px;
            color: #e0e0e0;
        }

        .tab-content {
            display: none;
            padding: 20px;
            background: var(--bg-color);
            border-radius: 0 0 8px 8px;
        }

        .tab-content.active {
            display: block;
        }

        .header-actions {
            display: flex;
            align-items: center;
            gap: 15px;
        }

        .dns-info-button {
            background: var(--button-bg);
            color: white;
            border: none;
            padding: 8px 15px;
            border-radius: 6px;
            cursor: pointer;
            font-weight: 500;
            display: flex;
            align-items: center;
            gap: 8px;
            transition: background-color 0.3s ease;
        }

        .dns-info-button:hover {
            background: var(--button-hover);
        }

        .dns-info-button svg {
            width: 16px;
            height: 16px;
            fill: currentColor;
        }

        .dns-modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.9);
            z-index: 1000;
        }

        .dns-modal-content {
            background: var(--modal-bg);
            margin: 2% auto;
            padding: 25px;
            width: 90%;
            max-width: 1200px;
            border-radius: 12px;
            max-height: 96vh;
            overflow-y: auto;
            color: var(--text-color);
            border: none;
            box-shadow: 0 4px 20px rgba(0,0,0,0.15);
        }

        .dns-section {
            margin-bottom: 30px;
            background: var(--header-bg);
            padding: 20px;
            border-radius: 8px;
        }

        .dns-section h3 {
            margin: 0 0 15px 0;
            color: var(--text-color);
            font-size: 1.2em;
        }

        .dns-section h4 {
            margin: 15px 0 10px 0;
            color: var(--text-color);
            font-size: 1em;
        }

        .dns-record {
            background: var(--bg-color);
            padding: 10px;
            margin: 5px 0;
            border-radius: 4px;
            font-family: monospace;
            font-size: 0.9em;
        }

        .security-status {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.9em;
            margin: 2px 5px 2px 0;
        }

        .status-enabled {
            background: #d4edda;
            color: #155724;
        }

        .status-disabled {
            background: #f8d7da;
            color: #721c24;
        }

        .status-warning {
            background: #fff3cd;
            color: #856404;
        }
    </style>
</head>
<body>
    <div class="theme-switch-wrapper">
        <label class="theme-switch" for="checkbox">
            <input type="checkbox" id="checkbox" />
            <div class="slider"></div>
        </label>
    </div>
    <div class="container">
        <div class="header">
            <div class="header-content">
                <h1>👀 Plainsight Scan Results - ` + result.Domain + ` 👀</h1>
                <p>Scan Date: ` + formattedDate + `</p>
            </div>
            <div class="header-actions">
                <button class="dns-info-button" id="dnsInfoButton" onclick="showDnsInfo(); return false;">
                    <svg viewBox="0 0 24 24">
                        <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-6h2v6zm0-8h-2V7h2v2z"/>
                    </svg>
                    DNS Info
                </button>`

	// Add company logo if available
	logoFilename := fmt.Sprintf("company_logo_%s.png", safeDomain)
	logoPath := filepath.Join(reportDir, logoFilename)
	if _, err := os.Stat(logoPath); err == nil {
		html += fmt.Sprintf(`<img src="%s" alt="Company Logo" class="company-logo" title="Logo sourced from Google Favicon service">`, logoFilename)
	} else {
		html += `<div class="company-logo" title="No company logo available"></div>`
	}

	html += `
            </div>
        </div>
    </div>

    <div id="dnsModal" class="dns-modal" onclick="if(event.target === this) closeDnsModal();">
        <div class="dns-modal-content">
            <span class="close-button" onclick="closeDnsModal(); return false;" style="cursor: pointer;">&times;</span>
            <h2>DNS Information</h2>
            <div class="dns-section">
                <h3>DNS Records</h3>`

	// Add DNS Records
	dnsRecords := result.DNSRecords
	if len(dnsRecords.A) > 0 {
		html += `<h4>A Records</h4>`
		for _, record := range dnsRecords.A {
			html += fmt.Sprintf(`<div class="dns-record">%s</div>`, htmlEscape(record))
		}
	}
	if len(dnsRecords.AAAA) > 0 {
		html += `<h4>AAAA Records</h4>`
		for _, record := range dnsRecords.AAAA {
			html += fmt.Sprintf(`<div class="dns-record">%s</div>`, htmlEscape(record))
		}
	}
	if len(dnsRecords.MX) > 0 {
		html += `<h4>MX Records</h4>`
		for _, record := range dnsRecords.MX {
			html += fmt.Sprintf(`<div class="dns-record">%s</div>`, htmlEscape(record))
		}
	}
	if len(dnsRecords.TXT) > 0 {
		html += `<h4>TXT Records</h4>`
		for _, record := range dnsRecords.TXT {
			html += fmt.Sprintf(`<div class="dns-record">%s</div>`, htmlEscape(record))
		}
	}
	if len(dnsRecords.SPF) > 0 {
		html += `<h4>SPF Records</h4>`
		for _, record := range dnsRecords.SPF {
			html += fmt.Sprintf(`<div class="dns-record">%s</div>`, htmlEscape(record))
		}
	}
	if len(dnsRecords.DMARC) > 0 {
		html += `<h4>DMARC Records</h4>`
		for _, record := range dnsRecords.DMARC {
			html += fmt.Sprintf(`<div class="dns-record">%s</div>`, htmlEscape(record))
		}
	}
	if len(dnsRecords.CNAME) > 0 {
		html += `<h4>CNAME Records</h4>`
		for _, record := range dnsRecords.CNAME {
			html += fmt.Sprintf(`<div class="dns-record">%s</div>`, htmlEscape(record))
		}
	}

	html += `
            </div>
            <div class="dns-section">
                <h3>DNS Security</h3>`

	// Add DNS Security info
	dnssecVal, dnssecOk := result.DNSSecurity["dnssec"]
	if dnssecOk {
		statusClass := "status-disabled"
		statusText := "Disabled"
		if dnssec, ok := dnssecVal.(bool); ok && dnssec {
			statusClass = "status-enabled"
			statusText = "Enabled"
		}
		html += fmt.Sprintf(`<div class="security-status %s">DNSSEC: %s</div>`, statusClass, statusText)
	}

	emailSecVal, emailSecOk := result.DNSSecurity["email_security"]
	if emailSecOk {
		if emailSec, ok := emailSecVal.(map[string]interface{}); ok {
			html += `<h4>Email Security</h4>`

			// SPF
			if spfVal, spfOk := emailSec["spf"]; spfOk {
				if spf, ok := spfVal.(map[string]interface{}); ok {
					spfStatus := "Disabled"
					spfClass := "status-disabled"
					if existsVal, existsOk := spf["exists"]; existsOk {
						if exists, ok := existsVal.(bool); ok && exists {
							spfStatus = "Enabled"
							spfClass = "status-enabled"
						}
					}
					html += fmt.Sprintf(`<div class="security-status %s">SPF: %s</div>`, spfClass, spfStatus)

					// Show SPF record if exists
					if recordVal, recordOk := spf["record"]; recordOk && recordVal != nil {
						if record, ok := recordVal.(string); ok && record != "" {
							html += fmt.Sprintf(`<div class="dns-record">%s</div>`, htmlEscape(record))
						}
					}

					// Show SPF issues
					if issuesVal, issuesOk := spf["issues"]; issuesOk {
						if issues, ok := issuesVal.([]interface{}); ok {
							for _, issueVal := range issues {
								if issue, ok := issueVal.(string); ok {
									html += fmt.Sprintf(`<div class="security-status status-warning">SPF Issue: %s</div>`, htmlEscape(issue))
								}
							}
						} else if issues, ok := issuesVal.([]string); ok {
							for _, issue := range issues {
								html += fmt.Sprintf(`<div class="security-status status-warning">SPF Issue: %s</div>`, htmlEscape(issue))
							}
						}
					}

					// Show SPF third-party references
					if thirdPartiesVal, tpOk := spf["third_parties"]; tpOk {
						var thirdParties []string
						if tp, ok := thirdPartiesVal.([]interface{}); ok {
							for _, tpVal := range tp {
								if tpStr, ok := tpVal.(string); ok {
									thirdParties = append(thirdParties, tpStr)
								}
							}
						} else if tp, ok := thirdPartiesVal.([]string); ok {
							thirdParties = tp
						}
						if len(thirdParties) > 0 {
							html += `<h4>SPF Third-Party References</h4>`
							for _, thirdParty := range thirdParties {
								html += fmt.Sprintf(`<div class="dns-record">include:%s</div>`, htmlEscape(thirdParty))
							}
						}
					}
				}
			}

			// DKIM
			if dkimVal, dkimOk := emailSec["dkim"]; dkimOk {
				if dkim, ok := dkimVal.(map[string]interface{}); ok {
					dkimStatus := "Disabled"
					dkimClass := "status-disabled"
					if existsVal, existsOk := dkim["exists"]; existsOk {
						if exists, ok := existsVal.(bool); ok && exists {
							dkimStatus = "Enabled"
							dkimClass = "status-enabled"
						}
					}
					html += fmt.Sprintf(`<div class="security-status %s">DKIM: %s</div>`, dkimClass, dkimStatus)

					// Show DKIM record if exists
					if recordVal, recordOk := dkim["record"]; recordOk && recordVal != nil {
						if record, ok := recordVal.(string); ok && record != "" {
							html += fmt.Sprintf(`<div class="dns-record">%s</div>`, htmlEscape(record))
						}
					}
				}
			}

			// DMARC
			if dmarcVal, dmarcOk := emailSec["dmarc"]; dmarcOk {
				if dmarc, ok := dmarcVal.(map[string]interface{}); ok {
					dmarcStatus := "Disabled"
					dmarcClass := "status-disabled"
					if existsVal, existsOk := dmarc["exists"]; existsOk {
						if exists, ok := existsVal.(bool); ok && exists {
							dmarcStatus = "Enabled"
							dmarcClass = "status-enabled"
						}
					}
					html += fmt.Sprintf(`<div class="security-status %s">DMARC: %s</div>`, dmarcClass, dmarcStatus)

					// Show DMARC record if exists
					if recordVal, recordOk := dmarc["record"]; recordOk && recordVal != nil {
						if record, ok := recordVal.(string); ok && record != "" {
							html += fmt.Sprintf(`<div class="dns-record">%s</div>`, htmlEscape(record))
						}
					}

					// Show DMARC issues
					if issuesVal, issuesOk := dmarc["issues"]; issuesOk {
						if issues, ok := issuesVal.([]interface{}); ok {
							for _, issueVal := range issues {
								if issue, ok := issueVal.(string); ok {
									html += fmt.Sprintf(`<div class="security-status status-warning">DMARC Issue: %s</div>`, htmlEscape(issue))
								}
							}
						} else if issues, ok := issuesVal.([]string); ok {
							for _, issue := range issues {
								html += fmt.Sprintf(`<div class="security-status status-warning">DMARC Issue: %s</div>`, htmlEscape(issue))
							}
						}
					}
				}
			}

			// Email providers
			if providersVal, providersOk := emailSec["email_providers"]; providersOk {
				var providers []string
				if prov, ok := providersVal.([]interface{}); ok {
					for _, pVal := range prov {
						if pStr, ok := pVal.(string); ok {
							providers = append(providers, pStr)
						}
					}
				} else if prov, ok := providersVal.([]string); ok {
					providers = prov
				}
				if len(providers) > 0 {
					html += `<h4>Email Providers</h4>`
					for _, provider := range providers {
						html += fmt.Sprintf(`<div class="dns-record">%s</div>`, htmlEscape(provider))
					}
				}
			}
		}
	}

	html += `
            </div>
        </div>
    </div>

    <div class="display-controls">
        <button data-cols="1" onclick="window.changeLayout(1, event); return false;">1 Column</button>
        <button data-cols="2" onclick="window.changeLayout(2, event); return false;">2 Columns</button>
        <button data-cols="3" onclick="window.changeLayout(3, event); return false;" class="active">3 Columns</button>
    </div>

    <div id="detailsModal" class="modal" onclick="if(event.target === this) closeModal();">
        <div class="modal-content">
            <span class="close-button" onclick="closeModal(); return false;" style="cursor: pointer;">&times;</span>
            <div class="tabs">
                <div class="tab active" data-tab="screenshot" onclick="window.switchTab('screenshot'); return false;">Screenshot</div>
                <div class="tab" data-tab="request" onclick="window.switchTab('request'); return false;">Request/Response</div>
            </div>
            <div id="screenshotTab" class="tab-content active">
                <img id="modalScreenshot" class="screenshot-modal" src="" alt="Screenshot" style="display: none;">
                <div id="noScreenshot" style="text-align: center; padding: 20px; color: var(--text-color); opacity: 0.7;">
                    Screenshots are not available in the Go version (requires Selenium/ChromeDriver)
                </div>
            </div>
            <div id="requestTab" class="tab-content">
                <div id="requestDetails" class="request-details"></div>
            </div>
        </div>
    </div>

    <div class="domain-section">
        <div class="domain-header">
            <div class="domain-info">
                <h2>` + result.Domain + `</h2>
                <span class="timestamp">Scanned: ` + formattedDate + `</span>
            </div>
            <div class="timezone-grid">`

	// Add timezone items
	for _, tzTime := range timezoneTimes {
		html += fmt.Sprintf(`<div class="timezone-item">%s</div>`, tzTime)
	}

	html += `
            </div>
        </div>
        <div class="services-grid cols-3">`

	// Add service cards
	for _, service := range result.Services {
		statusClass := "status-found"
		statusText := "Found"
		if service.RedirectURL != "" {
			statusText += `<span class="redirect-label">Redirect</span>`
		}

		// Create service data JSON - properly escape for HTML attribute
		// Screenshot path should already be relative and normalized
		serviceData, err := json.Marshal(service)
		if err != nil {
			// Fallback if marshaling fails
			serviceData = []byte("{}")
		}
		serviceDataStr := htmlEscape(string(serviceData))

		// Extract service name from URL
		serviceName := service.URL
		if parsedURL, err := url.Parse(service.URL); err == nil {
			serviceName = parsedURL.Host
		}

		// Escape service name and URL for HTML
		serviceNameEscaped := htmlEscape(serviceName)
		serviceURLEscaped := htmlEscape(service.URL)

		html += fmt.Sprintf(`
            <div class="service-card" data-service="%s">
                <h3>%s</h3>
                <span class="status %s">%s</span>
                <p><strong>URL:</strong> %s</p>`, serviceDataStr, serviceNameEscaped, statusClass, statusText, serviceURLEscaped)

		if service.RedirectURL != "" {
			// Truncate URL for card display (remove query parameters)
			truncatedRedirectURL := truncateURL(service.RedirectURL)
			redirectURLEscaped := htmlEscape(truncatedRedirectURL)
			html += fmt.Sprintf(`
                <p><strong>Redirect:</strong> <span style="color: #856404;">%s</span></p>`, redirectURLEscaped)
		}

		html += fmt.Sprintf(`
                <p><strong>Status:</strong> %d</p>`, service.Status)

		if service.ScreenshotPath != "" {
			// ScreenshotPath is already relative from reportDir, just normalize separators
			screenshotPath := strings.ReplaceAll(service.ScreenshotPath, "\\", "/")
			html += fmt.Sprintf(`<img src="%s" alt="Screenshot" class="screenshot">`, screenshotPath)
		}

		html += `
            </div>`
	}

	html += `
        </div>
    </div>

    <script>
        // Define functions in global scope
        window.showDnsInfo = function() {
            console.log('showDnsInfo called');
            const modal = document.getElementById('dnsModal');
            if (modal) {
                modal.style.display = 'block';
                console.log('DNS modal displayed');
            } else {
                console.error('dnsModal element not found');
            }
        };

        window.closeDnsModal = function() {
            const modal = document.getElementById('dnsModal');
            if (modal) {
                modal.style.display = 'none';
            }
        };

        window.closeModal = function() {
            const modal = document.getElementById('detailsModal');
            if (modal) {
                modal.style.display = 'none';
            }
        };

        window.changeLayout = function(cols, event) {
            const grid = document.querySelector('.services-grid');
            if (grid) {
                grid.className = 'services-grid cols-' + cols;
            }
            
            document.querySelectorAll('.display-controls button').forEach(btn => {
                btn.classList.remove('active');
            });
            if (event && event.target) {
                event.target.classList.add('active');
            } else {
                // Fallback: find button by onclick attribute
                const buttons = document.querySelectorAll('.display-controls button');
                buttons.forEach(btn => {
                    const onclick = btn.getAttribute('onclick') || '';
                    if (onclick.includes('changeLayout(' + cols + ')')) {
                        btn.classList.add('active');
                    }
                });
            }
        };

        window.switchTab = function(tabName) {
            const tabs = document.querySelectorAll('.tab');
            const contents = document.querySelectorAll('.tab-content');
            
            tabs.forEach(tab => tab.classList.remove('active'));
            contents.forEach(content => content.classList.remove('active'));
            
            // Find the clicked tab by data attribute
            const clickedTab = document.querySelector('.tab[data-tab="' + tabName + '"]');
            if (clickedTab) {
                clickedTab.classList.add('active');
            }
            
            const activeContent = document.getElementById(tabName + 'Tab');
            if (activeContent) {
                activeContent.classList.add('active');
            }
        };

        document.addEventListener('DOMContentLoaded', function() {
            // Setup DNS Info button
            const dnsButton = document.getElementById('dnsInfoButton');
            if (dnsButton) {
                dnsButton.addEventListener('click', function(e) {
                    e.preventDefault();
                    e.stopPropagation();
                    console.log('DNS button clicked');
                    window.showDnsInfo();
                });
            } else {
                console.error('DNS Info button not found');
            }
            
            const toggleSwitch = document.querySelector('.theme-switch input[type="checkbox"]');
            if (toggleSwitch) {
                const currentTheme = localStorage.getItem('theme') || 'light';
                
                if (currentTheme === 'dark') {
                    document.documentElement.setAttribute('data-theme', 'dark');
                    toggleSwitch.checked = true;
                }
                
                toggleSwitch.addEventListener('change', function(e) {
                    if (e.target.checked) {
                        document.documentElement.setAttribute('data-theme', 'dark');
                        localStorage.setItem('theme', 'dark');
                    } else {
                        document.documentElement.setAttribute('data-theme', 'light');
                        localStorage.setItem('theme', 'light');
                    }
                });
            }

            document.querySelectorAll('.service-card').forEach(card => {
                card.addEventListener('click', function(e) {
                    e.stopPropagation();
                    try {
                        let serviceDataStr = this.getAttribute('data-service');
                        if (!serviceDataStr) {
                            console.error('No data-service attribute found');
                            return;
                        }
                        // Replace HTML entities back to quotes
                        serviceDataStr = serviceDataStr.replace(/&quot;/g, '"');
                        const serviceData = JSON.parse(serviceDataStr);
                        
                        if (!serviceData) {
                            console.error('Failed to parse service data');
                            return;
                        }
                        
                        const screenshot = document.getElementById('modalScreenshot');
                        const noScreenshot = document.getElementById('noScreenshot');
                        const requestDetails = document.getElementById('requestDetails');
                        
                        // Debug: log service data to console
                        console.log('Service data:', serviceData);
                        console.log('Screenshot path:', serviceData.screenshot_path);
                        
                        if (serviceData.screenshot_path && serviceData.screenshot_path !== '' && serviceData.screenshot_path !== null) {
                            screenshot.src = serviceData.screenshot_path;
                            screenshot.style.display = 'block';
                            screenshot.onerror = function() {
                                console.error('Failed to load screenshot:', serviceData.screenshot_path);
                                screenshot.style.display = 'none';
                                if (noScreenshot) noScreenshot.style.display = 'block';
                            };
                            screenshot.onload = function() {
                                console.log('Screenshot loaded successfully:', serviceData.screenshot_path);
                            };
                            if (noScreenshot) noScreenshot.style.display = 'none';
                        } else {
                            console.log('No screenshot path found in service data');
                            screenshot.style.display = 'none';
                            if (noScreenshot) noScreenshot.style.display = 'block';
                        }
                        
                        let requestDetailsHtml = 
                            '<div class="header">Request/Response Details</div>' +
                            '<div class="section">' +
                            '<div class="section-title">Original URL</div>' +
                            '<div class="header-item">' + window.escapeHtml(serviceData.url || 'N/A') + '</div>' +
                            '</div>';
                        
                        if (serviceData.redirect_url) {
                            requestDetailsHtml += 
                                '<div class="section">' +
                                '<div class="section-title">Redirect URL</div>' +
                                '<div class="header-item">' + window.escapeHtml(serviceData.redirect_url) + '</div>' +
                                '</div>';
                        }
                        
                        requestDetailsHtml += 
                            '<div class="section">' +
                            '<div class="section-title">Status Code</div>' +
                            '<div class="header-item">' + (serviceData.status || 'N/A') + '</div>' +
                            '</div>';
                        
                        if (serviceData.request_headers && Object.keys(serviceData.request_headers).length > 0) {
                            requestDetailsHtml += 
                                '<div class="section">' +
                                '<div class="section-title">Request Headers</div>';
                            
                            for (const [key, value] of Object.entries(serviceData.request_headers)) {
                                requestDetailsHtml += '<div class="header-item">' + window.escapeHtml(key) + ': ' + window.escapeHtml(String(value)) + '</div>';
                            }
                            
                            requestDetailsHtml += '</div>';
                        }
                        
                        if (serviceData.headers && Object.keys(serviceData.headers).length > 0) {
                            requestDetailsHtml += 
                                '<div class="section">' +
                                '<div class="section-title">Response Headers</div>';
                            
                            for (const [key, value] of Object.entries(serviceData.headers)) {
                                requestDetailsHtml += '<div class="header-item">' + window.escapeHtml(key) + ': ' + window.escapeHtml(String(value)) + '</div>';
                            }
                            
                            requestDetailsHtml += '</div>';
                        }
                        
                        if (serviceData.response_body) {
                            const bodyText = serviceData.response_body.substring(0, 5000);
                            requestDetailsHtml += 
                                '<div class="section">' +
                                '<div class="section-title">Response Body</div>' +
                                '<div class="header-item" style="white-space: pre-wrap; font-family: monospace; max-height: 300px; overflow-y: auto;">' + 
                                window.escapeHtml(bodyText) + 
                                '</div>' +
                                '</div>';
                        }
                        
                        requestDetails.innerHTML = requestDetailsHtml;
                        const detailsModal = document.getElementById('detailsModal');
                        if (detailsModal) {
                            detailsModal.style.display = 'block';
                            window.switchTab('screenshot');
                        }
                    } catch (error) {
                        console.error('Error parsing service data:', error);
                        alert('Error loading service details: ' + error.message);
                    }
                });
            });
            
            window.escapeHtml = function(text) {
                const div = document.createElement('div');
                div.textContent = text;
                return div.innerHTML;
            };

            window.onclick = function(event) {
                const modal = document.getElementById('detailsModal');
                const dnsModal = document.getElementById('dnsModal');
                if (event.target == modal) {
                    closeModal();
                }
                if (event.target == dnsModal) {
                    closeDnsModal();
                }
            };
        });
    </script>
</body>
</html>`

	return html
}

func formatDate(dateStr string) (string, []string) {
	// Parse the date string
	dt, err := time.Parse("2006-01-02 15:04:05", dateStr)
	if err != nil {
		return dateStr, []string{}
	}

	// Get ordinal suffix
	day := dt.Day()
	suffix := getOrdinal(day)

	// Format date
	formatted := fmt.Sprintf("%d%s %s at %s %s",
		day, suffix, dt.Format("January 2006"), dt.Format("15:04:05"), dt.Format("MST"))

	// Add timezone conversions
	timezones := []struct {
		name string
		tz   *time.Location
	}{
		{"US/Pacific", mustLoadLocation("America/Los_Angeles")},
		{"US/Mountain", mustLoadLocation("America/Denver")},
		{"US/Central", mustLoadLocation("America/Chicago")},
		{"US/Eastern", mustLoadLocation("America/New_York")},
		{"UK", mustLoadLocation("Europe/London")},
	}

	var tzTimes []string
	for _, tz := range timezones {
		if tz.tz != nil {
			tzTime := dt.In(tz.tz)
			tzTimes = append(tzTimes, fmt.Sprintf("%s: %s", tz.name, tzTime.Format("15:04:05 MST")))
		}
	}

	return formatted, tzTimes
}

func getOrdinal(n int) string {
	if n >= 10 && n <= 20 {
		return "th"
	}
	switch n % 10 {
	case 1:
		return "st"
	case 2:
		return "nd"
	case 3:
		return "rd"
	default:
		return "th"
	}
}

func mustLoadLocation(name string) *time.Location {
	loc, err := time.LoadLocation(name)
	if err != nil {
		return nil
	}
	return loc
}

// truncateURL removes query parameters from a URL for display purposes
func truncateURL(fullURL string) string {
	parsedURL, err := url.Parse(fullURL)
	if err != nil {
		// If parsing fails, return original URL
		return fullURL
	}
	// Remove query parameters and fragment
	parsedURL.RawQuery = ""
	parsedURL.Fragment = ""
	return parsedURL.String()
}
