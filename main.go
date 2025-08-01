package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const endpointRegex = `(?i)(["'])(\/[a-zA-Z0-9_?%&=\/\-\#\.\(\)]+)(["'])`
const userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"
type Colors struct {
	Red    string
	Green  string
	Yellow string
	Blue   string
	End    string
	Bold   string
}
var c Colors

func initColors(noColor bool) {
	if noColor {
		c = Colors{}
	} else {
		c = Colors{
			Red:    "\033[91m",
			Green:  "\033[92m",
			Yellow: "\033[93m",
			Blue:   "\033[94m",
			End:    "\033[0m",
			Bold:   "\033[1m",
		}
	}
}


type linkFinderResult struct {
	sourceURL string
	endpoints []string
	err       error
}

func fetchAndFindLinks(client *http.Client, targetURL string, re *regexp.Regexp) ([]string, error) {
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return nil, fmt.Errorf("could not create request: %v", err)
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bad status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("could not read response body: %v", err)
	}

	matches := re.FindAllStringSubmatch(string(body), -1)
	endpoints := make([]string, 0, len(matches))
	for _, match := range matches {
		if len(match) > 1 {
			endpoints = append(endpoints, match[2])
		}
	}
	return endpoints, nil
}

func worker(client *http.Client, re *regexp.Regexp, jobs <-chan string, results chan<- linkFinderResult, wg *sync.WaitGroup) {
	defer wg.Done()
	for url := range jobs {
		endpoints, err := fetchAndFindLinks(client, url, re)
		results <- linkFinderResult{sourceURL: url, endpoints: endpoints, err: err}
	}
}

func main() {
	var (
		targetURL  string
		urlList    string
		outputFile string
		threads    int
		resolve    bool
		quiet      bool
		noColor    bool
	)

	flag.StringVar(&targetURL, "u", "", "Single URL to scan.")
	flag.StringVar(&urlList, "l", "", "File containing a list of URLs to scan.")
	flag.StringVar(&outputFile, "o", "", "File to save the final output of unique endpoints.")
	flag.IntVar(&threads, "t", 20, "Number of concurrent threads to use.")
	flag.BoolVar(&resolve, "r", false, "Resolve found paths to full URLs.")
	flag.BoolVar(&quiet, "q", false, "Silent mode. Only output the final list of unique endpoints.")
	flag.BoolVar(&noColor, "no-color", false, "Disable colorized output.")
	flag.Parse()

	initColors(noColor)

	urlsToScan := make([]string, 0)
	if targetURL != "" {
		urlsToScan = append(urlsToScan, targetURL)
	} else if urlList != "" {
		file, err := os.Open(urlList)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s[!] Error: The file '%s' was not found: %v%s\n", c.Red, urlList, err, c.End)
			os.Exit(1)
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			if line := strings.TrimSpace(scanner.Text()); line != "" {
				urlsToScan = append(urlsToScan, line)
			}
		}
	} else {
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			scanner := bufio.NewScanner(os.Stdin)
			for scanner.Scan() {
				if line := strings.TrimSpace(scanner.Text()); line != "" {
					urlsToScan = append(urlsToScan, line)
				}
			}
		}
	}

	if len(urlsToScan) == 0 {
		fmt.Fprintf(os.Stderr, "%sGoLinkFinder - A fast, concurrent endpoint finder for JavaScript files.%s\n", c.Bold, c.End)
		flag.Usage()
		fmt.Fprintf(os.Stderr, "\n%s[!] No input provided. Please use -u, -l, or pipe data from stdin.%s\n", c.Red, c.End)
		os.Exit(1)
	}

	re := regexp.MustCompile(endpointRegex)
	allFoundEndpoints := make(map[string]struct{})
	var finalEndpointsLock sync.Mutex

	jobs := make(chan string, len(urlsToScan))
	results := make(chan linkFinderResult, len(urlsToScan))

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	var wg sync.WaitGroup
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go worker(client, re, jobs, results, &wg)
	}

	for _, url := range urlsToScan {
		jobs <- url
	}
	close(jobs)

	if !quiet {
		fmt.Printf("%s[*] Scanning %d URL(s) with %d threads...%s\n", c.Yellow, len(urlsToScan), threads, c.End)
	}

	for i := 0; i < len(urlsToScan); i++ {
		res := <-results
		if res.err != nil {
			if !quiet {
				fmt.Fprintf(os.Stderr, "%s[-] Error scanning %s: %v%s\n", c.Red, res.sourceURL, res.err, c.End)
			}
			continue
		}

		if len(res.endpoints) > 0 {
			if !quiet {
				fmt.Printf("\n%s[+] Endpoints found in %s:%s\n", c.Blue, res.sourceURL, c.End)
			}

			baseURL, _ := url.Parse(res.sourceURL)
			for _, link := range res.endpoints {
				finalLink := link
				if resolve && baseURL != nil {
					relURL, err := url.Parse(link)
					if err == nil {
						finalLink = baseURL.ResolveReference(relURL).String()
					}
				}

				finalEndpointsLock.Lock()
				if _, exists := allFoundEndpoints[finalLink]; !exists {
					allFoundEndpoints[finalLink] = struct{}{}
					if !quiet {
						fmt.Printf("  %s%s%s\n", c.Green, finalLink, c.End)
					}
				}
				finalEndpointsLock.Unlock()
			}
		}
	}

	wg.Wait()
	close(results)

	sortedEndpoints := make([]string, 0, len(allFoundEndpoints))
	for endpoint := range allFoundEndpoints {
		sortedEndpoints = append(sortedEndpoints, endpoint)
	}
	sort.Strings(sortedEndpoints)

	if quiet {
		for _, endpoint := range sortedEndpoints {
			fmt.Println(endpoint)
		}
	}

	if outputFile != "" {
		if !quiet {
			fmt.Printf("\n%s[*] Saving %d unique endpoints to '%s'...%s\n", c.Yellow, len(sortedEndpoints), outputFile, c.End)
		}
		file, err := os.Create(outputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s[!] Error creating output file: %v%s\n", c.Red, err, c.End)
			os.Exit(1)
		}
		defer file.Close()

		writer := bufio.NewWriter(file)
		for _, endpoint := range sortedEndpoints {
			fmt.Fprintln(writer, endpoint)
		}
		writer.Flush()
	}

	if !quiet {
		fmt.Printf("\n%s%s[✔] Done. Found a total of %d unique endpoints.%s%s\n", c.Bold, c.Yellow, len(sortedEndpoints), c.End, c.End)
	}
}
