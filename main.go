package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/PuerkitoBio/goquery"
	"golang.org/x/net/proxy"
)

func main() {
	if len(os.Args) < 2 || os.Args[1] == "-h" || os.Args[1] == "--help" {
		printHelp()
		return
	}

	var targets []string
	var useTor bool
	var inputFile string

	// Argument parsing
	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		if args[i] == "-tor" {
			useTor = true
			continue
		}
		if args[i] == "-f" {
			if i+1 < len(args) {
				inputFile = args[i+1]
				i++ // skip next
			}
			continue
		}
		// If it's not a flag, and we haven't found a file, treat as single target
		if inputFile == "" && !strings.HasPrefix(args[i], "-") {
			targets = append(targets, args[i])
		}
	}

	if inputFile != "" {
		file, err := os.Open(inputFile)
		if err != nil {
			fmt.Println("File error:", err)
			return
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				targets = append(targets, line)
			}
		}
	}

	if len(targets) == 0 {
		fmt.Println("No targets specified.")
		printHelp()
		return
	}

	// Open report log file
	reportFile, err := os.OpenFile("scan_report.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("Error opening report log:", err)
		return
	}
	defer reportFile.Close()
	
	// Write header
	reportFile.WriteString(fmt.Sprintf("--- Scan started at %s ---\n", time.Now().Format(time.RFC3339)))

	if useTor {
		fmt.Println("Starting Tor Scraper Mode...")
		runTorScan(targets, reportFile)
	} else {
		for _, target := range targets {
			fmt.Println("Processing:", target)
			runTarget(target, reportFile)
		}
	}
}

func printHelp() {
	fmt.Println("Usage:")
	fmt.Println("  go run main.go <url>")
	fmt.Println("  go run main.go -f targets.txt")
	fmt.Println("  go run main.go -tor -f targets.txt")
	fmt.Println("")
	fmt.Println("Options:")
	fmt.Println("  -f <file>      Run against multiple URLs from file")
	fmt.Println("  -tor           Enable Tor proxy (SOCKS5 127.0.0.1:9150)")
	fmt.Println("  -h, --help     Show this help message")
}

func runTorScan(targets []string, reportLog *os.File) {
	// Setup Tor Client
	// 127.0.0.1:9150 is the default Tor SOCKS port
	dialer, err := proxy.SOCKS5("tcp", "127.0.0.1:9150", nil, proxy.Direct)
	if err != nil {
		fmt.Println("Error creating SOCKS5 dialer:", err)
		fmt.Println("Make sure Tor service is running on 127.0.0.1:9150")
		return
	}

	transport := &http.Transport{
		Dial: dialer.Dial,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   60 * time.Second,
	}

	// Setup Chromedp with Proxy and User-Agent
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.ProxyServer("socks5://127.0.0.1:9150"),
		chromedp.Flag("ignore-certificate-errors", true),
		chromedp.UserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"),
	)
	allocCtx, cancelAlloc := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancelAlloc()

	// IP Check
	checkIP(client)

	for _, target := range targets {
		// Ensure URL has scheme
		if !strings.HasPrefix(target, "http") {
			target = "http://" + target
		}

		fmt.Printf("[INFO] Scanning: %s ... ", target)

		req, err := http.NewRequest("GET", target, nil)
		if err != nil {
			fmt.Printf("-> INVALID URL (%v)\n", err)
			reportLog.WriteString(fmt.Sprintf("[FAIL] %s - Invalid URL: %v\n", target, err))
			continue
		}
		// User-Agent header as requested
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")

		resp, err := client.Do(req)
		if err != nil {
			// Log error but continue
			fmt.Printf("-> TIMEOUT/ERROR (%v)\n", err)
			reportLog.WriteString(fmt.Sprintf("[FAIL] %s - Error: %v\n", target, err))
			continue
		}

		if resp.StatusCode == 200 {
			fmt.Printf("-> SUCCESS\n")
			reportLog.WriteString(fmt.Sprintf("[SUCCESS] %s - HTTP 200\n", target))
			
			// Save HTML and Screenshot
			folder := saveTorResult(target, resp.Body)
			
			// Take Screenshot using Chromedp over Tor
			takeTorScreenshot(allocCtx, target, folder)
		} else {
			fmt.Printf("-> HTTP %s\n", resp.Status)
			reportLog.WriteString(fmt.Sprintf("[FAIL] %s - HTTP %s\n", target, resp.Status))
		}
		resp.Body.Close()
	}
}

func checkIP(client *http.Client) {
	fmt.Print("[INFO] Checking Tor Connection... ")
	resp, err := client.Get("https://check.torproject.org/api/ip")
	if err != nil {
		fmt.Printf("FAILED (%v)\n", err)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	fmt.Printf("SUCCESS. Current IP: %s\n", strings.TrimSpace(string(body)))
}

func takeTorScreenshot(allocCtx context.Context, targetURL string, folder string) {
	ctx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()

	// Increased timeout to 120s to handle slow Tor connections
	ctx, cancel = context.WithTimeout(ctx, 120*time.Second)
	defer cancel()

	var screenshot []byte
	err := chromedp.Run(ctx,
		chromedp.EmulateViewport(1920, 1080), // Set standard desktop resolution
		chromedp.Navigate(targetURL),
		chromedp.Sleep(30*time.Second), // Wait a bit more for Tor
		chromedp.FullScreenshot(&screenshot, 90),
	)

	if err != nil {
		fmt.Println("  -> Screenshot error:", err)
		return
	}

	os.WriteFile(filepath.Join(folder, "screenshot.png"), screenshot, 0644)
	fmt.Println("  -> Screenshot saved")
}

func saveTorResult(targetURL string, body io.Reader) string {
	parsedURL, _ := url.Parse(targetURL)
	baseFolder := "tor_results"

	if parsedURL != nil && parsedURL.Host != "" {
		baseFolder = filepath.Join("tor_results", sanitize(parsedURL.Host))
	}

	folder := nextRunFolder(baseFolder)
	os.MkdirAll(folder, 0755)

	data, err := io.ReadAll(body)
	if err != nil {
		fmt.Println("Error reading body:", err)
		return folder
	}

	htmlPath := filepath.Join(folder, "output.html")
	os.WriteFile(htmlPath, data, 0644)
	return folder
}

func runTarget(targetURL string, reportLog *os.File) {
	parsedURL, err := url.Parse(targetURL)
	baseFolder := "results"

	if err == nil && parsedURL.Host != "" {
		baseFolder = filepath.Join("results", sanitize(parsedURL.Host))
	}

	folder := nextRunFolder(baseFolder)
	os.MkdirAll(folder, 0755)

	// get & download html
	resp, err := http.Get(targetURL)
	if err != nil {
		fmt.Println("Request error:", err)
		reportLog.WriteString(fmt.Sprintf("[FAIL] %s - Request error: %v\n", targetURL, err))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		fmt.Println("HTTP Error:", resp.Status)
		reportLog.WriteString(fmt.Sprintf("[FAIL] %s - HTTP %s\n", targetURL, resp.Status))
		return
	}

	reportLog.WriteString(fmt.Sprintf("[SUCCESS] %s - HTTP 200\n", targetURL))

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Read error:", err)
		return
	}

	// save html
	htmlPath := filepath.Join(folder, "output.html")
	os.WriteFile(htmlPath, body, 0644)

	// extract urls
	urlsPath := filepath.Join(folder, "urls.txt")
	err = extractURLs(htmlPath, targetURL, urlsPath)
	if err != nil {
		fmt.Println("URL extraction error:", err)
	} else {
		fmt.Println("Extracted URLs saved to:", urlsPath)
	}

	// take screenshot
	ctx, cancel := chromedp.NewContext(context.Background())
	defer cancel()

	ctx, cancel = context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	var screenshot []byte
	err = chromedp.Run(ctx,
		chromedp.EmulateViewport(1920, 1080),
		chromedp.Navigate(targetURL),
		chromedp.Sleep(3*time.Second),
		chromedp.FullScreenshot(&screenshot, 90),
	)

	if err != nil {
		fmt.Println("Screenshot error:", err)
		return
	}

	os.WriteFile(filepath.Join(folder, "screenshot.png"), screenshot, 0644)

	fmt.Println("Saved to:", folder)
}

// sanitize replaces characters not suitable for folder names

func sanitize(s string) string {
	s = strings.ReplaceAll(s, ":", "_")
	s = strings.ReplaceAll(s, "/", "_")
	return s
}

func extractURLs(htmlPath string, baseURL string, outputPath string) error {
	file, err := os.Open(htmlPath)
	if err != nil {
		return err
	}
	defer file.Close()

	doc, err := goquery.NewDocumentFromReader(file)
	if err != nil {
		return err
	}

	base, err := url.Parse(baseURL)
	if err != nil {
		return err
	}

	seen := make(map[string]bool)
	var results []string

	doc.Find("a[href]").Each(func(i int, s *goquery.Selection) {
		href, _ := s.Attr("href")
		href = strings.TrimSpace(href)

		if href == "" {
			return
		}

		parsed, err := url.Parse(href)
		if err != nil {
			return
		}

		absolute := base.ResolveReference(parsed).String()

		if !seen[absolute] {
			seen[absolute] = true
			results = append(results, absolute)
		}
	})

	return os.WriteFile(outputPath, []byte(strings.Join(results, "\n")), 0644)
}

func nextRunFolder(base string) string {
	os.MkdirAll(base, 0755)

	for i := 1; ; i++ {
		folder := filepath.Join(base, fmt.Sprintf("run-%d", i))
		if _, err := os.Stat(folder); os.IsNotExist(err) {
			return folder
		}
	}
}
