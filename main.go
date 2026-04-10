package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

type NucleiResult struct {
	TemplateID string `json:"template-id"`
	Info       struct {
		Name     string `json:"name"`
		Severity string `json:"severity"`
	} `json:"info"`
	MatchedAt string   `json:"matched-at"`
	Extracted []string `json:"extracted-results"`
}

func main() {
	inputURL := flag.String("input", "", "URL to the text file containing links")
	flag.Parse()

	tgToken := os.Getenv("TG_BOT_TOKEN")
	tgChatID := os.Getenv("TG_CHAT_ID")
	if tgToken == "" || tgChatID == "" {
		log.Println("Warning: TG_BOT_TOKEN or TG_CHAT_ID is missing. Output will only be saved locally.")
	}

	var rawURLs []string
	var err error

	envInput := os.Getenv("INPUT_URLS")

	if *inputURL != "" {
		log.Println("[*] Fetching input file from URL...")
		rawURLs, err = fetchLines(*inputURL)
		if err != nil {
			log.Fatalf("Failed to fetch input URL: %v", err)
		}
	} else if envInput != "" {
		log.Println("[*] Reading URLs from pasted input...")
		envInput = strings.ReplaceAll(envInput, "\n", " ")
		envInput = strings.ReplaceAll(envInput, "\r", " ")
		envInput = strings.ReplaceAll(envInput, "\t", " ")
		words := strings.Split(envInput, " ")
		for _, w := range words {
			if w != "" {
				rawURLs = append(rawURLs, strings.TrimSpace(w))
			}
		}
	} else {
		log.Fatal("Please provide input using -input flag or INPUT_URLS environment variable")
	}

	log.Println("[*] Filtering JS files...")
	filteredURLs := filterJS(rawURLs)
	if len(filteredURLs) == 0 {
		log.Fatal("No JS URLs found after filtering.")
	}
	log.Printf("[*] Found %d matching JS URLs. Running httpx...", len(filteredURLs))

	liveURLs, err := runHttpx(filteredURLs)
	if err != nil {
		log.Fatalf("Httpx failed: %v", err)
	}
	log.Printf("[*] Found %d LIVE JS URLs.", len(liveURLs))
	if len(liveURLs) == 0 {
		log.Fatal("No live JS URLs found. Exiting.")
	}

	reportFile, err := os.Create("report.txt")
	if err != nil {
		log.Fatalf("Failed to create report file: %v", err)
	}
	defer reportFile.Close()

	writeHeader(reportFile, fmt.Sprintf("Live JS URLs Found: %d", len(liveURLs)))

	// 1. Run Nuclei
	log.Println("[*] Running Nuclei...")
	writeHeader(reportFile, "Nuclei Findings")
	nucleiRes, err := runNuclei(liveURLs)
	if err != nil {
		log.Printf("Nuclei error: %v", err)
	} else {
		reportFile.WriteString(nucleiRes)
	}

	// 2. Run JSLeak
	log.Println("[*] Running JSLeak...")
	writeHeader(reportFile, "JSLeak Findings")
	jsleakRes, err := runJSLeak(liveURLs)
	if err != nil {
		log.Printf("JSLeak error: %v", err)
	} else {
		reportFile.WriteString(jsleakRes)
	}

	// 3. Run Gf jsvar
	log.Println("[*] Running Gf Pattern (jsvar)...")
	writeHeader(reportFile, "Gf jsvar Findings")
	gfRes := runGfConcurrently(liveURLs, 10)
	reportFile.WriteString(gfRes)

	reportFile.Sync()

	// Send to Telegram
	if tgToken != "" && tgChatID != "" {
		log.Println("[*] Sending report to Telegram...")
		err = sendDocumentToTelegram(tgToken, tgChatID, "report.txt", "Automated JS Scan Results\nReport attached.")
		if err != nil {
			log.Printf("Failed to send telegram message: %v", err)
		} else {
			log.Println("[+] Telegram message sent successfully!")
		}
	} else {
		log.Println("[*] Telegram secrets not set. Skipping Telegram notification.")
	}

	// Cleanup
	os.Remove("live.txt")
	os.Remove("filtered.txt")
	os.Remove("nuclei_out.json")

	log.Println("[+] Done!")
}

func fetchLines(input string) ([]string, error) {
	var scanner *bufio.Scanner
	var err error

	if strings.HasPrefix(input, "http://") || strings.HasPrefix(input, "https://") {
		resp, err := http.Get(input)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		scanner = bufio.NewScanner(resp.Body)
	} else {
		file, err := os.Open(input)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		scanner = bufio.NewScanner(file)
	}

	var lines []string
	for scanner.Scan() {
		lines = append(lines, strings.TrimSpace(scanner.Text()))
	}
	return lines, scanner.Err()
}

func filterJS(urls []string) []string {
	// grep -Ei ".js(?|$)" | grep -Evi ".json|.jsp|.js.map"
	jsRegex := regexp.MustCompile(`(?i)\.js(\?.*)?$`)
	excludeRegex := regexp.MustCompile(`(?i)(\.json|\.jsp|\.js\.map)(\?.*)?$`)

	unique := make(map[string]bool)
	var filtered []string

	for _, u := range urls {
		if jsRegex.MatchString(u) && !excludeRegex.MatchString(u) {
			if !unique[u] {
				unique[u] = true
				filtered = append(filtered, u)
			}
		}
	}
	return filtered
}

func runHttpx(urls []string) ([]string, error) {
	os.WriteFile("filtered.txt", []byte(strings.Join(urls, "\n")), 0644)

	cmd := exec.Command("httpx", "-l", "filtered.txt", "-mc", "200", "-silent")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	var live []string
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		live = append(live, strings.TrimSpace(scanner.Text()))
	}
	os.WriteFile("live.txt", []byte(strings.Join(live, "\n")), 0644)
	return live, nil
}

func runNuclei(urls []string) (string, error) {
	cmd := exec.Command("nuclei", "-l", "live.txt", "-tags", "exposure,token,creds,endpoints,extract", "-severity", "critical,high,medium,info", "-j", "-o", "nuclei_out.json", "-silent")
	cmd.Run() // ignore err since nuclei returns error exit status on findings

	data, err := os.ReadFile("nuclei_out.json")
	if err != nil {
		return "No Nuclei findings or error reading output.\n\n", nil
	}

	var results string
	lines := strings.Split(string(data), "\n")
	for _, l := range lines {
		if strings.TrimSpace(l) == "" {
			continue
		}
		var r NucleiResult
		if err := json.Unmarshal([]byte(l), &r); err == nil {
			extracted := strings.Join(r.Extracted, ", ")
			if extracted == "" {
				extracted = r.Info.Name
			}
			results += fmt.Sprintf("[Nuclei] [%s] %s => Found at: %s\n", r.Info.Severity, extracted, r.MatchedAt)
		}
	}
	if results == "" {
		results = "No Nuclei findings.\n"
	}
	return results + "\n", nil
}

func runJSLeak(urls []string) (string, error) {
	cmd := exec.Command("jsleak", "-s")
	cmd.Stdin = strings.NewReader(strings.Join(urls, "\n"))
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("JSLeak returned error code: %v (Output snippet: %s...)", err, string(out)[:min(len(out), 50)])
	}

	res := string(out)
	if res == "" {
		return "No JSLeak findings.\n\n", nil
	}
	return res + "\n\n", nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func runGfConcurrently(urls []string, concurrency int) string {
	resultsChan := make(chan string, len(urls))
	urlChan := make(chan string, len(urls))

	var wg sync.WaitGroup

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for u := range urlChan {
				matches := runGfOnURL(u)
				if matches != "" {
					resultsChan <- matches
				}
			}
		}()
	}

	for _, u := range urls {
		urlChan <- u
	}
	close(urlChan)

	wg.Wait()
	close(resultsChan)

	var all string
	for res := range resultsChan {
		all += res
	}

	if all == "" {
		return "No Gf findings.\n\n"
	}
	return all + "\n"
}

func runGfOnURL(u string) string {
	resp, err := http.Get(u)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	cmd := exec.Command("gf", "jsvar")
	cmd.Stdin = resp.Body
	out, err := cmd.CombinedOutput()
	if err != nil || len(out) == 0 {
		return ""
	}

	var formatted string
	lines := strings.Split(string(out), "\n")
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l != "" {
			formatted += fmt.Sprintf("[Gf jsvar] %s => Found in: %s\n", l, u)
		}
	}
	return formatted
}

func writeHeader(w *os.File, title string) {
	w.WriteString(fmt.Sprintf("%s\n", strings.Repeat("=", len(title)+4)))
	w.WriteString(fmt.Sprintf("  %s\n", title))
	w.WriteString(fmt.Sprintf("%s\n\n", strings.Repeat("=", len(title)+4)))
}

func sendDocumentToTelegram(token, chatID, filename, caption string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	_ = writer.WriteField("chat_id", chatID)
	_ = writer.WriteField("caption", caption)

	part, err := writer.CreateFormFile("document", filepath.Base(filename))
	if err != nil {
		return err
	}
	_, err = io.Copy(part, file)
	if err != nil {
		return err
	}
	err = writer.Close()
	if err != nil {
		return err
	}

	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendDocument", token)
	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("bad status: %s, response: %s", resp.Status, string(respBody))
	}
	return nil
}
