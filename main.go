package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v2"
)

// ----------------------
// TCP Port Scanner
// ----------------------

// scanTCPPort attempts a TCP connection to a specific host and port.
func scanTCPPort(host string, port int, wg *sync.WaitGroup) {
	defer wg.Done()
	address := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", address, 500*time.Millisecond)
	if err != nil {
		return
	}
	conn.Close()
	fmt.Printf("TCP port %d is open\n", port)
}

// runTCPScanner scans a range of TCP ports.
func runTCPScanner(host string, startPort, endPort int) {
	var wg sync.WaitGroup
	for port := startPort; port <= endPort; port++ {
		wg.Add(1)
		go scanTCPPort(host, port, &wg)
	}
	wg.Wait()
}

// ----------------------
// UDP Port Scanner
// ----------------------

// scanUDPPort attempts a UDP "scan" on a given host and port.
// Note: UDP is connectionless; lack of response can be ambiguous.
func scanUDPPort(host string, port int, wg *sync.WaitGroup) {
	defer wg.Done()
	address := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("udp", address, 500*time.Millisecond)
	if err != nil {
		return
	}
	defer conn.Close()

	// Send a simple payload. Some protocols might expect different data.
	message := []byte("Hello")
	_, err = conn.Write(message)
	if err != nil {
		return
	}

	// Set a read deadline and attempt to read a response.
	buf := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	_, err = conn.Read(buf)
	if err == nil {
		fmt.Printf("UDP port %d is open/responsive\n", port)
	} else {
		// In a real-world scenario, no response could also mean filtered or open.
		// For this demo, we only print when we get a response.
	}
}

// runUDPScanner scans a range of UDP ports.
func runUDPScanner(host string, startPort, endPort int) {
	var wg sync.WaitGroup
	for port := startPort; port <= endPort; port++ {
		wg.Add(1)
		go scanUDPPort(host, port, &wg)
	}
	wg.Wait()
}

// ----------------------
// HTTP Proxy/Interceptor
// ----------------------

func handleConnect(w http.ResponseWriter, r *http.Request) {
	destConn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		destConn.Close()
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		destConn.Close()
		return
	}
	go transfer(destConn, clientConn)
	go transfer(clientConn, destConn)
}

func transfer(destination io.WriteCloser, source io.ReadCloser) {
	defer destination.Close()
	defer source.Close()
	io.Copy(destination, source)
}

func proxyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		log.Printf("Intercepted CONNECT request for %s", r.Host)
		handleConnect(w, r)
		return
	}

	log.Printf("Intercepted request: %s %s", r.Method, r.URL.String())
	outReq := r.Clone(r.Context())
	resp, err := http.DefaultTransport.RoundTrip(outReq)
	if err != nil {
		http.Error(w, "Error forwarding the request", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for key, values := range resp.Header {
		for _, v := range values {
			w.Header().Add(key, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func startProxy(listenAddr string) {
	handler := http.HandlerFunc(proxyHandler)
	server := &http.Server{
		Addr:    listenAddr,
		Handler: handler,
	}
	log.Printf("Starting proxy on %s", listenAddr)
	log.Fatal(server.ListenAndServe())
}

// ----------------------
// HTTP Repeater/Intruder
// ----------------------

func sendCustomRequest(method, targetURL string, payload []byte) {
	req, err := http.NewRequest(method, targetURL, bytes.NewReader(payload))
	if err != nil {
		log.Printf("Error creating request: %v", err)
		return
	}
	req.Header.Set("User-Agent", "CustomGoRepeater/1.0")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Request error: %v", err)
		return
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Printf("Response from %s: %d\n%s\n", targetURL, resp.StatusCode, body)
}

func runRepeater(method, targetURL, payload string, count int, delay time.Duration) {
	for i := 0; i < count; i++ {
		log.Printf("Sending request iteration %d", i+1)
		sendCustomRequest(method, targetURL, []byte(payload))
		time.Sleep(delay)
	}
}

// ----------------------
// Vulnerability Check Module (Template-Based)
// ----------------------

type VulnerabilityTemplate struct {
	Name        string   `yaml:"name"`
	Description string   `yaml:"description"`
	Matches     []string `yaml:"matches"`
}

func loadTemplates(filePath string) ([]VulnerabilityTemplate, error) {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	var templates []VulnerabilityTemplate
	err = yaml.Unmarshal(data, &templates)
	if err != nil {
		return nil, err
	}
	return templates, nil
}

// grabBanner grabs a banner from a plain TCP connection.
func grabBanner(host string, port int) (string, error) {
	address := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	reader := bufio.NewReader(conn)
	banner, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", err
	}
	return strings.TrimSpace(banner), nil
}

// grabTLSBanner connects via TLS and retrieves certificate details.
func grabTLSBanner(host string, port int) (string, error) {
	address := fmt.Sprintf("%s:%d", host, port)
	conn, err := tls.Dial("tcp", address, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return "", err
	}
	defer conn.Close()
	state := conn.ConnectionState()
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		return fmt.Sprintf("Subject: %s, Issuer: %s", cert.Subject, cert.Issuer), nil
	}
	return "", fmt.Errorf("no certificates found")
}

func checkUsingTemplates(banner string, templates []VulnerabilityTemplate) {
	found := false
	for _, tmpl := range templates {
		for _, match := range tmpl.Matches {
			if strings.Contains(banner, match) {
				fmt.Printf("Vulnerability Detected: %s\nDescription: %s\n", tmpl.Name, tmpl.Description)
				found = true
			}
		}
	}
	if !found {
		fmt.Println("No vulnerabilities detected based on the banner and templates.")
	}
}

// runVulnerabilityCheck grabs a banner (plain or TLS) and applies vulnerability templates.
func runVulnerabilityCheck(target string, port int, templatePath string, secure bool) {
	fmt.Printf("Connecting to %s on port %d...\n", target, port)
	var banner string
	var err error
	if secure {
		banner, err = grabTLSBanner(target, port)
	} else {
		banner, err = grabBanner(target, port)
	}
	if err != nil {
		fmt.Printf("Error grabbing banner: %v\n", err)
		return
	}
	fmt.Printf("Banner: %s\n", banner)
	templates, err := loadTemplates(templatePath)
	if err != nil {
		fmt.Printf("Error loading templates: %v\n", err)
		return
	}
	checkUsingTemplates(banner, templates)
}

// ----------------------
// Main: Mode Selection via Flags
// ----------------------

func main() {
	mode := flag.String("mode", "", "Mode to run: scanner, proxy, repeater, check")
	// Scanner flags
	scannerHost := flag.String("host", "127.0.0.1", "Target host for scanning")
	startPort := flag.Int("start", 1, "Start port for scanning")
	endPort := flag.Int("end", 1024, "End port for scanning")
	protocol := flag.String("protocol", "tcp", "Protocol for scanning: tcp or udp")

	// Proxy flags
	proxyAddr := flag.String("listen", ":8080", "Listen address for proxy")

	// Repeater flags
	targetURL := flag.String("url", "", "Target URL for repeater/intruder")
	method := flag.String("method", "GET", "HTTP method to use in repeater")
	payload := flag.String("data", "", "Payload for the repeater request")
	repeatCount := flag.Int("count", 1, "Number of times to send the request")
	delay := flag.Duration("delay", 2*time.Second, "Delay between requests")

	// Vulnerability check flags
	checkTarget := flag.String("checkhost", "", "Target host for vulnerability check")
	checkPort := flag.Int("checkport", 80, "Target port for vulnerability check")
	templatePath := flag.String("templates", "vuln_templates.yaml", "Path to vulnerability templates YAML file")
	checkSecure := flag.Bool("secure", false, "Use TLS for banner grabbing (default port 443 if not specified)")

	flag.Parse()

	switch *mode {
	case "scanner":
		fmt.Printf("Scanning host %s from port %d to %d over %s...\n", *scannerHost, *startPort, *endPort, *protocol)
		if strings.ToLower(*protocol) == "tcp" {
			runTCPScanner(*scannerHost, *startPort, *endPort)
		} else if strings.ToLower(*protocol) == "udp" {
			runUDPScanner(*scannerHost, *startPort, *endPort)
		} else {
			fmt.Println("Unsupported protocol. Please choose 'tcp' or 'udp'.")
		}

	case "proxy":
		fmt.Printf("Starting HTTP proxy on %s...\n", *proxyAddr)
		startProxy(*proxyAddr)

	case "repeater":
		if *targetURL == "" {
			log.Fatal("Error: -url flag is required for repeater mode.")
		}
		fmt.Printf("Repeating %s requests to %s (%d times)...\n", *method, *targetURL, *repeatCount)
		runRepeater(*method, *targetURL, *payload, *repeatCount, *delay)

	case "check":
		if *checkTarget == "" {
			log.Fatal("Error: -checkhost flag is required for vulnerability check mode.")
		}
		fmt.Printf("Running vulnerability check on %s:%d...\n", *checkTarget, *checkPort)
		runVulnerabilityCheck(*checkTarget, *checkPort, *templatePath, *checkSecure)

	default:
		fmt.Println("Usage:")
		flag.PrintDefaults()
	}
}
