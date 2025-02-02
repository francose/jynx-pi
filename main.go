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

	"github.com/go-ping/ping"
	"golang.org/x/net/proxy"
	"gopkg.in/yaml.v2"
)

// ----------------------
// TCP Port Scanner
// ----------------------

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

func scanUDPPort(host string, port int, wg *sync.WaitGroup) {
	defer wg.Done()
	address := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("udp", address, 500*time.Millisecond)
	if err != nil {
		return
	}
	defer conn.Close()
	message := []byte("Hello")
	_, err = conn.Write(message)
	if err != nil {
		return
	}
	buf := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	_, err = conn.Read(buf)
	if err == nil {
		fmt.Printf("UDP port %d is open/responsive\n", port)
	} else {
		log.Printf("UDP read error for port %d: %v", port, err)
	}
}

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
// HTTP Repeater/Intruder (with Proxy Support)
// ----------------------

func newHTTPClient(proxyAddr string) (*http.Client, error) {
	if proxyAddr != "" {
		dialer, err := proxy.SOCKS5("tcp", proxyAddr, nil, proxy.Direct)
		if err != nil {
			return nil, fmt.Errorf("failed to create proxy dialer: %v", err)
		}
		transport := &http.Transport{
			Dial: dialer.Dial,
		}
		return &http.Client{
			Transport: transport,
			Timeout:   10 * time.Second,
		}, nil
	}
	return &http.Client{Timeout: 10 * time.Second}, nil
}

func sendCustomRequest(client *http.Client, method, targetURL string, payload []byte) {
	req, err := http.NewRequest(method, targetURL, bytes.NewReader(payload))
	if err != nil {
		log.Printf("Error creating request: %v", err)
		return
	}
	req.Header.Set("User-Agent", "CustomGoRepeater/1.0")
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Request error: %v", err)
		return
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Printf("Response from %s: %d\n%s\n", targetURL, resp.StatusCode, body)
}

func runRepeater(client *http.Client, method, targetURL, payload string, count int, delay time.Duration) {
	for i := 0; i < count; i++ {
		log.Printf("Sending request iteration %d", i+1)
		sendCustomRequest(client, method, targetURL, []byte(payload))
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
// Local Network Device Discovery
// ----------------------

func hosts(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}
	if len(ips) > 2 {
		return ips[1 : len(ips)-1], nil
	}
	return ips, nil
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func discoverNetwork(cidr string) {
	ips, err := hosts(cidr)
	if err != nil {
		log.Fatalf("Error parsing CIDR: %v", err)
	}
	var wg sync.WaitGroup
	fmt.Printf("Starting device discovery on %s...\n", cidr)
	for _, ip := range ips {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			pinger, err := ping.NewPinger(ip)
			if err != nil {
				log.Printf("Error creating pinger for %s: %v", ip, err)
				return
			}
			pinger.SetPrivileged(true)
			pinger.Count = 1
			pinger.Timeout = 1 * time.Second
			err = pinger.Run()
			if err != nil {
				log.Printf("Ping error for %s: %v", ip, err)
				return
			}
			stats := pinger.Statistics()
			if stats.PacketsRecv > 0 {
				fmt.Printf("Device found: %s\n", ip)
			}
		}(ip)
	}
	wg.Wait()
}

// ----------------------
// Main: Mode Selection via Flags
// ----------------------

func main() {
	mode := flag.String("mode", "", "Mode to run: scanner, proxy, repeater, check, discover")
	// Scanner flags
	scannerHost := flag.String("host", "127.0.0.1", "Target host for scanning")
	startPort := flag.Int("start", 1, "Start port for scanning")
	endPort := flag.Int("end", 1024, "End port for scanning")
	protocol := flag.String("protocol", "tcp", "Protocol for scanning: tcp or udp")

	// Proxy flags (for built-in proxy mode, if needed)
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

	// Discovery flags
	cidr := flag.String("cidr", "", "CIDR for local network device discovery (e.g., 192.168.1.0/24)")

	// New Proxy flag: Use a SOCKS5 proxy for outbound HTTP connections (like Tor)
	socksProxy := flag.String("socks", "", "Optional SOCKS5 proxy address (e.g., 127.0.0.1:9050)")

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
		client, err := newHTTPClient(*socksProxy)
		if err != nil {
			log.Fatalf("Error creating HTTP client: %v", err)
		}
		fmt.Printf("Repeating %s requests to %s (%d times)...\n", *method, *targetURL, *repeatCount)
		runRepeater(client, *method, *targetURL, *payload, *repeatCount, *delay)
	case "check":
		if *checkTarget == "" {
			log.Fatal("Error: -checkhost flag is required for vulnerability check mode.")
		}
		fmt.Printf("Running vulnerability check on %s:%d...\n", *checkTarget, *checkPort)
		runVulnerabilityCheck(*checkTarget, *checkPort, *templatePath, *checkSecure)
	case "discover":
		if *cidr == "" {
			log.Fatal("Error: -cidr flag is required for discovery mode.")
		}
		discoverNetwork(*cidr)
	default:
		fmt.Println("Usage:")
		flag.PrintDefaults()
	}
}
