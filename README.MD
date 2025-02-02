

### 1. Build the Application

After ensuring your dependencies are set up (e.g., unsetting proxy variables if needed), compile the tool:

```bash
go build -o jynx-pi main.go
```

---

### 2. Available Modes and How to Use Them

The script has several modes that you can activate using the `-mode` flag:

#### **Scanner Mode**

Use this mode to perform a basic TCP port scan on a target host. You can specify the host and port range.

**TCP Scan Example:**

```bash
./jynx-pi -mode=scanner -host=192.168.1.100 -start=1 -end=1024
```

**UDP Scan Example:**
```bash
./jynx-pi -mode=scanner -host=192.168.1.100 -start=1 -end=1024 -protocol=udp

```

This command will try to connect to each port from 1 to 1024 on the host 192.168.1.100 and print out the ones that are open.

---

#### **Proxy Mode**

This mode starts an HTTP proxy that intercepts and logs HTTP requests before forwarding them. It’s useful if you want to manually inspect or modify traffic.

**Example:**

```bash
./jynx-pi -mode=proxy -listen=":8080"
```

This starts the proxy on port 8080.

---

#### **Repeater Mode**

Repeater mode sends repeated HTTP requests to a specified URL. This can be helpful for testing how a server handles repeated requests or for manual testing scenarios.

**Example:**

```bash
./jynx-pi -mode=repeater -url="http://example.com/api" -method=POST -data='{"key": "value"}' -count=5 -delay=3s
```

This command sends a POST request to the URL 5 times with a 3‑second delay between requests.

---

#### **Vulnerability Check Mode**

This mode performs a banner grab and then checks the result against vulnerability templates defined in a YAML file.  
By default, it performs a plain TCP banner grab. If you use the `-secure` flag, it will perform a TLS handshake (for HTTPS services) and then extract certificate details as the banner.

**Plain HTTP Example:**

```bash
./jynx-pi -mode=check -checkhost=facelegal.com -checkport=80 -templates=vuln_templates.yaml
```

**TLS/HTTPS Example:**

```bash
./jynx-pi -mode=check -checkhost=facelegal.com -checkport=443 -templates=vuln_templates.yaml -secure=true
```

Make sure you create a `vuln_templates.yaml` file with your vulnerability definitions (for example, to look for specific versions in banners or certificate data).

