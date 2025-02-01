


```markdown
# jynx-pi

**jynx-pi** is a multi-mode pentesting tool written in Go. It integrates several functions:
- **Port Scanning:** Scans a range of ports on a target host.
- **HTTP Proxy/Interceptor:** Intercepts and forwards HTTP traffic.
- **HTTP Repeater/Intruder:** Sends repeated/customized HTTP requests.
- **Vulnerability Check:** Grabs service banners and checks them against YAML-defined vulnerability templates.

> **Disclaimer:** Use this tool only on systems where you have explicit authorization.

## Prerequisites

- [Go](https://golang.org/dl/) (version 1.16 or later)
- Git (optional, for cloning the repository)

## Setup Instructions

1. **Clone or Download the Repository**

   ```bash
   git clone https://github.com/yourusername/jynx-pi.git
   cd jynx-pi
   ```

2. **Initialize Go Modules**

   Ensure you are in the project directory and initialize the module:

   ```bash
   go mod init jynx-pi
   ```

   Then tidy up to fetch dependencies:

   ```bash
   export GOPROXY=direct
   go mod tidy
   ```

   If you are using a proxy (such as in a WSL2 environment), make sure to unset any interfering proxy environment variables:

   ```bash
   unset http_proxy
   unset https_proxy
   unset HTTP_PROXY
   unset HTTPS_PROXY
   ```

3. **Build the Application**

   Compile the binary with:

   ```bash
   go build -o jynx-pi main.go
   ```

## Usage

The tool operates in several modes. You select the mode by using the `-mode` flag.

### 1. Scanner Mode

Scans a range of ports on a target host.

```bash
./jynx-pi -mode=scanner -host=192.168.1.100 -start=1 -end=1024
```

This command scans ports 1 to 1024 on the specified host.

### 2. Proxy Mode

Starts an HTTP proxy to intercept and forward traffic.

```bash
./jynx-pi -mode=proxy -listen=":8080"
```

The proxy will listen on port 8080.

### 3. Repeater Mode

Sends a customizable HTTP request repeatedly.

```bash
./jynx-pi -mode=repeater -url="http://example.com/api" -method=POST -data='{"key": "value"}' -count=5 -delay=3s
```

This sends a POST request to the target URL 5 times with a 3‑second delay between requests.

### 4. Vulnerability Check Mode

Grabs a service banner from a target and checks it against vulnerability templates defined in a YAML file.

#### Create a YAML Template File

Create a file named `vuln_templates.yaml` in the same directory as your binary, for example:

```yaml
- name: "Vulnerable Apache 2.4.29"
  description: "Apache version 2.4.29 is known to have vulnerabilities."
  matches:
    - "Apache/2.4.29"

- name: "Outdated OpenSSL"
  description: "An outdated version of OpenSSL may be vulnerable."
  matches:
    - "OpenSSL 1.0.1"
```

#### Run the Vulnerability Check

```bash
./jynx-pi -mode=check -checkhost=example.com -checkport=80 -templates=vuln_templates.yaml
```

This will connect to `example.com` on port 80, grab the banner, and check it against the patterns defined in `vuln_templates.yaml`.

## Troubleshooting

- **Proxy Issues:**  
  If Go is trying to use an unwanted proxy (like a SOCKS5 proxy at `127.0.0.1:9050`), ensure you unset any proxy variables as shown above.

- **Dependencies:**  
  Make sure you have a working internet connection for module downloads. If issues persist, double-check your `GOPROXY` settings.




## Additional Check

1. **Unset Proxy Environment Variables in Your Shell:**  
   Run the following commands in your terminal:

   ```bash
   unset http_proxy
   unset https_proxy
   unset HTTP_PROXY
   unset HTTPS_PROXY
   unset socks_proxy
   ```

2. **Confirm They Are Unset:**  
   Verify by running:

   ```bash
   env | grep -i proxy
   ```

   You should see no lines related to `http_proxy` or `https_proxy` (aside from any intentional settings like `GOPROXY=direct`).

3. **Re-run Your Command:**  
   Once these are unset, run your repeater mode command again:

   ```bash
   ./jynx-pi -mode=repeater -url="http://example.com/api" -method=POST -data='{"key": "value"}' -count=5 -delay=3s
   ```

## License

MIT