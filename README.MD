# jynx-pi

A Go networking exercise covering port scanning, HTTP proxying, request repeating, banner-based vulnerability checks, and ICMP host discovery — all in a single static binary.

> **Scope note:** this is a learning / portfolio project, not a production pentest tool. For real engagements use [`nmap`](https://nmap.org/), [`Burp Suite`](https://portswigger.net/burp), [`mitmproxy`](https://mitmproxy.org/), and [`nuclei`](https://github.com/projectdiscovery/nuclei) — they handle the long tail of edge cases this code doesn't. The point of `jynx-pi` is to show clean Go networking primitives (goroutines + `sync.WaitGroup`, SOCKS5 dialers, ICMP, TLS handshake, YAML templates) in one readable file.

> **Authorization:** use only against systems you own or have explicit written permission to test. See [LICENSE](LICENSE).

---

## Build

```bash
go build -o jynx-pi main.go
```

---

## Modes

Mode is selected with `-mode=<name>`. Each mode has its own flag set.

### Scanner — TCP / UDP port sweep

```bash
# TCP
./jynx-pi -mode=scanner -host=192.168.1.100 -start=1 -end=1024

# UDP (best-effort — see caveats below)
./jynx-pi -mode=scanner -host=192.168.1.100 -start=1 -end=1024 -protocol=udp
```

**Caveat:** the UDP mode sends a generic probe and waits for a response. Most real UDP services (DNS, SNMP, NTP, etc.) only respond to protocol-specific queries, so UDP results are best treated as hints. Use `nmap -sU` with NSE probes for accurate UDP scanning.

### Proxy — basic HTTP intercept / forward

```bash
./jynx-pi -mode=proxy -listen=":8080"
```

Logs `CONNECT` and regular HTTP requests as they pass through. **Does not perform TLS MITM** — for that you need a CA cert and rewriting machinery; use Burp / mitmproxy.

### Repeater — fire the same HTTP request N times

```bash
./jynx-pi -mode=repeater \
  -url="http://example.com/api" \
  -method=POST \
  -data='{"key":"value"}' \
  -count=5 \
  -delay=3s
```

### Vulnerability check — banner grab + template match

```bash
# Plain TCP banner
./jynx-pi -mode=check -checkhost=scanme.nmap.org -checkport=22 -templates=vuln_templates.yaml

# TLS handshake (cert subject/issuer as the "banner")
./jynx-pi -mode=check -checkhost=scanme.nmap.org -checkport=443 -templates=vuln_templates.yaml -secure=true
```

Templates are YAML with `name`, `description`, and a list of `matches` (substring patterns). See `vuln_templates.yaml` for an example.

### Discover — ICMP host sweep over a CIDR

```bash
sudo ./jynx-pi -mode=discover -cidr="192.168.1.0/24"
```

Requires root (raw ICMP sockets). For a /16 or larger, this currently spawns one goroutine per host without a worker pool — works fine for /24 lab subnets, will exhaust file descriptors on bigger ranges.

### SOCKS5 outbound (repeater only)

```bash
./jynx-pi -mode=repeater -url="http://example.com/api" -socks="127.0.0.1:9050" -count=3 -delay=3s
```

Routes outbound traffic through a SOCKS5 endpoint (e.g. a local Tor instance).

---

## Known limitations (it's a learning project)

- **No worker pool** on scanner / discover — large port or CIDR ranges will hit FD limits.
- **UDP scanner is generic** — false negatives on protocol-specific services.
- **HTTP proxy is forward-only** — no TLS MITM, no request history, no replay.
- **Vuln check uses `strings.Contains`** — no version-range or regex matching; false positives are possible (`"Apache/2.4.29"` matches `"Apache/2.4.290"`).
- **Banner grab reads one `\n`-terminated line** — fine for SSH-style services, not for HTTP without sending a request first.
- **Uses deprecated `ioutil`** and an archived `go-ping/ping` dependency. Modernization is a future cleanup.

The companion document for what a hardened version would look like: pick one mode and build it out properly (the vuln-check mode is the most interesting candidate — Nuclei-lite).

---

## License

[MIT](LICENSE). Educational / authorized-testing use only.
