# Network Checkup (ismywifihacked.com)

A free, one-click security checkup of the visitor's own internet connection: botnet
reputation (GreyNoise), DNS-hijack detection, and an exposure scan of the visitor's
public address. No accounts, no trackers.

## Layout

| Path | What |
|---|---|
| `src/netcheck/addrpolicy.py` | The only gate that decides what may be scanned |
| `src/netcheck/dns/` | Authoritative DNS server for `dns.<DOMAIN>` + token store |
| `src/netcheck/scan/` | Exposure scanner, SSRF-guarded SSDP fetch, XML parsing |
| `src/netcheck/reputation/` | GreyNoise and Shodan InternetDB clients |
| `src/netcheck/verdict/` | Turns results into green/yellow/red/"couldn't check" cards |
| `src/netcheck/web/` | FastAPI app, templates, static JS/CSS |
| `content/` | ASN groupings and per-ISP fix steps (YAML) |
| `deploy/` | Caddyfile, systemd units, server setup and deploy scripts |

## Development

```sh
uv sync
scripts/fetch-asn-db.sh          # optional: real ASN DB into data/asn/
uv run ruff check . && uv run ruff format --check . && uv run mypy && uv run pytest
```

Tests only ever talk to 127.0.0.1 (the scanner's loopback allowance exists only as a
constructor argument used by tests, never via configuration).

## Deployment

Server: DigitalOcean droplet, Debian 13, 1 vCPU / 1 GB.
IPv4 `192.241.148.110`, IPv6 `2604:a880:400:d1:0:5:41f0:3001`.

### 1. DNS records (Porkbun → Domain Management → DNS)

First **delete Porkbun's default parking records** (usually an `ALIAS`/`A` on the root
and a `CNAME` on `*` pointing at `pixie.porkbun.com`/`uixie.porkbun.com`).

| Type | Host | Answer | Why |
|---|---|---|---|
| A | *(blank / root)* | `192.241.148.110` | Website |
| AAAA | *(blank / root)* | `2604:a880:400:d1:0:5:41f0:3001` | Website over IPv6 |
| A | `www` | `192.241.148.110` | Redirects to the root |
| AAAA | `www` | `2604:a880:400:d1:0:5:41f0:3001` | |
| A | `v4` | `192.241.148.110` | IPv4-only host (no AAAA!) |
| AAAA | `v6` | `2604:a880:400:d1:0:5:41f0:3001` | IPv6-only host (no A!) |
| A | `ns1` | `192.241.148.110` | Name server address for the delegation |
| AAAA | `ns1` | `2604:a880:400:d1:0:5:41f0:3001` | |
| NS | `dns` | `ns1.ismywifihacked.com` | Delegates `dns.ismywifihacked.com` to our server |

No registrar "glue" is needed: `ns1.ismywifihacked.com` lives in the parent zone that
Porkbun already serves, so Porkbun answers its A/AAAA records directly.

Check (records can take a few minutes to appear):

```sh
dig +short ismywifihacked.com A
dig +short v6.ismywifihacked.com AAAA
dig +short NS dns.ismywifihacked.com          # -> ns1.ismywifihacked.com.
dig +short $(openssl rand -hex 16).dns.ismywifihacked.com   # -> 192.241.148.110 once the DNS service runs
```

### 2. One-time server setup

```sh
scp deploy/harden.sh deploy/lock-root-ssh.sh root@192.241.148.110:
ssh root@192.241.148.110 bash harden.sh <admin-user>
ssh <admin-user>@192.241.148.110 sudo true        # must succeed before the next step
ssh <admin-user>@192.241.148.110 sudo bash lock-root-ssh.sh
```

Then create `/etc/netcheck/netcheck.env` (root:root, 0600) from
`deploy/netcheck.env.example`. Secrets (the optional GreyNoise key) live only there.

What `harden.sh` sets up: key-only SSH, ufw allowing only 22/53/80/443, unattended
security upgrades, Caddy from its official repo, uv, separate unprivileged
`netcheck-web` and `netcheck-dns` users, and LLMNR/mDNS off.

### 3. Deploy

```sh
deploy/deploy.sh <admin-user>@192.241.148.110
```

Copies the tree to `/opt/netcheck/app` (root-owned, read-only to services), runs
`uv sync --locked --no-dev`, installs units and the Caddyfile, and restarts.

Services:

- `netcheck-web`: uvicorn on 127.0.0.1:8000 behind Caddy, user `netcheck-web`.
- `netcheck-dns`: binds :53 on the public addresses only (systemd-resolved owns
  127.0.0.53:53), user `netcheck-dns`, `CAP_NET_BIND_SERVICE` only.
- `netcheck-asn-update.timer`: weekly refresh of the ASN database.

Both services run with `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`,
`PrivateTmp`, `RestrictAddressFamilies`, an empty or minimal capability set and a
syscall filter. Check with `systemd-analyze security netcheck-web netcheck-dns`.

### 4. Testing from outside your home network

The scan only means something when run from the network you want to check, and the
DNS server must be checked from somewhere other than the VPS.

1. **DNS server is authoritative-only** (run from your laptop):
   ```sh
   dig @192.241.148.110 google.com                 # status: REFUSED, no "ra" flag
   dig @192.241.148.110 dns.ismywifihacked.com ANY # status: REFUSED
   dig @192.241.148.110 dns.ismywifihacked.com SOA # answer, flags include "aa"
   ```
2. **Full check from home:** open https://ismywifihacked.com on your home Wi-Fi and
   click "Scan me". Then try it from your phone **on mobile data** (Wi-Fi off). That
   should say "we can't see your router" (carrier-grade NAT), not give a pass.
3. **A known-exposed target:** from a *different* machine you control (e.g. a second
   cheap VPS), run `python3 -m http.server 8080` and load the site from that machine's
   browser or with curl through it. The report should flag port 8080 as red.
4. **Headers:** `curl -sI https://ismywifihacked.com` should show the CSP, HSTS,
   nosniff and `Referrer-Policy: no-referrer`, and no `Server` header.

### Operations

Adding API keys (run in your own terminal, not pasted anywhere else):

```sh
ssh dnlbroun@192.241.148.110 'sudo tee -a /etc/netcheck/netcheck.env >/dev/null && sudo systemctl restart netcheck-web'
# then type GREYNOISE_API_KEY=..., press Enter, then Ctrl-D
```

Result statistics (daily totals only, no per-visitor data):

```sh
ssh dnlbroun@192.241.148.110 sudo -u netcheck-web /opt/netcheck/app/.venv/bin/python -m netcheck.stats
```

Third-party lookups and their terms: GreyNoise Community API and Shodan InternetDB
(free for non-commercial use). If the site ever becomes commercial, both need
revisiting. (Spamhaus was considered and skipped: its free tier is for mail-server
operators.)

- Logs: `journalctl -u netcheck-web -u netcheck-dns`. Request/access logging is off on
  purpose: it would record visitor IPs.
- Results expire after 24h and rate-limit entries after 1h. Both are in-process or
  SQLite under `/var/lib/netcheck`, purged automatically.
