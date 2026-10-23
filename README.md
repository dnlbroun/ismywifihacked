# Is My Wi-Fi Hacked?

Source for [ismywifihacked.com](https://ismywifihacked.com): a free, one-click check of
your connection from the outside. It looks for exposed services, DNS hijacking and
signs of an infected device, then explains the results in plain language.

## What it checks

- **Open doors:** about 30 TCP ports, plus UPnP (SSDP), NAT-PMP and open-resolver
  probes, on the visitor's IPv4 and IPv6 addresses.
- **DNS hijacking:** the browser resolves a one-time name on our own authoritative DNS
  server, so we can see which resolver it used.
- **Botnet activity:** GreyNoise and AbuseIPDB (optional key).
- **History:** Shodan InternetDB.

Only the visitor's own address is ever scanned, and only after they click.
`src/netcheck/addrpolicy.py` is the one place that decides what may be scanned.

## Layout

| Path | What |
|---|---|
| `src/netcheck/scan/` | Scanner, SSRF-guarded SSDP fetch, device XML parsing |
| `src/netcheck/dns/` | Authoritative DNS server and token store |
| `src/netcheck/reputation/` | GreyNoise, AbuseIPDB and Shodan clients |
| `src/netcheck/verdict/` | Turns results into result cards |
| `src/netcheck/web/` | FastAPI app, templates, static files |
| `content/` | ASN groupings, generic fix steps, per-ISP router how-tos (with sources) |
| `deploy/` | Caddyfile, systemd units, server setup and deploy scripts |

## Development

```sh
uv sync
scripts/fetch-asn-db.sh   # optional: real ASN database into data/asn/
uv run ruff check . && uv run mypy && uv run pytest
```

Tests only talk to 127.0.0.1.

## Deployment

A single Debian VPS running Caddy, the web app and the DNS server.

**DNS records** (at the registrar):

| Type | Host | Value |
|---|---|---|
| A / AAAA | root, `www` | server IPv4 / IPv6 |
| A | `v4` | server IPv4 only |
| AAAA | `v6` | server IPv6 only |
| A / AAAA | `ns1` | server IPv4 / IPv6 |
| NS | `dns` | `ns1.ismywifihacked.com` |

**First-time server setup:**

```sh
scp deploy/harden.sh deploy/lock-root-ssh.sh root@SERVER:
ssh root@SERVER bash harden.sh ADMIN
ssh ADMIN@SERVER sudo bash lock-root-ssh.sh   # only after admin login works
```

Then create `/etc/netcheck/netcheck.env` (root, mode 600) from
`deploy/netcheck.env.example`.

**Deploy:** `deploy/deploy.sh ADMIN@SERVER`

**Check the DNS server from outside:** `dig @SERVER google.com` must return `REFUSED`
with no `ra` flag.

## Operations

```sh
# logs (no access logs: they would record visitor IPs)
ssh ADMIN@SERVER sudo journalctl -u netcheck-web -u netcheck-dns

# daily result totals
ssh ADMIN@SERVER sudo -u netcheck-web /opt/netcheck/app/.venv/bin/python -m netcheck.stats

# add an API key (GREYNOISE_API_KEY or ABUSEIPDB_API_KEY): type KEY=value, Enter, Ctrl-D
ssh ADMIN@SERVER 'sudo tee -a /etc/netcheck/netcheck.env >/dev/null && sudo systemctl restart netcheck-web'
```

The GreyNoise, AbuseIPDB and Shodan free tiers are for non-commercial use. Revisit
them if the site ever makes money.

## License

MIT. See [LICENSE](LICENSE).
