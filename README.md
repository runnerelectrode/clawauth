# clawauth

**Cryptographic identity for AI agents.** Generate Ed25519 keys, sign browser sessions with RFC 9421 HTTP Message Signatures, and prove who initiated every request.

Built on [OpenBotAuth](https://github.com/OpenBotAuth/openbotauth) and designed for [Vercel Agent Browser](https://github.com/vercel-labs/agent-browser) and [OpenClaw](https://openclaw.com).

## Why

When AI agents browse the web, websites need to know:
1. **Is this a human or a bot?** — Every signed request carries a cryptographic identity
2. **Which bot?** — Ed25519 key pairs uniquely identify each agent
3. **Who authorized it?** — Enterprise SSO binding via Okta/WorkOS/Descope

Benefits for agents:
- **Faster access** — Signed agents get residential IP treatment instead of bot blocking
- **Transparent identity** — Publishers can verify and whitelist your agent
- **Per-request signatures** — Every HTTP request gets a fresh signature via the signing proxy

## Install

```bash
npm install -g clawauth
```

Requires Node.js 18+ (uses built-in `crypto` module, zero external dependencies).

## Quick Start

```bash
# 1. Generate your agent's Ed25519 key pair
clawauth init

# 2. Register with OpenBotAuth (one-time)
clawauth register my-agent --token <your-oba-token>

# 3. Start the signing proxy (signs every request automatically)
clawauth proxy --verbose

# 4. Browse through the proxy — every request gets a fresh signature
agent-browser --proxy http://127.0.0.1:8421 open https://example.com
```

## How It Works

### Signing Proxy

The signing proxy sits between agent-browser and the target website, intercepting every HTTP/HTTPS request and adding fresh RFC 9421 signatures:

```
┌──────────────┐     ┌──────────────┐     ┌─────────────────┐
│ agent-browser │────>│  clawauth    │────>│  Target Website  │
│  (browsing)   │     │  proxy       │     │  (verification)  │
└──────────────┘     └──────────────┘     └─────────────────┘
                      │                           │
                      │  Fresh Ed25519 sign       │  Verify via
                      │  on EVERY request         │  JWKS / OBA
                      └───────────────────────────┘
```

This solves the per-request signing problem — RFC 9421 signatures are bound to `@method`, `@authority`, and `@path`, so setting headers once doesn't work for sub-resources, XHRs, and redirects.

```bash
# Single-agent (default key from ~/.config/openbotauth/)
clawauth proxy [--port 8421] [--verbose]

# Multi-agent
clawauth proxy --keys-dir ./keys --default-agent tars --verbose

# Use with agent-browser
agent-browser --proxy http://127.0.0.1:8421 open https://example.com
```

For HTTPS, the proxy generates a self-signed CA on first run at `~/.config/openbotauth/ca/`. Chromium-based browsers via agent-browser handle this automatically.

### Multi-Agent Proxy

Run one proxy for multiple agents. Each agent gets its own key directory:

```
keys/
  tars/key.json + config.json
  case/key.json + config.json
  kipp/key.json + config.json
```

Select which agent signs each request via the proxy URL username:

```bash
# Start multi-agent proxy
clawauth proxy --keys-dir ./keys --default-agent tars

# Default agent (tars)
HTTP_PROXY=http://127.0.0.1:8421 curl https://example.com

# Specific agent
HTTP_PROXY=http://case@127.0.0.1:8421 curl https://example.com
HTTP_PROXY=http://kipp@127.0.0.1:8421 curl https://example.com
```

Agent selection uses standard proxy authentication — the username from `http://username@host:port` maps to a key directory.

### Single-URL Signing

For simple cases where you only need to sign one page load:

```bash
# Output signed headers JSON
clawauth sign GET https://example.com

# Create a signed agent-browser session
clawauth session https://example.com
```

## OpenClaw Plugin

clawauth includes an OpenClaw gateway plugin that gives agents a `signed_fetch` tool for making signed HTTP requests.

### Installation

1. Place or symlink the clawauth directory in `~/.openclaw/extensions/clawauth/`
2. Enable in `openclaw.json`:
   ```json
   { "plugins": { "entries": { "clawauth": { "enabled": true } } } }
   ```
3. Add `signed_fetch` to your allowed tools list if using a sandbox
4. Restart the gateway

### Agent Setup

Each agent's workspace needs a `clawauth/` directory with its keys:

```
workspace/
  clawauth/
    key.json      # Ed25519 keypair (from clawauth init)
    config.json   # agent_id, jwksUrl (from clawauth register)
```

The plugin auto-loads keys per agent and provides a `signed_fetch` tool that signs every outbound request with RFC 9421 signatures. It also logs when agents use unsigned `web_fetch` while a signing key is available.

## HTTP Headers

Every signed request includes:

| Header | Purpose |
|--------|---------|
| `Signature` | `sig1=:<base64-ed25519-signature>:` |
| `Signature-Input` | Covered components `(@method @authority @path)`, `created`, `expires`, `nonce`, `keyid`, `alg` |
| `Signature-Agent` | JWKS URL for public key resolution (from OBA Registry) |

Signatures expire after 5 minutes and include a UUID nonce for replay protection.

## Security

- **No shell injection** — All subprocess calls use `execFileSync` (no shell interpolation)
- **SSRF protection** — DNS resolve-first with private/reserved IP blocking (127.x, 10.x, 172.16-31.x, 192.168.x, 169.254.x, ::1, fc00::, fe80::, link-local, multicast)
- **Hostname validation** — Regex + `isIP` check, rejects non-FQDN targets
- **Path traversal prevention** — Agent names validated against `/^[a-zA-Z0-9._-]+$/`, cert filenames use SHA-256 hashes
- **Buffer caps** — 64KB max header size to prevent memory exhaustion
- **Connection timeouts** — 2-minute timeout on HTTPS tunnels
- **Private keys** stored with `0600` permissions (owner-only read/write)
- HTTPS MITM proxy uses per-domain certificates signed by a local CA
- Never sends private keys or OBA tokens to any domain other than `api.openbotauth.org`

## CLI Reference

```
SETUP:
  clawauth init                             Generate Ed25519 key pair
  clawauth register [agent-name]            Register with OBA Registry
  clawauth register-sso                     Register via enterprise SSO

SIGN & BROWSE:
  clawauth proxy                            Start signing proxy (signs every request)
  clawauth sign <METHOD> <URL>              Output signed headers JSON
  clawauth session <URL>                    Signed agent-browser session (single URL)

INFO:
  clawauth whoami                           Show current identity
  clawauth export                           Export public key as JWKS

PROXY FLAGS:
  --port <port>                             Proxy port (default: 8421)
  --bind <address>                          Bind address (default: 127.0.0.1)
  --keys-dir <path>                         Multi-agent keys directory
  --default-agent <name>                    Default agent when no proxy auth
  --verbose, -v                             Verbose logging

OTHER FLAGS:
  --token <token>                           OBA Registry auth token
  --jwks <url>                              JWKS URL for Signature-Agent
  --session, -s <name>                      agent-browser session name
  --method <METHOD>                         HTTP method (default: GET)
  --format <jwk|jwks>                       Export format (default: jwks)

ENVIRONMENT:
  OBA_TOKEN                                 Registry auth token
  OBA_SSO_TOKEN                             SSO auth token
```

## Key Storage

```
~/.config/openbotauth/
├── key.json         # kid, x, publicKeyPem, privateKeyPem (chmod 600)
├── key.pub.json     # Public JWK for sharing (chmod 644)
├── config.json      # Agent ID, JWKS URL, registration info
├── token            # OBA bearer token (chmod 600)
└── ca/              # Proxy CA certificate (auto-generated)
    ├── ca.key       # CA private key
    └── ca.crt       # CA certificate
```

## License

MIT
