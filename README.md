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

### Signing Proxy (Recommended)

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
# Start proxy
clawauth proxy [--port 8421] [--verbose]

# Use with agent-browser
agent-browser --proxy http://127.0.0.1:8421 open https://example.com
```

For HTTPS, the proxy generates a self-signed CA on first run at `~/.config/openbotauth/ca/`. Chromium-based browsers via agent-browser handle this automatically.

### Single-URL Signing

For simple cases where you only need to sign one page load:

```bash
# Output signed headers JSON
clawauth sign GET https://example.com

# Create a signed agent-browser session
clawauth session https://example.com
```

## HTTP Headers

Every signed request includes:

| Header | Purpose |
|--------|---------|
| `Signature` | `sig1=:<base64-ed25519-signature>:` |
| `Signature-Input` | Covered components `(@method @authority @path)`, `created`, `expires`, `nonce`, `keyid`, `alg` |
| `Signature-Agent` | JWKS URL for public key resolution (from OBA Registry) |

Example:
```
Signature: sig1=:MEUCIQDx...=:
Signature-Input: sig1=("@method" "@authority" "@path");created=1234567890;expires=1234568190;nonce="uuid";keyid="abc123";alg="ed25519"
Signature-Agent: https://api.openbotauth.org/agent-jwks/your-agent-id
```

Signatures expire after 5 minutes and include a UUID nonce for replay protection.

## OBA Registration

Register your public key for remote verification:

```bash
# 1. Get a token at https://openbotauth.org/token (GitHub OAuth)
# 2. Register
clawauth register my-agent --token <your-oba-token>

# 3. Verify your JWKS endpoint
curl https://api.openbotauth.org/agent-jwks/<your-agent-id>
```

The JWKS URL is automatically included as the `Signature-Agent` header in all signed requests.

## Enterprise SSO

Register agent identities with your organization's SSO:

```bash
clawauth register-sso --provider okta --org org_123 --token $OBA_SSO_TOKEN
clawauth register-sso --provider workos --org org_456 --token $WORKOS_TOKEN
clawauth register-sso --provider descope --org proj_789 --token $DESCOPE_TOKEN
```

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

FLAGS:
  --token <token>                           OBA Registry auth token
  --jwks <url>                              JWKS URL for Signature-Agent
  --session, -s <name>                      agent-browser session name
  --method <METHOD>                         HTTP method (default: GET)
  --port <port>                             Proxy port (default: 8421)
  --verbose, -v                             Verbose logging
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

## Security

- Private keys stored with `0600` permissions (owner-only read/write)
- Signatures include nonce (UUID) for replay protection
- 5-minute expiration window on all signatures
- HTTPS MITM proxy uses per-domain certificates signed by a local CA
- Never send private keys or OBA tokens to any domain other than `api.openbotauth.org`

## License

MIT
