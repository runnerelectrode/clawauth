# clawauth

**Cryptographic identity for AI agents.** Generate Ed25519 keys, sign agent-browser sessions, and prove who initiated every request — human or bot.

Built on [OpenBotAuth](https://github.com/OpenBotAuth/openbotauth) (RFC 9421 HTTP Message Signatures) and designed for [Vercel Agent Browser](https://github.com/vercel-labs/agent-browser) CLI.

## Why

When AI agents browse the web, websites need to know:
1. **Is this a human or a bot?** — Every signed session carries a cryptographic identity
2. **Which bot?** — Ed25519 key pairs uniquely identify each agent
3. **Who authorized it?** — Enterprise SSO binding via Okta/WorkOS/Descope

Benefits for agents:
- **Faster access** — Signed agents get residential IP treatment instead of bot blocking
- **Transparent identity** — Publishers can verify and whitelist your agent
- **Sub-agent tracking** — Derived keys maintain a cryptographic chain from parent to child
- **Session-bound keys** — Ephemeral identities tied to OpenClaw chat sessions

## Install

```bash
npm install -g clawauth
```

Requires Node.js 18+ (uses built-in `crypto` module, zero external dependencies).

## Quick Start

```bash
# 1. Generate your agent's Ed25519 key pair
clawauth init my-agent

# 2. Start a signed browser session
clawauth session https://example.com --agent my-agent

# 3. Or pipe headers directly into agent-browser
agent-browser set headers "$(clawauth headers https://example.com)"
agent-browser open https://example.com
```

## How It Works

```
┌─────────────┐     ┌──────────────┐     ┌─────────────────┐
│  clawauth   │────>│ agent-browser│────>│  Target Website  │
│  (signing)  │     │  (browsing)  │     │  (verification)  │
└─────────────┘     └──────────────┘     └─────────────────┘
      │                    │                      │
      │  Ed25519 sign      │  HTTP + signed       │  Verify via
      │  RFC 9421 headers  │  headers              │  JWKS / OBA
      └────────────────────┴──────────────────────┘
```

1. **clawauth** generates Ed25519 key pairs and signs HTTP request components per RFC 9421
2. Signed headers (`Signature`, `Signature-Input`, `X-OBA-*`) are injected into **agent-browser** via `set headers`
3. Target websites verify the signature against the agent's public key (via JWKS endpoint or OBA Registry)

## HTTP Headers

Every signed request includes:

```
Signature: sig1=:<base64-ed25519-signature>:
Signature-Input: sig1=("@method" "@authority" "@path");created=1234567890;nonce="uuid";keyid="oba-my-agent-abc12345";alg="ed25519";tag="oba-browser-session"
X-OBA-Agent-ID: oba-my-agent-abc12345
X-OBA-Session-ID: oba-session-uuid
X-OBA-Agent-Name: my-agent
X-OBA-Timestamp: 1234567890
Signature-Agent: https://registry.openbotauth.org/jwks/my-agent.json
```

## Sub-Agent Identity

For OpenClaw sub-agents or parallel scraping tasks, derive child keys:

```bash
# Derive a sub-agent key from the parent
clawauth derive scraper --agent my-agent

# Create a signed session for the sub-agent
clawauth sub-session scraper https://api.example.com --session scraper1

# The sub-agent's key ID includes the parent's identity:
#   oba-my-agent-sub-scraper-a1b2c3d4
```

Child keys are derived via HKDF-SHA256 from the parent's private key material, maintaining a verifiable chain.

## Ephemeral Session Keys

For one-time OpenClaw sessions:

```bash
# Bind a cryptographic identity to an OpenClaw session
clawauth ephemeral https://example.com --openclaw-session "agent:main:discord:channel:123"
```

Ephemeral keys are unique per session and cannot be reused.

## Enterprise SSO

Register agent identities with your organization's SSO:

```bash
# Okta
clawauth register-sso --provider okta --org org_123 --token $OKTA_TOKEN

# WorkOS
clawauth register-sso --provider workos --org org_456 --token $WORKOS_TOKEN

# Descope
clawauth register-sso --provider descope --org proj_789 --token $DESCOPE_TOKEN
```

This binds the agent's cryptographic identity to your org, enabling:
- Audit trails of which employee's agent accessed what
- Centralized key revocation
- Policy enforcement via OBA Registry

## OBA Registry

Register your public key for remote verification:

```bash
# Get a token via GitHub OAuth
# https://registry.openbotauth.org/auth/github

clawauth register my-agent --token $OBA_TOKEN
```

Once registered, verifiers resolve your public key via:
```
GET https://registry.openbotauth.org/jwks/my-agent.json
```

## OpenClaw Integration

### Setting Headers

```
# In OpenClaw's browser tool
set headers --json '{"Signature":"sig1=:...:", "Signature-Input":"...", ...}'

# Or via agent-browser CLI
agent-browser set headers '{"Signature":"sig1=:...:", ...}'
```

### Sub-Agent Sessions (agentDir)

When OpenClaw spawns sub-agents, each gets its own derived identity:

```bash
# Parent agent initializes
clawauth init main-agent

# Sub-agent "researcher" gets a derived key
clawauth derive researcher --agent main-agent

# Sub-agent's browser session is signed with its own key
clawauth sub-session researcher https://target.com \
  --openclaw-session "agent:main:subagent:abc123"
```

The auth store loads from the target agent's `agentDir`, with the main agent's profiles as fallback.

## Comparison with Kernel Web Bot Auth

| Feature | clawauth | Kernel Web Bot Auth |
|---------|----------|---------------------|
| Mechanism | CLI + agent-browser headers | Chrome extension intercept |
| Key Storage | Local `~/.openbotauth/` | Extension storage |
| Standard | RFC 9421 | RFC 9421 |
| Algorithm | Ed25519 | Ed25519 |
| Sub-agent support | HKDF key derivation | N/A |
| Enterprise SSO | Okta/WorkOS/Descope | N/A |
| Session binding | OpenClaw session IDs | Browser tabs |
| Registry | OBA Registry (JWKS) | `.well-known` directory |

## CLI Reference

```
SETUP:
  clawauth init [agent-name]              Generate Ed25519 key pair
  clawauth register [agent-name]          Register with OBA Registry
  clawauth register-sso                   Register via enterprise SSO

BROWSE:
  clawauth session <url>                  Create signed agent-browser session
  clawauth headers <url>                  Output signed headers JSON
  clawauth ephemeral <url>                Ephemeral session-bound key

SUB-AGENTS:
  clawauth derive <label>                 Derive sub-agent key
  clawauth sub-session <label> <url>      Signed sub-agent session

INFO:
  clawauth whoami [agent-name]            Show agent identity
  clawauth list                           List agents and keys
  clawauth sessions                       List active sessions
  clawauth export [agent-name]            Export public key as JWKS
```

## Key Storage

```
~/.openbotauth/
├── config.json                 # Agent configuration and registry info
├── keys/
│   ├── default.jwk             # Private key (0600)
│   ├── default.pub.jwk         # Public key (0644)
│   └── default.jwks.json       # JWKS document (0644)
└── subkeys/
    ├── default-scraper.jwk     # Sub-agent private key
    └── default-scraper.pub.jwk # Sub-agent public key
```

## Security

- Private keys are stored with `0600` permissions (owner-only read/write)
- Signatures include nonce (UUID) for replay protection
- Timestamps enable clock skew validation
- Sub-agent keys are derived, not copied — parent key never leaves `~/.openbotauth/keys/`
- Ephemeral keys are session-scoped and tracked for cleanup

## License

MIT
