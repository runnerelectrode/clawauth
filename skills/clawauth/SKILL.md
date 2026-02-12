# clawauth

Cryptographic identity for AI agents using OpenBotAuth. Signs agent-browser sessions with Ed25519 keys and RFC 9421 HTTP Message Signatures.

## When to trigger

User wants to: browse websites with cryptographic identity, authenticate an agent-browser session, set up bot auth, generate agent keys, sign HTTP requests, create signed browser sessions, identify bot vs human sessions, set up OpenBotAuth, manage sub-agent identities, register with OBA, set up enterprise SSO for agents.

## Tools

Bash(clawauth:*, agent-browser:*)

## Instructions

You help users set up and use cryptographic identity for their AI agent browser sessions using OpenBotAuth (OBA) with Ed25519 signing.

### Core Workflow

1. **Initialize identity** (one-time setup):
```bash
clawauth init <agent-name>
```
This generates an Ed25519 key pair stored at `~/.openbotauth/keys/`.

2. **Start a signed browser session**:
```bash
# Option A: Full session setup (generates headers + prints agent-browser commands)
clawauth session <url> --agent <agent-name>

# Option B: Pipe headers directly into agent-browser
agent-browser set headers "$(clawauth headers <url>)"
agent-browser open <url>
```

3. **Register with OBA Registry** (optional, enables remote verification):
```bash
clawauth register <agent-name> --token <github-oauth-token>
```

### Signed Headers

Every signed session injects these RFC 9421 headers into agent-browser:

| Header | Purpose |
|--------|---------|
| `Signature` | RFC 9421 Ed25519 signature over request components |
| `Signature-Input` | Covered components, timestamp, keyid, algorithm |
| `X-OBA-Agent-ID` | Agent's key identifier |
| `X-OBA-Session-ID` | Unique session identifier |
| `X-OBA-Agent-Name` | Human-readable agent name |
| `X-OBA-Timestamp` | Signature creation time |
| `Signature-Agent` | JWKS URL for key resolution (if registered) |

### Sub-Agent Identity

For OpenClaw sub-agents, derive child keys from the parent:

```bash
# Derive a sub-agent key
clawauth derive scraper --agent main-agent

# Create a signed session for the sub-agent
clawauth sub-session scraper https://target.com --session scraper1
```

Sub-agent keys are derived using HKDF from the parent's key material, creating a cryptographic link between parent and child identities.

### Ephemeral Session Keys

For one-time sessions (OpenClaw ephemeral bots):

```bash
clawauth ephemeral <url> --openclaw-session <session-id>
```

This generates a session-bound key pair that is cryptographically linked to the parent agent but unique to the session.

### Enterprise SSO Registration

For organizations using Okta, WorkOS, or Descope:

```bash
clawauth register-sso --provider okta --org <org-id> --token <sso-token> --agent <agent-name>
```

This registers the agent's public key with the OBA Registry bound to the organization's SSO identity, enabling enterprise-grade bot identity verification.

### OpenClaw Integration

When running inside OpenClaw, use the session ID from OpenClaw's session context:

```bash
# The OpenClaw session ID binds the cryptographic identity to the chat session
clawauth session <url> --openclaw-session "agent:main:discord:channel:123456"

# For sub-agents spawned via sessions_spawn
clawauth sub-session <sub-label> <url> --openclaw-session "agent:main:subagent:<uuid>"
```

Headers are set via `agent-browser set headers` or OpenClaw's `set headers --json` command.

### Key Management Commands

```bash
clawauth whoami              # Show current agent identity
clawauth list                # List all agents, sub-agents, and keys
clawauth sessions            # List active signed sessions
clawauth export <agent-name> # Export public key as JWKS (for self-hosting)
```

### Important Notes

- Private keys are stored at `~/.openbotauth/keys/` with 0600 permissions — never expose them
- Always re-sign headers when the target URL changes (signatures are URL-bound)
- Ephemeral keys are session-scoped and should not be reused
- For parallel agent-browser sessions, use the `--session` flag to isolate each session
- Sub-agent keys maintain a cryptographic chain to the parent for audit purposes
- The `headers` command outputs raw JSON suitable for piping: `agent-browser set headers "$(clawauth headers <url>)"`

### Verification (Server-Side)

Publishers can verify signed requests using the OBA Verifier:

```bash
# The Signature and Signature-Input headers are verified against
# the public key at the JWKS URL in the keyid parameter.
# Response headers indicate the decision:
#   X-OBA-Decision: allow|deny|teaser
#   X-OBA-Agent-ID: <agent-identity>
```

### Typical Full Flow

```bash
# 1. One-time setup
clawauth init my-agent
clawauth register my-agent --token $OBA_TOKEN

# 2. Start authenticated browsing
clawauth session https://example.com --agent my-agent --session browse1

# 3. The output tells you to run:
#    agent-browser --session browse1 set headers '{"Signature":"sig1=:...:","Signature-Input":"...","X-OBA-Agent-ID":"...", ...}'
#    agent-browser --session browse1 open https://example.com

# 4. For sub-agents
clawauth derive data-collector --agent my-agent
clawauth sub-session data-collector https://api.example.com --session collector1

# 5. Check identity
clawauth whoami my-agent
```
