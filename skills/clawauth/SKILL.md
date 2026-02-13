# clawauth

Cryptographic identity for AI agent browser sessions. Signs HTTP requests with Ed25519 keys using RFC 9421 Message Signatures via OpenBotAuth.

## When to trigger

User wants to: browse websites with signed identity, authenticate a browser session, sign HTTP requests as a bot, set up OpenBotAuth headers, prove human-vs-bot session origin, manage agent keys, sign scraping sessions, register with OBA registry, set up enterprise SSO for agents.

## Tools

Bash

## Instructions

You help users cryptographically sign their browser sessions using OpenBotAuth (OBA) with Ed25519. This skill is **self-contained** — it uses inline Node.js (v18+) for all crypto operations. No external CLI tools are required.

### Key Storage

Keys are stored at `~/.config/openbotauth/key.json` in **OBA's canonical format**:

```json
{
  "kid": "<thumbprint-based-id>",
  "x": "<base64url-raw-public-key>",
  "publicKeyPem": "-----BEGIN PUBLIC KEY-----\n...",
  "privateKeyPem": "-----BEGIN PRIVATE KEY-----\n...",
  "createdAt": "..."
}
```

The OBA token lives at `~/.config/openbotauth/token` (chmod 600).

Agent registration info (agent_id, JWKS URL) should be saved in agent memory/notes after Step 3.

---

### Step 1: Check for existing identity

```bash
cat ~/.config/openbotauth/key.json 2>/dev/null && echo "---KEY EXISTS---" || echo "---NO KEY FOUND---"
```

**If a key exists:** read it to extract `kid`, `x`, and `privateKeyPem`. Check if the agent is already registered (look for agent_id in memory/notes). If registered, skip to Step 4 (signing).

**If no key exists:** proceed to Step 2.

---

### Step 2: Generate Ed25519 keypair (if no key exists)

Run this locally. Nothing leaves the machine.

```bash
node -e "
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();

// Derive kid from JWK thumbprint (matches OBA's format)
const spki = publicKey.export({ type: 'spki', format: 'der' });
if (spki.length !== 44) throw new Error('Unexpected SPKI length: ' + spki.length);
const rawPub = spki.subarray(12, 44);
const x = rawPub.toString('base64url');
const thumbprint = JSON.stringify({ kty: 'OKP', crv: 'Ed25519', x });
const hash = crypto.createHash('sha256').update(thumbprint).digest();
const kid = hash.toString('base64url').slice(0, 16);

const dir = path.join(os.homedir(), '.config', 'openbotauth');
fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
fs.writeFileSync(path.join(dir, 'key.json'), JSON.stringify({
  kid, x, publicKeyPem, privateKeyPem,
  createdAt: new Date().toISOString()
}, null, 2), { mode: 0o600 });

console.log('Key generated!');
console.log('kid:', kid);
console.log('x:', x);
"
```

Save the `kid` and `x` values — needed for registration.

---

### Step 3: Register with OpenBotAuth (if not yet registered)

This is a **one-time setup** that gives your agent a public JWKS endpoint for signature verification.

#### 3a. Get a token from the user

Ask the user:

> I need an OpenBotAuth token to register my cryptographic identity. Takes 30 seconds:
>
> 1. Go to **https://openbotauth.org/token**
> 2. Click "Login with GitHub"
> 3. Copy the token and paste it back to me
>
> The token looks like `oba_` followed by 64 hex characters.

When they provide it, save it:

```bash
node -e "
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const dir = path.join(os.homedir(), '.config', 'openbotauth');
fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
const token = process.argv[1].trim();
fs.writeFileSync(path.join(dir, 'token'), token, { mode: 0o600 });
console.log('Token saved.');
" "THE_TOKEN_HERE"
```

#### 3b. Register the agent

```bash
node -e "
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

const dir = path.join(os.homedir(), '.config', 'openbotauth');
const key = JSON.parse(fs.readFileSync(path.join(dir, 'key.json'), 'utf-8'));
const token = fs.readFileSync(path.join(dir, 'token'), 'utf-8').trim();

const AGENT_NAME = process.argv[1] || 'my-agent';
const API = 'https://api.openbotauth.org';

fetch(API + '/agents', {
  method: 'POST',
  headers: {
    'Authorization': 'Bearer ' + token,
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    name: AGENT_NAME,
    agent_type: 'agent',
    public_key: {
      kty: 'OKP',
      crv: 'Ed25519',
      kid: key.kid,
      x: key.x,
      use: 'sig',
      alg: 'EdDSA'
    }
  })
})
.then(r => r.json())
.then(d => {
  console.log('Agent registered!');
  console.log('Agent ID:', d.id);
  console.log('JWKS URL:', API + '/agent-jwks/' + d.id);
  console.log('');
  console.log('Save this to memory:');
  console.log(JSON.stringify({
    openbotauth: {
      agent_id: d.id,
      kid: key.kid,
      owner_url: API + '/agent-jwks/' + d.id
    }
  }, null, 2));
})
.catch(e => console.error('Registration failed:', e.message));
" "AGENT_NAME_HERE"
```

#### 3c. Verify registration

```bash
curl https://api.openbotauth.org/agent-jwks/YOUR_AGENT_ID
```

You should see your public key in the `keys` array. This is the URL that verifiers will use to check your signatures.

**Save the agent_id and JWKS URL to memory/notes** — you'll need the JWKS URL for the `Signature-Agent` header in every signed request.

---

### Step 4: Sign a browser session

Generate RFC 9421 signed headers for a target URL. The output is a JSON object for `set headers --json` (OpenClaw) or `agent-browser set headers`.

**Required inputs:**
- `TARGET_URL` — the URL being browsed
- `METHOD` — HTTP method (GET, POST, etc.)
- `JWKS_URL` — your JWKS endpoint from Step 3 (the `Signature-Agent` value)

```bash
node -e "
const { createPrivateKey, sign, randomUUID } = require('crypto');
const { readFileSync } = require('fs');
const { join } = require('path');
const { homedir } = require('os');

const METHOD = (process.argv[1] || 'GET').toUpperCase();
const TARGET_URL = process.argv[2];
const JWKS_URL = process.argv[3] || '';
const SESSION_ID = process.argv[4] || 'oba-session-' + randomUUID();

if (!TARGET_URL) { console.error('Usage: node sign.js METHOD URL JWKS_URL [SESSION_ID]'); process.exit(1); }

const key = JSON.parse(readFileSync(join(homedir(), '.config', 'openbotauth', 'key.json'), 'utf-8'));
const url = new URL(TARGET_URL);
const created = Math.floor(Date.now() / 1000);
const expires = created + 300;
const nonce = randomUUID();

// RFC 9421 signature base
const lines = [
  '\"@method\": ' + METHOD,
  '\"@authority\": ' + url.host,
  '\"@path\": ' + url.pathname + url.search
];
const sigInput = '(\"@method\" \"@authority\" \"@path\");created=' + created + ';expires=' + expires + ';nonce=\"' + nonce + '\";keyid=\"' + key.kid + '\";alg=\"ed25519\"';
lines.push('\"@signature-params\": ' + sigInput);

const base = lines.join('\n');
const pk = createPrivateKey(key.privateKeyPem);
const sig = sign(null, Buffer.from(base), pk).toString('base64');

const headers = {
  'Signature': 'sig1=:' + sig + ':',
  'Signature-Input': 'sig1=' + sigInput
};
if (JWKS_URL) {
  headers['Signature-Agent'] = JWKS_URL;
}

console.log(JSON.stringify(headers));
" "METHOD" "TARGET_URL" "JWKS_URL" "OPTIONAL_SESSION_ID"
```

Replace the arguments:
- `METHOD` — e.g., `GET`
- `TARGET_URL` — e.g., `https://example.com/page`
- `JWKS_URL` — e.g., `https://api.openbotauth.org/agent-jwks/your-agent-id`

### Step 5: Apply headers to browser session

**OpenClaw browser:**
```
set headers --json '<OUTPUT_FROM_STEP_4>'
```

**agent-browser CLI (if installed):**
```bash
agent-browser set headers '<OUTPUT_FROM_STEP_4>'
agent-browser open <url>
```

**With named session:**
```bash
agent-browser --session myagent set headers '<OUTPUT_FROM_STEP_4>'
agent-browser --session myagent open <url>
```

**Important: re-sign before each navigation.** Because RFC 9421 signatures are bound to `@method`, `@authority`, and `@path`, you must regenerate headers (Step 4) before navigating to a different URL.

---

### Step 6: Show current identity

```bash
node -e "
const { readFileSync, existsSync } = require('fs');
const { join } = require('path');
const { homedir } = require('os');
const f = join(homedir(), '.config', 'openbotauth', 'key.json');
if (!existsSync(f)) { console.log('No identity found. Run Step 2 first.'); process.exit(0); }
const k = JSON.parse(readFileSync(f, 'utf-8'));
console.log('kid:        ' + k.kid);
console.log('Public (x): ' + k.x);
console.log('Created:    ' + k.createdAt);
"
```

---

### Enterprise SSO Registration (Okta / WorkOS / Descope)

For organizations that want to bind agent identities to their SSO:

```bash
node -e "
const { readFileSync } = require('fs');
const { join } = require('path');
const { homedir } = require('os');

const PROVIDER = process.argv[1];
const ORG_ID = process.argv[2];
const TOKEN = process.argv[3];
const API = process.argv[4] || 'https://api.openbotauth.org';

const key = JSON.parse(readFileSync(join(homedir(), '.config', 'openbotauth', 'key.json'), 'utf-8'));

fetch(API + '/enterprise/keys', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer ' + TOKEN,
    'X-SSO-Provider': PROVIDER,
    'X-Org-ID': ORG_ID
  },
  body: JSON.stringify({
    key: { kty: 'OKP', crv: 'Ed25519', kid: key.kid, x: key.x, use: 'sig', alg: 'EdDSA' },
    sso: { provider: PROVIDER, orgId: ORG_ID },
    metadata: { tool: 'clawauth', platform: 'openclaw' }
  })
})
.then(r => r.json())
.then(d => console.log(JSON.stringify(d, null, 2)))
.catch(e => console.error('Failed:', e.message));
" "PROVIDER" "ORG_ID" "SSO_TOKEN"
```

Supported providers: `okta`, `workos`, `descope`.

---

### Signed Headers Reference

Every signed request produces these RFC 9421-compliant headers:

| Header | Purpose |
|--------|---------|
| `Signature` | `sig1=:<base64-ed25519-signature>:` |
| `Signature-Input` | Covered components `(@method @authority @path)`, `created`, `expires`, `nonce`, `keyid`, `alg` |
| `Signature-Agent` | JWKS URL for public key resolution (from OBA Registry) |

The `Signature-Input` encodes everything a verifier needs: which components were signed, when, by whom (keyid), and when it expires.

### OpenClaw Session Binding

When running inside OpenClaw, you can include the session key in the nonce or as a custom parameter to bind the signature to the originating chat:

```
agent:main:main                              # Main chat session
agent:main:discord:channel:123456789         # Discord channel
agent:main:subagent:<uuid>                   # Spawned sub-agent
```

This lets publishers trace whether a request came from the main agent or a sub-agent.

---

### Sub-Agent Identity (Tier 2 — TBD)

Sub-agent key derivation (HKDF from parent key) is planned but not yet implemented in a cryptographically sound way. For now, sub-agents should:

1. Generate their own independent keypair (Step 2)
2. Register separately with OBA (Step 3)
3. Optionally, the parent agent can publish a signed attestation linking the sub-agent's kid to its own

A proper delegation/attestation protocol is being designed.

---

### Per-Request Signing via Proxy (Recommended for Real Browsing)

RFC 9421 signatures are **per-request** — they are bound to the specific method, authority, and path. Setting headers once (Steps 4-5) only works for the initial page load. Sub-resources, XHRs, and redirects will carry stale signatures and get blocked.

**Solution: Use the clawauth signing proxy.** It intercepts every HTTP/HTTPS request and adds a fresh signature automatically.

```bash
# Install clawauth if not already installed
npm install -g clawauth

# Ensure you have a key (Step 2) and are registered (Step 3)

# Start the signing proxy
clawauth proxy --verbose

# In another terminal, browse through the proxy
agent-browser --proxy http://127.0.0.1:8421 open https://example.com
```

The proxy:
- Signs **every** outgoing request with a fresh RFC 9421 signature
- Handles both HTTP and HTTPS (generates a local CA for HTTPS MITM)
- Includes the `Signature-Agent` header (JWKS URL) on every request
- Runs on `127.0.0.1:8421` by default (configurable with `--port`)

**OpenClaw usage:**
```
# If clawauth CLI is available in the environment:
# 1. Start proxy in background
# 2. Use agent-browser with --proxy flag
```

**When to use Steps 4-5 instead:** Simple single-page-load scenarios where you control every navigation and can re-sign before each one.

---

### Important Notes

- Private keys live at `~/.config/openbotauth/key.json` with 0600 permissions — never expose them
- The OBA token at `~/.config/openbotauth/token` is also sensitive — never log or share it
- `Signature-Agent` must point to a publicly reachable JWKS URL for verification to work
- All crypto uses Node.js built-in `crypto` module — no npm dependencies required
- **Security:** Never send private keys or OBA tokens to any domain other than `api.openbotauth.org`

---

### File Layout

```
~/.config/openbotauth/
├── key.json       # kid, x, publicKeyPem, privateKeyPem (chmod 600)
├── key.pub.json   # Public JWK for sharing (chmod 644)
├── config.json    # Agent ID, JWKS URL, registration info
├── token          # oba_xxx bearer token (chmod 600)
└── ca/            # Proxy CA certificate (auto-generated)
    ├── ca.key     # CA private key
    └── ca.crt     # CA certificate
```

### Links

- **Website:** https://openbotauth.org
- **API:** https://api.openbotauth.org
- **Spec:** https://github.com/OpenBotAuth/openbotauth
- **IETF:** Web Bot Auth Architecture draft
