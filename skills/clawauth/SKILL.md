# clawauth

Cryptographic identity for AI agent browser sessions. Signs HTTP requests with Ed25519 keys using RFC 9421 Message Signatures via OpenBotAuth.

## When to trigger

User wants to: browse websites with signed identity, authenticate a browser session, sign HTTP requests as a bot, set up OpenBotAuth headers, prove human-vs-bot session origin, manage agent keys, sign scraping sessions, create sub-agent identities, register with OBA registry, set up enterprise SSO for agents.

## Tools

Bash

## Instructions

You help users cryptographically sign their browser sessions using OpenBotAuth (OBA) with Ed25519. This skill is **self-contained** — it uses inline Node.js (v18+) for all crypto operations. No external CLI tools are required.

### Key Storage

Keys are stored at `~/.config/openbotauth/key.json` (JWK format). If this file already exists, use it. If not, generate a new key pair.

### 1. Check for existing identity

```bash
cat ~/.config/openbotauth/key.json 2>/dev/null && echo "Key exists" || echo "No key found"
```

If a key exists, read it and extract the `kid` (Key ID) and public key `x` parameter. Skip to step 3.

### 2. Generate Ed25519 key pair (if no key exists)

```bash
node -e "
const { generateKeyPairSync, randomUUID } = require('crypto');
const { writeFileSync, mkdirSync } = require('fs');
const { join } = require('path');
const { homedir } = require('os');

const dir = join(homedir(), '.config', 'openbotauth');
mkdirSync(dir, { recursive: true });

const kid = 'oba-agent-' + randomUUID().slice(0, 8);
const { publicKey, privateKey } = generateKeyPairSync('ed25519');

const priv = privateKey.export({ format: 'jwk' });
const pub = publicKey.export({ format: 'jwk' });
priv.kid = kid; priv.use = 'sig'; priv.alg = 'EdDSA';
pub.kid = kid; pub.use = 'sig'; pub.alg = 'EdDSA';

writeFileSync(join(dir, 'key.json'), JSON.stringify(priv, null, 2), { mode: 0o600 });
writeFileSync(join(dir, 'key.pub.json'), JSON.stringify(pub, null, 2), { mode: 0o644 });
writeFileSync(join(dir, 'jwks.json'), JSON.stringify({ keys: [pub] }, null, 2), { mode: 0o644 });

console.log('Key ID: ' + kid);
console.log('Private: ' + join(dir, 'key.json'));
console.log('Public:  ' + join(dir, 'key.pub.json'));
console.log('JWKS:    ' + join(dir, 'jwks.json'));
"
```

### 3. Sign a browser session and generate headers

Given a target URL, generate RFC 9421 signed headers. This produces a JSON object that can be passed directly to OpenClaw's `set headers --json` or agent-browser's `set headers`.

```bash
node -e "
const { createPrivateKey, sign, randomUUID } = require('crypto');
const { readFileSync } = require('fs');
const { join } = require('path');
const { homedir } = require('os');

const TARGET_URL = process.argv[1];
const SESSION_ID = process.argv[2] || 'oba-session-' + randomUUID();

const jwk = JSON.parse(readFileSync(join(homedir(), '.config', 'openbotauth', 'key.json'), 'utf-8'));
const url = new URL(TARGET_URL);
const created = Math.floor(Date.now() / 1000);
const nonce = randomUUID();

// RFC 9421 signature base
const components = ['@method', '@authority', '@path'];
const lines = [
  '\"@method\": GET',
  '\"@authority\": ' + url.host,
  '\"@path\": ' + url.pathname
];
const sigInput = '(' + components.map(c => '\"' + c + '\"').join(' ') + ');created=' + created + ';nonce=\"' + nonce + '\";keyid=\"' + jwk.kid + '\";alg=\"ed25519\";tag=\"oba-browser-session\"';
lines.push('\"@signature-params\": ' + sigInput);

const base = lines.join('\n');
const pk = createPrivateKey({ key: jwk, format: 'jwk' });
const sig = sign(null, Buffer.from(base), pk).toString('base64');

const headers = {
  'Signature': 'sig1=:' + sig + ':',
  'Signature-Input': 'sig1=' + sigInput,
  'X-OBA-Agent-ID': jwk.kid,
  'X-OBA-Session-ID': SESSION_ID,
  'X-OBA-Timestamp': String(created)
};

console.log(JSON.stringify(headers));
" "TARGET_URL_HERE" "OPTIONAL_SESSION_ID_HERE"
```

Replace `TARGET_URL_HERE` with the actual URL. The output is a JSON object ready for use.

### 4. Apply headers to browser session

**OpenClaw browser:**
```
set headers --json '<OUTPUT_FROM_STEP_3>'
```

**agent-browser CLI (if installed):**
```bash
agent-browser set headers '<OUTPUT_FROM_STEP_3>'
agent-browser open <url>
```

**With named session:**
```bash
agent-browser --session myagent set headers '<OUTPUT_FROM_STEP_3>'
agent-browser --session myagent open <url>
```

### 5. Derive a sub-agent key

For OpenClaw sub-agents (spawned via `sessions_spawn`), derive a child key from the parent. The child key is cryptographically linked to the parent via HKDF-SHA256.

```bash
node -e "
const { generateKeyPairSync, hkdfSync, randomUUID } = require('crypto');
const { readFileSync, writeFileSync, mkdirSync } = require('fs');
const { join } = require('path');
const { homedir } = require('os');

const SUB_LABEL = process.argv[1];
const SESSION_ID = process.argv[2] || '';

const dir = join(homedir(), '.config', 'openbotauth', 'subkeys');
mkdirSync(dir, { recursive: true });

const parentJwk = JSON.parse(readFileSync(join(homedir(), '.config', 'openbotauth', 'key.json'), 'utf-8'));
const ikm = Buffer.from(parentJwk.d, 'base64url');
const info = SESSION_ID ? 'oba-subagent:' + SUB_LABEL + ':' + SESSION_ID : 'oba-subagent:' + SUB_LABEL;
const seed = hkdfSync('sha256', ikm, Buffer.from('openbotauth-derive-v1'), info, 32);

const { publicKey, privateKey } = generateKeyPairSync('ed25519');
const kid = 'oba-sub-' + SUB_LABEL + '-' + Buffer.from(seed).toString('hex').slice(0, 8);

const priv = privateKey.export({ format: 'jwk' });
const pub = publicKey.export({ format: 'jwk' });
priv.kid = kid; priv.use = 'sig'; priv.alg = 'EdDSA';
pub.kid = kid; pub.use = 'sig'; pub.alg = 'EdDSA';

writeFileSync(join(dir, SUB_LABEL + '.jwk'), JSON.stringify(priv, null, 2), { mode: 0o600 });
writeFileSync(join(dir, SUB_LABEL + '.pub.jwk'), JSON.stringify(pub, null, 2), { mode: 0o644 });

console.log('Sub-agent key derived:');
console.log('  Kid:    ' + kid);
console.log('  Parent: ' + parentJwk.kid);
console.log('  File:   ' + join(dir, SUB_LABEL + '.jwk'));
" "SUB_AGENT_LABEL" "OPTIONAL_SESSION_ID"
```

Then sign a session with the sub-agent key by reading from `~/.config/openbotauth/subkeys/<label>.jwk` instead of the parent key in Step 3.

### 6. Register with OBA Registry (optional)

Register the public key for remote verification by publishers:

```bash
node -e "
const { readFileSync } = require('fs');
const { join } = require('path');
const { homedir } = require('os');

const TOKEN = process.argv[1];
const REGISTRY = process.argv[2] || 'https://registry.openbotauth.org';

const pub = JSON.parse(readFileSync(join(homedir(), '.config', 'openbotauth', 'key.pub.json'), 'utf-8'));

fetch(REGISTRY + '/api/keys', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + TOKEN },
  body: JSON.stringify({ key: pub, metadata: { tool: 'clawauth', platform: 'openclaw' } })
})
.then(r => r.json())
.then(d => console.log(JSON.stringify(d, null, 2)))
.catch(e => console.error('Failed:', e.message));
" "YOUR_OBA_TOKEN"
```

Get a token via GitHub OAuth at: https://registry.openbotauth.org/auth/github

### 7. Enterprise SSO (Okta / WorkOS / Descope)

For organizations, bind the agent key to an SSO identity:

```bash
node -e "
const { readFileSync } = require('fs');
const { join } = require('path');
const { homedir } = require('os');

const PROVIDER = process.argv[1]; // okta, workos, or descope
const ORG_ID = process.argv[2];
const TOKEN = process.argv[3];
const REGISTRY = process.argv[4] || 'https://registry.openbotauth.org';

const pub = JSON.parse(readFileSync(join(homedir(), '.config', 'openbotauth', 'key.pub.json'), 'utf-8'));

fetch(REGISTRY + '/api/enterprise/keys', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer ' + TOKEN,
    'X-SSO-Provider': PROVIDER,
    'X-Org-ID': ORG_ID
  },
  body: JSON.stringify({ key: pub, sso: { provider: PROVIDER, orgId: ORG_ID }, metadata: { tool: 'clawauth', platform: 'openclaw' } })
})
.then(r => r.json())
.then(d => console.log(JSON.stringify(d, null, 2)))
.catch(e => console.error('Failed:', e.message));
" "PROVIDER" "ORG_ID" "SSO_TOKEN"
```

### 8. Show current identity

```bash
node -e "
const { readFileSync, existsSync } = require('fs');
const { join } = require('path');
const { homedir } = require('os');
const f = join(homedir(), '.config', 'openbotauth', 'key.pub.json');
if (!existsSync(f)) { console.log('No identity found. Generate one first.'); process.exit(0); }
const k = JSON.parse(readFileSync(f, 'utf-8'));
console.log('Agent ID:  ' + k.kid);
console.log('Algorithm: ' + k.alg);
console.log('Public Key (x): ' + k.x);
"
```

### Signed Headers Reference

Every signed session produces these RFC 9421-compliant headers:

| Header | Purpose |
|--------|---------|
| `Signature` | `sig1=:<base64-ed25519-signature>:` |
| `Signature-Input` | Covered components `(@method @authority @path)`, created timestamp, nonce, keyid, alg |
| `X-OBA-Agent-ID` | Agent's key ID — identifies who initiated the session |
| `X-OBA-Session-ID` | Unique per-session ID — tracks individual sessions |
| `X-OBA-Timestamp` | Unix timestamp of signature creation |
| `Signature-Agent` | JWKS URL for key resolution (when registered with OBA Registry) |

### OpenClaw Session Binding

When running inside OpenClaw, pass the current session key as the session ID to bind the cryptographic identity to the chat:

```
agent:main:main                              # Main chat session
agent:main:discord:channel:123456789         # Discord channel
agent:main:subagent:<uuid>                   # Spawned sub-agent
```

This allows publishers to verify whether a request came from the main agent or a sub-agent, and trace it back to the originating session.

### Important Notes

- Private keys live at `~/.config/openbotauth/key.json` with 0600 permissions — never expose them
- Re-sign headers when the target URL changes (signatures are URL-bound)
- Sub-agent keys at `~/.config/openbotauth/subkeys/` maintain a cryptographic chain to the parent
- For parallel sessions, use separate session IDs to isolate each one
- All crypto uses Node.js built-in `crypto` module — no npm dependencies required
