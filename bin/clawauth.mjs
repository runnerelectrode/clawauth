#!/usr/bin/env node

/**
 * clawauth CLI
 *
 * Cryptographic identity for AI agents using OpenBotAuth.
 * Integrates Ed25519 signing with agent-browser sessions.
 *
 * Usage:
 *   clawauth init                         Generate Ed25519 key pair
 *   clawauth register [agent-name]        Register with OBA Registry
 *   clawauth register-sso                 Register via enterprise SSO
 *   clawauth sign <method> <url>          Sign a request and output headers
 *   clawauth session <url>                Create a signed agent-browser session
 *   clawauth whoami                       Show current agent identity
 *   clawauth export                       Export public key as JWK
 */

import { randomUUID } from "node:crypto";

const args = process.argv.slice(2);
const command = args[0];

const OBA_API = "https://api.openbotauth.org";

async function main() {
  switch (command) {
    case "init":
      await cmdInit();
      break;
    case "register":
      await cmdRegister();
      break;
    case "register-sso":
      await cmdRegisterSSO();
      break;
    case "sign":
      await cmdSign();
      break;
    case "session":
      await cmdSession();
      break;
    case "whoami":
      await cmdWhoami();
      break;
    case "export":
      await cmdExport();
      break;
    case "help":
    case "--help":
    case "-h":
    case undefined:
      printHelp();
      break;
    default:
      console.error(`Unknown command: ${command}`);
      printHelp();
      process.exit(1);
  }
}

// ── Commands ───────────────────────────────────────────────────────────────

async function cmdInit() {
  const { keyExists, generateKeyPair } = await import("../lib/keygen.mjs");

  if (keyExists()) {
    const { loadKey } = await import("../lib/keygen.mjs");
    const key = loadKey();
    console.log(`Key already exists.`);
    console.log(`  kid: ${key.kid}`);
    console.log(`  x:   ${key.x}`);
    console.log(`\nTo register: clawauth register <agent-name>`);
    return;
  }

  console.log("Generating Ed25519 key pair...");
  const result = generateKeyPair();

  console.log(`\nKey generated!`);
  console.log(`  kid: ${result.kid}`);
  console.log(`  x:   ${result.x}`);
  console.log(`  Stored at: ${result.keyPath}`);
  console.log(`\nNext: clawauth register <agent-name>`);
}

async function cmdSign() {
  const method = args[1];
  const url = args[2];
  const jwksUrl = getFlag("--jwks") || getFlag("--signature-agent");

  if (!method || !url) {
    console.error("Usage: clawauth sign <METHOD> <URL> [--jwks <jwks-url>]");
    process.exit(1);
  }

  const { loadKey, loadConfig } = await import("../lib/keygen.mjs");
  const { signRequest } = await import("../lib/sign.mjs");

  const key = loadKey();
  const config = loadConfig();
  const resolvedJwksUrl = jwksUrl || config.jwksUrl || null;

  const { headers } = signRequest({
    method,
    url,
    privateKeyPem: key.privateKeyPem,
    kid: key.kid,
    jwksUrl: resolvedJwksUrl,
  });

  console.log(JSON.stringify(headers));
}

async function cmdSession() {
  const url = args[1];
  if (!url) {
    console.error("Usage: clawauth session <URL> [--method GET] [--session <name>] [--jwks <url>]");
    process.exit(1);
  }

  const method = getFlag("--method") || "GET";
  const sessionName = getFlag("--session") || getFlag("-s");
  const jwksUrl = getFlag("--jwks") || getFlag("--signature-agent");

  const { loadKey, loadConfig } = await import("../lib/keygen.mjs");
  const { signRequest } = await import("../lib/sign.mjs");

  const key = loadKey();
  const config = loadConfig();
  const resolvedJwksUrl = jwksUrl || config.jwksUrl || null;

  const { headers } = signRequest({
    method,
    url,
    privateKeyPem: key.privateKeyPem,
    kid: key.kid,
    jwksUrl: resolvedJwksUrl,
  });

  const headersJson = JSON.stringify(headers);
  const sessionFlag = sessionName ? `--session ${sessionName} ` : "";

  console.log(`Signed session for ${url}`);
  console.log(`  kid: ${key.kid}`);
  if (resolvedJwksUrl) console.log(`  Signature-Agent: ${resolvedJwksUrl}`);
  console.log(`\nRun:\n`);
  console.log(`  agent-browser ${sessionFlag}set headers '${headersJson}'`);
  console.log(`  agent-browser ${sessionFlag}open ${url}`);
  console.log(`\nNote: re-sign before navigating to a different URL.`);
}

async function cmdRegister() {
  const agentName = args[1] || "my-agent";
  const token = getFlag("--token") || process.env.OBA_TOKEN;

  if (!token) {
    console.log("To register, you need an OBA token.");
    console.log("");
    console.log("1. Go to https://openbotauth.org/token");
    console.log('2. Click "Login with GitHub"');
    console.log("3. Copy the token and run:");
    console.log(`   clawauth register ${agentName} --token <your-oba-token>`);
    console.log("");
    console.log("Or set OBA_TOKEN environment variable.");
    process.exit(1);
  }

  const { loadKey, saveToken, loadConfig, saveConfig } = await import(
    "../lib/keygen.mjs"
  );
  const key = loadKey();

  // Save token for future use
  saveToken(token);

  console.log(`Registering agent "${agentName}" with OBA...`);

  try {
    const response = await fetch(`${OBA_API}/agents`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        name: agentName,
        agent_type: "agent",
        public_key: {
          kty: "OKP",
          crv: "Ed25519",
          kid: key.kid,
          x: key.x,
          use: "sig",
          alg: "EdDSA",
        },
      }),
    });

    const data = await response.json();

    if (!response.ok) {
      console.error(`Registration failed (${response.status}):`, JSON.stringify(data));
      process.exit(1);
    }

    const jwksUrl = `${OBA_API}/agent-jwks/${data.id}`;

    // Save to config
    const config = loadConfig();
    config.agentId = data.id;
    config.agentName = agentName;
    config.jwksUrl = jwksUrl;
    config.registeredAt = new Date().toISOString();
    saveConfig(config);

    console.log(`\nRegistered!`);
    console.log(`  Agent ID: ${data.id}`);
    console.log(`  JWKS URL: ${jwksUrl}`);
    console.log(`\nVerify: curl ${jwksUrl}`);
    console.log(`\nNow run: clawauth session <url>`);
  } catch (err) {
    console.error(`Registration failed: ${err.message}`);
    process.exit(1);
  }
}

async function cmdRegisterSSO() {
  const provider = getFlag("--provider");
  const orgId = getFlag("--org");
  const token = getFlag("--token") || process.env.OBA_SSO_TOKEN;

  if (!provider || !orgId || !token) {
    console.error(
      "Usage: clawauth register-sso --provider <okta|workos|descope> --org <org-id> --token <sso-token>"
    );
    process.exit(1);
  }

  const { loadKey } = await import("../lib/keygen.mjs");
  const key = loadKey();

  console.log(`Registering via ${provider} SSO for org "${orgId}"...`);
  try {
    const response = await fetch(`${OBA_API}/enterprise/keys`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
        "X-SSO-Provider": provider,
        "X-Org-ID": orgId,
      },
      body: JSON.stringify({
        key: {
          kty: "OKP",
          crv: "Ed25519",
          kid: key.kid,
          x: key.x,
          use: "sig",
          alg: "EdDSA",
        },
        sso: { provider, orgId },
        metadata: { tool: "clawauth", platform: "openclaw" },
      }),
    });

    const data = await response.json();
    console.log(JSON.stringify(data, null, 2));
  } catch (err) {
    console.error(`SSO registration failed: ${err.message}`);
    process.exit(1);
  }
}

async function cmdWhoami() {
  const { keyExists, loadKey, loadConfig } = await import("../lib/keygen.mjs");

  if (!keyExists()) {
    console.log("No identity found. Run: clawauth init");
    return;
  }

  const key = loadKey();
  const config = loadConfig();

  console.log(`kid:        ${key.kid}`);
  console.log(`Public (x): ${key.x}`);
  console.log(`Created:    ${key.createdAt}`);

  if (config.agentId) {
    console.log(`Agent ID:   ${config.agentId}`);
    console.log(`Agent Name: ${config.agentName}`);
    console.log(`JWKS URL:   ${config.jwksUrl}`);
  } else {
    console.log(`Registry:   not registered`);
  }
}

async function cmdExport() {
  const { loadKey } = await import("../lib/keygen.mjs");
  const key = loadKey();

  const jwk = {
    kty: "OKP",
    crv: "Ed25519",
    kid: key.kid,
    x: key.x,
    use: "sig",
    alg: "EdDSA",
  };

  const format = getFlag("--format") || "jwks";
  if (format === "jwk") {
    console.log(JSON.stringify(jwk, null, 2));
  } else {
    console.log(JSON.stringify({ keys: [jwk] }, null, 2));
  }
}

// ── Helpers ────────────────────────────────────────────────────────────────

function getFlag(flag) {
  const idx = args.indexOf(flag);
  if (idx === -1 || idx + 1 >= args.length) return null;
  return args[idx + 1];
}

function printHelp() {
  console.log(`
clawauth - Cryptographic identity for AI agents (OpenBotAuth)

SETUP:
  clawauth init                             Generate Ed25519 key pair
  clawauth register [agent-name]            Register with OBA Registry
  clawauth register-sso                     Register via enterprise SSO

SIGN & BROWSE:
  clawauth sign <METHOD> <URL>              Output signed headers JSON
  clawauth session <URL>                    Signed agent-browser session

INFO:
  clawauth whoami                           Show current identity
  clawauth export                           Export public key as JWKS

FLAGS:
  --token <token>                           OBA Registry auth token
  --jwks <url>                              JWKS URL for Signature-Agent
  --session, -s <name>                      agent-browser session name
  --method <METHOD>                         HTTP method (default: GET)
  --provider <okta|workos|descope>          SSO provider
  --org <org-id>                            Organization ID for SSO
  --format <jwk|jwks>                       Export format (default: jwks)

ENVIRONMENT:
  OBA_TOKEN                                 Registry auth token
  OBA_SSO_TOKEN                             SSO auth token

EXAMPLES:
  clawauth init
  clawauth register my-agent --token oba_abc123...
  clawauth session https://example.com
  clawauth sign GET https://example.com --jwks https://api.openbotauth.org/agent-jwks/xyz
  agent-browser set headers "$(clawauth sign GET https://example.com)"
`);
}

main().catch((err) => {
  console.error(err.message);
  process.exit(1);
});
