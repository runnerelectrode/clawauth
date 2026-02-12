#!/usr/bin/env node

/**
 * clawauth CLI
 *
 * Cryptographic identity for AI agents using OpenBotAuth.
 * Integrates Ed25519 signing with agent-browser sessions.
 *
 * Usage:
 *   clawauth init [agent-name]          Generate Ed25519 key pair
 *   clawauth sign <url>                 Sign a browser session and get headers
 *   clawauth session <url>              Create a signed agent-browser session
 *   clawauth derive <sub-agent-label>   Derive a sub-agent key
 *   clawauth sub-session <label> <url>  Create a signed sub-agent session
 *   clawauth register [agent-name]      Register key with OBA Registry
 *   clawauth register-sso               Register via enterprise SSO
 *   clawauth list                       List agents and keys
 *   clawauth sessions                   List active sessions
 *   clawauth whoami                     Show current agent identity
 *   clawauth export [agent-name]        Export public key / JWKS
 *   clawauth headers <url>              Output only the signed headers JSON
 */

import { parseArgs } from "node:util";
import { randomUUID } from "node:crypto";

const args = process.argv.slice(2);
const command = args[0];

async function main() {
  switch (command) {
    case "init":
      await cmdInit();
      break;
    case "sign":
      await cmdSign();
      break;
    case "session":
      await cmdSession();
      break;
    case "derive":
      await cmdDerive();
      break;
    case "sub-session":
      await cmdSubSession();
      break;
    case "register":
      await cmdRegister();
      break;
    case "register-sso":
      await cmdRegisterSSO();
      break;
    case "list":
      await cmdList();
      break;
    case "sessions":
      await cmdSessions();
      break;
    case "whoami":
      await cmdWhoami();
      break;
    case "export":
      await cmdExport();
      break;
    case "headers":
      await cmdHeaders();
      break;
    case "ephemeral":
      await cmdEphemeral();
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
  const agentName = args[1] || "default";
  const { generateKeyPair } = await import("../lib/keygen.mjs");

  console.log(`Generating Ed25519 key pair for agent "${agentName}"...`);
  const result = generateKeyPair(agentName);

  console.log(`\nKey pair generated successfully!`);
  console.log(`  Key ID:       ${result.keyId}`);
  console.log(`  Private key:  ${result.keyPath}`);
  console.log(`  Public key:   ${result.pubKeyPath}`);
  console.log(`  JWKS:         ${result.jwksPath}`);
  console.log(`\nNext steps:`);
  console.log(`  clawauth register ${agentName}   # Register with OBA Registry`);
  console.log(`  clawauth session <url>           # Start a signed browser session`);
}

async function cmdSign() {
  const url = args[1];
  if (!url) {
    console.error("Usage: clawauth sign <url> [--agent <name>]");
    process.exit(1);
  }

  const agentName = getFlag("--agent") || getFlag("-a");
  const { createSignedSession } = await import("../lib/session.mjs");

  const session = createSignedSession({
    targetUrl: url,
    agentName: agentName || undefined,
  });

  console.log(JSON.stringify(session.headers, null, 2));
}

async function cmdSession() {
  const url = args[1];
  if (!url) {
    console.error(
      "Usage: clawauth session <url> [--agent <name>] [--session <name>] [--ephemeral] [--openclaw-session <id>]"
    );
    process.exit(1);
  }

  const agentName = getFlag("--agent") || getFlag("-a");
  const sessionName = getFlag("--session") || getFlag("-s");
  const openClawSessionId = getFlag("--openclaw-session");
  const ephemeral = args.includes("--ephemeral");

  const { createSignedSession, generateStartupCommands } = await import(
    "../lib/session.mjs"
  );

  const session = createSignedSession({
    targetUrl: url,
    agentName: agentName || undefined,
    sessionName: sessionName || undefined,
    openClawSessionId: openClawSessionId || undefined,
    ephemeral,
  });

  console.log(`Signed session created!`);
  console.log(`  Session ID: ${session.sessionId}`);
  console.log(`  Agent:      ${session.agentName}`);
  console.log(`  Key ID:     ${session.keyId}`);
  console.log(`\nRun these commands:\n`);

  const commands = generateStartupCommands({
    targetUrl: url,
    agentName: agentName || undefined,
    sessionName: sessionName || undefined,
    openClawSessionId: openClawSessionId || undefined,
    ephemeral,
  });

  for (const cmd of commands) {
    console.log(`  ${cmd}`);
  }
}

async function cmdDerive() {
  const subLabel = args[1];
  if (!subLabel) {
    console.error(
      "Usage: clawauth derive <sub-agent-label> [--agent <parent>]"
    );
    process.exit(1);
  }

  const parentAgent = getFlag("--agent") || getFlag("-a") || "default";
  const { deriveSubAgentKey } = await import("../lib/derive.mjs");

  console.log(
    `Deriving sub-agent key "${subLabel}" from parent "${parentAgent}"...`
  );
  const result = deriveSubAgentKey(parentAgent, subLabel);

  console.log(`\nSub-agent key derived!`);
  console.log(`  Key ID:       ${result.keyId}`);
  console.log(`  Parent:       ${result.parentAgent}`);
  console.log(`  Sub-agent:    ${result.subAgentLabel}`);
  console.log(`  Key file:     ${result.keyPath}`);
}

async function cmdSubSession() {
  const subLabel = args[1];
  const url = args[2];
  if (!subLabel || !url) {
    console.error(
      "Usage: clawauth sub-session <sub-agent-label> <url> [--agent <parent>] [--session <name>]"
    );
    process.exit(1);
  }

  const parentAgent = getFlag("--agent") || getFlag("-a") || "default";
  const sessionName = getFlag("--session") || getFlag("-s");
  const openClawSessionId = getFlag("--openclaw-session");

  const { createSubAgentSession } = await import("../lib/session.mjs");

  const session = createSubAgentSession({
    parentAgent,
    subAgentLabel: subLabel,
    targetUrl: url,
    sessionName: sessionName || undefined,
    openClawSessionId: openClawSessionId || undefined,
  });

  console.log(`Sub-agent session created!`);
  console.log(`  Session ID:       ${session.sessionId}`);
  console.log(`  Parent Agent:     ${session.parentAgent}`);
  console.log(`  Sub-agent:        ${session.subAgentLabel}`);
  console.log(`  Sub-agent Key ID: ${session.subAgentKeyId}`);
  console.log(`\nRun this command:\n`);
  console.log(`  ${session.command}`);
}

async function cmdRegister() {
  const agentName = args[1] || "default";
  const token = getFlag("--token") || process.env.OBA_TOKEN;
  const registryUrl = getFlag("--registry") || process.env.OBA_REGISTRY_URL;

  if (!token) {
    console.error(
      "Auth token required. Use --token <token> or set OBA_TOKEN env var."
    );
    console.error(
      "Get a token at: https://registry.openbotauth.org/auth/github"
    );
    process.exit(1);
  }

  const { registerKey } = await import("../lib/registry.mjs");

  console.log(`Registering agent "${agentName}" with OBA Registry...`);
  try {
    const result = await registerKey(agentName, {
      token,
      registryUrl: registryUrl || undefined,
    });
    console.log(`\nRegistered successfully!`);
    console.log(`  Agent ID:  ${result.agentId}`);
    console.log(`  JWKS URL:  ${result.jwksUrl}`);
  } catch (err) {
    console.error(`Registration failed: ${err.message}`);
    process.exit(1);
  }
}

async function cmdRegisterSSO() {
  const provider = getFlag("--provider");
  const orgId = getFlag("--org");
  const token = getFlag("--token") || process.env.OBA_SSO_TOKEN;
  const agentName = getFlag("--agent") || "default";
  const registryUrl = getFlag("--registry") || process.env.OBA_REGISTRY_URL;

  if (!provider || !orgId || !token) {
    console.error(
      "Usage: clawauth register-sso --provider <okta|workos|descope> --org <org-id> --token <sso-token> [--agent <name>]"
    );
    process.exit(1);
  }

  const { registerWithSSO } = await import("../lib/registry.mjs");

  console.log(`Registering via ${provider} SSO for org "${orgId}"...`);
  try {
    const result = await registerWithSSO(agentName, {
      provider,
      orgId,
      token,
      registryUrl: registryUrl || undefined,
    });
    console.log(`\nSSO registration successful!`);
    console.log(`  Agent ID:  ${result.agentId}`);
    console.log(`  JWKS URL:  ${result.jwksUrl}`);
    console.log(`  Provider:  ${provider}`);
    console.log(`  Org:       ${orgId}`);
  } catch (err) {
    console.error(`SSO registration failed: ${err.message}`);
    process.exit(1);
  }
}

async function cmdList() {
  const { listAgents, loadConfig } = await import("../lib/keygen.mjs");

  const agents = listAgents();
  const config = loadConfig();

  console.log("Agents:");
  for (const [name, info] of Object.entries(agents)) {
    const isDefault = config.defaultAgent === name ? " (default)" : "";
    const registered = info.registry ? " [registered]" : "";
    const sso = info.registry?.sso
      ? ` [${info.registry.sso.provider}]`
      : "";
    console.log(`  ${name}${isDefault}${registered}${sso}`);
    console.log(`    Key ID: ${info.keyId}`);
    if (info.registry?.jwksUrl) {
      console.log(`    JWKS:   ${info.registry.jwksUrl}`);
    }
  }

  if (config.subAgents && Object.keys(config.subAgents).length > 0) {
    console.log("\nSub-agents:");
    for (const [id, sub] of Object.entries(config.subAgents)) {
      const ephemeral = sub.ephemeral ? " [ephemeral]" : "";
      console.log(`  ${sub.subAgentLabel}${ephemeral} (parent: ${sub.parentAgent})`);
      console.log(`    Key ID: ${sub.keyId}`);
    }
  }
}

async function cmdSessions() {
  const { listSessions } = await import("../lib/session.mjs");

  const sessions = listSessions();
  if (Object.keys(sessions).length === 0) {
    console.log("No active sessions.");
    return;
  }

  console.log("Active sessions:");
  for (const [id, session] of Object.entries(sessions)) {
    const ephemeral = session.ephemeral ? " [ephemeral]" : "";
    console.log(`  ${id}${ephemeral}`);
    console.log(`    Agent:   ${session.agentName}`);
    console.log(`    URL:     ${session.targetUrl}`);
    console.log(`    Created: ${session.createdAt}`);
  }
}

async function cmdWhoami() {
  const { loadConfig, loadPublicKey } = await import("../lib/keygen.mjs");
  const config = loadConfig();
  const agentName = args[1] || config.defaultAgent || "default";

  try {
    const pubKey = loadPublicKey(agentName);
    console.log(`Agent: ${agentName}`);
    console.log(`Key ID: ${pubKey.kid}`);
    console.log(`Algorithm: ${pubKey.alg}`);
    console.log(`Public Key (x): ${pubKey.x}`);
    if (config.agents?.[agentName]?.registry) {
      const reg = config.agents[agentName].registry;
      console.log(`Registry: ${reg.url}`);
      console.log(`Agent ID: ${reg.agentId}`);
      console.log(`JWKS URL: ${reg.jwksUrl}`);
      if (reg.sso) {
        console.log(`SSO: ${reg.sso.provider} (org: ${reg.sso.orgId})`);
      }
    } else {
      console.log(`Registry: not registered`);
    }
  } catch (err) {
    console.error(err.message);
    process.exit(1);
  }
}

async function cmdExport() {
  const agentName = args[1] || "default";
  const format = getFlag("--format") || "jwks";
  const { loadPublicKey } = await import("../lib/keygen.mjs");

  try {
    const pubKey = loadPublicKey(agentName);
    if (format === "jwk") {
      console.log(JSON.stringify(pubKey, null, 2));
    } else {
      console.log(JSON.stringify({ keys: [pubKey] }, null, 2));
    }
  } catch (err) {
    console.error(err.message);
    process.exit(1);
  }
}

async function cmdHeaders() {
  const url = args[1];
  if (!url) {
    console.error("Usage: clawauth headers <url> [--agent <name>] [--session-id <id>]");
    process.exit(1);
  }

  const agentName = getFlag("--agent") || getFlag("-a");
  const sessionId = getFlag("--session-id") || `oba-session-${randomUUID()}`;

  const { loadPrivateKey, loadConfig } = await import("../lib/keygen.mjs");
  const { generateBrowserHeaders } = await import("../lib/sign.mjs");
  const { getJwksUrl } = await import("../lib/registry.mjs");

  const config = loadConfig();
  const agent = agentName || config.defaultAgent || "default";
  const privateKeyJwk = loadPrivateKey(agent);
  const jwksUrl = getJwksUrl(agent);

  const headersJson = generateBrowserHeaders({
    privateKeyJwk,
    keyId: privateKeyJwk.kid,
    targetUrl: url,
    sessionId,
    agentName: agent,
    jwksUrl,
  });

  // Output raw JSON for piping into agent-browser
  console.log(headersJson);
}

async function cmdEphemeral() {
  const url = args[1];
  if (!url) {
    console.error(
      "Usage: clawauth ephemeral <url> [--agent <name>] [--openclaw-session <id>]"
    );
    process.exit(1);
  }

  const agentName = getFlag("--agent") || getFlag("-a");
  const openClawSessionId = getFlag("--openclaw-session") || `eph-${randomUUID()}`;

  const { createSignedSession } = await import("../lib/session.mjs");

  const session = createSignedSession({
    targetUrl: url,
    agentName: agentName || undefined,
    openClawSessionId,
    ephemeral: true,
  });

  console.log(`Ephemeral session created!`);
  console.log(`  Session ID: ${session.sessionId}`);
  console.log(`  Key ID:     ${session.keyId}`);
  console.log(`\nRun:\n`);
  console.log(`  ${session.command}`);
}

// ── Helpers ────────────────────────────────────────────────────────────────

function getFlag(flag) {
  const idx = args.indexOf(flag);
  if (idx === -1 || idx + 1 >= args.length) return null;
  return args[idx + 1];
}

function printHelp() {
  console.log(`
clawauth - Cryptographic identity for AI agents (OpenBotAuth + Agent Browser)

SETUP:
  clawauth init [agent-name]              Generate Ed25519 key pair
  clawauth register [agent-name]          Register key with OBA Registry
  clawauth register-sso                   Register via enterprise SSO (Okta/WorkOS/Descope)

BROWSE WITH IDENTITY:
  clawauth session <url>                  Create a signed agent-browser session
  clawauth headers <url>                  Output signed headers JSON (for piping)
  clawauth ephemeral <url>                Create an ephemeral session-bound key

SUB-AGENTS:
  clawauth derive <sub-agent-label>       Derive a sub-agent key from parent
  clawauth sub-session <label> <url>      Create a signed sub-agent session

INFO:
  clawauth whoami [agent-name]            Show current agent identity
  clawauth list                           List all agents and sub-agents
  clawauth sessions                       List active sessions
  clawauth export [agent-name]            Export public key as JWKS

FLAGS:
  --agent, -a <name>                      Specify agent name
  --session, -s <name>                    Agent-browser session name
  --openclaw-session <id>                 Bind to OpenClaw session ID
  --ephemeral                             Use ephemeral session key
  --token <token>                         OBA Registry auth token
  --provider <okta|workos|descope>        SSO provider for enterprise
  --org <org-id>                          Organization ID for SSO
  --registry <url>                        Custom registry URL

ENVIRONMENT:
  OBA_TOKEN                               Registry auth token
  OBA_SSO_TOKEN                           SSO auth token
  OBA_REGISTRY_URL                        Custom registry URL

EXAMPLES:
  clawauth init my-agent
  clawauth session https://example.com --agent my-agent
  clawauth derive scraper --agent my-agent
  clawauth sub-session scraper https://example.com --session scraper1
  agent-browser set headers "$(clawauth headers https://example.com)"
`);
}

main().catch((err) => {
  console.error(err.message);
  process.exit(1);
});
