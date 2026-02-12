/**
 * Ed25519 Key Generation for OpenBotAuth
 *
 * Generates Ed25519 key pairs using Node.js built-in crypto.
 * Keys are stored in JWKS format for compatibility with RFC 9421
 * and the OBA Registry.
 */

import { generateKeyPairSync, randomUUID } from "node:crypto";
import { writeFileSync, mkdirSync, readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";

const OBA_DIR = join(homedir(), ".openbotauth");
const KEYS_DIR = join(OBA_DIR, "keys");
const CONFIG_FILE = join(OBA_DIR, "config.json");

export function ensureDirectories() {
  mkdirSync(KEYS_DIR, { recursive: true });
}

/**
 * Generate an Ed25519 key pair and store it locally.
 * Returns { keyId, publicKeyJwk, privateKeyJwk }
 */
export function generateKeyPair(agentName = "default") {
  ensureDirectories();

  const keyId = `oba-${agentName}-${randomUUID().slice(0, 8)}`;

  const { publicKey, privateKey } = generateKeyPairSync("ed25519");

  const publicKeyJwk = publicKey.export({ format: "jwk" });
  const privateKeyJwk = privateKey.export({ format: "jwk" });

  publicKeyJwk.kid = keyId;
  publicKeyJwk.use = "sig";
  publicKeyJwk.alg = "EdDSA";

  privateKeyJwk.kid = keyId;
  privateKeyJwk.use = "sig";
  privateKeyJwk.alg = "EdDSA";

  // Store private key locally
  const keyPath = join(KEYS_DIR, `${agentName}.jwk`);
  writeFileSync(keyPath, JSON.stringify(privateKeyJwk, null, 2), {
    mode: 0o600,
  });

  // Store public key for sharing
  const pubKeyPath = join(KEYS_DIR, `${agentName}.pub.jwk`);
  writeFileSync(pubKeyPath, JSON.stringify(publicKeyJwk, null, 2), {
    mode: 0o644,
  });

  // Generate JWKS file for the agent
  const jwksPath = join(KEYS_DIR, `${agentName}.jwks.json`);
  const jwks = { keys: [publicKeyJwk] };
  writeFileSync(jwksPath, JSON.stringify(jwks, null, 2), { mode: 0o644 });

  // Update config
  const config = loadConfig();
  if (!config.agents) config.agents = {};
  config.agents[agentName] = {
    keyId,
    keyPath,
    pubKeyPath,
    jwksPath,
    createdAt: new Date().toISOString(),
  };
  if (!config.defaultAgent) config.defaultAgent = agentName;
  saveConfig(config);

  return { keyId, publicKeyJwk, privateKeyJwk, keyPath, pubKeyPath, jwksPath };
}

/**
 * Load an existing private key for an agent
 */
export function loadPrivateKey(agentName = "default") {
  const keyPath = join(KEYS_DIR, `${agentName}.jwk`);
  if (!existsSync(keyPath)) {
    throw new Error(
      `No key found for agent "${agentName}". Run: clawauth init ${agentName}`
    );
  }
  return JSON.parse(readFileSync(keyPath, "utf-8"));
}

/**
 * Load an existing public key for an agent
 */
export function loadPublicKey(agentName = "default") {
  const pubKeyPath = join(KEYS_DIR, `${agentName}.pub.jwk`);
  if (!existsSync(pubKeyPath)) {
    throw new Error(
      `No public key found for agent "${agentName}". Run: clawauth init ${agentName}`
    );
  }
  return JSON.parse(readFileSync(pubKeyPath, "utf-8"));
}

/**
 * List all agents with their key info
 */
export function listAgents() {
  const config = loadConfig();
  return config.agents || {};
}

export function loadConfig() {
  if (!existsSync(CONFIG_FILE)) return {};
  return JSON.parse(readFileSync(CONFIG_FILE, "utf-8"));
}

export function saveConfig(config) {
  ensureDirectories();
  writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2), { mode: 0o600 });
}
