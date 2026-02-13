/**
 * Ed25519 Key Generation for OpenBotAuth
 *
 * Generates Ed25519 key pairs using Node.js built-in crypto.
 * Keys are stored in OBA's canonical PEM format at ~/.config/openbotauth/
 * with kid derived from JWK thumbprint (SHA-256, base64url, first 16 chars).
 */

import {
  generateKeyPairSync,
  createHash,
} from "node:crypto";
import { writeFileSync, mkdirSync, readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";

const OBA_DIR = join(homedir(), ".config", "openbotauth");
const KEY_FILE = join(OBA_DIR, "key.json");
const PUB_KEY_FILE = join(OBA_DIR, "key.pub.json");
const TOKEN_FILE = join(OBA_DIR, "token");

export function ensureDirectories() {
  mkdirSync(OBA_DIR, { recursive: true, mode: 0o700 });
}

/**
 * Generate an Ed25519 key pair in OBA's canonical format.
 * Stores { kid, x, publicKeyPem, privateKeyPem, createdAt } at ~/.config/openbotauth/key.json
 *
 * @returns {{ kid, x, publicKeyPem, privateKeyPem }}
 */
export function generateKeyPair() {
  ensureDirectories();

  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const publicKeyPem = publicKey
    .export({ type: "spki", format: "pem" })
    .toString();
  const privateKeyPem = privateKey
    .export({ type: "pkcs8", format: "pem" })
    .toString();

  // Derive kid from JWK thumbprint (matches OBA's format)
  const spki = publicKey.export({ type: "spki", format: "der" });
  if (spki.length !== 44)
    throw new Error(`Unexpected SPKI length: ${spki.length}`);
  const rawPub = spki.subarray(12, 44);
  const x = rawPub.toString("base64url");
  const thumbprint = JSON.stringify({ kty: "OKP", crv: "Ed25519", x });
  const hash = createHash("sha256").update(thumbprint).digest();
  const kid = hash.toString("base64url").slice(0, 16);

  const keyData = {
    kid,
    x,
    publicKeyPem,
    privateKeyPem,
    createdAt: new Date().toISOString(),
  };

  writeFileSync(KEY_FILE, JSON.stringify(keyData, null, 2), { mode: 0o600 });

  // Also write a public-only file for sharing
  const pubData = {
    kty: "OKP",
    crv: "Ed25519",
    kid,
    x,
    use: "sig",
    alg: "EdDSA",
  };
  writeFileSync(PUB_KEY_FILE, JSON.stringify(pubData, null, 2), {
    mode: 0o644,
  });

  return { kid, x, publicKeyPem, privateKeyPem, keyPath: KEY_FILE };
}

/**
 * Load the existing OBA key file.
 * Returns { kid, x, publicKeyPem, privateKeyPem, createdAt }
 */
export function loadKey() {
  if (!existsSync(KEY_FILE)) {
    throw new Error(
      `No key found at ${KEY_FILE}. Run: clawauth init`
    );
  }
  return JSON.parse(readFileSync(KEY_FILE, "utf-8"));
}

/**
 * Check if a key exists
 */
export function keyExists() {
  return existsSync(KEY_FILE);
}

/**
 * Load the OBA token
 */
export function loadToken() {
  if (!existsSync(TOKEN_FILE)) {
    throw new Error(
      `No token found at ${TOKEN_FILE}. Get one at https://openbotauth.org/token`
    );
  }
  return readFileSync(TOKEN_FILE, "utf-8").trim();
}

/**
 * Save the OBA token
 */
export function saveToken(token) {
  ensureDirectories();
  writeFileSync(TOKEN_FILE, token.trim(), { mode: 0o600 });
}

/**
 * Load config (agent_id, JWKS URL, etc.) from a separate config file
 */
export function loadConfig() {
  const configPath = join(OBA_DIR, "config.json");
  if (!existsSync(configPath)) return {};
  return JSON.parse(readFileSync(configPath, "utf-8"));
}

/**
 * Save config
 */
export function saveConfig(config) {
  ensureDirectories();
  const configPath = join(OBA_DIR, "config.json");
  writeFileSync(configPath, JSON.stringify(config, null, 2), { mode: 0o600 });
}
