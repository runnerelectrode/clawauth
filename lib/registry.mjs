/**
 * OBA Registry Client
 *
 * Handles registration of public keys with the OpenBotAuth Registry.
 * Supports both the public registry and enterprise SSO integration
 * via Okta, WorkOS, and Descope.
 */

import { loadPublicKey, loadConfig, saveConfig } from "./keygen.mjs";

const DEFAULT_REGISTRY_URL = "https://registry.openbotauth.org";

/**
 * Register an agent's public key with the OBA Registry.
 *
 * @param {string} agentName - Agent name
 * @param {Object} options
 * @param {string} [options.registryUrl] - Registry URL (default: public registry)
 * @param {string} [options.token] - Auth token (GitHub OAuth or SSO token)
 * @returns {Object} Registration result
 */
export async function registerKey(agentName, options = {}) {
  const { registryUrl = DEFAULT_REGISTRY_URL, token } = options;

  const publicKeyJwk = loadPublicKey(agentName);

  const response = await fetch(`${registryUrl}/api/keys`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify({
      key: publicKeyJwk,
      agentName,
      metadata: {
        tool: "clawauth",
        version: "0.1.0",
        platform: "agent-browser",
      },
    }),
  });

  if (!response.ok) {
    const body = await response.text();
    throw new Error(`Registry registration failed (${response.status}): ${body}`);
  }

  const result = await response.json();

  // Save registry info to config
  const config = loadConfig();
  if (!config.agents?.[agentName]) {
    throw new Error(`Agent "${agentName}" not found in local config`);
  }
  config.agents[agentName].registry = {
    url: registryUrl,
    agentId: result.agentId,
    jwksUrl: result.jwksUrl,
    registeredAt: new Date().toISOString(),
  };
  saveConfig(config);

  return result;
}

/**
 * Register via enterprise SSO (Okta, WorkOS, Descope).
 *
 * @param {string} agentName - Agent name
 * @param {Object} options
 * @param {string} options.provider - SSO provider: "okta" | "workos" | "descope"
 * @param {string} options.orgId - Organization ID
 * @param {string} options.token - SSO bearer token
 * @param {string} [options.registryUrl] - Registry URL
 * @returns {Object} Registration result with org binding
 */
export async function registerWithSSO(agentName, options = {}) {
  const {
    provider,
    orgId,
    token,
    registryUrl = DEFAULT_REGISTRY_URL,
  } = options;

  const publicKeyJwk = loadPublicKey(agentName);

  const response = await fetch(`${registryUrl}/api/enterprise/keys`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
      "X-SSO-Provider": provider,
      "X-Org-ID": orgId,
    },
    body: JSON.stringify({
      key: publicKeyJwk,
      agentName,
      sso: { provider, orgId },
      metadata: {
        tool: "clawauth",
        version: "0.1.0",
        platform: "agent-browser",
      },
    }),
  });

  if (!response.ok) {
    const body = await response.text();
    throw new Error(`SSO registration failed (${response.status}): ${body}`);
  }

  const result = await response.json();

  // Save SSO registration to config
  const config = loadConfig();
  config.agents[agentName].registry = {
    url: registryUrl,
    agentId: result.agentId,
    jwksUrl: result.jwksUrl,
    sso: { provider, orgId },
    registeredAt: new Date().toISOString(),
  };
  saveConfig(config);

  return result;
}

/**
 * Look up an agent's public key from the registry.
 *
 * @param {string} keyId - Key ID or agent ID
 * @param {string} [registryUrl] - Registry URL
 * @returns {Object} JWKS with the agent's public key
 */
export async function lookupKey(keyId, registryUrl = DEFAULT_REGISTRY_URL) {
  const response = await fetch(`${registryUrl}/api/jwks/${encodeURIComponent(keyId)}`);
  if (!response.ok) {
    throw new Error(`Key lookup failed (${response.status})`);
  }
  return response.json();
}

/**
 * Get the JWKS URL for an agent (from local config or registry).
 *
 * @param {string} agentName - Agent name
 * @returns {string|null} JWKS URL or null if not registered
 */
export function getJwksUrl(agentName) {
  const config = loadConfig();
  return config.agents?.[agentName]?.registry?.jwksUrl || null;
}
