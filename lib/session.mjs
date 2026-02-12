/**
 * Session Management for Agent Browser Integration
 *
 * Manages signed browser sessions, integrating clawauth with
 * agent-browser's `set headers` command. Handles session lifecycle,
 * header generation, and OpenClaw session binding.
 */

import { randomUUID } from "node:crypto";
import { loadPrivateKey, loadConfig, saveConfig } from "./keygen.mjs";
import { generateBrowserHeaders } from "./sign.mjs";
import { getJwksUrl } from "./registry.mjs";
import { generateEphemeralKey, deriveSubAgentKey } from "./derive.mjs";

/**
 * Create a new signed browser session.
 *
 * Generates session-specific signed headers and returns
 * the agent-browser command to set them.
 *
 * @param {Object} options
 * @param {string} options.targetUrl - URL to browse
 * @param {string} [options.agentName] - Agent name (default: config default)
 * @param {string} [options.sessionName] - Agent-browser session name
 * @param {string} [options.openClawSessionId] - OpenClaw session ID for binding
 * @param {boolean} [options.ephemeral] - Generate an ephemeral session key
 * @returns {{ sessionId, headers, command, headersJson }}
 */
export function createSignedSession(options = {}) {
  const config = loadConfig();
  const agentName = options.agentName || config.defaultAgent || "default";
  const sessionId = options.openClawSessionId || `oba-session-${randomUUID()}`;
  const targetUrl = options.targetUrl || "https://example.com";

  let privateKeyJwk;
  let keyId;

  if (options.ephemeral) {
    // Generate an ephemeral key bound to this session
    const ephemeral = generateEphemeralKey(agentName, sessionId);
    privateKeyJwk = ephemeral.privateKeyJwk;
    keyId = ephemeral.keyId;
  } else {
    // Use the agent's persistent key
    privateKeyJwk = loadPrivateKey(agentName);
    keyId = privateKeyJwk.kid;
  }

  const jwksUrl = getJwksUrl(agentName);

  const headersJson = generateBrowserHeaders({
    privateKeyJwk,
    keyId,
    targetUrl,
    sessionId,
    agentName,
    jwksUrl,
  });

  // Build the agent-browser command
  const sessionFlag = options.sessionName
    ? `--session ${options.sessionName} `
    : "";
  const command = `agent-browser ${sessionFlag}set headers '${headersJson}'`;

  // Track active session
  if (!config.activeSessions) config.activeSessions = {};
  config.activeSessions[sessionId] = {
    agentName,
    keyId,
    targetUrl,
    sessionName: options.sessionName || null,
    ephemeral: !!options.ephemeral,
    openClawSessionId: options.openClawSessionId || null,
    createdAt: new Date().toISOString(),
  };
  saveConfig(config);

  return {
    sessionId,
    headers: JSON.parse(headersJson),
    headersJson,
    command,
    agentName,
    keyId,
  };
}

/**
 * Create a signed session for a sub-agent.
 *
 * Derives a child key from the parent agent and creates
 * signed headers for the sub-agent's browser session.
 *
 * @param {Object} options
 * @param {string} options.parentAgent - Parent agent name
 * @param {string} options.subAgentLabel - Sub-agent identifier
 * @param {string} options.targetUrl - URL to browse
 * @param {string} [options.sessionName] - Agent-browser session name
 * @param {string} [options.openClawSessionId] - OpenClaw session ID
 * @returns {{ sessionId, headers, command, subAgentKeyId }}
 */
export function createSubAgentSession(options = {}) {
  const {
    parentAgent,
    subAgentLabel,
    targetUrl = "https://example.com",
    sessionName,
    openClawSessionId,
  } = options;

  const sessionId = openClawSessionId || `oba-sub-${randomUUID()}`;

  // Derive or load sub-agent key
  const subKey = deriveSubAgentKey(parentAgent, subAgentLabel, sessionId);

  const jwksUrl = getJwksUrl(parentAgent);

  const headersJson = generateBrowserHeaders({
    privateKeyJwk: subKey.privateKeyJwk,
    keyId: subKey.keyId,
    targetUrl,
    sessionId,
    agentName: `${parentAgent}:${subAgentLabel}`,
    jwksUrl,
  });

  const sessionFlag = sessionName ? `--session ${sessionName} ` : "";
  const command = `agent-browser ${sessionFlag}set headers '${headersJson}'`;

  return {
    sessionId,
    headers: JSON.parse(headersJson),
    headersJson,
    command,
    subAgentKeyId: subKey.keyId,
    parentAgent,
    subAgentLabel,
  };
}

/**
 * Generate the full agent-browser startup sequence with auth.
 *
 * Returns a list of commands to run in sequence:
 * 1. Set signed headers
 * 2. Open the target URL
 *
 * @param {Object} options - Same as createSignedSession
 * @returns {string[]} Array of agent-browser commands
 */
export function generateStartupCommands(options = {}) {
  const session = createSignedSession(options);
  const commands = [session.command];

  if (options.targetUrl) {
    const sessionFlag = options.sessionName
      ? `--session ${options.sessionName} `
      : "";
    commands.push(`agent-browser ${sessionFlag}open ${options.targetUrl}`);
  }

  return commands;
}

/**
 * List active sessions
 */
export function listSessions() {
  const config = loadConfig();
  return config.activeSessions || {};
}

/**
 * End a session (clear from tracking)
 */
export function endSession(sessionId) {
  const config = loadConfig();
  if (config.activeSessions?.[sessionId]) {
    delete config.activeSessions[sessionId];
    saveConfig(config);
    return true;
  }
  return false;
}
