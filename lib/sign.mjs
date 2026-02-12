/**
 * RFC 9421 HTTP Message Signature Implementation
 *
 * Signs HTTP requests using Ed25519 per the RFC 9421 spec.
 * Generates Signature and Signature-Input headers for
 * agent-browser session authentication.
 */

import { createPrivateKey, sign as cryptoSign, randomUUID } from "node:crypto";

/**
 * Build the signature base string per RFC 9421 Section 2.5
 *
 * @param {Object} params - Request parameters
 * @param {string} params.method - HTTP method (GET, POST, etc.)
 * @param {string} params.url - Full request URL
 * @param {Object} params.headers - Request headers
 * @param {string[]} coveredComponents - Components to include in signature
 * @param {Object} signatureParams - Signature parameters (created, keyid, nonce, etc.)
 * @returns {string} The signature base string
 */
export function buildSignatureBase(params, coveredComponents, signatureParams) {
  const url = new URL(params.url);
  const lines = [];

  for (const component of coveredComponents) {
    let value;
    switch (component) {
      case "@method":
        value = params.method.toUpperCase();
        break;
      case "@authority":
        value = url.host;
        break;
      case "@path":
        value = url.pathname;
        break;
      case "@scheme":
        value = url.protocol.replace(":", "");
        break;
      case "@target-uri":
        value = params.url;
        break;
      case "@request-target":
        value = `${url.pathname}${url.search}`;
        break;
      case "@query":
        value = url.search || "?";
        break;
      default:
        // Regular header
        value = params.headers?.[component.toLowerCase()] || "";
        break;
    }
    lines.push(`"${component}": ${value}`);
  }

  // Build signature params string
  const paramParts = [];
  paramParts.push(
    `(${coveredComponents.map((c) => `"${c}"`).join(" ")})`
  );
  if (signatureParams.created)
    paramParts.push(`created=${signatureParams.created}`);
  if (signatureParams.nonce)
    paramParts.push(`nonce="${signatureParams.nonce}"`);
  if (signatureParams.keyid)
    paramParts.push(`keyid="${signatureParams.keyid}"`);
  if (signatureParams.alg) paramParts.push(`alg="${signatureParams.alg}"`);
  if (signatureParams.tag) paramParts.push(`tag="${signatureParams.tag}"`);

  const sigParamsLine = `"@signature-params": ${paramParts.join(";")}`;
  lines.push(sigParamsLine);

  return lines.join("\n");
}

/**
 * Sign an HTTP request per RFC 9421
 *
 * @param {Object} options
 * @param {string} options.method - HTTP method
 * @param {string} options.url - Target URL
 * @param {Object} options.headers - Existing request headers
 * @param {Object} options.privateKeyJwk - Ed25519 private key in JWK format
 * @param {string} options.keyId - Key identifier (keyid parameter)
 * @param {string} options.sessionId - Session identifier for tracking
 * @param {string} [options.tag] - Signature tag (e.g., "oba-session")
 * @returns {{ signature: string, signatureInput: string, allHeaders: Object }}
 */
export function signRequest(options) {
  const {
    method = "GET",
    url,
    headers = {},
    privateKeyJwk,
    keyId,
    sessionId,
    tag = "oba-session",
  } = options;

  const created = Math.floor(Date.now() / 1000);
  const nonce = randomUUID();

  // Components we sign
  const coveredComponents = ["@method", "@authority", "@path"];

  const signatureParams = {
    created,
    nonce,
    keyid: keyId,
    alg: "ed25519",
    tag,
  };

  // Build signature base
  const signatureBase = buildSignatureBase(
    { method, url, headers },
    coveredComponents,
    signatureParams
  );

  // Create Ed25519 private key object
  const privateKey = createPrivateKey({ key: privateKeyJwk, format: "jwk" });

  // Sign the base string
  const signature = cryptoSign(null, Buffer.from(signatureBase), privateKey);
  const signatureB64 = signature.toString("base64");

  // Build header values
  const sigInputComponents = coveredComponents
    .map((c) => `"${c}"`)
    .join(" ");
  const signatureInput =
    `sig1=(${sigInputComponents})` +
    `;created=${created}` +
    `;nonce="${nonce}"` +
    `;keyid="${keyId}"` +
    `;alg="ed25519"` +
    `;tag="${tag}"`;

  return {
    signature: `sig1=:${signatureB64}:`,
    signatureInput,
    sessionId,
    allHeaders: {
      ...headers,
      Signature: `sig1=:${signatureB64}:`,
      "Signature-Input": signatureInput,
      "X-OBA-Agent-ID": keyId,
      "X-OBA-Session-ID": sessionId || nonce,
      "X-OBA-Timestamp": created.toString(),
    },
  };
}

/**
 * Generate signed headers JSON for use with agent-browser `set headers`
 *
 * @param {Object} options
 * @param {Object} options.privateKeyJwk - Ed25519 private key in JWK format
 * @param {string} options.keyId - Key identifier
 * @param {string} options.targetUrl - URL being browsed
 * @param {string} options.sessionId - Browser session ID
 * @param {string} [options.agentName] - Agent name for tracking
 * @param {string} [options.jwksUrl] - JWKS endpoint URL for key resolution
 * @returns {string} JSON string of headers for agent-browser
 */
export function generateBrowserHeaders(options) {
  const {
    privateKeyJwk,
    keyId,
    targetUrl,
    sessionId,
    agentName = "default",
    jwksUrl,
  } = options;

  const keyIdOrJwks = jwksUrl || keyId;

  const { allHeaders } = signRequest({
    method: "GET",
    url: targetUrl,
    privateKeyJwk,
    keyId: keyIdOrJwks,
    sessionId,
    tag: "oba-browser-session",
  });

  // Only include OBA-specific headers (agent-browser manages the rest)
  const obaHeaders = {
    Signature: allHeaders.Signature,
    "Signature-Input": allHeaders["Signature-Input"],
    "X-OBA-Agent-ID": keyId,
    "X-OBA-Session-ID": allHeaders["X-OBA-Session-ID"],
    "X-OBA-Agent-Name": agentName,
    "X-OBA-Timestamp": allHeaders["X-OBA-Timestamp"],
  };

  if (jwksUrl) {
    obaHeaders["Signature-Agent"] = jwksUrl;
  }

  return JSON.stringify(obaHeaders);
}
