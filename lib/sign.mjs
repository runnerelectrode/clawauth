/**
 * RFC 9421 HTTP Message Signature Implementation
 *
 * Signs HTTP requests using Ed25519 per the RFC 9421 spec.
 * Uses PEM private keys from OBA's key.json format.
 * Generates Signature, Signature-Input, and Signature-Agent headers.
 */

import { createPrivateKey, sign as cryptoSign, randomUUID } from "node:crypto";

/**
 * Build the signature base string per RFC 9421 Section 2.5
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
        value = url.pathname + url.search;
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
  if (signatureParams.expires)
    paramParts.push(`expires=${signatureParams.expires}`);
  if (signatureParams.nonce)
    paramParts.push(`nonce="${signatureParams.nonce}"`);
  if (signatureParams.keyid)
    paramParts.push(`keyid="${signatureParams.keyid}"`);
  if (signatureParams.alg)
    paramParts.push(`alg="${signatureParams.alg}"`);

  const sigParamsLine = `"@signature-params": ${paramParts.join(";")}`;
  lines.push(sigParamsLine);

  return { base: lines.join("\n"), sigInput: paramParts.join(";") };
}

/**
 * Sign an HTTP request per RFC 9421
 *
 * @param {Object} options
 * @param {string} options.method - HTTP method
 * @param {string} options.url - Target URL
 * @param {string} options.privateKeyPem - PEM-encoded Ed25519 private key
 * @param {string} options.kid - Key identifier (from OBA key.json)
 * @param {string} [options.jwksUrl] - JWKS endpoint for Signature-Agent header
 * @returns {{ headers: Object }}
 */
export function signRequest(options) {
  const {
    method = "GET",
    url,
    privateKeyPem,
    kid,
    jwksUrl,
  } = options;

  const created = Math.floor(Date.now() / 1000);
  const expires = created + 300; // 5 minute validity
  const nonce = randomUUID();

  const coveredComponents = ["@method", "@authority", "@path"];

  const signatureParams = {
    created,
    expires,
    nonce,
    keyid: kid,
    alg: "ed25519",
  };

  const { base, sigInput } = buildSignatureBase(
    { method, url },
    coveredComponents,
    signatureParams
  );

  const privateKey = createPrivateKey(privateKeyPem);
  const signature = cryptoSign(null, Buffer.from(base), privateKey);
  const signatureB64 = signature.toString("base64");

  const headers = {
    Signature: `sig1=:${signatureB64}:`,
    "Signature-Input": `sig1=${sigInput}`,
  };

  if (jwksUrl) {
    headers["Signature-Agent"] = jwksUrl;
  }

  return { headers };
}

/**
 * Generate signed headers JSON for use with agent-browser / OpenClaw
 */
export function generateBrowserHeaders(options) {
  const { headers } = signRequest(options);
  return JSON.stringify(headers);
}
