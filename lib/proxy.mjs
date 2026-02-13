/**
 * clawauth Signing Proxy
 *
 * Local MITM proxy that intercepts every outgoing HTTP/HTTPS request
 * and adds fresh RFC 9421 Ed25519 signatures before forwarding.
 *
 * For HTTPS: generates a self-signed CA on first run, then creates
 * per-domain TLS certificates on the fly. Chromium must be launched
 * with certificate error bypass for this to work.
 *
 * Usage:
 *   clawauth proxy [--port 8421] [--verbose]
 *
 * Then:
 *   agent-browser --proxy http://127.0.0.1:8421 open https://example.com
 *
 * All requests (HTTP and HTTPS) get a fresh per-request signature.
 */

import { createServer as createHttpServer, request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { createServer as createTlsServer } from "node:tls";
import { connect } from "node:net";
import {
  createPrivateKey,
  sign as cryptoSign,
  randomUUID,
} from "node:crypto";
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import { execSync } from "node:child_process";

const OBA_DIR = join(homedir(), ".config", "openbotauth");
const KEY_FILE = join(OBA_DIR, "key.json");
const CONFIG_FILE = join(OBA_DIR, "config.json");
const CA_DIR = join(OBA_DIR, "ca");
const CA_KEY_FILE = join(CA_DIR, "ca.key");
const CA_CERT_FILE = join(CA_DIR, "ca.crt");

// ── Credentials ────────────────────────────────────────────────────────────

function loadObaCredentials() {
  if (!existsSync(KEY_FILE)) {
    console.error(`No key found at ${KEY_FILE}. Run: clawauth init`);
    process.exit(1);
  }

  const key = JSON.parse(readFileSync(KEY_FILE, "utf-8"));
  let jwksUrl = null;

  if (existsSync(CONFIG_FILE)) {
    const config = JSON.parse(readFileSync(CONFIG_FILE, "utf-8"));
    jwksUrl = config.jwksUrl || null;
  }

  return { key, jwksUrl };
}

// ── RFC 9421 Signing ───────────────────────────────────────────────────────

function signForRequest(method, authority, path, kid, privateKeyPem, jwksUrl) {
  const created = Math.floor(Date.now() / 1000);
  const expires = created + 300;
  const nonce = randomUUID();

  const lines = [
    `"@method": ${method.toUpperCase()}`,
    `"@authority": ${authority}`,
    `"@path": ${path}`,
  ];

  const sigInput =
    `("@method" "@authority" "@path")` +
    `;created=${created}` +
    `;expires=${expires}` +
    `;nonce="${nonce}"` +
    `;keyid="${kid}"` +
    `;alg="ed25519"`;

  lines.push(`"@signature-params": ${sigInput}`);

  const base = lines.join("\n");
  const pk = createPrivateKey(privateKeyPem);
  const sig = cryptoSign(null, Buffer.from(base), pk).toString("base64");

  const headers = {
    signature: `sig1=:${sig}:`,
    "signature-input": `sig1=${sigInput}`,
  };

  if (jwksUrl) {
    headers["signature-agent"] = jwksUrl;
  }

  return headers;
}

// ── CA Certificate Generation ──────────────────────────────────────────────

function ensureCA() {
  mkdirSync(CA_DIR, { recursive: true, mode: 0o700 });

  if (existsSync(CA_KEY_FILE) && existsSync(CA_CERT_FILE)) {
    return {
      key: readFileSync(CA_KEY_FILE, "utf-8"),
      cert: readFileSync(CA_CERT_FILE, "utf-8"),
    };
  }

  // Generate CA using openssl (available on macOS/Linux)
  console.log("Generating proxy CA certificate (one-time)...");

  execSync(
    `openssl req -x509 -new -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 ` +
      `-keyout "${CA_KEY_FILE}" -out "${CA_CERT_FILE}" -days 3650 ` +
      `-subj "/CN=clawauth Signing Proxy CA/O=OpenBotAuth"`,
    { stdio: "pipe" }
  );

  execSync(`chmod 600 "${CA_KEY_FILE}"`);
  console.log(`  CA key:  ${CA_KEY_FILE}`);
  console.log(`  CA cert: ${CA_CERT_FILE}`);
  console.log("");

  return {
    key: readFileSync(CA_KEY_FILE, "utf-8"),
    cert: readFileSync(CA_CERT_FILE, "utf-8"),
  };
}

// Cache for per-domain TLS contexts
const certCache = new Map();

function getDomainCert(hostname, ca) {
  if (certCache.has(hostname)) return certCache.get(hostname);

  // Generate a per-domain cert signed by our CA using openssl
  const tmpKey = join(CA_DIR, `_tmp_${hostname}.key`);
  const tmpCsr = join(CA_DIR, `_tmp_${hostname}.csr`);
  const tmpCert = join(CA_DIR, `_tmp_${hostname}.crt`);
  const tmpExt = join(CA_DIR, `_tmp_${hostname}.ext`);

  try {
    // Generate domain key
    execSync(
      `openssl ecparam -genkey -name prime256v1 -noout -out "${tmpKey}"`,
      { stdio: "pipe" }
    );

    // Generate CSR
    execSync(
      `openssl req -new -key "${tmpKey}" -out "${tmpCsr}" -subj "/CN=${hostname}"`,
      { stdio: "pipe" }
    );

    // Write extensions file for SAN
    writeFileSync(
      tmpExt,
      `subjectAltName=DNS:${hostname}\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth`
    );

    // Sign with CA (SHA-256 required by modern TLS stacks)
    execSync(
      `openssl x509 -req -sha256 -in "${tmpCsr}" -CA "${CA_CERT_FILE}" -CAkey "${CA_KEY_FILE}" ` +
        `-CAcreateserial -out "${tmpCert}" -days 365 -extfile "${tmpExt}"`,
      { stdio: "pipe" }
    );

    const result = {
      key: readFileSync(tmpKey, "utf-8"),
      cert: readFileSync(tmpCert, "utf-8"),
    };

    certCache.set(hostname, result);
    return result;
  } finally {
    // Clean up temp files
    for (const f of [tmpKey, tmpCsr, tmpCert, tmpExt]) {
      try {
        execSync(`rm -f "${f}"`, { stdio: "pipe" });
      } catch {}
    }
  }
}

// ── Proxy Server ───────────────────────────────────────────────────────────

export function startProxy(options = {}) {
  const port = options.port || 8421;
  const verbose = options.verbose || false;

  const { key: obaKey, jwksUrl } = loadObaCredentials();
  const overrideJwksUrl = options.jwksUrl || jwksUrl;
  const ca = ensureCA();

  let requestCount = 0;

  function log(reqId, msg) {
    if (verbose) console.log(`[${reqId}] ${msg}`);
  }

  const server = createHttpServer((clientReq, clientRes) => {
    // Plain HTTP forward proxy
    const reqId = ++requestCount;
    const url = new URL(clientReq.url);
    const authority = url.host;
    const path = url.pathname + url.search;

    const sigHeaders = signForRequest(
      clientReq.method,
      authority,
      path,
      obaKey.kid,
      obaKey.privateKeyPem,
      overrideJwksUrl
    );

    log(reqId, `HTTP ${clientReq.method} ${authority}${path} → signed`);

    const outHeaders = { ...clientReq.headers };
    delete outHeaders["proxy-connection"];
    delete outHeaders["proxy-authorization"];
    Object.assign(outHeaders, sigHeaders);
    outHeaders.host = authority;

    const reqFn = url.protocol === "https:" ? httpsRequest : httpRequest;
    const proxyReq = reqFn(
      {
        hostname: url.hostname,
        port: url.port || (url.protocol === "https:" ? 443 : 80),
        path: path,
        method: clientReq.method,
        headers: outHeaders,
      },
      (proxyRes) => {
        clientRes.writeHead(proxyRes.statusCode, proxyRes.headers);
        proxyRes.pipe(clientRes);
      }
    );

    proxyReq.on("error", (err) => {
      log(reqId, `Error: ${err.message}`);
      clientRes.writeHead(502);
      clientRes.end("Proxy error");
    });

    clientReq.pipe(proxyReq);
  });

  // HTTPS MITM via CONNECT
  server.on("connect", (req, clientSocket, head) => {
    const reqId = ++requestCount;
    const [hostname, portStr] = req.url.split(":");
    const targetPort = parseInt(portStr) || 443;

    log(reqId, `CONNECT ${hostname}:${targetPort} → MITM`);

    // Tell the client the tunnel is established
    clientSocket.write(
      "HTTP/1.1 200 Connection Established\r\n" +
        "Proxy-Agent: clawauth-proxy\r\n" +
        "\r\n"
    );

    // Generate a TLS cert for this domain and create a local TLS server
    const domainCert = getDomainCert(hostname, ca);

    const tlsServer = createTlsServer(
      { key: domainCert.key, cert: domainCert.cert },
      (tlsSocket) => {
        // Now we see decrypted HTTP requests
        let data = Buffer.alloc(0);

        tlsSocket.on("data", (chunk) => {
          data = Buffer.concat([data, chunk]);

          // Try to parse the HTTP request from the decrypted data
          const headerEnd = data.indexOf("\r\n\r\n");
          if (headerEnd === -1) return; // Need more data

          const headerStr = data.subarray(0, headerEnd).toString();
          const bodyStart = data.subarray(headerEnd + 4);
          const lines = headerStr.split("\r\n");
          const [method, path] = lines[0].split(" ");

          // Parse headers
          const reqHeaders = {};
          for (let i = 1; i < lines.length; i++) {
            const colonIdx = lines[i].indexOf(":");
            if (colonIdx > 0) {
              const name = lines[i].substring(0, colonIdx).trim().toLowerCase();
              const value = lines[i].substring(colonIdx + 1).trim();
              reqHeaders[name] = value;
            }
          }

          // Determine content-length for body
          const contentLength = parseInt(reqHeaders["content-length"]) || 0;
          const fullPath = path || "/";

          // Sign this request
          const sigHeaders = signForRequest(
            method,
            hostname + (targetPort !== 443 ? `:${targetPort}` : ""),
            fullPath,
            obaKey.kid,
            obaKey.privateKeyPem,
            overrideJwksUrl
          );

          log(reqId, `HTTPS ${method} ${hostname}${fullPath} → signed`);

          // Merge signature headers
          Object.assign(reqHeaders, sigHeaders);

          // Forward via real HTTPS to target
          const proxyReq = httpsRequest(
            {
              hostname,
              port: targetPort,
              path: fullPath,
              method,
              headers: reqHeaders,
              rejectUnauthorized: true,
            },
            (proxyRes) => {
              // Build HTTP response to send back through TLS
              let response = `HTTP/1.1 ${proxyRes.statusCode} ${proxyRes.statusMessage}\r\n`;
              const resHeaders = proxyRes.rawHeaders;
              for (let i = 0; i < resHeaders.length; i += 2) {
                response += `${resHeaders[i]}: ${resHeaders[i + 1]}\r\n`;
              }
              response += "\r\n";

              tlsSocket.write(response);
              proxyRes.pipe(tlsSocket);
            }
          );

          proxyReq.on("error", (err) => {
            log(reqId, `HTTPS proxy error: ${err.message}`);
            tlsSocket.end(
              "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"
            );
          });

          if (bodyStart.length > 0) {
            proxyReq.write(bodyStart);
          }

          // If there's more body to come, pipe it
          if (contentLength > bodyStart.length) {
            tlsSocket.on("data", (moreData) => {
              proxyReq.write(moreData);
            });
          }

          // Use a short timeout to flush remaining body
          if (contentLength <= bodyStart.length) {
            proxyReq.end();
          } else {
            // Wait for remaining body
            let received = bodyStart.length;
            const bodyHandler = (moreData) => {
              received += moreData.length;
              proxyReq.write(moreData);
              if (received >= contentLength) {
                proxyReq.end();
                tlsSocket.removeListener("data", bodyHandler);
              }
            };
            tlsSocket.on("data", bodyHandler);
          }
        });
      }
    );

    // Connect the client socket to our local TLS server via a socket pair
    const { port: tlsPort } = tlsServer.listen(0, "127.0.0.1", () => {
      const localConn = connect(tlsServer.address().port, "127.0.0.1", () => {
        localConn.write(head);
        localConn.pipe(clientSocket);
        clientSocket.pipe(localConn);
      });

      localConn.on("error", () => clientSocket.end());
      clientSocket.on("error", () => localConn.end());
      clientSocket.on("close", () => {
        tlsServer.close();
        localConn.end();
      });
    });
  });

  server.listen(port, "127.0.0.1", () => {
    console.log(`clawauth signing proxy on http://127.0.0.1:${port}`);
    console.log(`  kid: ${obaKey.kid}`);
    if (overrideJwksUrl) console.log(`  Signature-Agent: ${overrideJwksUrl}`);
    console.log(`  CA cert: ${CA_CERT_FILE}`);
    console.log("");
    console.log("Usage with agent-browser:");
    console.log(`  agent-browser --proxy http://127.0.0.1:${port} open <url>`);
    console.log("");
    console.log("Every request (HTTP and HTTPS) gets a fresh RFC 9421 signature.");
    console.log("Press Ctrl+C to stop.\n");
  });

  return server;
}

// ── Direct invocation ──────────────────────────────────────────────────────

const isDirectRun =
  process.argv[1]?.endsWith("proxy.mjs") ||
  process.argv[1]?.includes("clawauth") && process.argv[2] === "proxy";

if (isDirectRun && process.argv[2] !== "proxy") {
  // Running as: node lib/proxy.mjs [flags]
  const args = process.argv.slice(2);
  const getFlag = (flag) => {
    const idx = args.indexOf(flag);
    return idx !== -1 && idx + 1 < args.length ? args[idx + 1] : null;
  };

  startProxy({
    port: parseInt(getFlag("--port")) || 8421,
    jwksUrl: getFlag("--jwks") || null,
    verbose: args.includes("--verbose") || args.includes("-v"),
  });
}
