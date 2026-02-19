/**
 * clawauth Signing Proxy
 *
 * Local MITM proxy that intercepts every outgoing HTTP/HTTPS request
 * and adds fresh RFC 9421 Ed25519 signatures before forwarding.
 *
 * Security hardening:
 *   - execFileSync (no shell) for all openssl calls
 *   - Hostname validation (regex + isIP)
 *   - SHA-256 hashed filenames (no path traversal)
 *   - SSRF protection (private/reserved IP blocking)
 *   - Header buffer size cap (64KB)
 *   - Connection: close (no keep-alive until parser supports it)
 *   - Connection timeouts (2 min)
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
import { connect, isIP } from "node:net";
import {
  createPrivateKey,
  sign as cryptoSign,
  randomUUID,
  createHash,
} from "node:crypto";
import { readFileSync, writeFileSync, existsSync, mkdirSync, unlinkSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import { execFileSync } from "node:child_process";
import { lookup } from "node:dns/promises";

const OBA_DIR = join(homedir(), ".config", "openbotauth");
const KEY_FILE = join(OBA_DIR, "key.json");
const CONFIG_FILE = join(OBA_DIR, "config.json");
const CA_DIR = join(OBA_DIR, "ca");
const CA_KEY_FILE = join(CA_DIR, "ca.key");
const CA_CERT_FILE = join(CA_DIR, "ca.crt");

const MAX_HEADER_SIZE = 64 * 1024; // 64KB max header buffer
const CONNECTION_TIMEOUT_MS = 120_000; // 2 minute connection timeout

// ── SSRF Protection ─────────────────────────────────────────────────────────

function isPrivateIP(ip) {
  if (!ip) return true;
  // IPv4 private/reserved ranges
  if (/^127\./.test(ip)) return true;                         // loopback
  if (/^10\./.test(ip)) return true;                          // RFC 1918
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(ip)) return true;    // RFC 1918
  if (/^192\.168\./.test(ip)) return true;                    // RFC 1918
  if (/^169\.254\./.test(ip)) return true;                    // link-local
  if (/^0\./.test(ip)) return true;                           // current network
  if (ip === "255.255.255.255") return true;                  // broadcast
  if (/^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./.test(ip)) return true; // CGN (100.64/10)
  if (/^192\.0\.0\./.test(ip)) return true;                   // IETF protocol assignments
  if (/^198\.1[89]\./.test(ip)) return true;                  // benchmark testing
  if (/^203\.0\.113\./.test(ip)) return true;                 // documentation
  if (/^(22[4-9]|2[3-5]\d)\./.test(ip)) return true;         // multicast + reserved
  // IPv6 private/reserved
  if (/^(::1|fc|fd|fe80)/i.test(ip)) return true;            // loopback, ULA, link-local
  if (/^::ffff:(127\.|10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|169\.254\.)/.test(ip)) return true;
  return false;
}

async function resolveAndCheck(hostname) {
  if (isIP(hostname)) {
    if (isPrivateIP(hostname)) throw new Error(`SSRF blocked: private IP`);
    return hostname;
  }
  try {
    const { address } = await lookup(hostname);
    if (isPrivateIP(address)) throw new Error(`SSRF blocked: private IP`);
    return address;
  } catch (e) {
    if (e.message.startsWith("SSRF")) throw e;
    throw new Error(`DNS resolution failed for ${hostname}: ${e.code || e.message}`);
  }
}

// ── Hostname Validation ─────────────────────────────────────────────────────

const HOSTNAME_RE = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
function isValidHostname(h) {
  return typeof h === "string" && h.length > 0 && h.length <= 253 && (HOSTNAME_RE.test(h) || isIP(h) > 0);
}

// ── Credentials ─────────────────────────────────────────────────────────────

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

// ── RFC 9421 Signing ────────────────────────────────────────────────────────

// Cache parsed private keys to avoid PEM parsing on every request
const keyCache = new Map();
function getPrivateKey(privateKeyPem) {
  if (keyCache.has(privateKeyPem)) return keyCache.get(privateKeyPem);
  const pk = createPrivateKey(privateKeyPem);
  keyCache.set(privateKeyPem, pk);
  return pk;
}

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
  const pk = getPrivateKey(privateKeyPem);
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

// ── CA Certificate Generation ───────────────────────────────────────────────

function ensureCA() {
  mkdirSync(CA_DIR, { recursive: true, mode: 0o700 });

  if (existsSync(CA_KEY_FILE) && existsSync(CA_CERT_FILE)) {
    return {
      key: readFileSync(CA_KEY_FILE, "utf-8"),
      cert: readFileSync(CA_CERT_FILE, "utf-8"),
    };
  }

  console.log("Generating proxy CA certificate (one-time)...");

  execFileSync("openssl", [
    "req", "-x509", "-new", "-nodes",
    "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
    "-keyout", CA_KEY_FILE, "-out", CA_CERT_FILE,
    "-days", "3650",
    "-subj", "/CN=clawauth Signing Proxy CA/O=OpenBotAuth",
  ], { stdio: "pipe" });

  execFileSync("chmod", ["600", CA_KEY_FILE], { stdio: "pipe" });
  console.log(`  CA key:  ${CA_KEY_FILE}`);
  console.log(`  CA cert: ${CA_CERT_FILE}`);
  console.log("");

  return {
    key: readFileSync(CA_KEY_FILE, "utf-8"),
    cert: readFileSync(CA_CERT_FILE, "utf-8"),
  };
}

// Cache for per-domain TLS contexts (hashed filenames prevent path traversal)
const certCache = new Map();

function getDomainCert(hostname, ca) {
  if (!isValidHostname(hostname)) throw new Error("Invalid hostname: " + hostname.slice(0, 50));
  if (certCache.has(hostname)) return certCache.get(hostname);

  const hHash = createHash("sha256").update(hostname).digest("hex").slice(0, 16);
  const tmpKey = join(CA_DIR, `_t_${hHash}.key`);
  const tmpCsr = join(CA_DIR, `_t_${hHash}.csr`);
  const tmpCert = join(CA_DIR, `_t_${hHash}.crt`);
  const tmpExt = join(CA_DIR, `_t_${hHash}.ext`);

  try {
    execFileSync("openssl", [
      "ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", tmpKey,
    ], { stdio: "pipe" });

    execFileSync("openssl", [
      "req", "-new", "-key", tmpKey, "-out", tmpCsr, "-subj", `/CN=${hostname}`,
    ], { stdio: "pipe" });

    writeFileSync(
      tmpExt,
      `subjectAltName=DNS:${hostname}\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth`
    );

    execFileSync("openssl", [
      "x509", "-req", "-sha256", "-in", tmpCsr,
      "-CA", CA_CERT_FILE, "-CAkey", CA_KEY_FILE,
      "-CAcreateserial", "-out", tmpCert,
      "-days", "365", "-extfile", tmpExt,
    ], { stdio: "pipe" });

    const result = {
      key: readFileSync(tmpKey, "utf-8"),
      cert: readFileSync(tmpCert, "utf-8"),
    };

    certCache.set(hostname, result);
    return result;
  } finally {
    for (const f of [tmpKey, tmpCsr, tmpCert, tmpExt]) {
      try { unlinkSync(f); } catch {}
    }
  }
}

// ── Proxy Server ────────────────────────────────────────────────────────────

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

  const server = createHttpServer(async (clientReq, clientRes) => {
    const reqId = ++requestCount;

    try {
      const url = new URL(clientReq.url);
      const authority = url.host;
      const path = url.pathname + url.search;

      if (!isValidHostname(url.hostname)) {
        clientRes.writeHead(400); clientRes.end("Invalid hostname"); return;
      }
      const resolvedIP = await resolveAndCheck(url.hostname);

      const sigHeaders = signForRequest(
        clientReq.method, authority, path,
        obaKey.kid, obaKey.privateKeyPem, overrideJwksUrl
      );

      log(reqId, `HTTP ${clientReq.method} ${authority}${path} → signed (${resolvedIP})`);

      const outHeaders = { ...clientReq.headers };
      delete outHeaders["proxy-connection"];
      delete outHeaders["proxy-authorization"];
      Object.assign(outHeaders, sigHeaders);
      outHeaders.host = authority;

      const reqFn = url.protocol === "https:" ? httpsRequest : httpRequest;
      const proxyReq = reqFn(
        {
          hostname: resolvedIP,
          servername: url.hostname,
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
        if (!clientRes.headersSent) { clientRes.writeHead(502); clientRes.end("Proxy error"); }
      });

      clientReq.pipe(proxyReq);
    } catch (e) {
      log(reqId, `Blocked: ${e.message}`);
      if (!clientRes.headersSent) { clientRes.writeHead(403); clientRes.end(e.message); }
    }
  });

  // HTTPS MITM via CONNECT
  server.on("connect", async (req, clientSocket, head) => {
    const reqId = ++requestCount;
    const [hostname, portStr] = req.url.split(":");
    const targetPort = parseInt(portStr) || 443;

    // Validate hostname and port
    if (!isValidHostname(hostname) || targetPort < 1 || targetPort > 65535) {
      log(reqId, `CONNECT rejected: invalid ${hostname}:${targetPort}`);
      clientSocket.write("HTTP/1.1 400 Bad Request\r\n\r\n");
      clientSocket.end();
      return;
    }

    // SSRF check — resolve once, reuse IP for connection
    let resolvedIP;
    try {
      resolvedIP = await resolveAndCheck(hostname);
    } catch (e) {
      log(reqId, `CONNECT blocked: ${e.message}`);
      clientSocket.write("HTTP/1.1 403 Forbidden\r\n\r\n");
      clientSocket.end();
      return;
    }

    log(reqId, `CONNECT ${hostname}:${targetPort} → MITM (${resolvedIP})`);

    clientSocket.write(
      "HTTP/1.1 200 Connection Established\r\n" +
        "Proxy-Agent: clawauth-proxy\r\n" +
        "\r\n"
    );

    const domainCert = getDomainCert(hostname, ca);

    const tlsServer = createTlsServer(
      { key: domainCert.key, cert: domainCert.cert },
      (tlsSocket) => {
        let data = Buffer.alloc(0);

        tlsSocket.on("data", (chunk) => {
          data = Buffer.concat([data, chunk]);

          // Buffer size cap
          if (data.length > MAX_HEADER_SIZE) {
            log(reqId, "Header too large, dropping connection");
            tlsSocket.end("HTTP/1.1 431 Request Header Fields Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            return;
          }

          const headerEnd = data.indexOf("\r\n\r\n");
          if (headerEnd === -1) return;

          const headerStr = data.subarray(0, headerEnd).toString();
          const bodyStart = data.subarray(headerEnd + 4);
          const lines = headerStr.split("\r\n");
          const [method, path] = lines[0].split(" ");

          const reqHeaders = {};
          for (let i = 1; i < lines.length; i++) {
            const colonIdx = lines[i].indexOf(":");
            if (colonIdx > 0) {
              const name = lines[i].substring(0, colonIdx).trim().toLowerCase();
              const value = lines[i].substring(colonIdx + 1).trim();
              reqHeaders[name] = value;
            }
          }

          const contentLength = parseInt(reqHeaders["content-length"]) || 0;
          const fullPath = path || "/";

          const sigHeaders = signForRequest(
            method,
            hostname + (targetPort !== 443 ? `:${targetPort}` : ""),
            fullPath,
            obaKey.kid, obaKey.privateKeyPem, overrideJwksUrl
          );

          log(reqId, `HTTPS ${method} ${hostname}${fullPath} → signed`);

          Object.assign(reqHeaders, sigHeaders);
          // Force Connection: close — no keep-alive until parser supports it
          reqHeaders["connection"] = "close";

          reqHeaders["host"] = hostname + (targetPort !== 443 ? `:${targetPort}` : "");
          const proxyReq = httpsRequest(
            {
              hostname: resolvedIP,
              servername: hostname,
              port: targetPort,
              path: fullPath,
              method,
              headers: reqHeaders,
              rejectUnauthorized: true,
            },
            (proxyRes) => {
              let response = `HTTP/1.1 ${proxyRes.statusCode} ${proxyRes.statusMessage}\r\n`;
              const resHeaders = proxyRes.rawHeaders;
              for (let i = 0; i < resHeaders.length; i += 2) {
                response += `${resHeaders[i]}: ${resHeaders[i + 1]}\r\n`;
              }
              response += "Connection: close\r\n";
              response += "\r\n";

              tlsSocket.write(response);
              proxyRes.pipe(tlsSocket);
            }
          );

          proxyReq.on("error", (err) => {
            log(reqId, `HTTPS proxy error: ${err.message}`);
            tlsSocket.end(
              "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
          });

          if (bodyStart.length > 0) {
            proxyReq.write(bodyStart);
          }

          if (contentLength <= bodyStart.length) {
            proxyReq.end();
          } else {
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

    // Connection timeout
    const connTimeout = setTimeout(() => {
      log(reqId, "Connection timeout, closing");
      clientSocket.end();
    }, CONNECTION_TIMEOUT_MS);

    tlsServer.listen(0, "127.0.0.1", () => {
      const localConn = connect(tlsServer.address().port, "127.0.0.1", () => {
        localConn.write(head);
        localConn.pipe(clientSocket);
        clientSocket.pipe(localConn);
      });

      localConn.on("error", () => clientSocket.end());
      clientSocket.on("error", () => localConn.end());
      clientSocket.on("close", () => {
        clearTimeout(connTimeout);
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
    console.log(`  SSRF protection: enabled (private/reserved IPs blocked)`);
    console.log("");
    console.log("Usage with agent-browser:");
    console.log(`  agent-browser --proxy http://127.0.0.1:${port} open <url>`);
    console.log("");
    console.log("Every request (HTTP and HTTPS) gets a fresh RFC 9421 signature.");
    console.log("Press Ctrl+C to stop.\n");
  });

  return server;
}

// ── Direct invocation ───────────────────────────────────────────────────────

const isDirectRun =
  process.argv[1]?.endsWith("proxy.mjs") ||
  process.argv[1]?.includes("clawauth") && process.argv[2] === "proxy";

if (isDirectRun && process.argv[2] !== "proxy") {
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
