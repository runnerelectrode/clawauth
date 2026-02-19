/**
 * clawauth Signing Proxy — Multi-Agent
 *
 * Local MITM proxy that intercepts every outgoing HTTP/HTTPS request
 * and adds fresh RFC 9421 Ed25519 signatures before forwarding.
 *
 * Multi-agent: each agent gets its own signing key, selected via the
 * proxy URL username. Set HTTP_PROXY=http://agentid@127.0.0.1:8421
 * and the proxy signs with that agent's key.
 *
 * Key directory layout (--keys-dir):
 *   keys/
 *     tars/key.json + config.json
 *     case/key.json + config.json
 *     kipp/key.json + config.json
 *
 * Falls back to single-key mode (~/.config/openbotauth/key.json)
 * when no --keys-dir is provided.
 *
 * Security:
 *   - execFileSync (no shell) for all openssl calls
 *   - Hostname validation (regex + isIP)
 *   - SHA-256 hashed filenames (no path traversal)
 *   - SSRF protection (private/reserved IP blocking, resolve-once)
 *   - Header buffer size cap (64KB)
 *   - Connection: close (no keep-alive until parser supports it)
 *   - Connection timeouts (2 min)
 *
 * Usage:
 *   # Single-key (backward compatible):
 *   clawauth proxy [--port 8421] [--verbose]
 *
 *   # Multi-agent:
 *   clawauth proxy --keys-dir ./keys --default-agent tars [--port 8421]
 *
 *   # Agent-specific proxy URL:
 *   HTTP_PROXY=http://tars@127.0.0.1:8421 curl https://example.com
 *   HTTP_PROXY=http://case@127.0.0.1:8421 curl https://example.com
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
import { readFileSync, writeFileSync, existsSync, mkdirSync, unlinkSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import { execFileSync } from "node:child_process";
import { lookup } from "node:dns/promises";

const OBA_DIR = join(homedir(), ".config", "openbotauth");
const CA_DIR = join(OBA_DIR, "ca");
const CA_KEY_FILE = join(CA_DIR, "ca.key");
const CA_CERT_FILE = join(CA_DIR, "ca.crt");

const MAX_HEADER_SIZE = 64 * 1024;
const CONNECTION_TIMEOUT_MS = 120_000;

// ── SSRF Protection ─────────────────────────────────────────────────────────

function isPrivateIP(ip) {
  if (!ip) return true;
  if (/^127\./.test(ip)) return true;
  if (/^10\./.test(ip)) return true;
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(ip)) return true;
  if (/^192\.168\./.test(ip)) return true;
  if (/^169\.254\./.test(ip)) return true;
  if (/^0\./.test(ip)) return true;
  if (ip === "255.255.255.255") return true;
  if (/^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./.test(ip)) return true;
  if (/^192\.0\.0\./.test(ip)) return true;
  if (/^198\.1[89]\./.test(ip)) return true;
  if (/^203\.0\.113\./.test(ip)) return true;
  if (/^(22[4-9]|2[3-5]\d)\./.test(ip)) return true;
  if (/^(::1|fc|fd|fe80)/i.test(ip)) return true;
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

// ── Multi-Agent Key Loading ─────────────────────────────────────────────────

function loadSingleAgent(keyFile, configFile) {
  if (!existsSync(keyFile)) return null;
  const key = JSON.parse(readFileSync(keyFile, "utf-8"));
  let jwksUrl = null;
  if (configFile && existsSync(configFile)) {
    const config = JSON.parse(readFileSync(configFile, "utf-8"));
    jwksUrl = config.jwksUrl || null;
  }
  return {
    kid: key.kid,
    privateKey: createPrivateKey(key.privateKeyPem),
    jwksUrl,
  };
}

function loadAgentKeys(options = {}) {
  const agents = new Map();

  if (options.keysDir && existsSync(options.keysDir)) {
    // Multi-agent: load from keysDir/{agentId}/key.json
    const entries = readdirSync(options.keysDir);
    for (const entry of entries) {
      const dir = join(options.keysDir, entry);
      if (!statSync(dir).isDirectory()) continue;
      const agent = loadSingleAgent(join(dir, "key.json"), join(dir, "config.json"));
      if (agent) {
        agents.set(entry, agent);
      }
    }
  }

  if (options.agents) {
    // Programmatic: explicit agent map
    for (const [id, conf] of Object.entries(options.agents)) {
      const agent = loadSingleAgent(conf.keyFile, conf.configFile);
      if (agent) agents.set(id, agent);
    }
  }

  // Fallback: single-key mode from ~/.config/openbotauth/
  if (agents.size === 0) {
    const keyFile = join(OBA_DIR, "key.json");
    const configFile = join(OBA_DIR, "config.json");
    const agent = loadSingleAgent(keyFile, configFile);
    if (!agent) {
      console.error(`No keys found. Provide --keys-dir or place key.json in ${OBA_DIR}`);
      process.exit(1);
    }
    agents.set("default", agent);
  }

  return agents;
}

// ── Agent Selection from Proxy-Authorization ────────────────────────────────

function extractAgentId(headers) {
  const authHeader = headers["proxy-authorization"];
  if (!authHeader) return null;
  // Proxy-Authorization: Basic <base64(username:password)>
  const match = authHeader.match(/^Basic\s+(.+)$/i);
  if (!match) return null;
  try {
    const decoded = Buffer.from(match[1], "base64").toString();
    const username = decoded.split(":")[0];
    return username || null;
  } catch { return null; }
}

// ── RFC 9421 Signing ────────────────────────────────────────────────────────

function signForRequest(method, authority, path, agent) {
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
    `;keyid="${agent.kid}"` +
    `;alg="ed25519"`;

  lines.push(`"@signature-params": ${sigInput}`);

  const base = lines.join("\n");
  const sig = cryptoSign(null, Buffer.from(base), agent.privateKey).toString("base64");

  const headers = {
    signature: `sig1=:${sig}:`,
    "signature-input": `sig1=${sigInput}`,
  };

  if (agent.jwksUrl) {
    headers["signature-agent"] = agent.jwksUrl;
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
  const bindAddresses = options.bind || ["127.0.0.1"];
  const verbose = options.verbose || false;

  const agents = loadAgentKeys(options);
  const defaultAgentId = options.defaultAgent || agents.keys().next().value;
  const defaultAgent = agents.get(defaultAgentId);

  if (!defaultAgent) {
    console.error(`Default agent "${defaultAgentId}" not found. Available: ${[...agents.keys()].join(", ")}`);
    process.exit(1);
  }

  // Apply jwksUrl override to all agents if provided
  if (options.jwksUrl) {
    for (const agent of agents.values()) {
      agent.jwksUrl = options.jwksUrl;
    }
  }

  const ca = ensureCA();
  let requestCount = 0;

  function log(reqId, msg) {
    if (verbose) console.log(`[${reqId}] ${msg}`);
  }

  function resolveAgent(headers) {
    const agentId = extractAgentId(headers);
    if (agentId && agents.has(agentId)) return { id: agentId, agent: agents.get(agentId) };
    return { id: defaultAgentId, agent: defaultAgent };
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

      const { id: agentId, agent } = resolveAgent(clientReq.headers);
      const sigHeaders = signForRequest(clientReq.method, authority, path, agent);

      log(reqId, `HTTP ${clientReq.method} ${authority}${path} → signed [${agentId}] (${resolvedIP})`);

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

    if (!isValidHostname(hostname) || targetPort < 1 || targetPort > 65535) {
      log(reqId, `CONNECT rejected: invalid ${hostname}:${targetPort}`);
      clientSocket.write("HTTP/1.1 400 Bad Request\r\n\r\n");
      clientSocket.end();
      return;
    }

    let resolvedIP;
    try {
      resolvedIP = await resolveAndCheck(hostname);
    } catch (e) {
      log(reqId, `CONNECT blocked: ${e.message}`);
      clientSocket.write("HTTP/1.1 403 Forbidden\r\n\r\n");
      clientSocket.end();
      return;
    }

    // Resolve agent from CONNECT request headers
    const { id: agentId, agent } = resolveAgent(req.headers);

    log(reqId, `CONNECT ${hostname}:${targetPort} → MITM [${agentId}] (${resolvedIP})`);

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

          // Sign with the agent resolved from the CONNECT request
          const sigHeaders = signForRequest(
            method,
            hostname + (targetPort !== 443 ? `:${targetPort}` : ""),
            fullPath,
            agent
          );

          log(reqId, `HTTPS ${method} ${hostname}${fullPath} → signed [${agentId}]`);

          Object.assign(reqHeaders, sigHeaders);
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

  // Listen on first address, then add remaining
  const primaryBind = bindAddresses[0];
  server.listen(port, primaryBind, () => {
    const addrs = bindAddresses.map(a => `http://${a}:${port}`).join(", ");
    console.log(`clawauth signing proxy on ${addrs}`);
    console.log(`  agents: ${[...agents.keys()].join(", ")} (default: ${defaultAgentId})`);
    for (const [id, agent] of agents) {
      console.log(`    ${id}: kid=${agent.kid}${agent.jwksUrl ? ` → ${agent.jwksUrl}` : ""}`);
    }
    console.log(`  CA cert: ${CA_CERT_FILE}`);
    console.log(`  SSRF protection: enabled`);
    console.log("");
    console.log("Usage:");
    console.log(`  # Default agent:`);
    console.log(`  HTTP_PROXY=http://${primaryBind}:${port} curl https://example.com`);
    if (agents.size > 1) {
      const exampleAgent = [...agents.keys()].find(k => k !== defaultAgentId) || defaultAgentId;
      console.log(`  # Specific agent:`);
      console.log(`  HTTP_PROXY=http://${exampleAgent}@${primaryBind}:${port} curl https://example.com`);
    }
    console.log("");
    console.log("Every request gets a fresh RFC 9421 signature.\n");

    // Bind additional addresses using the same server socket
    for (let i = 1; i < bindAddresses.length; i++) {
      const extraServer = createHttpServer(server.listeners("request")[0]);
      extraServer.on("connect", server.listeners("connect")[0]);
      extraServer.listen(port, bindAddresses[i], () => {
        console.log(`  Also listening on http://${bindAddresses[i]}:${port}`);
      });
    }
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

  // Collect all --bind flags
  const bindAddrs = [];
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--bind" && i + 1 < args.length) bindAddrs.push(args[++i]);
  }

  startProxy({
    port: parseInt(getFlag("--port")) || 8421,
    bind: bindAddrs.length > 0 ? bindAddrs : ["127.0.0.1"],
    keysDir: getFlag("--keys-dir") || null,
    defaultAgent: getFlag("--default-agent") || null,
    jwksUrl: getFlag("--jwks") || null,
    verbose: args.includes("--verbose") || args.includes("-v"),
  });
}
