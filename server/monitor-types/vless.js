const { MonitorType } = require("./monitor-type");
const { UP } = require("../../src/util");
const { spawn } = require("child_process");
const { mkdtemp, writeFile, rm } = require("fs/promises");
const { tmpdir } = require("os");
const path = require("path");
const net = require("net");
const http = require("http");

const DEFAULT_PROBE = "http://www.gstatic.com/generate_204";

/**
 * Convert a VLESS share link into an Xray outbound.
 * @param {string} value VLESS share link
 * @returns {object} Xray outbound configuration
 * @throws {Error} If the link is invalid or unsupported
 */
function parseVlessUri(value) {
    let uri;
    try {
        uri = new URL(value);
    } catch {
        throw new Error("Invalid VLESS URI");
    }
    if (uri.protocol !== "vless:" || !uri.hostname || !Number.isInteger(Number(uri.port)) || Number(uri.port) < 1 || Number(uri.port) > 65535 || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(decodeURIComponent(uri.username))) {
        throw new Error("VLESS URI requires a UUID, hostname and port");
    }

    const q = uri.searchParams;
    const type = q.get("type") || "tcp";
    const security = q.get("security") || "none";
    if (!["tcp", "grpc", "xhttp"].includes(type) || !["none", "tls", "reality"].includes(security)) {
        throw new Error("Unsupported VLESS transport or security");
    }
    const streamSettings = { method: type === "tcp" ? "raw" : type, security };
    if (security === "reality") {
        const publicKey = q.get("pbk");
        const serverName = q.get("sni");
        if (!publicKey || !serverName) {
            throw new Error("REALITY requires pbk and sni");
        }
        streamSettings.realitySettings = {
            password: publicKey,
            serverName,
            fingerprint: q.get("fp") || "chrome",
            shortId: q.get("sid") || "",
            spiderX: q.get("spx") || "",
        };
    } else if (security === "tls") {
        streamSettings.tlsSettings = { serverName: q.get("sni") || uri.hostname };
        if (q.get("fp")) {
            streamSettings.tlsSettings.fingerprint = q.get("fp");
        }
        if (q.get("alpn")) {
            streamSettings.tlsSettings.alpn = q.get("alpn").split(",");
        }
    }
    if (type === "grpc") {
        streamSettings.grpcSettings = {
            serviceName: q.get("serviceName") || "",
            ...(q.get("authority") ? { authority: q.get("authority") } : {}),
        };
    } else if (type === "xhttp") {
        streamSettings.xhttpSettings = {
            path: q.get("path") || "/",
            ...(q.get("host") ? { host: q.get("host") } : {}),
            ...(q.get("mode") ? { mode: q.get("mode") } : {}),
        };
    }

    const flow = q.get("flow");
    if (flow && flow !== "xtls-rprx-vision") {
        throw new Error("Unsupported VLESS flow");
    }
    return {
        protocol: "vless",
        settings: {
            address: uri.hostname,
            port: Number(uri.port),
            id: decodeURIComponent(uri.username),
            encryption: q.get("encryption") || "none",
            ...(flow ? { flow } : {}),
        },
        streamSettings,
    };
}

/**
 * Reserve an unused loopback port for a short lived Xray process.
 * @returns {Promise<number>} Available port
 */
async function freePort() {
    const server = net.createServer();
    await new Promise((resolve, reject) => server.once("error", reject).listen(0, "127.0.0.1", resolve));
    const port = server.address().port;
    await new Promise((resolve) => server.close(resolve));
    return port;
}

/**
 * Send an HTTP request through Xray's local HTTP proxy.
 * @param {number} port Local proxy port
 * @param {string} target HTTP target URL
 * @param {number} timeoutMs Check timeout
 * @param {import("child_process").ChildProcess} child Xray process
 * @returns {Promise<void>} Resolves on a successful response
 */
async function probe(port, target, timeoutMs, child) {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
        if (child.spawnError) {
            throw new Error(`Cannot start Xray: ${child.spawnError.code}`);
        }
        if (child.exitCode !== null) {
            throw new Error("Xray exited before the probe");
        }
        try {
            await new Promise((resolve, reject) => {
                const req = http.get({ host: "127.0.0.1", port, path: target, headers: { Host: new URL(target).host }, timeout: Math.min(3000, deadline - Date.now()) }, (res) => {
                    res.resume();
                    if (res.statusCode >= 200 && res.statusCode < 300) {
                        resolve();
                    } else {
                        reject(new Error(`Probe returned HTTP ${res.statusCode}`));
                    }
                });
                req.on("timeout", () => req.destroy(new Error("Probe timed out")));
                req.on("error", reject);
            });
            return;
        } catch (error) {
            if (error.code !== "ECONNREFUSED") {
                throw error;
            }
            await new Promise((resolve) => setTimeout(resolve, 100));
        }
    }
    throw new Error("Xray did not start before timeout");
}

class VlessMonitorType extends MonitorType {
    name = "vless";

    /**
     * @inheritdoc
     */
    async check(monitor, heartbeat) {
        const outbound = parseVlessUri(monitor.url);
        const target = monitor.hostname || DEFAULT_PROBE;
        let probeUrl;
        try {
            probeUrl = new URL(target);
        } catch {
            throw new Error("Invalid probe URL");
        }
        if (probeUrl.protocol !== "http:") {
            throw new Error("Probe URL must use HTTP");
        }

        const timeoutMs = Math.max(1000, (Number(monitor.timeout) || 20) * 1000);
        const port = await freePort();
        const dir = await mkdtemp(path.join(tmpdir(), "uptime-kuma-vless-"));
        const configPath = path.join(dir, "config.json");
        const config = {
            log: { loglevel: "warning" },
            inbounds: [{ listen: "127.0.0.1", port, protocol: "http", tag: "probe" }],
            outbounds: [{ ...outbound, tag: "vless" }],
            routing: { rules: [{ type: "field", inboundTag: ["probe"], outboundTag: "vless" }] },
        };
        let child;
        try {
            await writeFile(configPath, JSON.stringify(config), { mode: 0o600 });
            const start = Date.now();
            child = spawn(process.env.XRAY_BINARY || "xray", ["run", "-config", configPath], { stdio: "ignore" });
            child.on("error", (error) => {
                child.spawnError = error;
            });
            await probe(port, probeUrl.href, timeoutMs, child);
            heartbeat.ping = Date.now() - start;
            heartbeat.msg = `${heartbeat.ping} ms`;
            heartbeat.status = UP;
        } finally {
            if (child && child.exitCode === null) {
                child.kill();
            }
            await rm(dir, { recursive: true, force: true });
        }
    }
}

module.exports = { VlessMonitorType, parseVlessUri };
