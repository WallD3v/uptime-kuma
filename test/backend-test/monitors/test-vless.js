const { test } = require("node:test");
const assert = require("node:assert/strict");
const { parseVlessUri } = require("../../../server/monitor-types/vless");

const uuid = "5783a3e7-e373-51cd-8642-b83782b807c5";

test("VLESS TCP with REALITY creates an authenticated raw outbound", () => {
    const outbound = parseVlessUri(`vless://${uuid}@example.com:443?type=tcp&security=reality&pbk=public-key&sid=01234567&sni=example.com&fp=chrome&flow=xtls-rprx-vision`);
    assert.equal(outbound.settings.id, uuid);
    assert.equal(outbound.settings.flow, "xtls-rprx-vision");
    assert.equal(outbound.streamSettings.method, "raw");
    assert.deepEqual(outbound.streamSettings.realitySettings, {
        password: "public-key",
        serverName: "example.com",
        fingerprint: "chrome",
        shortId: "01234567",
        spiderX: "",
    });
});

test("VLESS gRPC and XHTTP preserve transport options", () => {
    const grpc = parseVlessUri(`vless://${uuid}@example.com:443?type=grpc&security=tls&serviceName=service&authority=cdn.example.com`);
    assert.deepEqual(grpc.streamSettings.grpcSettings, { serviceName: "service", authority: "cdn.example.com" });
    const xhttp = parseVlessUri(`vless://${uuid}@example.com:443?type=xhttp&security=tls&path=%2Fproxy&host=cdn.example.com&mode=stream-up`);
    assert.deepEqual(xhttp.streamSettings.xhttpSettings, { path: "/proxy", host: "cdn.example.com", mode: "stream-up" });
});

test("VLESS links with missing credentials or unsupported transports fail", () => {
    assert.throws(() => parseVlessUri("vless://example.com:443"), /UUID/);
    assert.throws(() => parseVlessUri(`vless://${uuid}@example.com:443?type=ws`), /Unsupported/);
    assert.throws(() => parseVlessUri(`vless://${uuid}@example.com:443?security=reality`), /pbk and sni/);
});
