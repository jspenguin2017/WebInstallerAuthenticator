#!/usr/bin/env node

// MIT License
//
// Copyright (c) 2018 Hugo Xu
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.

// -------------------------------------------------------------------------- //

// Main script

// -------------------------------------------------------------------------- //

"use strict";

// -------------------------------------------------------------------------- //

const DEBUG = false;

// -------------------------------------------------------------------------- //

const SEPARATOR = "=".repeat(80);

// -------------------------------------------------------------------------- //

const assert = require("assert");
const crypto = require("crypto");
const fs = require("fs");
const http = require("http");
const https = require("https");
const url = require("url");

// -------------------------------------------------------------------------- //

const keyMake = (bytes = 32) => {
    assert(Number.isInteger(bytes));
    assert(16 < bytes && bytes < 2048);

    return crypto.randomBytes(bytes).toString("hex");
};

const key = keyMake();
const keyEncoded = Buffer.from("user:" + key).toString("base64");
const keyBuffer = Buffer.from(keyEncoded);

// -------------------------------------------------------------------------- //

const authCheck = (req) => {
    assert(req instanceof http.IncomingMessage);

    const auth = req.headers.authorization;
    if (!auth)
        return false;

    const [type, token] = auth.split(" ");
    const tokenBuffer = Buffer.from(token);
    if (tokenBuffer.length !== keyBuffer.length)
        return false;

    return crypto.timingSafeEqual(tokenBuffer, keyBuffer);
};

// -------------------------------------------------------------------------- //

const usage = () => {
    console.log("Usage: wiauth domain target");
    console.log("");
    console.log("  domain - domain of this proxy server");
    console.log("  target - address to web installer");
    console.log("           a port, a domain, or both");
    console.log("           domain defaults to localhost");
    console.log("");
    console.log("Make sure to secure your installer with firewall");
    process.exit(1);
};

const argParse = () => {
    // (node, file), domain, target
    const out = [];

    out.push(process.argv[2]);
    let target = process.argv[3];
    if (target) {
        if (/^\d+$/.test(target))
            target = "localhost:" + target;
    }
    out.push(target);

    return out;
};

const [domain, target] = argParse();

if (!target)
    usage();

assert(typeof domain === "string" && typeof target === "string");

console.log("Proxy server : " + domain);
console.log("Prxied server: " + target);
console.log(SEPARATOR);

// -------------------------------------------------------------------------- //

const cert = { cert: null, key: null };

try {
    const certRoot = "/etc/letsencrypt/live/" + domain + "/";
    cert.cert = fs.readFileSync(certRoot + "fullchain.pem", "utf8");
    cert.key = fs.readFileSync(certRoot + "privkey.pem", "utf8");
} catch (err) {
    console.warn(err.stack);
    console.warn("Could not load certificate!");
    console.warn("Starting in INSECURE mode!");
    console.log(SEPARATOR);
}

// -------------------------------------------------------------------------- //

const setupProxyRequest = (req) => {
    delete req.headers.authorization;
    req.headers.host = target;

    const options = url.parse("http://" + target + req.url);
    options.method = req.method;
    options.headers = req.headers;

    return options;
};

// -------------------------------------------------------------------------- //

const requestValidate = (req, res) => {
    assert(req instanceof http.IncomingMessage);
    assert(res instanceof http.ServerResponse);

    console.log("Incoming request: " + req.url);

    if (req.url.startsWith("/"))
        return true;

    console.log("    400 Bad request");
    res.writeHead(400);
    res.end();
    return false;
};

const requestRedirect = (req, res) => {
    if (!requestValidate(req, res))
        return;

    console.log("    301 Https upgrade");
    res.writeHead(301, { "Location": "https://" + domain + url });
    res.end();
};

const requestHandler = (req, res) => {
    if (!requestValidate(req, res))
        return;

    if (authCheck(req)) {
        console.log("    Authenticated");

        const remote = http.request(setupProxyRequest(req), (remoteRes) => {
            res.writeHead(
                remoteRes.statusCode,
                remoteRes.statusMessage,
                remoteRes.headers,
            );

            remoteRes.pipe(res);
        });

        remote.on("error", () => {
            res.destroy();
        });
        req.pipe(remote);

        return;
    }

    console.log("    401 Authentication required");
    res.writeHead(401, { "WWW-Authenticate": "basic" });
    res.end();
};

// -------------------------------------------------------------------------- //

const websocketRedirect = (req, socket, head) => {
    // TODO Can we upgrade to WebSocket Secure?
    console.warn("Insecure WebSocket connection");
    return websocketHandler(req, socket, head);
};

// TODO Refactor, handle the first line as well
// TODO Also, auto-detect status message from status code
const websocketWriteHeaders = (headers, socket) => {
    for (const key in headers)
        socket.write(key + ": " + headers[key] + "\r\n");
    socket.write("\r\n");
};

const websocketHandler = (req, socket, head) => {
    // Mostly copied from
    // https://bit.ly/2CAlZZj (GitHub nodejitsu/node-http-proxy)

    console.log("WebSocket request: " + req.url);

    if (
        req.method !== "GET" ||
        !req.url.startsWith("/") ||
        !req.headers.upgrade ||
        req.headers.upgrade.toLowerCase() !== "websocket"
    ) {
        console.log("    400 Bad request");
        socket.write("HTTP/" + req.httpVersion + " 400 Bad Request\r\n");
        socket.end("\r\n");
        return;
    }

    if (!authCheck(req)) {
        console.log("    401 Authentication required");
        socket.write("HTTP/" + req.httpVersion + " 401 Unauthorized\r\n");
        socket.write("WWW-Authenticate: basic\r\n");
        socket.end("\r\n");
        return;
    }

    // TODO Find out why are these needed
    // TODO https://bit.ly/2yu9X0z (GitHub nodejitsu/node-http-proxy)
    socket.setTimeout(0);
    socket.setNoDelay(true);
    socket.setKeepAlive(true, 0);

    const remote = http.request(setupProxyRequest(req), (remoteRes) => {
        // TODO Make sure this is right, it is not in the documentation
        // TODO I think it should be "!remoteRes.headers.upgrade"
        if (!remoteRes.upgrade) {
            console.log("    Authenticated, WebSocket upgrade failed");
            socket.write(
                "HTTP/" + remoteRes.httpVersion + " " +
                remoteRes.statusCode + " " +
                remoteRes.statusMessage + "\r\n"
            );
            websocketWriteHeaders(remoteRes.headers, socket);
            remoteRes.pipe(socket);
        }
    });

    remote.on("upgrade", (remoteRes, remoteSocket, remoteHead) => {
        socket.on("error", () => {
            remoteSocket.destroy();
        });
        remoteSocket.on("error", () => {
            socket.destroy();
        });

        console.log("    Authenticated, WebSocket upgrade succeeded");
        socket.write(
            "HTTP/" + remoteRes.httpVersion + " 101 Switching Protocol\r\n",
        );
        websocketWriteHeaders(remoteRes.headers, socket);

        if (head)
            remoteSocket.write(head);
        if (remoteHead)
            socket.write(remoteHead);

        socket.pipe(remoteSocket);
        remoteSocket.pipe(socket);
    });

    remote.on("error", () => {
        socket.destroy();
    });

    remote.end();
};

// -------------------------------------------------------------------------- //

const servers = [];

if (cert.key) {
    let server;

    server = http.createServer(requestRedirect);
    server.listen(80);
    server.on("upgrade", websocketRedirect);
    servers.push(server);

    server = https.createServer(cert, requestHandler);
    server.listen(443);
    server.on("upgrade", websocketHandler);
    servers.push(server);
} else {
    let server;

    server = http.createServer(requestHandler);
    server.listen(80);
    server.on("upgrade", websocketHandler);
    servers.push(server);
}

// -------------------------------------------------------------------------- //

const shutdown = () => {
    // TODO Maybe gracefully shutdown server?
    process.exit(0);
};

const shutdownSignals = ["SIGHUP", "SIGTERM", "SIGINT"];

for (const sig of shutdownSignals)
    process.on(sig, shutdown);

// -------------------------------------------------------------------------- //

console.log("Authentication for this session:");
console.log("User: user");
console.log("Pass: " + key);
console.log(SEPARATOR);

// -------------------------------------------------------------------------- //
