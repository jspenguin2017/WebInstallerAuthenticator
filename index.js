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

const SEPARATOR = "=".repeat(80);

console.log("Web Installer Authenticator");
console.log(SEPARATOR);

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
const keyBase64 = Buffer.from("user:" + key).toString("base64");
const keyBuffer = Buffer.from(keyBase64);

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
    console.log("    domain - Domain that this proxy server is on");
    console.log("    target - Proxied server, a port, a domain, or both");
    console.log("             Domain defaults to localhost");
    console.log(
        "Make sure to set up your firewall so that your installer cannot be " +
        "accessed by other means!"
    );
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
        target = "http://" + target;
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
        console.log("    200 Normal request");

        delete req.headers.authorization;

        const options = url.parse(target + req.url);
        options.method = req.method;
        options.headers = req.headers;

        // TODO: Debug
        console.log(options);

        const remote = http.request(options, (remoteRes) => {
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

// TODO: Handle websocket

// -------------------------------------------------------------------------- //

const servers = [];

if (cert.key) {
    let server;

    server = http.createServer(requestRedirect);
    server.listen(80);
    servers.push(server);

    server = https.createServer(cert, requestHandler);
    server.listen(443);
    servers.push(server);
} else {
    let server;

    server = http.createServer(requestHandler);
    server.listen(80);
    servers.push(server);
}

// -------------------------------------------------------------------------- //

console.log("Authentication for this session:");
console.log("User: user");
console.log("Pass: " + key);
console.log(SEPARATOR);

// -------------------------------------------------------------------------- //
