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

console.log("Web Installer Authenticator");

// -------------------------------------------------------------------------- //

const assert = require("assert");
const crypto = require("crypto");
const fs = require("fs");
const http = require("http");
const https = require("https");

const httpProxy = require("http-proxy");

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

const authCookieName = "web-installer-authenticator";

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
    console.log("Usage:");
    console.log("    wiauth domain");
    process.exit(1);
};

// -------------------------------------------------------------------------- //

// node, file, domain
const domain = process.argv[2];

if (!domain)
    usage();

// -------------------------------------------------------------------------- //

const cert = { cert: null, key: null };

try {
    const certRoot = "/etc/letsencrypt/live/" + domain + "/";
    cert.cert = fs.readFileSync(certRoot + "fullchain.pem", "utf8");
    cert.key = fs.readFileSync(certRoot + "privkey.pem", "utf8");
} catch (err) {
    console.warn("=".repeat(80));
    console.warn(err.stack);
    console.warn("Could not load certificate!");
    console.warn("Starting in INSECURE mode!");
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

const requestUpgrade = (req, res) => {
    if (!requestValidate(req, res))
        return;

    console.log("    301 Upgrade");
    res.writeHead(301, { "Location": "https://" + domain + url });
    res.end();
};

const requestHandler = (req, res) => {
    if (!requestValidate(req, res))
        return;

    if (authCheck(req)) {
        console.log("    200 Authenticated");
        res.end("ok"); // TODO
        return;
    }

    console.log("    401 Authentication required");
    res.writeHead(401, { "WWW-Authenticate": "basic" });
    res.end();
};

// -------------------------------------------------------------------------- //

const servers = [];

if (cert.key) {
    let server;

    server = http.createServer(requestUpgrade);
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

console.log("=".repeat(80));
console.log("Authentication for this session:");
console.log("User: user");
console.log("Pass: " + key);

console.log("=".repeat(80));

// -------------------------------------------------------------------------- //
