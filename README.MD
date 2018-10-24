# Web Installer Authenticator

[![NPM](https://nodei.co/npm/web-installer-authenticator.png)](https://nodei.co/npm/web-installer-authenticator/)

Make sure you win the race

## Quick start

```Bash
sudo npm install --global web-installer-authenticator
wiauth your-domain.example.com localhost:3000
```

**Important: make sure your web installer is behind a firewall such that only
`localhost` can access it.**

A TLS certificate is highly recommended, although not required.

## Why

I was recently testing out various software on my Lightsail server, and I am
disappointed by the poor security of web installers.

A lot of web installers treat the first user to connect to the installer as
administrator, which is unfortunately not guaranteed to be you.

Web Installer Authenticator will crate a cryptographically secure random key
to make sure the person tying into the shell is the same person connecting to
the web installer.

## Features

- Enforces HTTPS when a TLS certificate is available
- Handles both normal and WebSocket connections

## Options

The available options are quite limited, I will expand it as I need them.

```
wiauth domain target

domain - Domain or IP address of your server
target - Target server, must be behind a firewall, should be just a port
```
