# Web Installer Authenticator

[![NPM](https://nodei.co/npm/web-installer-authenticator.png)](https://nodei.co/npm/web-installer-authenticator/)

Make sure you win the race

## Motivation

I was recently testing out various software on my Lightsail server, and I am
disappointed by the poor security of web installers.

A lot of web installers treat the first user to connect as the administrator,
which is unfortunately not guaranteed to be you.

Web Installer Authenticator will crate a cryptographically secure random key
to make sure the person typing into the terminal is the same person connecting
to the web installer.

## Features

- Handles both normal and WebSocket connections
- Enforces HTTPS when a TLS certificate is available

## Installation

You need the latest version of Node.js.

```Bash
sudo npm install --global web-installer-authenticator
```

## Usage

```
Usage: wiauth domain target

  domain - domain of this proxy server
  target - address to web installer
           a port, a domain, or both
           domain defaults to localhost

Make sure to secure your installer with firewall
```

**It is up to you to secure your installer with a firewall!**

A TLS certificate is highly recommended, you can get free ones from Let's
Encrypt.

## Contacts

Simply open an issue on GitHub. I will give you further instructions on
communicating privately if you are reporting a vulnerability.
