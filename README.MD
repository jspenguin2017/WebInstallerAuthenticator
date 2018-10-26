# Web Installer Authenticator

[![NPM](https://nodei.co/npm/web-installer-authenticator.png)](https://nodei.co/npm/web-installer-authenticator/)

Make sure you win the race

## Motivation

I was recently testing out various software on my Lightsail server, and I am
disappointed by the poor security of web installers. A lot of them treat the
first user to connect as the administrator, which is unfortunately not
guaranteed to be you.

Web Installer Authenticator will crate a cryptographically secure random key
to make sure the person typing into the terminal is the same person connecting
to the web installer.

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

**It is up to you to
[secure your installer](https://serverfault.com/questions/247176/iptables-only-allow-localhost-access)
with a firewall!**

A TLS certificate is highly recommended, you can get free ones from Let's
Encrypt.

## Contacts

Simply open an issue
[on GitHub](https://github.com/jspenguin2017/WebInstallerAuthenticator/issues).

If you are reporting a vulnerability or otherwise wish to communicate
privately, you can open a confidential issue
[on GitLab](https://gitlab.com/xuhaiyang1234/VulnerabilityReports/issues).
