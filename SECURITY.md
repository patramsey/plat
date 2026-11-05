# Security Policy

## Supported Versions

`plat` is pre-1.0. Only the latest release is supported: fixes ship in a
new release rather than being backported to older ones.

## Reporting a Vulnerability

Please report security issues privately using GitHub's
[private vulnerability reporting](https://github.com/patramsey/plat/security/advisories/new)
feature (Security tab → Report a vulnerability) rather than opening a
public issue.

Include:
- The affected version (`plat --version`)
- Steps to reproduce
- The impact you believe the issue has

This is a small, actively-maintained project without a formal SLA, but
reports will be acknowledged and addressed as promptly as possible. A fix
will typically ship as a patch release once confirmed.

## Scope

`plat` queries third-party WHOIS/RDAP servers and renders their responses
to a terminal or as JSON. Relevant categories of concern include (but
aren't limited to):

- Terminal escape-sequence injection from untrusted WHOIS/RDAP response
  data
- Parser panics or resource exhaustion triggered by malformed or hostile
  server responses
- Any case where a malicious server could cause `plat` to execute
  unintended commands or write outside its intended output stream

Vulnerabilities in third-party dependencies should generally be reported
upstream, but flagging them here is welcome too if you're not sure where
they apply.
