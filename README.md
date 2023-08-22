Bolt Card Hub
======

A fork of Bluewallets [LndHub](https://github.com/BlueWallet/LndHub) with support for bolt card connections.

INSTALLATION
------------
See [LndHub](https://github.com/BlueWallet/LndHub) for LndHub related installation details.

In addition to LndHub, the Bolt Card Hub requires:

- ports 9000/9001 must be forwarded on the router
- set FUNCTION_INTERNAL_API=Enabled in the settings database table of the bolt card server
- url/service_url for boltcard service in config.js should be HTTP, not HTTPS

## Responsible disclosure

Found critical bugs/vulnerabilities? Please email them to bluewallet@bluewallet.io
Thanks!
