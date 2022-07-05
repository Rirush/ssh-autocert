# SSH Autocert

An ACME-inspired protocol and tool for automatic issuance of SSH host certificates. (WIP)

It's like "HTTP-01", but for SSH certificates, and over SSH.

## Motivation

This probably has already been done before. The goal of this project is to learn a bit more about SSH certificates,
working with SSH from Go, and challenges of automatic certificate issuance.

In the current state, this is guaranteed to be insecure. One of the goals is probably making this software as secure
as possible.

## TODO for initial release

- [ ] Split both client and server into separate files.
- [ ] Improve server logging
- [ ] Document the protocol
- [ ] Add HTTPS server for Autocert host key retrieval
- [ ] Pin SSH host key when verifying challenge
- [ ] Add configuration for Autocert server