# Security policy

## Intended use

Use this application only in CTF competitions you are registered for, against targets the organisers list as in scope, and in practice environments you own or are allowed to use. Follow each competition's rules on AI assistance and automation.

## What the app does and does not protect against

- Challenge files are untrusted. The built-in analysis only reads them. Running them is your decision; use container mode for that.
- Container mode isolates a command from the host and from the network. WSL and host-shell modes do not.
- The authorised-target check reads command text and can be evaded by code that computes a destination at run time. See `docs/ARCHITECTURE.md` for the full list of limits.

## Reporting a vulnerability

If you find a way to bypass the command classification, the target scope check or the container isolation, please open a private security advisory on the repository rather than a public issue, with steps to reproduce.
