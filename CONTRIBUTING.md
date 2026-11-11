# Contributing

Thanks for helping. This project is for authorised CTF competitions and isolated practice environments; contributions should fit that purpose.

## Getting started

```bash
npm install
npm test
npm start
```

## Ground rules

- **Tests**: add or update a test in `test/` for any change to `src/*.js` outside the renderer. `npm test` must pass.
- **Safety code** (`safety.js`, `scope.js`, `sandbox.js`, the `proc:run` handler in `main.js`): changes need tests for both the allowed and the refused case, and must not loosen a default.
- **Tools**: when adding a tool, document its purpose, how to install it, an example command, its limitations and its licence. Do not bundle tool binaries in this repository.
- **Honest claims**: do not describe a feature as working unless you ran it. Say what was not tested.
- **No real targets**: examples and practice challenges use local files or reserved names such as `*.example`, `*.test` and `10.x` lab addresses.
- **Style**: plain JavaScript, 2-space indent, no new runtime dependencies without discussion.

## Practice challenges

Put them in `samples/` with a short README giving the category, the intended approach and the flag. Only include material you created or have the right to share.

## Reporting security problems

See [SECURITY.md](SECURITY.md).
