# Third-party licences

## Bundled with the app

| Package | Version | Licence | Use |
|---|---|---|---|
| electron | 33.2.1 | MIT | Desktop runtime (dev dependency, shipped in builds) |
| electron-builder | 25.1.8 | MIT | Packaging (dev dependency, not shipped) |

The app has no other runtime npm dependencies. Transitive dev dependencies are listed in `package-lock.json`; run `npx license-checker --summary` to audit them.

## Not bundled: installed by the user

The app calls these if they are present. Each keeps its own licence; none is redistributed in this repository. Licences below are from memory of each project and should be confirmed against the project before you redistribute anything.

| Tool | Licence (to confirm) |
|---|---|
| Ollama | MIT |
| Docker Engine / Podman | Apache-2.0 |
| binwalk | MIT |
| ExifTool | Artistic / GPL |
| Wireshark / tshark | GPL-2.0 |
| The Sleuth Kit | mixed (IPL, CPL, GPL-2.0) |
| Volatility 3 | Volatility Software License |
| steghide, foremost, John the Ripper, radare2, GDB | GPL / LGPL family or public domain |

Models downloaded through Ollama carry their own licences; check the model page before use.
