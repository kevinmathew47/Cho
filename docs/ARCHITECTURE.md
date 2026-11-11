# Architecture and roadmap

Cho CTF Workspace is a desktop workspace for **authorised CTF competitions and isolated practice environments**. It helps a participant organise a challenge, look at the files, run established tools, and reason about the results with a local AI assistant. It does not support every security tool and cannot promise a solve.

## Technology stack

| Layer | Choice | Why |
|---|---|---|
| Shell | Electron (Node main process, sandboxed renderer, context-isolated preload) | Cross-platform desktop app, one language |
| UI | Plain HTML/CSS/JS, no framework | Small, easy to audit and contribute to |
| AI | Ollama over HTTP on localhost | Runs offline; challenge data stays on the machine |
| Execution | Docker or Podman container (preferred), WSL, or the host shell | Container mode needs no Kali install |
| Storage | One folder per challenge with `challenge.json`, `notes.md`, `solve.py` | Plain files, easy to back up or put in git |
| Tests | Node's `assert`, no test framework | Zero extra dependencies |

## Process layout

```
renderer (UI, no Node access)
   │  preload.js: a fixed list of IPC calls
main process
   ├─ analyzers.js / meta.js / zip.js   built-in, pure-JS first-pass analysis
   ├─ safety.js      classifies a command: auto / needs approval / blocked
   ├─ scope.js       network commands must name only authorised targets
   ├─ sandbox.js     builds the container run (network none by default)
   ├─ prompt.js      system prompt: mode, challenge, files, targets
   ├─ ollama.js      local model client
   └─ tools-catalog.js   tool list shown in the Toolbox
```

## Controlled execution

Every command goes through the main process, which the UI cannot bypass:

1. **Blocked**: destructive commands or commands reaching outside the challenge folder never run for the agent.
2. **Approval**: anything that uses the network waits for a click, in every assistant mode.
3. **Scope**: a network command runs only if every host it names is in that challenge's *Authorised targets*. A command whose destination cannot be read is refused.
4. **Isolation** (container mode): a fresh container per command, challenge folder as the only mount, all capabilities dropped, no network unless step 3 passed.

Known limits, stated plainly:

- The scope check reads the command text. A script that builds a hostname at run time is not caught by it. In container mode such a script still has no network unless the command itself named an authorised host; in WSL or host-shell mode it is not contained.
- When the network is enabled for an in-scope command, the container can reach any host, not only the authorised one. Per-host egress filtering is on the roadmap.
- WSL and host-shell modes are convenience modes, not sandboxes. Run untrusted challenge binaries in container mode.

## Interface layout

Top bar (challenge switcher, search, environment status) · left navigation · challenge explorer (file tree) · centre (challenge details, file viewer, console with Terminal / Python / Output) · right (assistant with avatar, mode, context, task progress, findings) · status bar.

## AI assistance

- Modes: **Hint** (nudges), **Guided** (one approved step at a time), **Agent** (runs local analysis, stops for approval and scope).
- The assistant must label claims: `VERIFIED:` only for facts shown by command output or the built-in analysis, `ASSUMPTION:` for anything inferred. The UI renders them differently.
- Flags found by pattern matching are *candidates* until the user confirms them on the competition platform.
- Check each competition's rules on AI and automation before using the assistant. Hint mode, or turning the assistant off, is there for events that restrict it.

## Roadmap

**Done (prototype)**: challenge projects, file explorer and viewers, built-in analysis and decoders, console, tool catalogue, local assistant with three modes, command classification, authorised-target scope, container runner, tests.

**MVP, next**
1. Tool plugins: one manifest per tool (`plugins/<tool>/tool.json` + `README.md`) with purpose, install, example commands, limitations and licence, replacing the hard-coded catalogue.
2. Command history per challenge, searchable, exportable to the notes.
3. Container image build and status from inside the app.
4. Findings model with an explicit verified / assumed state and the evidence (command and output) attached.
5. Example practice challenges for each category, with intended solutions.

**Later**: per-host egress filtering for the container, macOS and Linux packaging, write-up export, optional remote model providers behind an explicit setting.
