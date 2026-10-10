# FortID CTF 2026 — Writeups
<img width="1367" height="896" alt="image" src="https://github.com/user-attachments/assets/470d00cb-f7c6-4cfb-b113-efd39c81ac36" />

A structured collection of challenge writeups for FortID CTF 2026.

> **Publication note:** Publish challenge solutions only when permitted by the official competition rules and organizers.

## Categories

| Category | Description |
|---|---|
| [Binary Exploitation](Binary-Exploitation/README.md) | Memory corruption, binary analysis, and exploitation challenges. |
| [Reverse Engineering](Reverse-Engineering/README.md) | Program analysis and understanding compiled or obfuscated logic. |
| [Cryptography](Cryptography/README.md) | Ciphers, cryptographic implementations, and protocol puzzles. |
| [Web](Web/README.md) | Web application vulnerabilities and challenge solutions. |
| [Miscellaneous](Miscellaneous/README.md) | Challenges that do not fit another category. |
| [Intro](Intro/README.md) | Beginner and introductory challenges. |
| [OSINT](OSINT/README.md) | Open-source intelligence challenges. |

## Challenge directory structure

Create a separate directory for each challenge inside its category. Every challenge directory should contain:

- `README.md` — challenge overview, methodology, analysis, solution, and lessons learned.
- `files/` — all challenge-provided artifacts, such as supplied source code, binaries, archives, configuration files, and other attachments. Preserve original filenames when practical.
- Optional scripts or helper files created during analysis, plus an `images/` directory for screenshots or diagrams.

### Files directory conventions

Each challenge must have its own `files/` directory. Store only artifacts actually supplied for that challenge in it; do not invent missing files or put exploit scripts created during solving in this directory unless they were part of the original challenge package. If no downloadable files were provided, include a `files/README.md` stating that no challenge files were supplied. Respect competition rules and do not publish restricted or sensitive material.

A starter example is available at [templates/challenge/files/README.md](templates/challenge/files/README.md).

Keep reports reproducible, concise, and based on verified results. Do not include flags, challenge files, or solutions before publication is allowed by the organizers.
