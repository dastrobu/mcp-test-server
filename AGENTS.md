# Agent Guidelines

This document outlines the specific rules and best practices for AI agents contributing to this project.

## Git Policy

### Signed Commits
All commits made by AI agents **MUST** be signed.

If a GPG signing operation fails (e.g., due to a missing TTY or GPG configuration issues), do not push unsigned code. Instead:
1. Ensure your environment is correctly configured for signing.
2. Use `--no-gpg-sign` **ONLY** if explicitly instructed by the repository owner for debugging purposes.
3. Prefer using the project's preferred signing method (GPG, SSH, or S/MIME).

## Coding Standards

- Follow the established Rust idioms in the codebase.
- Ensure all new tools are documented in `README.md`.
- Run `cargo test` and `cargo check` before submitting a Pull Request.