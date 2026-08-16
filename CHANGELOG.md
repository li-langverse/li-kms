# Changelog

## 0.0.1 (2026-08-16)

- Carve the pure-Li KMS out of `lic` (branch `feat/li-kms-crypto`, MR #1516) into
  a self-contained repo:
  - `src/kms_core.li`, `src/kms_envelope.li`, `src/kms_exploits.li`,
    `src/kms_persist.li`, `src/kms_http.li`, `src/kms_server.li`
  - `runtime/li_rt_crypto.c/.h` — Monocypher-backed Ed25519 + XChaCha20-Poly1305,
    base64, and binary-safe file I/O externs
  - `runtime/vendor/monocypher/` — vendored Monocypher
  - `li.toml`, `Makefile`, `tests/run_tests.sh`, `docs/runtime-seam-api.md`
