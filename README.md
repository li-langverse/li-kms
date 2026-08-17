# li-kms

Pure-Li key-management service: envelope encryption (KEK → per-project DEK wrap),
Ed25519 sign/verify, a full HTTP KMS API, and binary-safe base64/file persistence —
all implemented in Li, with the crypto primitives provided by Monocypher-backed
runtime externs (`runtime/li_rt_crypto.c`).

The Li sources used to live as `examples/kms_*.li` on the `lic` branch
`feat/li-kms-crypto` (GitLab MR #1516). They are carved out here so the KMS can
evolve and be consumed independently of the compiler tree.

## Layout

- `src/` — the Li programs (each with its own `main`, selftests return 0 on success):
  - `kms_core.li` — Ed25519 keypair/sign/verify + XChaCha20-Poly1305 seal/open.
  - `kms_envelope.li` — KEK/DEK envelope: wrap a DEK under a KEK, seal data, sign.
  - `kms_exploits.li` — regression selftest: nonce-reuse leak, wrong key, bad MAC/CT all fail.
  - `kms_persist.li` — bootstrap a KEK, persist wrapped DEK + MAC + nonce as base64, reload.
  - `kms_http.li` — minimal TCP/HTTP smoke server (GET /health).
  - `kms_server.li` — full HTTP KMS API (encrypt/decrypt/sign/verify over HTTP).
- `runtime/` — C side: `li_rt_crypto.c/.h` implement the externs on Monocypher
  (`vendor/monocypher/`, BSD-2-Clause OR CC0-1.0).
- `seam/kms-runtime-seam.li` — the `extern def` declarations this package needs;
  merge into `std.runtime.seam` of your lic build (MR #1516 removed them from `lic`).
- `docs/runtime-seam-api.md` — the seam API + what stays in lic (rng ptr fix,
  tcp_recv full-request read, bytes ABI).
- `tests/run_tests.sh` — build + run the selftests (`make test`).
- `tests/kms_verify.c` — C-level parity harness that drives `runtime/li_rt_crypto.c`
  through the same scenarios as the Li selftests (`make verify`; no lic needed).

## Build & test

Requires a `lic` build whose `std.runtime.seam` includes the KMS externs
(see `docs/runtime-seam-api.md`) and the lic runtime library (`libli_rt.a`).

```bash
# runtime crypto externs (static lib)
make                              # -> build/librt_crypto.a

# selftests (core, envelope, exploits, persist)
LIC=/path/to/lic LI_RT_LIB=/path/to/libli_rt.a LI_RT_LIBS=build/librt_crypto.a make test

# HTTP API smoke test (starts src/kms_server.li on :54400, curls it, kills it)
LIC=/path/to/lic LI_RT_LIB=/path/to/libli_rt.a LI_RT_LIBS=build/librt_crypto.a make test-http
```

When using the seeded-lowlic build, `LI_NATIVE_RT=1` is needed if the runtime is
used natively:

```bash
LI_NATIVE_RT=1 LIC=.../lic \
  LI_RT_LIB=.../runtime/libli_rt.a \
  LI_RT_LIBS=build/librt_crypto.a make test
```

## Dependency direction (important)

This package depends **only on `lic`** (compiler + runtime + `std.runtime.seam`),
never the other way around. `lic` must not depend on downstream packages such as
`li-kms`; see the lic repo rule `.cursor/rules/li-no-downstream-deps.mdc`.

## License

- Li sources: GPL-3.0-or-later (matches the li ecosystem).
- `runtime/vendor/monocypher/`: BSD-2-Clause OR CC0-1.0, copyright Loup Vaillant.
