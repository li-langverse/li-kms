# Runtime seam API required by li-kms

The Li programs in `src/` `import std.runtime.seam` and use the externs below.
They ship with the `lic` runtime once MR #1516 (`feat/li-kms-crypto`) lands; the
C implementations live in this repo under `runtime/li_rt_crypto.c` (Monocypher-backed).

`std.runtime.seam` must declare (exact `extern def` from the branch)::

```li
extern def net_buf_alloc(size: int) raises Alloc -> ptr
extern def net_buf_free(p: ptr) raises Alloc -> unit
extern def net_byte_at_i(b: ptr, off: int) -> int
extern def li_rt_vec_i32_set(buf: ptr, lane: int, v: int) -> unit
extern def bytes_slice_i(b: ptr, off: int, n: int) raises Alloc -> ptr
extern def bytes_append_i(a: ptr, b: ptr) raises Alloc -> ptr
extern def container_str_len_i(s: ptr) -> int
extern def tcp_listen(port: int) raises Net -> int
extern def tcp_accept(listen_fd: int) raises Net -> int
extern def tcp_close(conn_fd: int) raises Net -> unit
extern def tcp_http_write_response(conn: int, status: int, body: ptr) raises Net -> int
extern def tcp_recv_i(conn: int, max_bytes: int) raises Net -> ptr
extern def li_rt_rng_fill_bytes(out_buf: ptr, n: int) -> int
extern def li_rt_crypto_ed25519_keypair(pk: ptr, sk: ptr, seed: ptr) -> int
extern def li_rt_crypto_ed25519_sign(sig: ptr, msg: ptr, msg_len: int, sk: ptr) -> int
extern def li_rt_crypto_ed25519_verify(sig: ptr, msg: ptr, msg_len: int, pk: ptr) -> int
extern def li_rt_crypto_lock(mac: ptr, ct: ptr, pt: ptr, pt_len: int, key: ptr, nonce: ptr) -> int
extern def li_rt_crypto_unlock(pt: ptr, mac: ptr, ct: ptr, ct_len: int, key: ptr, nonce: ptr) -> int
extern def li_rt_b64_encode(in_buf: ptr, in_len: int, out: ptr) -> int
extern def li_rt_b64_decode(in_buf: ptr, in_len: int, out: ptr) -> int
extern def li_rt_file_write_bytes(path: str, data: ptr, n: int) -> int
extern def li_rt_file_read_bytes(path: str, buf: ptr, cap: int) -> int
extern def li_rt_memcpy_off(dst: ptr, dst_off: int, src: ptr, n: int) -> int
extern def li_rt_memset_zero(buf: ptr, n: int) -> int
```

Notes:

- `li_rt_rng_fill_bytes` must take `out_buf: ptr` (the branch fixes a previous
  `int` typo that null-deref'd the seam). Keep the pointer signature.
- `tcp_recv_i` returns a full request buffer (headers + body); see the
  `kms_http.li` / `kms_server.li` parsing for buffer-layout assumptions.
- `net_byte_at_i` indexes raw bytes; HTTP parsing in `kms_server.li` is offset-based.
