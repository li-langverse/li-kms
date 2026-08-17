# Runtime seam API required by li-kms

The canonical seam fragment lives in this repo: `seam/kms-runtime-seam.li`.
Merge it into `std.runtime.seam` of whatever lic build you compile against
(commit `85a6463e` on `feat/li-kms-crypto` / MR #1516 removed the KMS externs
from `lic` — they are owned here now).

The full `extern def` surface these programs rely on (from `std.runtime.seam`):

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

- `li_rt_rng_fill_bytes` must take `out_buf: ptr` (the `int`→`ptr` fix stays in
  `lic`'s shared runtime; keep the pointer signature).
- `tcp_recv_i` returns a full request buffer (headers + body); the full-request
  read stays in `lic` (`runtime/li_rt_net.c` + `net_trusted` regression test).
- `net_byte_at_i` indexes raw bytes; HTTP parsing in `kms_server.li` is offset-based.
- The KMS-only externs above (crypto/b64/file/mem) live in `seam/kms-runtime-seam.li`
