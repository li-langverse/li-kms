#ifndef LI_RT_CRYPTO_H
#define LI_RT_CRYPTO_H

#include <stdint.h>

/* Crypto + KMS support primitives (Monocypher-backed + small base64/file helpers).
 * Buffers are caller-owned; sizes in bytes.
 * - Ed25519: sk[64] (expanded), pk[32], seed[32], sig[64]
 * - XChaCha20-Poly1305 (crypto_aead_lock): key[32], nonce[24], mac[16]
 * verify/unlock return 0 on success, -1 on failure.
 * - base64: out buffer must be large enough (encode: 4*ceil(n/3)+1, decode: n).
 * - file read/write are binary-safe; return bytes written/read, or -1 on error.
 */

int32_t li_rt_crypto_ed25519_keypair(uint8_t *pk, uint8_t *sk, uint8_t *seed);
int32_t li_rt_crypto_ed25519_sign(uint8_t *sig, const uint8_t *msg, int32_t msg_len, const uint8_t *sk);
int32_t li_rt_crypto_ed25519_verify(const uint8_t *sig, const uint8_t *msg, int32_t msg_len, const uint8_t *pk);
int32_t li_rt_crypto_lock(uint8_t *mac, uint8_t *ct, const uint8_t *pt, int32_t pt_len, const uint8_t *key, const uint8_t *nonce);
int32_t li_rt_crypto_unlock(uint8_t *pt, const uint8_t *mac, const uint8_t *ct, int32_t ct_len, const uint8_t *key, const uint8_t *nonce);

int32_t li_rt_b64_encode(const uint8_t *in, int32_t in_len, char *out);
int32_t li_rt_b64_decode(const char *in, int32_t in_len, uint8_t *out);

int32_t li_rt_file_write_bytes(const char *path, const uint8_t *data, int32_t n);
int32_t li_rt_file_read_bytes(const char *path, uint8_t *buf, int32_t cap);

int32_t li_rt_memcpy_off(uint8_t *dst, int32_t dst_off, const uint8_t *src, int32_t n);
int32_t li_rt_memset_zero(uint8_t *buf, int32_t n);

#endif
