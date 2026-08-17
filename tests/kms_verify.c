/* kms_verify.c — drives runtime/li_rt_crypto.c through the same scenarios as
 * the pure-Li selftests (kms_core, kms_envelope, kms_exploits, kms_persist).
 * Return 0 when everything passes. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "li_rt_crypto.h"

/* li_rt_rng_fill_bytes lives in lic's li_rt.h; provide it here so the harness
 * is self-contained (mirrors what the lic runtime provides for the .li code). */
int32_t li_rt_rng_fill_bytes(uint8_t *out, int32_t n) {
#ifdef __APPLE__
  arc4random_buf(out, (size_t)n);
#else
  FILE *f = fopen("/dev/urandom", "rb");
  if (!f) return -1;
  size_t got = fread(out, 1, (size_t)n, f);
  fclose(f);
  if ((int32_t)got != n) return -1;
#endif
  return n;
}

static int fail = 0;
#define CHECK(cond, msg) do { if (!(cond)) { printf("FAIL: %s\n", msg); fail = 1; } } while (0)

/* Mirrors kms_persist.li / kms_http.li byte helpers */
static uint8_t byte_at(const uint8_t *b, int32_t off) { return b[off]; }

static void test_core(void) {
  uint8_t seed[32], sk[64], pk[32], msg[8], sig[64], dek[32], nonce[24], mac[16], ct[8], pt[8];
  li_rt_rng_fill_bytes(seed, 32);
  li_rt_crypto_ed25519_keypair(pk, sk, seed);
  uint32_t m0 = 12345, m1 = 67890;
  memcpy(msg, &m0, 4); memcpy(msg + 4, &m1, 4);
  li_rt_crypto_ed25519_sign(sig, msg, 8, sk);
  CHECK(li_rt_crypto_ed25519_verify(sig, msg, 8, pk) == 0, "core: verify ok");
  CHECK(li_rt_crypto_ed25519_verify(sig, msg, 8, sk) != 0, "core: verify wrong pk fails");
  li_rt_rng_fill_bytes(dek, 32);
  li_rt_rng_fill_bytes(nonce, 24);
  li_rt_crypto_lock(mac, ct, msg, 8, dek, nonce);
  CHECK(li_rt_crypto_unlock(pt, mac, ct, 8, dek, nonce) == 0, "core: unlock ok");
  CHECK(memcmp(pt, msg, 8) == 0, "core: plaintext matches");
  uint8_t dek2[32], pt2[8];
  li_rt_rng_fill_bytes(dek2, 32);
  CHECK(li_rt_crypto_unlock(pt2, mac, ct, 8, dek2, nonce) != 0, "core: wrong-key unlock fails");
}

static void test_exploits(void) {
  uint8_t key[32], nonce[24], pt1[16], pt2[16], mac1[16], ct1[16], mac2[16], ct2[16], wrongkey[32];
  li_rt_rng_fill_bytes(key, 32);
  li_rt_memset_zero(nonce, 24);              /* nonce reuse on purpose */
  uint32_t a = 0x41414141U, b = 0x42424242U;
  memcpy(pt1, &a, 4); memcpy(pt2, &b, 4);
  li_rt_crypto_lock(mac1, ct1, pt1, 4, key, nonce);
  li_rt_crypto_lock(mac2, ct2, pt2, 4, key, nonce);
  int leak_ok = 1;
  for (int i = 0; i < 4; i++)
    if ((byte_at(ct1, i) ^ byte_at(ct2, i)) != (byte_at(pt1, i) ^ byte_at(pt2, i)))
      leak_ok = 0;   /* keystream reused exactly */
  CHECK(leak_ok == 1, "exploits: nonce-reuse keystream leak pinned");
  li_rt_rng_fill_bytes(wrongkey, 32);
  uint8_t pt3[16];
  CHECK(li_rt_crypto_unlock(pt3, mac1, ct1, 4, wrongkey, nonce) != 0, "exploits: wrong key fails");
  uint8_t mac3[16]; li_rt_memset_zero(mac3, 16);
  uint8_t pt4[16];
  CHECK(li_rt_crypto_unlock(pt4, mac3, ct1, 4, key, nonce) != 0, "exploits: bad MAC fails");
  uint8_t pt5[16];
  CHECK(li_rt_crypto_unlock(pt5, mac1, ct2, 4, key, nonce) != 0, "exploits: bad CT fails");
}

static void test_envelope(void) {
  uint8_t kek[32], dek[32], dnonce[24], dmac[16], dct[32], dek2[32];
  li_rt_rng_fill_bytes(kek, 32);
  li_rt_rng_fill_bytes(dek, 32);
  li_rt_rng_fill_bytes(dnonce, 24);
  li_rt_crypto_lock(dmac, dct, dek, 32, kek, dnonce);          /* wrap DEK under KEK */
  CHECK(li_rt_crypto_unlock(dek2, dmac, dct, 32, kek, dnonce) == 0, "env: wrap/unwrap");
  CHECK(memcmp(dek, dek2, 32) == 0, "env: DEK roundtrip");
  uint8_t kek2[32]; li_rt_rng_fill_bytes(kek2, 32);
  uint8_t dek3[32];
  CHECK(li_rt_crypto_unlock(dek3, dmac, dct, 32, kek2, dnonce) != 0, "env: wrong KEK fails");
  uint8_t msg[8]; uint32_t m0 = 12345, m1 = 67890;
  memcpy(msg, &m0, 4); memcpy(msg + 4, &m1, 4);
  uint8_t mnonce[24], mmac[16], mct[8], msg2[8];
  li_rt_rng_fill_bytes(mnonce, 24);
  li_rt_crypto_lock(mmac, mct, msg, 8, dek, mnonce);
  CHECK(li_rt_crypto_unlock(msg2, mmac, mct, 8, dek, mnonce) == 0, "env: data seal/open");
  CHECK(memcmp(msg, msg2, 8) == 0, "env: data roundtrip");
  uint8_t seed[32], sk[64], pk[32], sig[64];
  li_rt_rng_fill_bytes(seed, 32);
  li_rt_crypto_ed25519_keypair(pk, sk, seed);
  li_rt_crypto_ed25519_sign(sig, msg, 8, sk);
  CHECK(li_rt_crypto_ed25519_verify(sig, msg, 8, pk) == 0, "env: sign/verify");
}

static void test_persist(void) {
  uint8_t kek[32]; li_rt_rng_fill_bytes(kek, 32);
  char b64[64];
  int32_t en = li_rt_b64_encode(kek, 32, b64);
  CHECK(en > 0 && b64[en] == '\0', "persist: b64 encodes");
  uint8_t kek2[32];
  int32_t dn = li_rt_b64_decode(b64, en, kek2);
  CHECK(dn == 32 && memcmp(kek, kek2, 32) == 0, "persist: b64 roundtrip");
  CHECK(li_rt_file_write_bytes("/tmp/kms_verify.b64", (const uint8_t *)b64, en) == en, "persist: file write");
  char rb[64];
  int32_t rn = li_rt_file_read_bytes("/tmp/kms_verify.b64", (uint8_t *)rb, 64);
  CHECK(rn == en && memcmp(rb, b64, en) == 0, "persist: file read");
  remove("/tmp/kms_verify.b64");
}

int main(void) {
  test_core();
  test_exploits();
  test_envelope();
  test_persist();
  if (!fail) printf("ALL KMS VERIFY CHECKS PASSED\n");
  return fail;
}
