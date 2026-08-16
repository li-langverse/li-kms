#include "li_rt_crypto.h"

#include <stddef.h>
#include <string.h>
#include <stdio.h>

#include "vendor/monocypher/monocypher.h"

int32_t li_rt_crypto_ed25519_keypair(uint8_t *pk, uint8_t *sk, uint8_t *seed) {
  crypto_eddsa_key_pair(sk, pk, seed);
  return 0;
}

int32_t li_rt_crypto_ed25519_sign(uint8_t *sig, const uint8_t *msg, int32_t msg_len, const uint8_t *sk) {
  crypto_eddsa_sign(sig, sk, msg, (size_t)msg_len);
  return 0;
}

int32_t li_rt_crypto_ed25519_verify(const uint8_t *sig, const uint8_t *msg, int32_t msg_len, const uint8_t *pk) {
  return crypto_eddsa_check(sig, pk, msg, (size_t)msg_len); /* 0 ok, -1 fail */
}

int32_t li_rt_crypto_lock(uint8_t *mac, uint8_t *ct, const uint8_t *pt, int32_t pt_len, const uint8_t *key, const uint8_t *nonce) {
  crypto_aead_lock(ct, mac, key, nonce, 0, 0, pt, (size_t)pt_len);
  return 0;
}

int32_t li_rt_crypto_unlock(uint8_t *pt, const uint8_t *mac, const uint8_t *ct, int32_t ct_len, const uint8_t *key, const uint8_t *nonce) {
  return crypto_aead_unlock(pt, mac, key, nonce, 0, 0, ct, (size_t)ct_len); /* 0 ok, -1 fail */
}

static const char B64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int32_t li_rt_b64_encode(const uint8_t *in, int32_t in_len, char *out) {
  int32_t i = 0, o = 0;
  while (i + 2 < in_len) {
    uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8) | (uint32_t)in[i + 2];
    out[o++] = B64[(v >> 18) & 63];
    out[o++] = B64[(v >> 12) & 63];
    out[o++] = B64[(v >> 6) & 63];
    out[o++] = B64[v & 63];
    i += 3;
  }
  if (i + 1 == in_len) {
    uint32_t v = (uint32_t)in[i] << 16;
    out[o++] = B64[(v >> 18) & 63];
    out[o++] = B64[(v >> 12) & 63];
    out[o++] = '=';
    out[o++] = '=';
  } else if (i + 2 == in_len) {
    uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8);
    out[o++] = B64[(v >> 18) & 63];
    out[o++] = B64[(v >> 12) & 63];
    out[o++] = B64[(v >> 6) & 63];
    out[o++] = '=';
  }
  out[o] = '\0';
  return o;
}

static int32_t b64_val(char c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '+') return 62;
  if (c == '/') return 63;
  return -1;
}

int32_t li_rt_b64_decode(const char *in, int32_t in_len, uint8_t *out) {
  int32_t o = 0, quad = 0, acc = 0, i = 0;
  for (i = 0; i < in_len && in[i] != '='; i++) {
    int32_t v = b64_val(in[i]);
    if (v < 0) continue;
    acc = (acc << 6) | v;
    quad++;
    if (quad == 4) {
      out[o++] = (uint8_t)((acc >> 16) & 0xff);
      out[o++] = (uint8_t)((acc >> 8) & 0xff);
      out[o++] = (uint8_t)(acc & 0xff);
      acc = 0;
      quad = 0;
    }
  }
  if (quad == 3) {
    out[o++] = (uint8_t)((acc >> 10) & 0xff);
    out[o++] = (uint8_t)((acc >> 2) & 0xff);
  } else if (quad == 2) {
    out[o++] = (uint8_t)((acc >> 4) & 0xff);
  }
  return o;
}

int32_t li_rt_file_write_bytes(const char *path, const uint8_t *data, int32_t n) {
  if (path == NULL || data == NULL || n < 0) return -1;
  FILE *f = fopen(path, "wb");
  if (f == NULL) return -1;
  size_t w = fwrite(data, 1, (size_t)n, f);
  fclose(f);
  return (int32_t)w;
}

int32_t li_rt_file_read_bytes(const char *path, uint8_t *buf, int32_t cap) {
  if (path == NULL || buf == NULL || cap < 0) return -1;
  FILE *f = fopen(path, "rb");
  if (f == NULL) return -1;
  size_t n = fread(buf, 1, (size_t)cap, f);
  fclose(f);
  return (int32_t)n;
}

int32_t li_rt_memcpy_off(uint8_t *dst, int32_t dst_off, const uint8_t *src, int32_t n) {
  if (dst == NULL || src == NULL || n < 0) return -1;
  memcpy(dst + dst_off, src, (size_t)n);
  return n;
}

int32_t li_rt_memset_zero(uint8_t *buf, int32_t n) {
  if (buf == NULL || n < 0) return -1;
  memset(buf, 0, (size_t)n);
  return n;
}
