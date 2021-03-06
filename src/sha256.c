/*
 * SHA-256 hash implementation and interface functions
 * Copyright (c) 2003-2012, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "ofc/types.h"
#include "ofc/net.h"
#include "ofc/net_internal.h"
#include "ofc/libc.h"
#include "of_security/sha256.h"

struct SHA1Context {
  OFC_UINT32 state[5];
  OFC_UINT32 count[2];
  OFC_UCHAR buffer[64];
};

OFC_VOID SHA1Init(struct SHA1Context *context);
OFC_VOID SHA1Update(struct SHA1Context *context, const OFC_VOID *data, 
		     OFC_UINT32  len);
OFC_VOID SHA1Final(OFC_UCHAR digest[20], struct SHA1Context *context);
OFC_VOID SHA1Transform(OFC_UINT32 state[5], const OFC_UCHAR buffer[64]);

#define SHA1_MAC_LEN 20

OFC_INT hmac_sha1_vector(const OFC_UCHAR *key, OFC_SIZET key_len, 
			  OFC_SIZET num_elem, const OFC_UCHAR *addr[], 
			  const OFC_SIZET *len, OFC_UCHAR *mac);
OFC_INT hmac_sha1(const OFC_UCHAR *key, OFC_SIZET key_len, 
		   const OFC_UCHAR *data, OFC_SIZET data_len,
		   OFC_UCHAR *mac);
OFC_INT sha1_prf(const OFC_UCHAR *key, OFC_SIZET key_len, 
		  const OFC_CHAR *label, const OFC_UCHAR *data, 
		  OFC_SIZET data_len, OFC_UCHAR *buf, 
		  OFC_SIZET buf_len);
OFC_INT sha1_t_prf(const OFC_UCHAR *key, OFC_SIZET key_len, 
		    const OFC_CHAR *label, const OFC_UCHAR *seed, 
		    OFC_SIZET seed_len, OFC_UCHAR *buf, 
		    OFC_SIZET buf_len);
OFC_INT tls_prf_sha1_md5(const OFC_UCHAR *secret, OFC_SIZET secret_len,
			  const OFC_CHAR *label, const OFC_UCHAR *seed,
			  OFC_SIZET seed_len, OFC_CHAR *out, 
			  OFC_SIZET outlen);
OFC_INT pbkdf2_sha1(const OFC_CHAR *passphrase, const OFC_UCHAR *ssid, 
		     OFC_SIZET ssid_len, OFC_INT iterations, 
		     OFC_UCHAR *buf, OFC_SIZET buflen);

#define SHA256_BLOCK_SIZE 64

struct sha256_state {
  OFC_UINT64 length;
  OFC_UINT32 state[8], curlen;
  OFC_UCHAR buf[SHA256_BLOCK_SIZE];
};

OFC_VOID sha256_init(struct sha256_state *md);
OFC_INT sha256_process(struct sha256_state *md, const OFC_UCHAR *in,
			OFC_ULONG inlen);
OFC_INT sha256_done(struct sha256_state *md, OFC_UCHAR *out);

/**
 * sha256_vector - SHA256 hash for data vector
 * @num_elem: Number of elements in the data vector
 * @addr: Pointers to the data areas
 * @len: Lengths of the data blocks
 * @mac: Buffer for the hash
 * Returns: 0 on success, -1 of failure
 */
OFC_INT sha256_vector(OFC_SIZET num_elem, const OFC_UCHAR *addr[], 
		       const OFC_SIZET *len, OFC_UCHAR *mac)
{
  struct sha256_state ctx;
  OFC_SIZET i;

  sha256_init(&ctx);
  for (i = 0; i < num_elem; i++)
    if (sha256_process(&ctx, addr[i], len[i]))
      return -1;
  if (sha256_done(&ctx, mac))
    return -1;
  return 0;
}


/* ===== start - public domain SHA256 implementation ===== */

/* This is based on SHA256 implementation in LibTomCrypt that was released into
 * public domain by Tom St Denis. */

/* the K array */
static const OFC_UINT32 K[64] = {
  0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL, 0x3956c25bUL,
  0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL, 0xd807aa98UL, 0x12835b01UL,
  0x243185beUL, 0x550c7dc3UL, 0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL,
  0xc19bf174UL, 0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL,
  0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL, 0x983e5152UL,
  0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL, 0xc6e00bf3UL, 0xd5a79147UL,
  0x06ca6351UL, 0x14292967UL, 0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL,
  0x53380d13UL, 0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
  0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL, 0xd192e819UL,
  0xd6990624UL, 0xf40e3585UL, 0x106aa070UL, 0x19a4c116UL, 0x1e376c08UL,
  0x2748774cUL, 0x34b0bcb5UL, 0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL,
  0x682e6ff3UL, 0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL,
  0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL
};

/* Various logical functions */
#define RORc(x, y) \
  ( ((((OFC_ULONG) (x) & 0xFFFFFFFFUL) >> (OFC_ULONG) ((y) & 31)) | \
     ((OFC_ULONG) (x) << (OFC_ULONG) (32 - ((y) & 31)))) & 0xFFFFFFFFUL)
#define Ch(x,y,z)       (z ^ (x & (y ^ z)))
#define Maj(x,y,z)      (((x | y) & z) | (x & y)) 
#define S(x, n)         RORc((x), (n))
#define R(x, n)         (((x)&0xFFFFFFFFUL)>>(n))
#define Sigma0(x)       (S(x, 2) ^ S(x, 13) ^ S(x, 22))
#define Sigma1(x)       (S(x, 6) ^ S(x, 11) ^ S(x, 25))
#define Gamma0(x)       (S(x, 7) ^ S(x, 18) ^ R(x, 3))
#define Gamma1(x)       (S(x, 17) ^ S(x, 19) ^ R(x, 10))

#define RND(a,b,c,d,e,f,g,h,i) \
  t0 = h + Sigma1(e) + Ch(e, f, g) + K[i] + W[i]; \
  t1 = Sigma0(a) + Maj(a, b, c); \
  d += t0; \
  h  = t0 + t1

/* compress 512-bits */
static OFC_INT sha256_compress(struct sha256_state *md, OFC_UCHAR *buf)
{
  OFC_UINT32 S[8], W[64], t0, t1;
  OFC_UINT32 t;
  OFC_INT i;

  /* copy state into S */
  for (i = 0; i < 8; i++) {
    S[i] = md->state[i];
  }

  /* copy the state into 512-bits into W[0..15] */
  for (i = 0; i < 16; i++)
    {
      W[i] = OFC_NET_NTOL (buf, (4*i)) ;
    }

  /* fill W[16..63] */
  for (i = 16; i < 64; i++) {
    W[i] = Gamma1(W[i - 2]) + W[i - 7] + Gamma0(W[i - 15]) +
      W[i - 16];
  }        

  /* Compress */
  for (i = 0; i < 64; ++i) {
    RND(S[0], S[1], S[2], S[3], S[4], S[5], S[6], S[7], i);
    t = S[7]; S[7] = S[6]; S[6] = S[5]; S[5] = S[4]; 
    S[4] = S[3]; S[3] = S[2]; S[2] = S[1]; S[1] = S[0]; S[0] = t;
  }

  /* feedback */
  for (i = 0; i < 8; i++) {
    md->state[i] = md->state[i] + S[i];
  }
  return 0;
}

/* Initialize the hash state */
OFC_VOID sha256_init(struct sha256_state *md)
{
  md->curlen = 0;
  md->length = 0;
  md->state[0] = 0x6A09E667UL;
  md->state[1] = 0xBB67AE85UL;
  md->state[2] = 0x3C6EF372UL;
  md->state[3] = 0xA54FF53AUL;
  md->state[4] = 0x510E527FUL;
  md->state[5] = 0x9B05688CUL;
  md->state[6] = 0x1F83D9ABUL;
  md->state[7] = 0x5BE0CD19UL;
}

/**
   Process a block of memory though the hash
   @param md     The hash state
   @param in     The data to hash
   @param inlen  The length of the data (octets)
   @return CRYPT_OK if successful
*/
OFC_INT sha256_process(struct sha256_state *md, const OFC_UCHAR *in,
			OFC_ULONG inlen)
{
  OFC_ULONG n;

  if (md->curlen >= sizeof(md->buf))
    return -1;

  while (inlen > 0) {
    if (md->curlen == 0 && inlen >= SHA256_BLOCK_SIZE) {
      if (sha256_compress(md, (OFC_UCHAR *) in) < 0)
	return -1;
      md->length += SHA256_BLOCK_SIZE * 8;
      in += SHA256_BLOCK_SIZE;
      inlen -= SHA256_BLOCK_SIZE;
    } else {
      n = OFC_MIN(inlen, (SHA256_BLOCK_SIZE - md->curlen));

      ofc_memcpy(md->buf + md->curlen, in, n);
      md->curlen += n;
      in += n;
      inlen -= n;
      if (md->curlen == SHA256_BLOCK_SIZE) {
	if (sha256_compress(md, md->buf) < 0)
	  return -1;
	md->length += 8 * SHA256_BLOCK_SIZE;
	md->curlen = 0;
      }
    }
  }

  return 0;
}


/**
   Terminate the hash to get the digest
   @param md  The hash state
   @param out [out] The destination of the hash (32 bytes)
   @return CRYPT_OK if successful
*/
OFC_INT sha256_done(struct sha256_state *md, OFC_UCHAR *out)
{
  OFC_INT i;

  if (md->curlen >= sizeof(md->buf))
    return -1;

  /* increase the length of the message */
  md->length += md->curlen * 8;

  /* append the '1' bit */
  md->buf[md->curlen++] = (OFC_UCHAR) 0x80;

  /* if the length is currently above 56 bytes we append zeros
   * then compress.  Then we can fall back to padding zeros and length
   * encoding like normal.
   */
  if (md->curlen > 56) {
    while (md->curlen < SHA256_BLOCK_SIZE) {
      md->buf[md->curlen++] = (OFC_UCHAR) 0;
    }
    sha256_compress(md, md->buf);
    md->curlen = 0;
  }

  /* pad up to 56 bytes of zeroes */
  while (md->curlen < 56) {
    md->buf[md->curlen++] = (OFC_UCHAR) 0;
  }

  /* store length */
  OFC_NET_LLTON ((md->buf + 56), 0, md->length) ;
  sha256_compress(md, md->buf);

  /* copy output */
  for (i = 0; i < 8; i++)
    OFC_NET_LTON (out, (4 * i), md->state[i]) ;
  

  return 0;
}

/* ===== end - public domain SHA256 implementation ===== */

/**
 * hmac_sha256_vector - HMAC-SHA256 over data vector (RFC 2104)
 * @key: Key for HMAC operations
 * @key_len: Length of the key in bytes
 * @num_elem: Number of elements in the data vector
 * @addr: Pointers to the data areas
 * @len: Lengths of the data blocks
 * @mac: Buffer for the hash (32 bytes)
 * Returns: 0 on success, -1 on failure
 */
OFC_INT hmac_sha256_vector(const OFC_UCHAR *key, OFC_SIZET key_len, 
			    OFC_SIZET num_elem, const OFC_UCHAR *addr[], 
			    const OFC_SIZET *len, OFC_UCHAR *mac)
{
  OFC_UCHAR k_pad[64]; /* padding - key XORd with ipad/opad */
  OFC_UCHAR tk[32];
  const OFC_UCHAR *_addr[6];
  OFC_SIZET _len[6], i;

  if (num_elem > 5) {
    /*
     * Fixed limit on the number of fragments to avoid having to
     * allocate memory (which could fail).
     */
    return -1;
  }

  /* if key is longer than 64 bytes reset it to key = SHA256(key) */
  if (key_len > 64) {
    if (sha256_vector(1, &key, &key_len, tk) < 0)
      return -1;
    key = tk;
    key_len = 32;
  }

  /* the HMAC_SHA256 transform looks like:
   *
   * SHA256(K XOR opad, SHA256(K XOR ipad, text))
   *
   * where K is an n byte key
   * ipad is the byte 0x36 repeated 64 times
   * opad is the byte 0x5c repeated 64 times
   * and text is the data being protected */

  /* start out by storing key in ipad */
  ofc_memset(k_pad, 0, sizeof(k_pad));
  ofc_memcpy(k_pad, key, key_len);
  /* XOR key with ipad values */
  for (i = 0; i < 64; i++)
    k_pad[i] ^= 0x36;

  /* perform inner SHA256 */
  _addr[0] = k_pad;
  _len[0] = 64;
  for (i = 0; i < num_elem; i++) {
    _addr[i + 1] = addr[i];
    _len[i + 1] = len[i];
  }
  if (sha256_vector(1 + num_elem, _addr, _len, mac) < 0)
    return -1;

  ofc_memset(k_pad, 0, sizeof(k_pad));
  ofc_memcpy(k_pad, key, key_len);
  /* XOR key with opad values */
  for (i = 0; i < 64; i++)
    k_pad[i] ^= 0x5c;

  /* perform outer SHA256 */
  _addr[0] = k_pad;
  _len[0] = 64;
  _addr[1] = mac;
  _len[1] = SHA256_MAC_LEN;
  return sha256_vector(2, _addr, _len, mac);
}


/**
 * hmac_sha256 - HMAC-SHA256 over data buffer (RFC 2104)
 * @key: Key for HMAC operations
 * @key_len: Length of the key in bytes
 * @data: Pointers to the data area
 * @data_len: Length of the data area
 * @mac: Buffer for the hash (32 bytes)
 * Returns: 0 on success, -1 on failure
 */
OFC_INT hmac_sha256(const OFC_UCHAR *key, OFC_SIZET key_len, 
		     const OFC_UCHAR *data, OFC_SIZET data_len, 
		     OFC_UCHAR *mac)
{
  return hmac_sha256_vector(key, key_len, 1, &data, &data_len, mac);
}
