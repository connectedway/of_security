/* NTLM SASL plugin
 * Ken Murchison
 * $Id: ntlm.c,v 1.36 2011/01/14 14:35:57 murch Exp $
 *
 * References:
 *   http://www.innovation.ch/java/ntlm.html
 *   http://www.opengroup.org/comsource/techref2/NCH1222X.HTM
 *   http://www.ubiqx.org/cifs/rfc-draft/draft-leach-cifs-v1-spec-02.html
 */
/* 
 * Copyright (c) 1998-2003 Carnegie Mellon University.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "Carnegie Mellon University" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For permission or any other legal
 *    details, please contact  
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Computing Services
 *     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "of_security/saslint.h"

#include "ofc/socket.h"
#include "ofc/libc.h"
#include "ofc/time.h"
#include "ofc/net.h"
#include "ofc/net_internal.h"
#include "ofc/heap.h"

#include "of_security/md4.h"
#include "of_security/md5.h"
#include "of_security/opensslv.h"
#include "of_security/hmac-md5.h"

#include "of_security/des.h"

#include "of_security/sasl.h"
#include "of_security/saslplug.h"

#include "of_security/plugin_common.h"

/*****************************  Common Section  *****************************/

typedef unsigned char u_char ;

enum {
    NTLM_NONCE_LENGTH		= 8,
    NTLM_HASH_LENGTH		= 21,
    NTLM_RESP_LENGTH		= 24,
    NTLM_SESSKEY_LENGTH		= 16,
};

struct ntlm_credentials
{
  unsigned char password_hash[MD4_DIGEST_LENGTH] ;
  char *username ;
  char *domain ;
  unsigned char server_challenge[NTLM_NONCE_LENGTH] ;
  unsigned char timestamp[8] ;
  unsigned char credentials_hash[MD5_DIGEST_LENGTH] ;
  unsigned char user_session_key[MD5_DIGEST_LENGTH] ;
  unsigned char encrypted_session_key[MD5_DIGEST_LENGTH] ;
} ;

#define NTLMSSP_SIGN_VERSION 1

#define CLI_SIGN "session key to client-to-server signing key magic constant"
#define CLI_SEAL "session key to client-to-server sealing key magic constant"
#define SRV_SIGN "session key to server-to-client signing key magic constant"
#define SRV_SEAL "session key to server-to-client sealing key magic constant"

void printkey (char *text, const unsigned char *data, int len)
{
  int i ;	

  ofc_printf ("%s (%d): ", text, len) ;
  for (i = 0 ; i < len ; i++)
    ofc_printf ("\\x%02x", data[i]) ;
  ofc_printf ("\n") ;
}

//#define OFC_UINT16_MAX 65535U
typedef OFC_UINT16 uint16;

//#define OFC_UINT32_MAX 4294967295U
typedef OFC_UINT32 uint32;

#define NTLM_SIGNATURE		"NTLMSSP"

enum {
    NTLM_TYPE_REQUEST		= 1,
    NTLM_TYPE_CHALLENGE		= 2,
    NTLM_TYPE_RESPONSE		= 3
};

enum {
    NTLM_USE_UNICODE		= 0x00000001,
    NTLM_USE_ASCII		= 0x00000002,
    NTLM_ASK_TARGET		= 0x00000004,
    NTLM_NEGOTIATE_SIGN         = 0x00000010,
    NTLM_AUTH_NTLM		= 0x00000200,
    NTLM_ALWAYS_SIGN		= 0x00008000,
    NTLM_TARGET_IS_DOMAIN	= 0x00010000,
    NTLM_TARGET_IS_SERVER	= 0x00020000,
    NTLM_AUTH_NTLMV2            = 0x00080000,
    NTLM_NEGOTIATE_TARGETINFO   = 0x00800000,
    NTLM_NEGOTIATE_VERSION      = 0x02000000,
    NTLM_NEGOTIATE_128          = 0x20000000,
    NTLM_NEGOTIATE_KEY_EXCH     = 0x40000000,
    NTLM_FLAGS_MASK		= 0x6288ffdf
};

enum {
    NTLM_SIG_OFFSET		= 0,
    NTLM_TYPE_OFFSET		= 8,

    NTLM_TYPE1_FLAGS_OFFSET	= 12,
    NTLM_TYPE1_DOMAIN_OFFSET	= 16,
    NTLM_TYPE1_WORKSTN_OFFSET	= 24,
    NTLM_TYPE1_VERSION_OFFSET   = 32,
    NTLM_TYPE1_DATA_OFFSET	= 40,
    NTLM_TYPE1_MINSIZE		= 16,

    NTLM_TYPE2_TARGET_OFFSET	= 12,
    NTLM_TYPE2_FLAGS_OFFSET	= 20,
    NTLM_TYPE2_CHALLENGE_OFFSET	= 24,
    NTLM_TYPE2_CONTEXT_OFFSET	= 32,
    NTLM_TYPE2_TARGETINFO_OFFSET= 40,
    NTLM_TYPE2_VERSION_OFFSET   = 48,
    NTLM_TYPE2_DATA_OFFSET	= 56,
    NTLM_TYPE2_MINSIZE		= 32,

    NTLM_TYPE3_LMRESP_OFFSET	= 12,
    NTLM_TYPE3_NTRESP_OFFSET	= 20,
    NTLM_TYPE3_DOMAIN_OFFSET	= 28,
    NTLM_TYPE3_USER_OFFSET	= 36,
    NTLM_TYPE3_WORKSTN_OFFSET	= 44,
    NTLM_TYPE3_SESSIONKEY_OFFSET= 52,
    NTLM_TYPE3_FLAGS_OFFSET	= 60,
    NTLM_TYPE3_VERSION_OFFSET   = 64,
    NTLM_TYPE3_MIC_OFFSET       = 72,
    NTLM_TYPE3_MIC_SIZE         = 16,
    NTLM_TYPE3_DATA_OFFSET	= 88,
    NTLM_TYPE3_MINSIZE		= 52,

    NTLM_BUFFER_LEN_OFFSET	= 0,
    NTLM_BUFFER_MAXLEN_OFFSET	= 2,
    NTLM_BUFFER_OFFSET_OFFSET	= 4,
    NTLM_BUFFER_SIZE		= 8,

    NTLM_VERSION_MAJOR_OFFSET   = 0,
    NTLM_VERSION_MINOR_OFFSET   = 1,
    NTLM_VERSION_BUILD_OFFSET   = 2,
    NTLM_VERSION_REV_OFFSET     = 4,
    NTLM_VERSION_SIZE           = 8
};

#define NTLM_VERSION_MAJOR 6
#define NTLM_VERSION_MINOR 1
#define NTLM_VERSION_BUILD 0
#define NTLM_VERSION_REV 15

#define ATTR_TYPE 0
#define ATTR_LEN 2
#define ATTR_DATA 4  

/* machine-independent routines to convert to/from Intel byte-order */
#define htois(is, hs) \
    (is)[0] = hs & 0xff; \
    (is)[1] = (unsigned char)((unsigned)hs >> 8)

void htoit(unsigned char *it, OFC_CTCHAR *ht, int l)
{
  int ix ;
  for (ix = 0 ; ix < l ; ix++)
    {
      htois (it+(ix*2),ht[ix]) ;
    }
}

#define itohs(is) \
  (((const unsigned char *)is)[0] | \
   (((const unsigned char *)is)[1] << 8))

#define htoil(il, hl) \
    (il)[0] = hl & 0xff; \
    (il)[1] = (hl >> 8) & 0xff; \
    (il)[2] = (hl >> 16) & 0xff; \
    (il)[3] = hl >> 24

#define itohl(il) \
  (((const unsigned char*)il)[0] | \
   (((const unsigned char *)il)[1] << 8) | \
   (((const unsigned char *)il)[2] << 16) | \
   (((const unsigned char *)il)[3] << 24))

#define N 128   // 2^8

OFC_VOID swap(OFC_UCHAR *a, OFC_UCHAR *b) 
{
  OFC_INT tmp = *a;
  *a = *b;
  *b = tmp;
}

OFC_VOID KSA(OFC_UCHAR *key, OFC_UCHAR *S) {

  OFC_INT len = NTLM_SESSKEY_LENGTH ;
  OFC_INT j = 0;
  OFC_INT i ;

  for(i = 0; i < N; i++)
    S[i] = i;

  for(i = 0; i < N; i++) 
    {
      j = (j + S[i] + key[i % len]) % N;

      swap(&S[i], &S[j]);
    }
}

OFC_VOID PRGA(OFC_UCHAR *S, OFC_UCHAR *plaintext, OFC_UCHAR *ciphertext) 
{
  OFC_INT i = 0;
  OFC_INT j = 0;
  OFC_SIZET n;
  OFC_SIZET len;
  OFC_INT rnd ;
  
  for(n = 0, len = NTLM_SESSKEY_LENGTH; n < len; n++) 
    {
      i = (i + 1) % N;
      j = (j + S[i]) % N;

      swap(&S[i], &S[j]);
      rnd = S[(S[i] + S[j]) % N];

      ciphertext[n] = rnd ^ plaintext[n];

    }
}

OFC_VOID RC4(OFC_UCHAR *key, OFC_UCHAR *plaintext, OFC_UCHAR *ciphertext) 
{
  OFC_UCHAR S[N];
  KSA(key, S);

  PRGA(S, plaintext, ciphertext);
}

typedef struct datablob {
	OFC_UCHAR *data;
	size_t length;
} OFC_DATA_BLOB;

struct arcfour_state {
	OFC_UCHAR sbox[256];
	OFC_UCHAR index_i;
	OFC_UCHAR index_j;
};

/* initialise the arcfour sbox with key */
void arcfour_init(struct arcfour_state *state, const OFC_DATA_BLOB *key)
{
	size_t ind;
	OFC_UCHAR j = 0;
	for (ind = 0; ind < sizeof(state->sbox); ind++) {
		state->sbox[ind] = (OFC_UCHAR)ind;
	}

	for (ind = 0; ind < sizeof(state->sbox); ind++) {
		OFC_UCHAR tc;

		j += (state->sbox[ind] + key->data[ind%key->length]);

		tc = state->sbox[ind];
		state->sbox[ind] = state->sbox[j];
		state->sbox[j] = tc;
	}
	state->index_i = 0;
	state->index_j = 0;
}

/* crypt the data with arcfour */
void arcfour_crypt_sbox(struct arcfour_state *state, OFC_UCHAR *data,
			int len)
{
	int ind;

	for (ind = 0; ind < len; ind++) {
		OFC_UCHAR tc;
		OFC_UCHAR t;

		state->index_i++;
		state->index_j += state->sbox[state->index_i];

		tc = state->sbox[state->index_i];
		state->sbox[state->index_i] = state->sbox[state->index_j];
		state->sbox[state->index_j] = tc;

		t = state->sbox[state->index_i] + state->sbox[state->index_j];
		data[ind] = data[ind] ^ state->sbox[t];
	}
}

/*
  arcfour encryption with a blob key
*/
void arcfour_crypt_blob(OFC_UCHAR *data, int len, const OFC_DATA_BLOB *key)
{
	struct arcfour_state state;
	arcfour_init(&state, key);
	arcfour_crypt_sbox(&state, data, len);
}

/*
  a variant that assumes a 16 byte key. This should be removed
  when the last user is gone
*/
void arcfour_crypt(OFC_UCHAR *data, const OFC_UCHAR keystr[16], int len)
{
	OFC_UCHAR keycopy[16];
	OFC_DATA_BLOB key ;

	key.data = keycopy ;
	key.length = sizeof(keycopy) ;

	ofc_memcpy(keycopy, keystr, sizeof(keycopy));

	arcfour_crypt_blob(data, len, &key);
}

/* convert string to all upper case */
static const char *ucase(const char *str, OFC_SIZET len)
{
    char *cp = (char *) str;

    if (!len) len = ofc_strlen(str);
    
    while (len && cp && *cp) {
	*cp = OFC_TOUPPER((int) *cp);
	cp++;
	len--;
    }

    return (str);
}

/* copy src to dst as unicode (in Intel byte-order) */
static void to_unicode(OFC_UCHAR *dst, const unsigned char *src, OFC_SIZET len)
{
    for (; len; len--) {
	*dst++ = *src++;
	*dst++ = 0;
    }
}

/* copy unicode src (in Intel byte-order) to dst */
static void from_unicode(char *dst, OFC_UCHAR *src, int len)
{
    for (; len; len--) {
	*dst++ = *src & 0x7f;
	src += 2;
    }
}

/* load a string into an NTLM buffer */
static void load_buffer(OFC_UCHAR *buf, const OFC_UCHAR *str, OFC_UINT16 len,
			int unicode, OFC_UCHAR *base, OFC_UINT32 *offset)
{
    if (len) {
	if (unicode) {
	  to_unicode(base + *offset, str, len);
	    len *= 2;
	}
	else {
	    ofc_memcpy(base + *offset, str, len);
	}
    }

    htois(buf + NTLM_BUFFER_LEN_OFFSET, len);
    htois(buf + NTLM_BUFFER_MAXLEN_OFFSET, len);
    htoil(buf + NTLM_BUFFER_OFFSET_OFFSET, *offset);
    *offset += len;
}

/* unload a string from an NTLM buffer */
static int unload_buffer(const sasl_utils_t *utils, const OFC_UCHAR *buf,
			 OFC_UCHAR **str, unsigned *outlen,
			 int unicode, const OFC_UCHAR *base, unsigned msglen)
{
    uint16 len = itohs(buf + NTLM_BUFFER_LEN_OFFSET);

    if (len) {
	uint32 offset;

	*str = utils->malloc(len + 1); /* add 1 for NUL */
	if (*str == OFC_NULL) {
	    MEMERROR(utils->conn);
	    return SASL_NOMEM;
	}

	offset = itohl(buf + NTLM_BUFFER_OFFSET_OFFSET);

	/* sanity check */
	if (offset > msglen || len > (msglen - offset)) return SASL_BADPROT;

	if (unicode) {
	    len /= 2;
	    from_unicode((char *) *str, (OFC_UCHAR *) base + offset, len);
	}
	else
	    ofc_memcpy(*str, base + offset, len);

	(*str)[len] = '\0'; /* add NUL */
    }
    else {
	*str = OFC_NULL;
    }

    if (outlen) *outlen = len;

    return SASL_OK;
}

/*
 * NTLM encryption/authentication routines per section 2.10 of
 * draft-leach-cifs-v1-spec-02
 */
static void E(unsigned char *out, unsigned char *K, unsigned Klen,
	      unsigned char *D, unsigned Dlen)
	      
{
    unsigned k, d;
    DES_cblock K64;
    DES_key_schedule ks;
    unsigned char *Dp;
#define KEY_SIZE   7
#define BLOCK_SIZE 8

    for (k = 0; k < Klen; k += KEY_SIZE, K += KEY_SIZE) {
	/* convert 56-bit key to 64-bit */
	K64[0] = K[0];
	K64[1] = ((K[0] << 7) & 0xFF) | (K[1] >> 1);
	K64[2] = ((K[1] << 6) & 0xFF) | (K[2] >> 2);
	K64[3] = ((K[2] << 5) & 0xFF) | (K[3] >> 3);
	K64[4] = ((K[3] << 4) & 0xFF) | (K[4] >> 4);
	K64[5] = ((K[4] << 3) & 0xFF) | (K[5] >> 5);
	K64[6] = ((K[5] << 2) & 0xFF) | (K[6] >> 6);
	K64[7] =  (K[6] << 1) & 0xFF;

 	of_security_DES_set_odd_parity(&K64); /* XXX is this necessary? */
 	of_security_DES_set_key(&K64, &ks);

	for (d = 0, Dp = D; d < Dlen;
	     d += BLOCK_SIZE, Dp += BLOCK_SIZE, out += BLOCK_SIZE) {
 	    of_security_DES_ecb_encrypt((void *) Dp, (void *) out, &ks, DES_ENCRYPT);
	}
    }
}

static unsigned char *P16_lm(unsigned char *P16, sasl_secret_t *passwd,
			     const sasl_utils_t *utils,
			     char **buf,
			     unsigned *buflen,
			     int *result)
{
    char P14[14];
    unsigned char S8[] = { 0x4b, 0x47, 0x53, 0x21, 0x40, 0x23, 0x24, 0x25 };

    ofc_strncpy(P14, (char *) passwd->data, sizeof(P14));
    ucase(P14, sizeof(P14));

    E(P16, (unsigned char *) P14, sizeof(P14), S8, sizeof(S8));
    *result = SASL_OK;
    return P16;
}

static unsigned char *P16_nt(unsigned char *P16, sasl_secret_t *passwd,
			     const sasl_utils_t *utils,
			     char **buf, unsigned *buflen, int *result)
{
  if (of_security_plug_buf_alloc(utils, buf, buflen, 2 * (unsigned) passwd->len) != SASL_OK) 
    {
      SETERROR(utils, "cannot allocate P16_nt unicode buffer");
      *result = SASL_NOMEM;
    }
  else 
    {
      to_unicode((unsigned char *) *buf, passwd->data, passwd->len);
      of_security_MD4((unsigned char *) *buf, 2 * passwd->len, P16);
      *result = SASL_OK;
    }
  return P16;
}

static unsigned char *P21(unsigned char *P21, sasl_secret_t *passwd,
			  unsigned char * (*P16)(unsigned char *,
						 sasl_secret_t *,
						 const sasl_utils_t *,
						 char **, unsigned *, int *),
			  const sasl_utils_t *utils,
			  char **buf, unsigned *buflen, int *result)
{
    ofc_memset(P16(P21, passwd, utils, buf, buflen, result) + 16, 0, 5);
    return P21;
}

static unsigned char *P24(unsigned char *P24, unsigned char *P21,
			  unsigned char *C8)
		      
{
    E(P24, P21, NTLM_HASH_LENGTH, C8, NTLM_NONCE_LENGTH);
    return P24;
}

static unsigned char *V2(unsigned char *V2, sasl_secret_t *passwd,
			 const char *authid, const char *target,
			 const unsigned char *challenge,
			 const unsigned char *blob, unsigned bloblen,
			 const sasl_utils_t *utils,
			 char **buf, unsigned *buflen, int *result)
{
    HMAC_MD5_CTX ctx ;
    // this is 16
    unsigned char hash[HMAC_MD5_SIZE] ;

    char *upper;
    unsigned int len;

    /* Allocate enough space for the unicode target */
    len = (unsigned int) (ofc_strlen(authid) + ofc_strlen(target));

    if (of_security_plug_buf_alloc(utils, buf, buflen, 2 * len + 1) != SASL_OK) {
	SETERROR(utils, "cannot allocate NTLMv2 hash");
	*result = SASL_NOMEM;
    }
    else {
	/* NTLMv2hash = HMAC-MD5(NTLMhash, unicode(ucase(authid + domain))) */
	P16_nt(hash, passwd, utils, buf, buflen, result);

	/* Use the tail end of the buffer for ucase() conversion */
	upper = *buf + len;
	ofc_strcpy(upper, authid);
	if (target) ofc_strcat(upper, target);
	ucase(upper, len);
	to_unicode((unsigned char *) *buf, (unsigned char *) upper, len);

	of_security_hmac_md5((unsigned char *) *buf, 2 * len, hash, 
		       MD4_DIGEST_LENGTH, hash) ;

	of_security_hmac_md5_init (&ctx, hash, HMAC_MD5_SIZE) ;
	of_security_hmac_md5_update(&ctx, challenge, NTLM_NONCE_LENGTH) ;
	of_security_hmac_md5_update(&ctx, blob, bloblen);
	of_security_hmac_md5_final(V2,&ctx);

	/* the blob is concatenated outside of this function */

	*result = SASL_OK;
    }

    return V2;
}

static void ntlm_proof (struct ntlm_credentials *credentials,
			unsigned char *blob,
			OFC_SIZET blob_length,
			unsigned char resp[MD5_DIGEST_LENGTH])
{
  HMAC_MD5_CTX ctx ;

  of_security_hmac_md5_init (&ctx, credentials->credentials_hash,
			    sizeof (credentials->credentials_hash)) ;
  of_security_hmac_md5_update(&ctx, credentials->server_challenge,
			     NTLM_NONCE_LENGTH) ;
  of_security_hmac_md5_update (&ctx, blob, blob_length) ;

  of_security_hmac_md5_final(resp, &ctx) ;
}

static int ntlm_sesskey (struct ntlm_credentials *credentials, 
			 unsigned char *resp)
{
  HMAC_MD5_CTX ctx ;
  int result ;

  of_security_hmac_md5_init (&ctx, credentials->credentials_hash,
			    sizeof (credentials->credentials_hash)) ;
  of_security_hmac_md5_update(&ctx, resp, 16) ;

  of_security_hmac_md5_final(credentials->user_session_key, &ctx) ;

  result = SASL_OK ;

  return (result) ;
}

/*****************************  Server Section  *****************************/

typedef struct server_context {
    int state;

    uint32 flags;
    unsigned char nonce[NTLM_NONCE_LENGTH];

    /* per-step mem management */
    char *out_buf;
    unsigned out_buf_len;

    unsigned char send_key[NTLM_SESSKEY_LENGTH] ;
    unsigned char seal_key[NTLM_SESSKEY_LENGTH] ;
    struct arcfour_state send_seal_state;
    unsigned char session_key[NTLM_SESSKEY_LENGTH] ;
    struct ntlm_credentials *credentials ;
} server_context_t;

/*
 * Create a server challenge message (type 2) consisting of:
 *
 * signature (8 bytes)
 * message type (uint32)
 * target name (buffer)
 * flags (uint32)
 * challenge (8 bytes)
 * context (8 bytes)
 * target info (buffer)
 * data
 */
static int create_challenge(const sasl_utils_t *utils,
			    const OFC_UCHAR *target_info,
			    OFC_UINT16 target_info_length,
			    char **buf, unsigned *buflen,
			    const char *target, uint32 flags,
			    const u_char *nonce, unsigned int*outlen)
{
    uint32 offset = NTLM_TYPE2_DATA_OFFSET;
    u_char *base;

    if (!nonce) {
	SETERROR(utils, "need nonce for NTLM challenge");
	return SASL_FAIL;
    }

    *outlen = offset + 2 * (unsigned int) ofc_strlen(target) + target_info_length ;

    if (of_security_plug_buf_alloc(utils, buf, buflen, *outlen) != SASL_OK) {
	SETERROR(utils, "cannot allocate NTLM challenge");
	return SASL_NOMEM;
    }

    base = (unsigned char *) *buf;
    ofc_memset(base, 0, *outlen);
    ofc_memcpy(base + NTLM_SIG_OFFSET, NTLM_SIGNATURE, sizeof(NTLM_SIGNATURE));
    htoil(base + NTLM_TYPE_OFFSET, NTLM_TYPE_CHALLENGE);
    load_buffer(base + NTLM_TYPE2_TARGET_OFFSET,
		(const OFC_UCHAR *) ucase((const char *) target, 0), (uint16) ofc_strlen(target), flags & NTLM_USE_UNICODE,
		base, &offset);
    htoil(base + NTLM_TYPE2_FLAGS_OFFSET, flags);
    ofc_memcpy(base + NTLM_TYPE2_CHALLENGE_OFFSET, nonce, NTLM_NONCE_LENGTH);

    load_buffer(base + NTLM_TYPE2_TARGETINFO_OFFSET,
		(const OFC_UCHAR *) target_info, 
		(uint16) target_info_length, 0,
		base, &offset);

    if (flags & NTLM_NEGOTIATE_VERSION) {
      *(base + NTLM_TYPE2_VERSION_OFFSET + NTLM_VERSION_MAJOR_OFFSET) = NTLM_VERSION_MAJOR ;
      *(base + NTLM_TYPE2_VERSION_OFFSET + NTLM_VERSION_MINOR_OFFSET) = NTLM_VERSION_MINOR ;
      htois(base + NTLM_TYPE2_VERSION_OFFSET + NTLM_VERSION_BUILD_OFFSET, NTLM_VERSION_BUILD) ;
      htoil(base + NTLM_TYPE2_VERSION_OFFSET + NTLM_VERSION_REV_OFFSET, NTLM_VERSION_REV) ;
    }

    return SASL_OK;
}

static int ntlm_server_mech_new(void *glob_context,
				sasl_server_params_t *sparams,
				const char *challenge,
				unsigned intchallen,
				void **conn_context)
{
    server_context_t *text;

    /* holds state are in */
    text = sparams->utils->malloc(sizeof(server_context_t));
    if (text == OFC_NULL) {
	MEMERROR( sparams->utils->conn );
	return SASL_NOMEM;
    }
    
    ofc_memset(text, 0, sizeof(server_context_t));
    
    text->state = 1;
    
    *conn_context = text;
    
    return SASL_OK;
}

static int ntlm_server_mech_step1(server_context_t *text,
				  sasl_server_params_t *sparams,
				  const char *clientin,
				  unsigned int clientinlen,
				  const char **serverout,
				  unsigned int *serveroutlen,
				  sasl_out_params_t *oparams)
{
    char *domain = OFC_NULL;
    int result;
    unsigned char *target_info ;
    unsigned char *ptargetinfo ;
    char timestamp[8];
    OFC_FILETIME filetime ;
    OFC_UINT64 ft ;
    OFC_SIZET netbios_name_len ;
    OFC_SIZET target_info_length ;

    if (!clientin || clientinlen < NTLM_TYPE1_MINSIZE ||
	ofc_memcmp(clientin, NTLM_SIGNATURE, sizeof(NTLM_SIGNATURE)) ||
	itohl(clientin + NTLM_TYPE_OFFSET) != NTLM_TYPE_REQUEST) 
      {
	SETERROR(sparams->utils, "client didn't issue valid NTLM request");
	return SASL_BADPROT;
      }

    text->flags = itohl(clientin + NTLM_TYPE1_FLAGS_OFFSET);

    sparams->utils->log(OFC_NULL, SASL_LOG_DEBUG,
			"client flags: %x", text->flags);

    text->flags &= NTLM_FLAGS_MASK; /* mask off the bits we don't support */
    text->flags |= NTLM_NEGOTIATE_TARGETINFO ;

    /* if client can do Unicode, turn off ASCII */
    if (text->flags & NTLM_USE_UNICODE) text->flags &= ~NTLM_USE_ASCII;

    /* generate challenge internally */

    /* if client asked for target, use FQDN as server target */
    if (text->flags & NTLM_ASK_TARGET) {
      domain = ofc_strdup (sparams->serverFQDN) ;
      if (domain == OFC_NULL)
	return (SASL_FAIL) ;
      text->flags |= NTLM_TARGET_IS_SERVER;
    }

    /* generate a nonce */
    sparams->utils->rand(sparams->utils->rpool,
			 (char *) text->nonce, NTLM_NONCE_LENGTH);

    netbios_name_len = ofc_tstrlen (sparams->netbios_name) ;

    ofc_time_get_file_time (&filetime) ;
    OFC_LARGE_INTEGER_SET (ft, 
			    filetime.dwLowDateTime, 
			    filetime.dwHighDateTime) ;
    OFC_NET_LLTOSMB (&timestamp, 0, ft) ;

    target_info_length = 
      ATTR_DATA + 2*netbios_name_len +  /* netbios domain */
      ATTR_DATA + 2*netbios_name_len +  /* netbios computer */
      ATTR_DATA + 2 +			/* dns domain */
      ATTR_DATA + 2*netbios_name_len +   /* dns computer */
      ATTR_DATA + sizeof (timestamp) +	 /* timestamp */
      ATTR_DATA ;			 /* end of list */

    target_info = ofc_malloc (target_info_length) ;

    ptargetinfo = target_info ;
    htois (ptargetinfo + ATTR_TYPE, 2) ;
    htois (ptargetinfo + ATTR_LEN, (int) 2*netbios_name_len) ;
    htoit (ptargetinfo + ATTR_DATA, sparams->netbios_name, (int) netbios_name_len) ;
    ptargetinfo += ATTR_DATA + 2*netbios_name_len ;

    htois (ptargetinfo + ATTR_TYPE, 1) ;
    htois (ptargetinfo + ATTR_LEN, (int) 2*netbios_name_len) ;
    htoit (ptargetinfo + ATTR_DATA, sparams->netbios_name, (int) netbios_name_len) ;
    ptargetinfo += ATTR_DATA + 2*netbios_name_len ;

    htois (ptargetinfo + ATTR_TYPE, 4) ;
    htois (ptargetinfo + ATTR_LEN, 2) ;
    htoit (ptargetinfo + ATTR_DATA, TSTR(""), 1) ;
    ptargetinfo += ATTR_DATA + 2 ;

    htois (ptargetinfo + ATTR_TYPE, 3) ;
    htois (ptargetinfo + ATTR_LEN, 2*netbios_name_len) ;
    htoit (ptargetinfo + ATTR_DATA, sparams->netbios_name, (int) netbios_name_len) ;
    ptargetinfo += ATTR_DATA + 2*netbios_name_len ;

    htois (ptargetinfo + ATTR_TYPE, 7) ;
    htois (ptargetinfo + ATTR_LEN, sizeof(timestamp)) ;
    ofc_memcpy (ptargetinfo + ATTR_DATA, timestamp, sizeof(timestamp)) ;
    ptargetinfo += ATTR_DATA + sizeof(timestamp) ;

    htois (ptargetinfo + ATTR_TYPE, 0) ;
    htois (ptargetinfo + ATTR_LEN, 0) ;
    ptargetinfo += ATTR_DATA ;

    result = create_challenge(sparams->utils,
			      target_info, (OFC_UINT16) target_info_length,
			      &text->out_buf, &text->out_buf_len,
			      domain, text->flags, text->nonce, serveroutlen);
    if (result != SASL_OK) goto cleanup;

    *serverout = text->out_buf;

    text->state = 2;
    
    result = SASL_CONTINUE;

  cleanup:
    ofc_free (target_info) ;

    if (domain) sparams->utils->free(domain);

    return result;
}

static OFC_BOOL parseBlob (const OFC_UCHAR **target_info,
			    OFC_UINT16 *target_info_length,
			    const OFC_UCHAR **cnonce,
			    const unsigned char **timestamp,
			    unsigned char *blob,
			    const OFC_UINT16 blob_len)
{
  OFC_CHAR blob_signature[4] = { 0x01, 0x01, 0x00, 0x00 } ;
  OFC_SIZET offset ;
  OFC_BOOL ret ;

  ret = OFC_TRUE ;
  offset = 0 ;

  if (ofc_memcmp (blob_signature, blob+offset, sizeof(blob_signature)) != 0)
    ret = OFC_FALSE ;
  else 
    {
      offset += sizeof(blob_signature) ;
      /* reserved */
      offset += 4 ;
      /* timestamp */
      if (timestamp != OFC_NULL)
	*timestamp = blob+offset ;
      offset += 8 ;
      if (cnonce != OFC_NULL)
	*cnonce = blob+offset ;
      offset += NTLM_NONCE_LENGTH ;
      /* unknown */
      offset += 4 ;
      /* target info */
      if (target_info != OFC_NULL)
	*target_info = blob+offset ;
      if (target_info_length != OFC_NULL)
	*target_info_length = blob_len - (OFC_UINT16) offset ;
    }
  return (ret) ;
}

static int ntlm_create_password_hash (const sasl_secret_t *passwd,
				      unsigned char *hash)
{
  int result ;
  unsigned char *buf ;

  buf = ofc_malloc (passwd->len * sizeof (OFC_UINT16)) ;
  if (buf == OFC_NULL)
    result = SASL_NOMEM ;
  else
    {
      to_unicode(buf, passwd->data, passwd->len);
      of_security_MD4(buf, 2 * passwd->len, hash);
      result = SASL_OK ;

      ofc_free (buf) ;
    }
  return (result) ;
}

struct ntlm_credentials *ntlm_create_credentials (const sasl_secret_t *passwd,
						  const char *username,
						  const char *domain,
						  const unsigned char 
						  challenge[NTLM_NONCE_LENGTH],
						  const unsigned char
						  timestamp[8])
{
  int result ;
  struct ntlm_credentials *credentials ;
  HMAC_MD5_CTX ctx ;
  unsigned char *unicode_username ;
  unsigned char *unicode_domain ;
  unsigned char *upper_username ;
  unsigned char *upper_domain ;
  OFC_SIZET username_length = 0 ;
  OFC_SIZET domain_length = 0 ;

  credentials = ofc_malloc (sizeof (struct ntlm_credentials)) ;
  if (credentials == OFC_NULL)
    result = SASL_NOMEM ;
  else
    {
      result = ntlm_create_password_hash (passwd, 
					  credentials->password_hash) ;

      credentials->username = ofc_strdup (username) ;
      credentials->domain = ofc_strdup (domain) ;
      ofc_memcpy (credentials->server_challenge, challenge, 
		   NTLM_NONCE_LENGTH) ;
      ofc_memcpy (credentials->timestamp, timestamp, 8) ;

      unicode_username = OFC_NULL ;
      upper_username = (unsigned char *) ofc_strdup (credentials->username) ;
      if (upper_username != OFC_NULL)
	{
	  username_length = ofc_strlen (credentials->username) ;
	  ucase ((char *) upper_username, username_length) ;
	  unicode_username = 
	    ofc_malloc (username_length * sizeof (OFC_UINT16)) ;
	  if (unicode_username != OFC_NULL)
	    to_unicode (unicode_username, upper_username, username_length) ;
	  ofc_free (upper_username) ;
	}
	    
      unicode_domain = OFC_NULL ;
      upper_domain = (unsigned char *) ofc_strdup (credentials->domain) ;
      if (upper_domain != OFC_NULL)
	{
	  
	  domain_length = ofc_strlen (credentials->domain) ;
	  unicode_domain = 
	    ofc_malloc (domain_length * sizeof (OFC_UINT16)) ;
	  if (unicode_domain != OFC_NULL)
	    to_unicode (unicode_domain, upper_domain, domain_length) ;
	  ofc_free (upper_domain) ;
	}
	    
      if (unicode_username != OFC_NULL)
	{
	  of_security_hmac_md5_init (&ctx, credentials->password_hash,
				    sizeof (credentials->password_hash)) ;
	  of_security_hmac_md5_update(&ctx, unicode_username, 
				     username_length * sizeof (OFC_UINT16)) ;
	  if (unicode_domain != OFC_NULL)
	    {
	      of_security_hmac_md5_update(&ctx, unicode_domain, 
					 domain_length * sizeof (OFC_UINT16)) ;
	    }
	  of_security_hmac_md5_final(credentials->credentials_hash,&ctx);
	}
      else
	{
	  ofc_free (credentials->username) ;
	  ofc_free (credentials->domain) ;
	  ofc_free (credentials) ;
	  credentials = OFC_NULL ;
	}
      if (unicode_username != OFC_NULL)
	ofc_free (unicode_username) ;
      if (unicode_domain != OFC_NULL)
	ofc_free (unicode_domain) ;
    }
  return (credentials) ;
}

OFC_VOID ntlm_free_credentials (struct ntlm_credentials *credentials)
{
  if (credentials->username)
    ofc_free (credentials->username) ;
  credentials->username = OFC_NULL ;

  if (credentials->domain)
    ofc_free (credentials->domain) ;
  credentials->domain = OFC_NULL ;

  ofc_free (credentials) ;
}  

OFC_VOID ntlm_server_sign_init (server_context_t *text)
{
  struct ntlm_credentials *credentials ;
  OFC_DATA_BLOB key ;
  MD5_CTX ctx ;

#if 0
  credentials = text->credentials ;

  of_security_MD5Init (&ctx) ;

  of_security_MD5Update (&ctx, credentials->user_session_key, 
			NTLM_SESSKEY_LENGTH) ;
  of_security_MD5Update (&ctx, (const OFC_UCHAR *)SRV_SIGN, 
			ofc_strlen(SRV_SIGN)+1) ;

  of_security_MD5Final (text->send_key, &ctx) ;

  of_security_MD5Init (&ctx) ;
  of_security_MD5Update (&ctx, credentials->user_session_key, 
			NTLM_SESSKEY_LENGTH) ;
  of_security_MD5Update (&ctx, (const OFC_UCHAR *)SRV_SEAL, 
			ofc_strlen(SRV_SEAL)+1) ;
  of_security_MD5Final (text->seal_key, &ctx) ;

  key.data = text->seal_key ;
  key.length = 16 ;
  arcfour_init(&text->send_seal_state, &key) ;
#else
  credentials = text->credentials ;

  of_security_MD5Init (&ctx) ;

  of_security_MD5Update (&ctx, credentials->user_session_key, 
			NTLM_SESSKEY_LENGTH) ;
  of_security_MD5Update (&ctx, (const OFC_UCHAR *)CLI_SIGN, 
			ofc_strlen(CLI_SIGN)+1) ;

  of_security_MD5Final (text->send_key, &ctx) ;

  of_security_MD5Init (&ctx) ;
  of_security_MD5Update (&ctx, credentials->user_session_key, 
			NTLM_SESSKEY_LENGTH) ;
  of_security_MD5Update (&ctx, (const OFC_UCHAR *)CLI_SEAL, 
			ofc_strlen(CLI_SEAL)+1) ;
  of_security_MD5Final (text->seal_key, &ctx) ;

  key.data = text->seal_key ;
  key.length = 16 ;
  arcfour_init(&text->send_seal_state, &key) ;
#endif
}

static int ntlm_server_mech_step2(server_context_t *text,
				  sasl_server_params_t *sparams,
				  const char *clientin,
				  unsigned int clientinlen,
				  const char **serverout,
				  unsigned int *serveroutlen,
				  sasl_out_params_t *oparams)
{
    unsigned char *lm_resp = OFC_NULL, *nt_resp = OFC_NULL;
    char *domain = OFC_NULL, *authid = OFC_NULL;
    unsigned int lm_resp_len, nt_resp_len, domain_len, authid_len;
    int result;
    sasl_secret_t *password = OFC_NULL;
    OFC_SIZET pass_len;
    const char *password_request[] = { SASL_AUX_PASSWORD,
				       OFC_NULL };
    struct propval auxprop_values[2];
    unsigned char hash[NTLM_HASH_LENGTH];
    unsigned char resp[NTLM_RESP_LENGTH];
    OFC_UCHAR *session_key = OFC_NULL ;
    unsigned session_key_length ;

    if (!clientin || clientinlen < NTLM_TYPE3_MINSIZE ||
	ofc_memcmp(clientin, NTLM_SIGNATURE, sizeof(NTLM_SIGNATURE)) || 
	itohl(clientin + NTLM_TYPE_OFFSET) != NTLM_TYPE_RESPONSE)
      {
	SETERROR(sparams->utils, "client didn't issue valid NTLM response");
	return SASL_BADPROT;
      }

    result = unload_buffer(sparams->utils, (const OFC_UCHAR *) clientin + NTLM_TYPE3_LMRESP_OFFSET,
			   (u_char **) &lm_resp, &lm_resp_len, 0,
			   (const OFC_UCHAR *) clientin, clientinlen);
    if (result != SASL_OK) goto cleanup;

    result = unload_buffer(sparams->utils, (const OFC_UCHAR *) clientin + NTLM_TYPE3_NTRESP_OFFSET,
			   (u_char **) &nt_resp, &nt_resp_len, 0,
			   (const OFC_UCHAR *) clientin, clientinlen);
    if (result != SASL_OK) goto cleanup;

    result = unload_buffer(sparams->utils, (const OFC_UCHAR *) clientin + NTLM_TYPE3_DOMAIN_OFFSET,
			   (u_char **) &domain, &domain_len,
			   text->flags & NTLM_USE_UNICODE,
			   (const OFC_UCHAR *) clientin, clientinlen);
    if (result != SASL_OK) goto cleanup;

    result = unload_buffer(sparams->utils, (const OFC_UCHAR *) clientin + NTLM_TYPE3_USER_OFFSET,
			   (u_char **) &authid, &authid_len,
			   text->flags & NTLM_USE_UNICODE,
			   (const OFC_UCHAR *) clientin, clientinlen);
    if (result != SASL_OK) goto cleanup;

    result = unload_buffer(sparams->utils, (const OFC_UCHAR *) clientin + NTLM_TYPE3_SESSIONKEY_OFFSET,
			   (u_char **) &session_key, &session_key_length,
			   0,
			   (const OFC_UCHAR *) clientin, clientinlen);
    if (result != SASL_OK) goto cleanup;

    /* require at least one response and an authid */
    if ((!lm_resp && !nt_resp) ||
	(lm_resp && lm_resp_len < NTLM_RESP_LENGTH) ||
	(nt_resp && nt_resp_len < NTLM_RESP_LENGTH) ||
	!authid) {
	SETERROR(sparams->utils, "client issued incorrect/nonexistent responses");
	result = SASL_BADPROT;
	goto cleanup;
    }

    sparams->utils->log(OFC_NULL, SASL_LOG_DEBUG,
			"client user: %s", authid);
    if (domain) sparams->utils->log(OFC_NULL, SASL_LOG_DEBUG,
				    "client domain: %s", domain);

    /* verify the response internally */

    /* fetch user's password */
    result = sparams->utils->prop_request(sparams->propctx, password_request);
    if (result != SASL_OK) goto cleanup;
    
    /* this will trigger the getting of the aux properties */
    result = sparams->canon_user(sparams->utils->conn, authid, authid_len,
				 SASL_CU_AUTHID | SASL_CU_AUTHZID, oparams);
    if (result != SASL_OK) goto cleanup;

    result = sparams->utils->prop_getnames(sparams->propctx,
					   password_request,
					   auxprop_values);
    if (result < 0 ||
	(!auxprop_values[0].name || !auxprop_values[0].values)) {
      /* We didn't find this username */
      SETERROR(sparams->utils, "no secret in database");
      result = sparams->transition ? SASL_TRANS : SASL_NOUSER;
      goto cleanup;
    }
    
#if !defined(OFC_PARAM_ALWAYS_AUTHENTICATE)

    pass_len = ofc_strlen((OFC_CHAR *) auxprop_values[0].values[0]);
    if (pass_len == 0) {
      SETERROR(sparams->utils, "empty secret");
      result = SASL_FAIL;
      goto cleanup;
    }
#else
    pass_len = 0 ;
#endif
    password = sparams->utils->malloc(sizeof(sasl_secret_t) + pass_len);
    if (!password) {
      result = SASL_NOMEM;
      goto cleanup;
    }
	
    password->len = (unsigned int) pass_len;
    ofc_strncpy((OFC_CHAR *) password->data, auxprop_values[0].values[0], pass_len + 1);

    /* erase the plaintext password */
    sparams->utils->prop_erase(sparams->propctx, password_request[0]);

    /* calculate our own response(s) and compare with client's */
    result = SASL_OK;
    if (nt_resp && (nt_resp_len > NTLM_RESP_LENGTH)) 
      {
	const unsigned char *cnonce ;
	const unsigned char *timestamp ;
	sparams->utils->log(OFC_NULL, SASL_LOG_DEBUG,
			    "calculating NTv2 response");
	/*
	 * Ok, we need to parse the blob
	 */
	if (parseBlob (OFC_NULL, OFC_NULL,
		       &cnonce,
		       &timestamp,
		       nt_resp+MD5_DIGEST_LENGTH, nt_resp_len-MD5_DIGEST_LENGTH) == OFC_TRUE)
	  {
	    unsigned char proof[MD5_DIGEST_LENGTH] ;

	    /*
	     * What about client nonce?
	     */
	    text->credentials = 
	      ntlm_create_credentials (password, authid, domain,
				       (const unsigned char *) 
				       text->nonce, timestamp) ;
	    ntlm_proof (text->credentials, 
			nt_resp+MD5_DIGEST_LENGTH, nt_resp_len-MD5_DIGEST_LENGTH,
			proof) ;

	    if (ofc_memcmp(nt_resp, proof, MD5_DIGEST_LENGTH)) 
	      {
		ntlm_free_credentials (text->credentials) ;
		text->credentials = 
		  ntlm_create_credentials (password, authid, OFC_NULL,
					   (const unsigned char *) 
					   text->nonce, timestamp) ;
		ntlm_proof (text->credentials, 
			    nt_resp+MD5_DIGEST_LENGTH, nt_resp_len-MD5_DIGEST_LENGTH,
			    proof) ;
		if (ofc_memcmp(nt_resp, proof, MD5_DIGEST_LENGTH)) 
		  {
		    ntlm_free_credentials(text->credentials) ;
		    text->credentials = OFC_NULL ;
		    SETERROR(sparams->utils, "incorrect NTLMv2 response");
		    result = SASL_BADAUTH;
		  }
	      }
	    if (result != SASL_BADAUTH)
	      {
		/* get the user session key.  We know it's the same proof
		 * string the client has */
		result = ntlm_sesskey (text->credentials, nt_resp) ;
	      }
	  }
	else
	  {
	    SETERROR(sparams->utils, "incorrect NTLMv2 response");
	    result = SASL_BADAUTH;
	  }
      }
    else if (nt_resp) {
      /* Try NT response */
      sparams->utils->log(OFC_NULL, SASL_LOG_DEBUG,
			  "calculating NT response");
      P24(resp, P21(hash, password, P16_nt, sparams->utils,
		    &text->out_buf, &text->out_buf_len, &result),
	  text->nonce);
      if (ofc_memcmp(nt_resp, resp, NTLM_RESP_LENGTH)) {
	SETERROR(sparams->utils, "incorrect NTLM response");
	result = SASL_BADAUTH;
      }
    }
    else if (lm_resp) {
      /* Try LMv2 response */
      sparams->utils->log(OFC_NULL, SASL_LOG_DEBUG,
			  "calculating LMv2 response");
      V2(resp, password, authid, domain, text->nonce,
	 lm_resp + MD5_DIGEST_LENGTH, lm_resp_len - MD5_DIGEST_LENGTH,
	 sparams->utils, &text->out_buf, &text->out_buf_len,
	 &result);
		
      /* No need to compare the blob */
      if (ofc_memcmp(lm_resp, resp, MD5_DIGEST_LENGTH)) {
	/* Try LM response */
	sparams->utils->log(OFC_NULL, SASL_LOG_DEBUG,
			    "calculating LM response");
	P24(resp, P21(hash, password, P16_lm, sparams->utils,
		      &text->out_buf, &text->out_buf_len, &result),
	    text->nonce);
	if (ofc_memcmp(lm_resp, resp, NTLM_RESP_LENGTH)) {
	  SETERROR(sparams->utils, "incorrect LMv1/v2 response");
	  result = SASL_BADAUTH;
	}
      }
    }

    ofc_free (password) ;

    if (result == SASL_OK && session_key_length == NTLM_SESSKEY_LENGTH)
      {
	unsigned char server_session_key[NTLM_SESSKEY_LENGTH] ;

	ofc_memcpy (text->credentials->encrypted_session_key, session_key, NTLM_SESSKEY_LENGTH) ;
	ofc_memcpy (server_session_key,
		     text->credentials->encrypted_session_key, NTLM_SESSKEY_LENGTH) ;
	/* when this is encrypted, it's encrypted with the client_session_key which is
	 * just a random number.  should we decrypt with just a random number too??
	 */
	arcfour_crypt(server_session_key,
		      text->credentials->user_session_key, NTLM_SESSKEY_LENGTH) ;
	ofc_memcpy (text->credentials->user_session_key,
		     server_session_key, NTLM_SESSKEY_LENGTH) ;
	ntlm_server_sign_init (text) ;
      }

    if (result != SASL_OK) goto cleanup;

    /* Now we've got to get the session key */

    /* set oparams */
    oparams->doneflag = 1;
    oparams->mech_ssf = 0;
    oparams->maxoutbuf = 0;
    oparams->encode_context = OFC_NULL;
    oparams->encode = OFC_NULL;
    oparams->decode_context = OFC_NULL;
    oparams->decode = OFC_NULL;
    oparams->param_version = 0;

    result = SASL_OK;

  cleanup:
    if (session_key) sparams->utils->free(session_key);
    if (lm_resp) sparams->utils->free(lm_resp);
    if (nt_resp) sparams->utils->free(nt_resp);
    if (domain) sparams->utils->free(domain);
    if (authid) sparams->utils->free(authid);

    return result;
}

static int ntlm_server_mech_step(void *conn_context,
				 sasl_server_params_t *sparams,
				 const char *clientin,
				 unsigned int clientinlen,
				 const char **serverout,
				 unsigned int *serveroutlen,
				 sasl_out_params_t *oparams)
{
    server_context_t *text = (server_context_t *) conn_context;
    
    *serverout = OFC_NULL;
    *serveroutlen = 0;
    
    if (text == OFC_NULL) {
	return SASL_BADPROT;
    }

    if (clientin != NULL &&
	clientinlen >= (NTLM_TYPE_OFFSET + sizeof (uint32))) {
	  if (itohl(clientin + NTLM_TYPE_OFFSET) == NTLM_TYPE_REQUEST)
	    /* reset state */
	    text->state = 1 ;
	}

    sparams->utils->log(OFC_NULL, SASL_LOG_DEBUG,
		       "NTLM server step %d\n", text->state);

    switch (text->state) {
	
    case 1:
        return ntlm_server_mech_step1(text, sparams, clientin, clientinlen,
				      serverout, serveroutlen, oparams);
	
    case 2:
	return ntlm_server_mech_step2(text, sparams, clientin, clientinlen,
				      serverout, serveroutlen, oparams);
	
    default:
	sparams->utils->log(OFC_NULL, SASL_LOG_ERR,
			   "Invalid NTLM server step %d\n", text->state);
	return SASL_FAIL;
    }
    
    return SASL_FAIL; /* should never get here */
}

static void ntlm_server_mech_dispose(void *conn_context,
				     const sasl_utils_t *utils)
{
    server_context_t *text = (server_context_t *) conn_context;
    
    if (!text) return;
    
    if (text->out_buf) utils->free(text->out_buf);

    if (text->credentials)
      ntlm_free_credentials (text->credentials) ;
    text->credentials = OFC_NULL ;

    utils->free(text);
}

static int ntlm_server_mech_key(void *conn_context,
				unsigned char recv_key[NTLM_SESSKEY_LENGTH],
				unsigned char send_key[NTLM_SESSKEY_LENGTH])
{
    server_context_t *text = (server_context_t *) conn_context;

    if (!text) return (SASL_FAIL) ;

    if (text->credentials != OFC_NULL)
      {
	ofc_memcpy (recv_key, text->credentials->user_session_key, 
		     NTLM_SESSKEY_LENGTH) ;
	ofc_memcpy (send_key, text->credentials->user_session_key,
		   NTLM_SESSKEY_LENGTH) ;
      }
    else
      ofc_memset (send_key, '\0', NTLM_SESSKEY_LENGTH) ;

    return (SASL_OK) ;
}

static sasl_server_plug_t ntlm_server_plugins[] = 
{
    {
	"NTLM",				/* mech_name */
	0,				/* max_ssf */
	SASL_SEC_NOPLAINTEXT
	| SASL_SEC_NOANONYMOUS,		/* security_flags */
	SASL_FEAT_WANT_CLIENT_FIRST
	| SASL_FEAT_SUPPORTS_HTTP,	/* features */
	OFC_NULL,				/* glob_context */
	&ntlm_server_mech_new,		/* mech_new */
	&ntlm_server_mech_step,		/* mech_step */
	&ntlm_server_mech_dispose,	/* mech_dispose */
	OFC_NULL,			/* mech_free */
	OFC_NULL,			/* mech_setpass */
	OFC_NULL,			/* mech_user_query */
	OFC_NULL,			/* mech_idle */
	OFC_NULL,			/* mech_avail */
	&ntlm_server_mech_key		/* mech_session_key */
    }
};

int of_security_ntlm_server_plug_init(sasl_utils_t *utils,
			       int maxversion,
			       int *out_version,
			       sasl_server_plug_t **pluglist,
			       int *plugcount)
{
    if (maxversion < SASL_SERVER_PLUG_VERSION) {
	SETERROR(utils, "NTLM version mismatch");
	return SASL_BADVERS;
    }
    
    *out_version = SASL_SERVER_PLUG_VERSION;
    *pluglist = ntlm_server_plugins;
    *plugcount = 1;
    
    return SASL_OK;
}

/*****************************  Client Section  *****************************/

typedef struct client_context {
    int state;

    /* per-step mem management */
    char *out_buf;
    unsigned int out_buf_len;

    char *negotiate ;
    unsigned int negotiate_len ;

    OFC_UINT32 send_seqnum ;
    OFC_UINT32 recv_seqnum ;
    unsigned char send_key[NTLM_SESSKEY_LENGTH] ;
    unsigned char seal_key[NTLM_SESSKEY_LENGTH] ;
    struct arcfour_state send_seal_state;
    unsigned char session_key[NTLM_SESSKEY_LENGTH] ;
    struct ntlm_credentials *credentials ;
    OFC_TCHAR *target ;
} client_context_t;

/*
 * Create a client request (type 1) consisting of:
 *
 * signature (8 bytes)
 * message type (uint32)
 * flags (uint32)
 * domain (buffer)
 * workstation (buffer)
 * data
 */
static int create_request(const sasl_utils_t *utils,
			  char **buf, unsigned int *buflen,
			  const char *domain, const char *wkstn,
			  unsigned int *outlen)
{
  uint32 flags = ( NTLM_USE_UNICODE | NTLM_NEGOTIATE_128 | 0x00800011 |
		     NTLM_NEGOTIATE_KEY_EXCH | NTLM_ALWAYS_SIGN |
		     NTLM_ASK_TARGET | NTLM_AUTH_NTLM | 
		     NTLM_NEGOTIATE_VERSION | NTLM_NEGOTIATE_TARGETINFO |
		     NTLM_AUTH_NTLMV2);

    uint32 offset = NTLM_TYPE1_DATA_OFFSET;
    OFC_UCHAR *base;

    *outlen = (unsigned int) (offset + ofc_strlen(domain) + ofc_strlen(wkstn));
    if (of_security_plug_buf_alloc(utils, buf, buflen, *outlen) != SASL_OK) {
	SETERROR(utils, "cannot allocate NTLM request");
	return SASL_NOMEM;
    }

    base = (unsigned char *) *buf;
    ofc_memset(base, 0, *outlen);
    ofc_memcpy(base + NTLM_SIG_OFFSET, NTLM_SIGNATURE, sizeof(NTLM_SIGNATURE));
    htoil(base + NTLM_TYPE_OFFSET, NTLM_TYPE_REQUEST);
    htoil(base + NTLM_TYPE1_FLAGS_OFFSET, flags);
    ofc_memcpy(base + NTLM_TYPE1_VERSION_OFFSET, "\x06\x01\x00\x00\x00\x00\x00\x0f", 8) ;
    load_buffer(base + NTLM_TYPE1_DOMAIN_OFFSET,
		(unsigned char *) domain, (uint16) ofc_strlen(domain), 0, base, &offset);
    load_buffer(base + NTLM_TYPE1_WORKSTN_OFFSET,
		(unsigned char *) wkstn, (uint16) ofc_strlen(wkstn), 0, base, &offset);

    return SASL_OK;
}

/*
 * Create a client response (type 3) consisting of:
 *
 * signature (8 bytes)
 * message type (uint32)
 * LM/LMv2 response (buffer)
 * NTLM/NTLMv2 response (buffer)
 * domain (buffer)
 * user name (buffer)
 * workstation (buffer)
 * session key (buffer)
 * flags (uint32)
 * data
 */
static int create_response(const sasl_utils_t *utils,
			   char **buf, unsigned int *buflen,
			   const OFC_UCHAR *lm_resp, const OFC_UCHAR *nt_resp,
			   const OFC_SIZET nt_resp_len,
			   const char *domain, const char *user,
			   const char *wkstn, const OFC_UCHAR *key,
			   OFC_UINT32 flags, unsigned int *outlen)
{
    uint32 offset = NTLM_TYPE3_DATA_OFFSET;
    OFC_UCHAR *base;

    if (!lm_resp && !nt_resp) {
	SETERROR(utils, "need at least one NT/LM response");
	return SASL_FAIL;
    }

    *outlen = (unsigned int) (offset + (flags & NTLM_USE_UNICODE ? 2 : 1) * 
	(ofc_strlen(domain) + ofc_strlen(user) + ofc_strlen(wkstn)));
    if (lm_resp) *outlen += NTLM_RESP_LENGTH;
    if (nt_resp) *outlen += nt_resp_len ;
    if (key) *outlen += NTLM_SESSKEY_LENGTH;

    if (of_security_plug_buf_alloc(utils, buf, buflen, *outlen) != SASL_OK) {
	SETERROR(utils, "cannot allocate NTLM response");
	return SASL_NOMEM;
    }

    base = (unsigned char *) *buf;
    ofc_memset(base, 0, *outlen);
    ofc_memcpy(base + NTLM_SIG_OFFSET, NTLM_SIGNATURE, sizeof(NTLM_SIGNATURE));
    htoil(base + NTLM_TYPE_OFFSET, NTLM_TYPE_RESPONSE);
    load_buffer(base + NTLM_TYPE3_LMRESP_OFFSET,
		lm_resp, lm_resp ? NTLM_RESP_LENGTH : 0, 0, base, &offset);
    load_buffer(base + NTLM_TYPE3_NTRESP_OFFSET,
		nt_resp, nt_resp ? (OFC_UINT16) nt_resp_len : 0, 0, base, &offset);
    load_buffer(base + NTLM_TYPE3_DOMAIN_OFFSET,
		(const unsigned char *) ucase(domain, 0), (uint16) ofc_strlen(domain), flags & NTLM_USE_UNICODE,
		(unsigned char *) base, &offset);
    load_buffer(base + NTLM_TYPE3_USER_OFFSET,
		(unsigned char *) user, (uint16) ofc_strlen(user), flags & NTLM_USE_UNICODE, base, &offset);
    load_buffer(base + NTLM_TYPE3_WORKSTN_OFFSET,
		(unsigned char *) ucase(wkstn, 0), (uint16) ofc_strlen(wkstn), flags & NTLM_USE_UNICODE,
		base, &offset);
    load_buffer(base + NTLM_TYPE3_SESSIONKEY_OFFSET,
		key, key ? NTLM_SESSKEY_LENGTH : 0, 0, base, &offset);
    htoil(base + NTLM_TYPE3_FLAGS_OFFSET, flags);
    ofc_memcpy(base + NTLM_TYPE3_VERSION_OFFSET, "\x06\x01\x00\x00\x00\x00\x00\x0f", 8) ;

    return SASL_OK;
}

static int ntlm_client_mech_new(void *glob_context,
			       sasl_client_params_t *params,
			       void **conn_context)
{
    client_context_t *text;
    
    /* holds state are in */
    text = params->utils->malloc(sizeof(client_context_t));
    if (text == OFC_NULL) {
	MEMERROR( params->utils->conn );
	return SASL_NOMEM;
    }
    
    ofc_memset(text, 0, sizeof(client_context_t));
    
    text->state = 1;
    
    *conn_context = text;
    
    return SASL_OK;
}

static int ntlm_client_mech_step1(client_context_t *text,
				  sasl_client_params_t *params,
				  const char *serverin,
				  unsigned int serverinlen,
				  sasl_interact_t **prompt_need,
				  const char **clientout,
				  unsigned int *clientoutlen,
				  sasl_out_params_t *oparams)
{
    int result;
    
    /* check if sec layer strong enough */
    if (params->props.min_ssf > params->external_ssf) {
	SETERROR(params->utils, "SSF requested of NTLM plugin");
	return SASL_TOOWEAK;
    }

    /* we don't care about domain or wkstn */
    result = create_request(params->utils, &text->out_buf, &text->out_buf_len,
			    OFC_NULL, /*params->clientFQDN*/ OFC_NULL,
			    clientoutlen);
    if (result != SASL_OK) return result;

    *clientout = text->out_buf;
    
    text->negotiate = ofc_malloc (text->out_buf_len) ;
    ofc_memcpy (text->negotiate, text->out_buf, text->out_buf_len) ;
    text->negotiate_len = text->out_buf_len ;
     
    text->state = 2;
    
    return SASL_CONTINUE;
}

static OFC_SIZET createBlob (const OFC_UCHAR *target_info,
			      const OFC_UINT16 target_info_length,
			      OFC_CHAR *cnonce,
			      const unsigned char *timestamp_in,
			      unsigned char *timestamp_out,
			      unsigned char *blob)
{
  OFC_CHAR blob_signature[4] = { 0x01, 0x01, 0x00, 0x00 } ;
  OFC_CHAR reserved[4] = { 0x00, 0x00, 0x00, 0x00 } ;
  OFC_CHAR unknown1[4] = { 0x00, 0x00, 0x00, 0x00 } ;
  OFC_UCHAR timestamp[8] ;
  OFC_SIZET offset ;

  /* we need a time of day in epoch time, number of ms from Jan 1, 1601 */
  OFC_FILETIME filetime ;
  OFC_UINT64 ft ;

#if defined(OFC_NTLMV2_TARGET_TIMESTAMP)
  const OFC_UCHAR *ptarget = target_info ;

  /*
   * Only look in the target attributes if we have the timestamp
   * workaround enabled
   */
  while (itohs(ptarget + ATTR_TYPE) != 0 &&
	 itohs(ptarget + ATTR_TYPE) != 7)
    {
      ptarget = ptarget + ATTR_DATA + itohs(ptarget + ATTR_LEN) ;
    }

  if (itohs(ptarget + ATTR_TYPE) == 7)
    {
      ofc_memcpy (timestamp, ptarget + ATTR_DATA, 
		   itohs(ptarget + ATTR_LEN)) ; 
    }
  else
#endif
    {
      if (timestamp_in != OFC_NULL)
	{
	  ofc_memcpy (timestamp, timestamp_in, sizeof(timestamp)) ;
	}
      else
	{
	  ofc_time_get_file_time (&filetime) ;
	  OFC_LARGE_INTEGER_SET (ft, 
				  filetime.dwLowDateTime+1, 
				  filetime.dwHighDateTime) ;
	  OFC_NET_LLTOSMB (&timestamp, 0, ft) ;
	}
    }

  offset = 0 ;

  ofc_memcpy (blob+offset, blob_signature, sizeof(blob_signature)) ;
  offset += sizeof(blob_signature) ;
  ofc_memcpy (blob+offset, reserved, sizeof(reserved)) ;
  offset += sizeof(reserved) ;
  ofc_memcpy (blob+offset, timestamp, sizeof(timestamp)) ;
  offset += sizeof(timestamp) ;
  ofc_memcpy (blob+offset, cnonce, NTLM_NONCE_LENGTH) ;
  offset += NTLM_NONCE_LENGTH ;
  ofc_memcpy (blob+offset, unknown1, sizeof(unknown1)) ;
  offset += sizeof(unknown1) ;
  ofc_memcpy (blob+offset, target_info, target_info_length) ;
  offset += target_info_length ;

  if (timestamp_out != OFC_NULL)
    ofc_memcpy (timestamp_out, timestamp, 8) ;
  return (offset) ;
}

OFC_VOID UpdateTargetInfo (OFC_CHAR **target_info, 
			    OFC_SIZET *target_info_len,
			    OFC_CCHAR *serverFQDN)
{
  OFC_CHAR *ptarget = *target_info ;
  OFC_SIZET size ;
  OFC_CHAR *to ;
  OFC_CHAR *from ;
  OFC_CHAR *end ;
  OFC_SIZET attr_size ;
  OFC_CHAR *target_name ;
  OFC_SIZET target_name_size ;
  OFC_INT i ;

  /*
   * Only look in the target attributes if we have the timestamp
   * workaround enabled
   */
  while (itohs(ptarget + ATTR_TYPE) != 0 &&
	 itohs(ptarget + ATTR_TYPE) != 9)
    {
      ptarget = ptarget + ATTR_DATA + itohs(ptarget + ATTR_LEN) ;
    }

  if (itohs(ptarget + ATTR_TYPE) == 9)
    {
      to = ptarget ;
      attr_size = ATTR_DATA + itohs (ptarget + ATTR_LEN) ;
      from = ptarget + attr_size ;
      end = *target_info + *target_info_len ;
      size = end - from ;

      /* basically, let's delete it, we'll readd it */
      ofc_memcpy (to, from, size) ;

      *target_info_len -= attr_size ;
    }
		   
  /* Now let's add target name */
  target_name_size = ofc_strlen (serverFQDN) + ofc_strlen ("cifs/") ;
  target_name = ofc_malloc (target_name_size + 1) ;
  ofc_snprintf (target_name, target_name_size + 1, "cifs/%s", serverFQDN) ;

  size = ATTR_DATA + sizeof (OFC_UINT16) * target_name_size ;

  *target_info_len += size ;
  *target_info = ofc_realloc (*target_info, *target_info_len) ;
		   
  /* now let's find the end of list */
  ptarget = *target_info ;

  while (itohs(ptarget + ATTR_TYPE) != 0)
    {
      ptarget = ptarget + ATTR_DATA + itohs(ptarget + ATTR_LEN) ;
    }

  htois ((ptarget + ATTR_TYPE), 9) ;
  htois ((ptarget + ATTR_LEN), sizeof(OFC_UINT16)*target_name_size) ;
  for (i = 0 ; i < target_name_size ; i++) 
    {
      htois ((ptarget + ATTR_DATA + sizeof(OFC_UINT16)*i), target_name[i]) ;
    }
  ofc_free (target_name) ;

  /* step to end of list */
  ptarget = ptarget + ATTR_DATA + itohs(ptarget + ATTR_LEN) ;
  htois ((ptarget + ATTR_TYPE), 0) ;
  htois ((ptarget + ATTR_LEN), 0) ;

  /* Now let's add channel bindings */
  ptarget = *target_info ;

  while (itohs(ptarget + ATTR_TYPE) != 0 &&
	 itohs(ptarget + ATTR_TYPE) != 0x0a)
    {
      ptarget = ptarget + ATTR_DATA + itohs(ptarget + ATTR_LEN) ;
    }

  if (itohs(ptarget + ATTR_TYPE) == 0xa)
    {
      to = ptarget ;
      attr_size = ATTR_DATA + itohs (ptarget + ATTR_LEN) ;
      from = ptarget + attr_size ;
      end = *target_info + *target_info_len ;
      size = end - from ;

      /* basically, let's delete it, we'll readd it */
      ofc_memcpy (to, from, size) ;

      *target_info_len -= attr_size ;
    }
		   
  /* Now let's add channel bindings */
  size = ATTR_DATA + 16 ;

  *target_info_len += size ;
  *target_info = ofc_realloc (*target_info, *target_info_len) ;
		   
  /* now let's find the end of list */
  ptarget = *target_info ;

  while (itohs(ptarget + ATTR_TYPE) != 0)
    {
      ptarget = ptarget + ATTR_DATA + itohs(ptarget + ATTR_LEN) ;
    }

  htois ((ptarget + ATTR_TYPE), 0x0A) ;
  htois ((ptarget + ATTR_LEN), 16) ;
  ofc_memset (ptarget + ATTR_DATA, '\0', 16) ;

  /* step to end of list */
  ptarget = ptarget + ATTR_DATA + itohs(ptarget + ATTR_LEN) ;
  htois ((ptarget + ATTR_TYPE), 0) ;
  htois ((ptarget + ATTR_LEN), 0) ;

  /* ** */
  /* Now let's add flags */
  ptarget = *target_info ;

  while (itohs(ptarget + ATTR_TYPE) != 0 &&
	 itohs(ptarget + ATTR_TYPE) != 0x06)
    {
      ptarget = ptarget + ATTR_DATA + itohs(ptarget + ATTR_LEN) ;
    }

  if (itohs(ptarget + ATTR_TYPE) == 0x06)
    {
      to = ptarget ;
      attr_size = ATTR_DATA + itohs (ptarget + ATTR_LEN) ;
      from = ptarget + attr_size ;
      end = *target_info + *target_info_len ;
      size = end - from ;

      /* basically, let's delete it, we'll readd it */
      ofc_memcpy (to, from, size) ;

      *target_info_len -= attr_size ;
    }
		   
  /* Now let's add channel bindings */
  size = ATTR_DATA + 4 ;

  *target_info_len += size ;
  *target_info = ofc_realloc (*target_info, *target_info_len) ;
		   
  /* now let's find the end of list */
  ptarget = *target_info ;

  while (itohs(ptarget + ATTR_TYPE) != 0)
    {
      ptarget = ptarget + ATTR_DATA + itohs(ptarget + ATTR_LEN) ;
    }

  htois ((ptarget + ATTR_TYPE), 0x06) ;
  htois ((ptarget + ATTR_LEN), 4) ;
  htoil ((ptarget + ATTR_DATA), 0x00000002) ;
  ptarget = ptarget + ATTR_DATA + itohs(ptarget + ATTR_LEN) ;

  /* Now let's add restrictions */
  size = ATTR_DATA + 48 ;

  *target_info_len += size ;
  *target_info = ofc_realloc (*target_info, *target_info_len) ;
		   
  ptarget = *target_info ;

  while (itohs(ptarget + ATTR_TYPE) != 0)
    {
      ptarget = ptarget + ATTR_DATA + itohs(ptarget + ATTR_LEN) ;
    }

  htois ((ptarget + ATTR_TYPE), 0x08) ;
  htois ((ptarget + ATTR_LEN), 48) ;
  ofc_memcpy (ptarget + ATTR_DATA, 
	       "\x30\x00\x00\x00\x00\x00\x00\x00"
	       "\x00\x00\x00\x00\x00\x00\x00\x00"
	       "\x27\x67\x70\xb5\x52\x61\x21\x51"
	       "\xba\xd2\x73\xe6\x2b\x7c\x29\x33"
	       "\x17\xf1\xe6\x3a\x57\x5e\xbd\x44"
	       "\xdc\x39\x2a\xda\x38\xbe\xf6\xba", 48) ;

  /* step to end of list */
  ptarget = ptarget + ATTR_DATA + itohs(ptarget + ATTR_LEN) ;
  
  htois ((ptarget + ATTR_TYPE), 0) ;
  htois ((ptarget + ATTR_LEN), 0) ;
}

static int ntlm_response (struct ntlm_credentials *credentials,
			  unsigned char *blob,
			  OFC_SIZET blob_length,
			  unsigned char resp[MD5_DIGEST_LENGTH])
{
  int result ;
  ntlm_proof (credentials, blob, blob_length, resp) ;

  ofc_memcpy (resp+MD5_DIGEST_LENGTH, blob, blob_length) ;
  result = SASL_OK ;
  return (result) ;
}

OFC_VOID ntlm_client_sign_init (client_context_t *text)
{
  struct ntlm_credentials *credentials ;
  OFC_DATA_BLOB key ;
  MD5_CTX ctx ;

  credentials = text->credentials ;

  of_security_MD5Init (&ctx) ;

  of_security_MD5Update (&ctx, credentials->user_session_key, 
			NTLM_SESSKEY_LENGTH) ;
  of_security_MD5Update (&ctx, (const OFC_UCHAR *)CLI_SIGN, 
			ofc_strlen(CLI_SIGN)+1) ;

  of_security_MD5Final (text->send_key, &ctx) ;

  of_security_MD5Init (&ctx) ;
  of_security_MD5Update (&ctx, credentials->user_session_key, 
			NTLM_SESSKEY_LENGTH) ;
  of_security_MD5Update (&ctx, (const OFC_UCHAR *)CLI_SEAL, 
			ofc_strlen(CLI_SEAL)+1) ;
  of_security_MD5Final (text->seal_key, &ctx) ;

  key.data = text->seal_key ;
  key.length = 16 ;
  arcfour_init(&text->send_seal_state, &key) ;
}

static int ntlm_client_mech_step2(client_context_t *text,
				  sasl_client_params_t *params,
				  const unsigned char *serverin,
				  unsigned int serverinlen,
				  sasl_interact_t **prompt_need,
				  const char **clientout,
				  unsigned int *clientoutlen,
				  sasl_out_params_t *oparams)
{
    char *authid = OFC_NULL;
    sasl_secret_t *password = OFC_NULL;
    unsigned int free_password = 0 ; /* set if we need to free password */
    char *domain = OFC_NULL;
    char *plug_timestamp = OFC_NULL;
    unsigned char timestamp[8] ;
    int auth_result = SASL_OK;
    int pass_result = SASL_OK;
    int domain_result = SASL_OK;
    int timestamp_result = SASL_OK;
    uint32 flags = 0;
    unsigned char hash[NTLM_HASH_LENGTH];
    unsigned char *resp = OFC_NULL ;
    unsigned char *lm_resp = OFC_NULL, *nt_resp = OFC_NULL;
    OFC_SIZET nt_resp_len = 0;
    int result;
    const char *sendv2;
    char cnonce[NTLM_NONCE_LENGTH] ;
    unsigned char client_session_key[NTLM_SESSKEY_LENGTH] ;
    unsigned char mic[NTLM_SESSKEY_LENGTH] ;
    HMAC_MD5_CTX ctx ;
    struct ntlm_credentials *credentials = NULL ;
    OFC_UINT16 *tname = OFC_NULL ;
    unsigned tlen ;
    OFC_TCHAR *pname ;

    if (!serverin || serverinlen < NTLM_TYPE2_MINSIZE ||
	ofc_memcmp(serverin, NTLM_SIGNATURE, sizeof(NTLM_SIGNATURE)) ||
	itohl(serverin + NTLM_TYPE_OFFSET) != NTLM_TYPE_CHALLENGE) {
	SETERROR(params->utils, "server didn't issue valid NTLM challenge");
	return SASL_BADPROT;
    }

    /* try to get the authid */
    if (oparams->authid == OFC_NULL) {
	auth_result = of_security_plug_get_userid(params->utils, &authid, prompt_need);
	
	if ((auth_result != SASL_OK) && (auth_result != SASL_INTERACT))
	    return auth_result;
    }
    
    /* try to get the password */
    if (password == OFC_NULL) {
	pass_result = of_security_plug_get_password(params->utils, &password,
					 &free_password, prompt_need);
	
	if ((pass_result != SASL_OK) && (pass_result != SASL_INTERACT))
	    return pass_result;
    }

    /* try to get the domain */
    if (domain == OFC_NULL) {
      domain_result = of_security_plug_get_domain(params->utils, &domain,
					      prompt_need);
	
	if ((domain_result != SASL_OK) && (domain_result != SASL_INTERACT))
	    return domain_result;
    }

    /* try to get the password */
    if (plug_timestamp == OFC_NULL) {
      timestamp_result = 
	of_security_plug_get_timestamp(params->utils, &plug_timestamp,
				 prompt_need);
	
	if ((timestamp_result != SASL_OK) && 
	    (timestamp_result != SASL_INTERACT))
	  {
	    timestamp_result = SASL_OK ;
	  }
	else
	  {
	    if (timestamp_result == SASL_OK)
	      {
		ofc_memcpy (timestamp, plug_timestamp, 8) ;
		ofc_free (plug_timestamp) ;
	      }
	  }
    }

    /* free prompts we got */
    if (prompt_need && *prompt_need) {
	params->utils->free(*prompt_need);
	*prompt_need = OFC_NULL;
    }
    
    /* if there are prompts not filled in */
    if ((auth_result == SASL_INTERACT) || (pass_result == SASL_INTERACT) ||
	(domain_result == SASL_INTERACT) || 
	(timestamp_result == SASL_INTERACT)) {
	/* make the prompt list */
	result =
	    of_security_plug_make_prompts(params->utils, prompt_need,
				    auth_result == SASL_INTERACT ?
				    "Please enter your authentication name" : 
				    OFC_NULL, OFC_NULL,
				    OFC_NULL,
				    OFC_NULL,
				    pass_result == SASL_INTERACT ?
				    "Please enter your password" : 
				    OFC_NULL, OFC_NULL,
				    OFC_NULL, OFC_NULL, OFC_NULL,
				    OFC_NULL, 
				    domain_result == SASL_INTERACT ?
				    "Please enter your domain" : OFC_NULL,
				    OFC_NULL,
				    timestamp_result == SASL_INTERACT ?
				    "Please enter the timestamp" : OFC_NULL, 
				    OFC_NULL);
	if (result != SASL_OK) goto cleanup;
	
	return SASL_INTERACT;
    }
    
    result = params->canon_user(params->utils->conn, authid, 0,
				SASL_CU_AUTHID | SASL_CU_AUTHZID, oparams);
    if (result != SASL_OK) goto cleanup;

    flags = itohl(serverin + NTLM_TYPE2_FLAGS_OFFSET);
    params->utils->log(OFC_NULL, SASL_LOG_DEBUG,
		       "server flags: %x", flags);

    flags &= NTLM_FLAGS_MASK; /* mask off the bits we don't support */

    params->utils->log(OFC_NULL, SASL_LOG_DEBUG,
		       "client domain: %s", domain);

    /* should we send a NTLMv2 response? */
    params->utils->getopt(params->utils->getopt_context,
			  "NTLM", "ntlm_v2", &sendv2, OFC_NULL);
    resp = ofc_malloc (4096) ;


    unload_buffer(params->utils, (const OFC_UCHAR *) serverin + 
		  NTLM_TYPE2_TARGET_OFFSET,
		  (u_char **) &tname, &tlen,
		  0,
		  (const OFC_UCHAR *) serverin, serverinlen);

    /*
     * The buffer is in 2 byte unicode.  Need to convert to tchars
     */
    if (text->target != OFC_NULL)
      ofc_free (text->target) ;
    text->target = ofc_malloc (((tlen / sizeof(OFC_UINT16)) + 1) * 
				   sizeof (OFC_TCHAR)) ;
    pname = text->target ;
    for (int i = 0 ; i < (tlen / sizeof (OFC_UINT16)) ; i++)
      {
	*pname++ = OFC_NET_SMBTOS (tname, i * sizeof(OFC_UINT16)) ;
      }
    *pname = TCHAR_EOS ;

    if (sendv2 &&
	(sendv2[0] == '1' || sendv2[0] == 'y' ||
	 (sendv2[0] == 'o' && sendv2[1] == 'n') || sendv2[0] == 't')) {

	/* put the cnonce in place after the LMv2 HMAC */
        unsigned char *blob = resp + MD5_DIGEST_LENGTH;
	OFC_SIZET blob_length ;
	OFC_CHAR *target_info ;
	OFC_SIZET target_info_len ;
	OFC_UCHAR lm_resp_default[24] = {0, 0, 0, 0, 0, 0, 0, 0,
					 0, 0, 0, 0, 0, 0, 0, 0,
					 0, 0, 0, 0, 0, 0, 0, 0} ;
	lm_resp = lm_resp_default ;

	params->utils->rand(params->utils->rpool, cnonce, NTLM_NONCE_LENGTH);

	params->utils->log(OFC_NULL, SASL_LOG_DEBUG,
			   "calculating NTLMv2 response");

	/* is this the ntlmv2_client_data */
	/* copy target info */
	target_info_len = itohs(serverin + NTLM_TYPE2_TARGETINFO_OFFSET + 0) ;
	target_info = ofc_malloc (target_info_len) ;

	ofc_memcpy (target_info, (const unsigned char *) serverin + 
		     itohl(serverin + NTLM_TYPE2_TARGETINFO_OFFSET + 4),
		     target_info_len) ;

	/*
	 * This is the same as msrpc_gen.  generate_client_data
	 */
	blob_length = 
	  createBlob ((OFC_UCHAR *) target_info,
		      (OFC_UINT16) target_info_len,
		      cnonce, timestamp, timestamp,
		      blob) ;

	ofc_free (target_info) ;
	/*
	 * v2 hash,
	 * srv challenge
	 * cli data (blob)
	 */
	credentials = 
	  ntlm_create_credentials (password, oparams->authid, domain,
				   (const unsigned char *) 
				   serverin + NTLM_TYPE2_CHALLENGE_OFFSET, 
				   timestamp) ;
	text->credentials = credentials ;

	/* so smbowfencrypt_ntv2 takes ntlm_v2_hash( credentals hash), 
	   server_challenge and blob and generates something */
	result = ntlm_response (credentials, blob, blob_length, resp) ;

	/* 
	 * this creates a temporary user session key.  It will be 
	 * used, then overwritten below
	 */
	result = ntlm_sesskey (credentials, resp) ;

	/* if key exchange */
	/* the session key above is what samba gets from clie_credentials_get_ntlm_response */
	/* generate client_session_key */
	params->utils->rand(params->utils->rpool,
			    (char *) client_session_key, 
			    NTLM_SESSKEY_LENGTH);
	/* encrypt new with old */
	ofc_memcpy (credentials->encrypted_session_key, 
		     client_session_key, 16) ;
	arcfour_crypt(credentials->encrypted_session_key, 
		      credentials->user_session_key, 16) ;
	    
	ofc_memcpy (credentials->user_session_key, client_session_key,
		     NTLM_SESSKEY_LENGTH) ;

	nt_resp = resp;
	nt_resp_len = MD5_DIGEST_LENGTH + blob_length ;
    }
    else if (flags & NTLM_AUTH_NTLM) {
	params->utils->log(OFC_NULL, SASL_LOG_DEBUG,
			   "calculating NT response");
	P24(resp, P21(hash, password, P16_nt, params->utils,
		      &text->out_buf, &text->out_buf_len, &result),
	    (unsigned char *) serverin + NTLM_TYPE2_CHALLENGE_OFFSET);
	nt_resp = resp;
	nt_resp_len = MD5_DIGEST_LENGTH + NTLM_NONCE_LENGTH ;
    }
    else {
	params->utils->log(OFC_NULL, SASL_LOG_DEBUG,
			   "calculating LM response");
	P24(resp, P21(hash, password, P16_lm, params->utils,
		      &text->out_buf, &text->out_buf_len, &result),
	    (unsigned char *) serverin + NTLM_TYPE2_CHALLENGE_OFFSET);
	lm_resp = resp;
    }
    if (result != SASL_OK || credentials == NULL) goto cleanup;

    if (text->out_buf)
      params->utils->free(text->out_buf);
    text->out_buf = OFC_NULL ;

    result = create_response(params->utils, &text->out_buf, &text->out_buf_len,
			     lm_resp, nt_resp, nt_resp_len, 
			     domain, oparams->authid,
			     params->clientFQDN,
			     credentials->encrypted_session_key,
			     flags, clientoutlen);

    if (result != SASL_OK) goto cleanup;

    of_security_hmac_md5_init (&ctx, credentials->user_session_key, 
			      NTLM_SESSKEY_LENGTH) ;

    of_security_hmac_md5_update (&ctx, (OFC_UCHAR *) text->negotiate, text->negotiate_len) ;
    of_security_hmac_md5_update (&ctx, serverin, serverinlen) ;
    of_security_hmac_md5_update (&ctx, (OFC_UCHAR *) text->out_buf, *clientoutlen) ;
    of_security_hmac_md5_final(mic,&ctx);

    ofc_memcpy (text->out_buf + NTLM_TYPE3_MIC_OFFSET, mic, 
		 NTLM_TYPE3_MIC_SIZE) ;
    ntlm_client_sign_init (text) ;
    *clientout = text->out_buf;

    /* set oparams */
    oparams->doneflag = 1;
    oparams->mech_ssf = 0;
    oparams->maxoutbuf = 0;
    oparams->encode_context = OFC_NULL;
    oparams->encode = OFC_NULL;
    oparams->decode_context = OFC_NULL;
    oparams->decode = OFC_NULL;
    oparams->param_version = 0;
    
    result = SASL_OK;

  cleanup:
    ofc_free (authid) ;
    ofc_free (domain) ;
    if (tname) params->utils->free(tname);
    if (resp) ofc_free(resp) ;
    if (free_password) ofc_free (password) ;

    return result;
}

static int ntlm_client_mech_step(void *conn_context,
				sasl_client_params_t *params,
				const char *serverin,
				unsigned int serverinlen,
				sasl_interact_t **prompt_need,
				const char **clientout,
				unsigned int *clientoutlen,
				sasl_out_params_t *oparams)
{
    client_context_t *text = (client_context_t *) conn_context;
    
    *clientout = OFC_NULL;
    *clientoutlen = 0;
    
    params->utils->log(OFC_NULL, SASL_LOG_DEBUG,
		       "NTLM client step %d\n", text->state);

    switch (text->state) {
	
    case 1:
	return ntlm_client_mech_step1(text, params, serverin, serverinlen,
				      prompt_need, clientout, clientoutlen,
				      oparams);
	
    case 2:
        return ntlm_client_mech_step2(text, params, 
				      (unsigned char *) serverin, serverinlen,
				      prompt_need, clientout, clientoutlen,
				      oparams);
	
    default:
	params->utils->log(OFC_NULL, SASL_LOG_ERR,
			   "Invalid NTLM client step %d\n", text->state);
	return SASL_FAIL;
    }
    
    return SASL_FAIL; /* should never get here */
}

static void ntlm_client_mech_dispose(void *conn_context,
				    const sasl_utils_t *utils)
{
    client_context_t *text = (client_context_t *) conn_context;
    
    if (!text) return;
    
    if (text->out_buf) utils->free(text->out_buf);
    
    if (text->credentials)
      ntlm_free_credentials (text->credentials) ;
    text->credentials = OFC_NULL ;

    if (text->negotiate)
      ofc_free (text->negotiate) ;
    text->negotiate = OFC_NULL ;
    if (text->target)
      ofc_free (text->target) ;
    text->target = OFC_NULL ;

    utils->free(text);
}

static int ntlm_client_mech_key(void *conn_context,
				unsigned char recv_key[NTLM_SESSKEY_LENGTH],
				unsigned char send_key[NTLM_SESSKEY_LENGTH])
{
    client_context_t *text = (client_context_t *) conn_context;

    if (!text) return (SASL_FAIL) ;


    if (text->credentials != OFC_NULL)
      {
	ofc_memcpy (recv_key, text->credentials->user_session_key, 
		     NTLM_SESSKEY_LENGTH) ;
	ofc_memcpy (send_key, text->credentials->user_session_key,
		     NTLM_SESSKEY_LENGTH) ;
      }
    else
      ofc_memset (send_key, '\0', NTLM_SESSKEY_LENGTH) ;

    return (SASL_OK) ;
}

static int ntlm_client_mech_name(void *conn_context,
				 OFC_TCHAR *name, size_t name_len)
{
    client_context_t *text = (client_context_t *) conn_context;

    if (!text) return (SASL_FAIL) ;

    if (text->target != OFC_NULL)
      {
	size_t len ;
	len = OFC_MIN(name_len, (ofc_tstrlen (text->target)+1)) ;
	ofc_tstrncpy (name, text->target, len) ;
      }

    return (SASL_OK) ;
}

static int ntlm_client_mechlistmic(void *conn_context,
				   const OFC_UCHAR *mechlist, 
				   OFC_SIZET length,
				   unsigned char mic[NTLM_SESSKEY_LENGTH])
{
    client_context_t *text = (client_context_t *) conn_context;
    HMAC_MD5_CTX ctx ;
    OFC_UCHAR seqnum[4] ;
    OFC_UCHAR digest[16] ;

    OFC_NET_LTOSMB (&seqnum[0], 0, text->send_seqnum)
    text->send_seqnum++ ;

    of_security_hmac_md5_init (&ctx, text->send_key, NTLM_SESSKEY_LENGTH) ;
    of_security_hmac_md5_update(&ctx, (const OFC_UCHAR *)&seqnum[0], 4) ;
    of_security_hmac_md5_update(&ctx, (const OFC_UCHAR *)mechlist, length) ;
    of_security_hmac_md5_final(digest,&ctx);

    arcfour_crypt_sbox(&text->send_seal_state, digest, 8) ;

    OFC_NET_LTOSMB (&mic[0], 0, NTLMSSP_SIGN_VERSION) ;
    ofc_memcpy (&mic[4], &digest[0], 8) ;
    ofc_memcpy (&mic[12], &seqnum[0], 4) ;

    return (SASL_OK) ;
}

static sasl_client_plug_t ntlm_client_plugins[] = 
{
    {
	"NTLM",				/* mech_name */
	0,				/* max_ssf */
	SASL_SEC_NOPLAINTEXT
	| SASL_SEC_NOANONYMOUS,		/* security_flags */
	SASL_FEAT_WANT_CLIENT_FIRST,	/* features */
	OFC_NULL,				/* required_prompts */
	OFC_NULL,				/* glob_context */
	&ntlm_client_mech_new,		/* mech_new */
	&ntlm_client_mech_step,		/* mech_step */
	&ntlm_client_mech_dispose,	/* mech_dispose */
	OFC_NULL,				/* mech_free */
	OFC_NULL,				/* idle */
	&ntlm_client_mech_key,
	&ntlm_client_mech_name,
	&ntlm_client_mechlistmic
    }
};

int of_security_ntlm_client_plug_init(sasl_utils_t *utils,
			       int maxversion,
			       int *out_version,
			       sasl_client_plug_t **pluglist,
			       int *plugcount)
{
    if (maxversion < SASL_CLIENT_PLUG_VERSION) {
	SETERROR(utils, "NTLM version mismatch");
	return SASL_BADVERS;
    }
    
    *out_version = SASL_CLIENT_PLUG_VERSION;
    *pluglist = ntlm_client_plugins;
    *plugcount = 1;
    
    return SASL_OK;
}
