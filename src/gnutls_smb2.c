/* Copyright (c) 2021 Connected Way, LLC. All rights reserved.
 * Use of this source code is governed by a Creative Commons 
 * Attribution-NoDerivatives 4.0 International license that can be
 * found in the LICENSE file.
 */

#include "ofc/types.h"
#include "ofc/libc.h"
#include "ofc/net_internal.h"
#include "ofc/heap.h"
#include "ofc/process.h"

#include "of_security/security_smb2.h"
#include "of_security/gnutls_smb2.h"

#include <gnutls/crypto.h>

struct of_security_signing_ctx *
gnutls_smb2_signing_ctx(OFC_UCHAR *session_key,
                        OFC_SIZET session_key_len)
{
  OFC_UINT8 zero = 0;
  OFC_UINT32 len ;
  OFC_UINT32 one;
  struct of_security_signing_ctx *signing_ctx;
  const OFC_SIZET digest_len = gnutls_hash_get_len(GNUTLS_DIG_SHA256);
  OFC_UINT8 digest[digest_len];
  const OFC_ULONG signing_key_len = 16;
  gnutls_hmac_hd_t hmac_hnd;

  int rc;

  signing_ctx = ofc_malloc(sizeof (struct of_security_signing_ctx));

  OFC_NET_LTON(&one, 0, 1);
  OFC_NET_LTON(&len, 0, (signing_key_len * 8));

  rc = gnutls_hmac_init(&hmac_hnd,
                        GNUTLS_MAC_SHA256,
                        session_key,
                        session_key_len);
  rc = gnutls_hmac(hmac_hnd, 
                   (const unsigned char *) &one,
                   sizeof(one));
  rc = gnutls_hmac(hmac_hnd,
                   (const unsigned char *) "SMB2AESCMAC",
                   12);
  rc = gnutls_hmac(hmac_hnd,
                   (const unsigned char *) &zero,
                   1);
  rc = gnutls_hmac(hmac_hnd,
                   (const unsigned char *) "SmbSign",
                   8);
  rc = gnutls_hmac(hmac_hnd,
                   (const unsigned char *) &len,
                   sizeof(len));
                                    
  gnutls_hmac_deinit(hmac_hnd, digest);

  signing_ctx->keylen = OFC_MIN(signing_key_len, digest_len);
  ofc_memcpy(signing_ctx->key, digest, signing_ctx->keylen);
    
#if 0
  of_security_print_key("gnutls Signing Key: ", signing_ctx->key);
#endif

  gnutls_hmac_init(&hmac_hnd,
                   GNUTLS_MAC_AES_CMAC_128,
                   signing_ctx->key,
                   signing_ctx->keylen);
  signing_ctx->impl_signing_ctx = hmac_hnd;

  return (signing_ctx);
}

OFC_VOID
gnutls_smb2_sign_vector(struct of_security_signing_ctx *signing_ctx,
                        OFC_INT num_elem,
                         OFC_UINT8 **ptext_vec,
                         OFC_SIZET *ptext_size_vec,
                         OFC_UINT8 *digest, OFC_SIZET digest_len)
{
  gnutls_hmac_hd_t hmac_hnd = signing_ctx->impl_signing_ctx;
  OFC_UINT8 mac[gnutls_hash_get_len(GNUTLS_MAC_AES_CMAC_128)];
  int i;

  for (i = 0 ; i < num_elem; i++)
    {
      gnutls_hmac(hmac_hnd,
                  ptext_vec[i], ptext_size_vec[i]);
    }
  gnutls_hmac_output(hmac_hnd, mac);
#if 0
  smb_client_session_print_key("gnutls sign: ", mac);
#endif
  ofc_memcpy(digest, mac, digest_len);
}

OFC_VOID gnutls_smb2_sign(struct of_security_signing_ctx *signing_ctx,
                           OFC_UINT8 *ptext,
                           OFC_SIZET ptext_size,
                           OFC_UINT8 *digest, OFC_SIZET digest_len)
{
  gnutls_hmac_hd_t hmac_hnd = signing_ctx->impl_signing_ctx;
  OFC_UINT8 mac[gnutls_hash_get_len(GNUTLS_MAC_AES_CMAC_128)];

  gnutls_hmac(hmac_hnd,
              ptext, ptext_size);
  gnutls_hmac_output(hmac_hnd, mac);
#if 0
  smb_client_session_print_key("gnutls sign: ", mac);
#endif
  ofc_memcpy(digest, mac, digest_len);
}

OFC_VOID
gnutls_smb2_signing_ctx_free(struct of_security_signing_ctx *signing_ctx)
{
  gnutls_hmac_hd_t hmac_hnd = signing_ctx->impl_signing_ctx;
  
  gnutls_hmac_deinit(hmac_hnd, OFC_NULL);
  ofc_free(signing_ctx);
}

struct of_security_cipher_ctx *
gnutls_smb2_encryption_ctx(enum smb2_cipher_type cipher_type,
			   OFC_UCHAR *session_key, OFC_SIZET session_key_len)
{
  OFC_UINT8 zero = 0;
  OFC_UINT32 len ;
  OFC_UINT32 one;
  
  struct of_security_cipher_ctx *cipher_ctx;

  gnutls_hmac_hd_t hmac_hnd;
  const OFC_SIZET digest_len = gnutls_hash_get_len(GNUTLS_DIG_SHA256);
  OFC_UINT8 digest[digest_len];
  int rc;

  cipher_ctx = ofc_malloc(sizeof(struct of_security_cipher_ctx));

  cipher_ctx->keylen = OFC_MIN(digest_len, 16);

  OFC_NET_LTON(&one, 0, 1);
  OFC_NET_LTON(&len, 0, (cipher_ctx->keylen * 8));

  rc = gnutls_hmac_init(&hmac_hnd,
                        GNUTLS_MAC_SHA256,
                        session_key, session_key_len);
  rc = gnutls_hmac(hmac_hnd, 
                   (const unsigned char *) &one,
                   sizeof(one));
  rc = gnutls_hmac(hmac_hnd,
                   (const unsigned char *) "SMB2AESCCM",
                   11);
  rc = gnutls_hmac(hmac_hnd,
                   (const unsigned char *) &zero,
                   1);
  if (cipher_type == SMB2_CIPHER_TYPE_SERVER)
    rc = gnutls_hmac(hmac_hnd,
		     (const unsigned char *) "ServerOut",
		     10);
  else
    rc = gnutls_hmac(hmac_hnd,
		     (const unsigned char *) "ServerIn ",
		     10);
  rc = gnutls_hmac(hmac_hnd,
                   (const unsigned char *) &len,
                   sizeof(len));
                                    
  gnutls_hmac_deinit(hmac_hnd, digest);
  ofc_memcpy(cipher_ctx->key,
             digest,
             cipher_ctx->keylen);

#if 0
  of_security_print_key("gnutls Encryption Key: ",
                                smb_client_session->encryption_key);
#endif

  gnutls_datum_t key_datum;
  key_datum.data = cipher_ctx->key;
  key_datum.size = cipher_ctx->keylen;

  gnutls_aead_cipher_hd_t *encryption_cipher_hnd =
    ofc_malloc(sizeof(gnutls_aead_cipher_hd_t));

  rc = gnutls_aead_cipher_init(encryption_cipher_hnd,
                               GNUTLS_CIPHER_AES_128_CCM,
                               &key_datum);

  cipher_ctx->impl_cipher_ctx = encryption_cipher_hnd;
  return (cipher_ctx);
}

OFC_VOID
gnutls_smb2_encrypt(struct of_security_cipher_ctx *cipher_ctx,
                     OFC_UCHAR *iv, OFC_SIZET iv_size,
                     OFC_UINT8 *aead, OFC_SIZET aead_size,
                     OFC_SIZET tag_size,
                     OFC_UINT8 *ptext, OFC_SIZET ptext_size,
                     OFC_UINT8 *ctext, OFC_SIZET ctext_size)
{
  gnutls_aead_cipher_hd_t *encryption_cipher_hnd =
    cipher_ctx->impl_cipher_ctx ;
  size_t gnutls_ctext_size = ctext_size;

  gnutls_aead_cipher_encrypt(*encryption_cipher_hnd,
                             iv, iv_size,
                             aead, aead_size,
                             tag_size,
                             ptext,
                             ptext_size,
                             ctext, &gnutls_ctext_size);
#if 0
  of_security_print_key("gnutls encrypt signature :",
                        ctext + ctext_size);
#endif
}

OFC_VOID
gnutls_smb2_encryption_ctx_free(struct of_security_cipher_ctx *cipher_ctx)
{
  gnutls_aead_cipher_hd_t *encryption_cipher_hnd =
    cipher_ctx->impl_cipher_ctx ;

  gnutls_aead_cipher_deinit(*encryption_cipher_hnd);
  ofc_free(encryption_cipher_hnd);
  ofc_free(cipher_ctx);
}
  
struct of_security_cipher_ctx *
gnutls_smb2_decryption_ctx(enum smb2_cipher_type cipher_type,
			   OFC_UCHAR *session_key,
                           OFC_SIZET session_key_len)
{
  OFC_UINT8 zero = 0;
  OFC_UINT32 len ;
  OFC_UINT32 one;
  
  struct of_security_cipher_ctx *cipher_ctx;

  gnutls_hmac_hd_t hmac_hnd;
  const OFC_SIZET digest_len = gnutls_hash_get_len(GNUTLS_DIG_SHA256);
  OFC_UINT8 digest[digest_len];
  int rc;

  cipher_ctx = ofc_malloc(sizeof(struct of_security_cipher_ctx));

  cipher_ctx->keylen = OFC_MIN(digest_len, 16);

  OFC_NET_LTON(&one, 0, 1);
  OFC_NET_LTON(&len, 0, (cipher_ctx->keylen * 8));

  rc = gnutls_hmac_init(&hmac_hnd,
                        GNUTLS_MAC_SHA256,
                        session_key, session_key_len);
  rc = gnutls_hmac(hmac_hnd, 
                   (const unsigned char *) &one,
                   sizeof(one));
  rc = gnutls_hmac(hmac_hnd,
                   (const unsigned char *) "SMB2AESCCM",
                   11);
  rc = gnutls_hmac(hmac_hnd,
                   (const unsigned char *) &zero,
                   1);
  if (cipher_type == SMB2_CIPHER_TYPE_SERVER)
    rc = gnutls_hmac(hmac_hnd,
		     (const unsigned char *) "ServerIn ",
		     10);
  else
    rc = gnutls_hmac(hmac_hnd,
		     (const unsigned char *) "ServerOut",
		     10);
  rc = gnutls_hmac(hmac_hnd,
                   (const unsigned char *) &len,
                   sizeof(len));
                                    
  gnutls_hmac_deinit(hmac_hnd, digest);
  ofc_memcpy(cipher_ctx->key,
             digest,
             cipher_ctx->keylen);

#if 0
  of_security_print_key("gnutls Encryption Key: ",
                                smb_client_session->encryption_key);
#endif

  gnutls_datum_t key_datum;
  key_datum.data = cipher_ctx->key;
  key_datum.size = cipher_ctx->keylen;

  gnutls_aead_cipher_hd_t *decryption_cipher_hnd =
    ofc_malloc(sizeof(gnutls_aead_cipher_hd_t));

  rc = gnutls_aead_cipher_init(decryption_cipher_hnd,
                               GNUTLS_CIPHER_AES_128_CCM,
                               &key_datum);

  cipher_ctx->impl_cipher_ctx = decryption_cipher_hnd;
  return (cipher_ctx);
}

OFC_BOOL gnutls_smb2_decrypt(struct of_security_cipher_ctx *cipher_ctx,
                              OFC_UCHAR *iv, OFC_SIZET iv_size,
                              OFC_UINT8 *aead, OFC_SIZET aead_size,
                              OFC_SIZET tag_size,
                              OFC_UINT8 *ctext, OFC_SIZET ctext_size,
                              OFC_UINT8 *ptext, OFC_SIZET ptext_size)
{
  gnutls_aead_cipher_hd_t *decryption_cipher_hnd =
    cipher_ctx->impl_cipher_ctx ;
  size_t gnutls_ptext_size = ptext_size;
  OFC_BOOL ret = OFC_TRUE;

  if (gnutls_aead_cipher_decrypt(*decryption_cipher_hnd,
                                 iv, iv_size,
                                 aead, aead_size,
                                 tag_size,
                                 ctext, ctext_size,
                                 ptext, &gnutls_ptext_size) < 0)
    ret = OFC_FALSE;
  return (ret);
}
  
OFC_VOID
gnutls_smb2_decryption_ctx_free(struct of_security_cipher_ctx *cipher_ctx)
{
  gnutls_aead_cipher_hd_t *decryption_cipher_hnd =
    cipher_ctx->impl_cipher_ctx ;

  gnutls_aead_cipher_deinit(*decryption_cipher_hnd);
  ofc_free(decryption_cipher_hnd);
  ofc_free(cipher_ctx);
}

OFC_VOID gnutls_smb2_rand_bytes(OFC_UCHAR *output, OFC_SIZET output_size)
{
  gnutls_rnd(GNUTLS_RND_NONCE, output, output_size);
}


