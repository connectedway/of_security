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
#include "of_security/openssl_smb2.h"
#include "of_security/sha256.h"

#include <openssl/opensslv.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000
#include <openssl/core_names.h>
#include <openssl/params.h>
#else
#include <openssl/cmac.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#endif

OFC_INT openssl_sha512_vector(OFC_SIZET num_elem, const OFC_UCHAR *addr[],
                              const OFC_SIZET *len, OFC_UCHAR *mac)
{
  SHA512_CTX ctx;

  SHA512_Init(&ctx);
  for (OFC_INT i = 0 ; i < num_elem ; i++)
    {
      SHA512_Update(&ctx, addr[i], len[i]);
    }
  SHA512_Final(mac, &ctx);
}

#if OPENSSL_VERSION_NUMBER >= 0x30000000
struct of_security_signing_ctx *
openssl_smb2_signing_ctx(OFC_UCHAR *session_key,
                         OFC_SIZET session_key_len,
			 OFC_UCHAR *label,
                         OFC_SIZET label_size,
                         OFC_UCHAR *context,
                         OFC_SIZET context_size)
{
  OFC_UINT8 zero = 0;
  OFC_UINT32 len ;
  OFC_UINT32 one;
  EVP_MAC *mac;
  EVP_MAC_CTX *macctx;
  struct of_security_signing_ctx *signing_ctx;
  OSSL_PARAM params[2];
  size_t digest_len = SHA256_MAC_LEN;
  OFC_UINT8 digest[SHA256_MAC_LEN];
  const OFC_ULONG signing_key_len = 16;
  EVP_MAC_CTX *evp_signing_ctx;

  int rc;

  signing_ctx = ofc_malloc(sizeof (struct of_security_signing_ctx));

  OFC_NET_LTON(&one, 0, 1);
  OFC_NET_LTON(&len, 0, (signing_key_len * 8));

  mac = EVP_MAC_fetch(OFC_NULL, "HMAC", NULL);
  macctx = EVP_MAC_CTX_new(mac);
  EVP_MAC_free(mac);

  params[0] = OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0);
  params[1] = OSSL_PARAM_construct_end();
  
  EVP_MAC_init(macctx, session_key, session_key_len, params);
  EVP_MAC_update(macctx, (const unsigned char *) &one, sizeof(one));
  EVP_MAC_update(macctx, (const unsigned char *) label, label_size);
  EVP_MAC_update(macctx, (const unsigned char *) &zero, 1);
  EVP_MAC_update(macctx, (const unsigned char *) context, context_size);
  EVP_MAC_update(macctx, (const unsigned char *) &len, sizeof(len));

  EVP_MAC_final(macctx, digest, &digest_len, digest_len);
  EVP_MAC_CTX_free(macctx);

  signing_ctx->keylen = OFC_MIN(signing_key_len, digest_len);
  ofc_memcpy(signing_ctx->key, digest, signing_ctx->keylen);
#if defined(KEY_DEBUG)
  of_security_print_key("openssl Signing Key: ", signing_ctx->key);
#endif

  mac = EVP_MAC_fetch(OFC_NULL, "CMAC", NULL);
  evp_signing_ctx = EVP_MAC_CTX_new(mac);
  EVP_MAC_free(mac);

  params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER,
                                               "aes-128-cbc", 0);
  params[1] = OSSL_PARAM_construct_end();

  EVP_MAC_CTX_set_params(evp_signing_ctx, params);

  signing_ctx->impl_signing_ctx = evp_signing_ctx;

  return (signing_ctx);
}
#else
struct of_security_signing_ctx *
openssl_smb2_signing_ctx(OFC_UCHAR *session_key,
                         OFC_SIZET session_key_len,
			 OFC_UCHAR *label,
                         OFC_SIZET label_size,
                         OFC_UCHAR *context,
                         OFC_SIZET context_size)
{
  OFC_UINT8 zero = 0;
  OFC_UINT32 len ;
  OFC_UINT32 one;
  struct of_security_signing_ctx *signing_ctx;
  unsigned int digest_len = SHA256_MAC_LEN;
  OFC_UINT8 digest[SHA256_MAC_LEN];
  const OFC_ULONG signing_key_len = 16;
  CMAC_CTX *evp_signing_ctx;
  HMAC_CTX *macctx;
  const EVP_MD* md;

  int rc;

  signing_ctx = ofc_malloc(sizeof (struct of_security_signing_ctx));

  OFC_NET_LTON(&one, 0, 1);
  OFC_NET_LTON(&len, 0, (signing_key_len * 8));
  
  macctx = HMAC_CTX_new();

  md = EVP_sha256();
  HMAC_Init_ex(macctx, session_key, session_key_len, md, NULL);
  
  HMAC_Update(macctx, (const unsigned char *) &one, sizeof(one));
  HMAC_Update(macctx, (const unsigned char *) label, label_size);
  HMAC_Update(macctx, (const unsigned char *) &zero, 1);
  HMAC_Update(macctx, (const unsigned char *) context, context_size);
  HMAC_Update(macctx, (const unsigned char *) &len, sizeof(len));
	      
  HMAC_Final(macctx, digest, &digest_len);
  HMAC_CTX_free(macctx);

  signing_ctx->keylen = OFC_MIN(signing_key_len, digest_len);
  ofc_memcpy(signing_ctx->key, digest, signing_ctx->keylen);
#if defined(KEY_DEBUG)
  of_security_print_key("openssl Signing Key: ", signing_ctx->key);
#endif
	      
  evp_signing_ctx = CMAC_CTX_new();
  signing_ctx->impl_signing_ctx = evp_signing_ctx;

  return (signing_ctx);
}
#endif

#if OPENSSL_VERSION_NUMBER >= 0x30000000
OFC_VOID
openssl_smb2_sign_vector(struct of_security_signing_ctx *signing_ctx,
                         OFC_INT num_elem,
                         OFC_UINT8 **ptext_vec,
                         OFC_SIZET *ptext_size_vec,
                         OFC_UINT8 *digest, OFC_SIZET digest_len)
{
  EVP_MAC_CTX *evp_signing_ctx = signing_ctx->impl_signing_ctx;
  size_t evp_digest_len;
  int i;

  evp_digest_len = digest_len;

  EVP_MAC_init(evp_signing_ctx,
               signing_ctx->key, signing_ctx->keylen, NULL);
  for (i = 0 ; i < num_elem; i++)
    {
      EVP_MAC_update(evp_signing_ctx, 
                     ptext_vec[i], ptext_size_vec[i]);
    }
  EVP_MAC_final(evp_signing_ctx,
                digest, &evp_digest_len, evp_digest_len);
#if defined(KEY_DEBUG)
  of_security_print_key("openssl vector sign: ", digest);
#endif
}
#else
OFC_VOID
openssl_smb2_sign_vector(struct of_security_signing_ctx *signing_ctx,
                         OFC_INT num_elem,
                         OFC_UINT8 **ptext_vec,
                         OFC_SIZET *ptext_size_vec,
                         OFC_UINT8 *digest, OFC_SIZET digest_len)
{
  CMAC_CTX *evp_signing_ctx = signing_ctx->impl_signing_ctx;
  size_t evp_digest_len;
  int i;
  const EVP_CIPHER* cipher;

  evp_digest_len = digest_len;

  cipher = EVP_aes_128_cbc();
  CMAC_Init(evp_signing_ctx, signing_ctx->key, signing_ctx->keylen,
	    cipher, NULL);

  for (i = 0 ; i < num_elem; i++)
    {
      CMAC_Update(evp_signing_ctx, ptext_vec[i], ptext_size_vec[i]);
    }
  CMAC_Final(evp_signing_ctx,
	     digest, &evp_digest_len);
#if defined(KEY_DEBUG)
  of_security_print_key("openssl vector sign: ", digest);
#endif
}
#endif

#if OPENSSL_VERSION_NUMBER >= 0x30000000
OFC_VOID openssl_smb2_sign(struct of_security_signing_ctx *signing_ctx,
                           OFC_UINT8 *ptext,
                           OFC_SIZET ptext_size,
                           OFC_UINT8 *digest, OFC_SIZET digest_len)
{
  EVP_MAC_CTX *evp_signing_ctx = signing_ctx->impl_signing_ctx;
  size_t evp_digest_len;

  evp_digest_len = digest_len;

  EVP_MAC_init(evp_signing_ctx,
               signing_ctx->key, signing_ctx->keylen, NULL);
  EVP_MAC_update(evp_signing_ctx, 
                 ptext, ptext_size);
  EVP_MAC_final(evp_signing_ctx,
                digest, &evp_digest_len, evp_digest_len);
#if defined(KEY_DEBUG)
  of_security_print_key("openssl sign: ", digest);
#endif
}
#else
OFC_VOID openssl_smb2_sign(struct of_security_signing_ctx *signing_ctx,
                           OFC_UINT8 *ptext,
                           OFC_SIZET ptext_size,
                           OFC_UINT8 *digest, OFC_SIZET digest_len)
{
  CMAC_CTX *evp_signing_ctx = signing_ctx->impl_signing_ctx;
  size_t evp_digest_len;
  const EVP_CIPHER* cipher;

  evp_digest_len = digest_len;

  cipher = EVP_aes_128_cbc();
  CMAC_Init(evp_signing_ctx, signing_ctx->key, signing_ctx->keylen,
	    cipher, NULL);

  CMAC_Update(evp_signing_ctx, 
	      ptext, ptext_size);
  CMAC_Final(evp_signing_ctx,
	     digest, &evp_digest_len);

#if defined(KEY_DEBUG)
  of_security_print_key("openssl sign: ", digest);
#endif
}
#endif

#if OPENSSL_VERSION_NUMBER >= 0x30000000
OFC_VOID
openssl_smb2_signing_ctx_free(struct of_security_signing_ctx *signing_ctx)
{
  EVP_MAC_CTX *evp_signing_ctx = signing_ctx->impl_signing_ctx;

  EVP_MAC_CTX_free(evp_signing_ctx);
  ofc_free(signing_ctx);
}
#else
OFC_VOID
openssl_smb2_signing_ctx_free(struct of_security_signing_ctx *signing_ctx)
{
  CMAC_CTX *evp_signing_ctx = signing_ctx->impl_signing_ctx;

  CMAC_CTX_free(evp_signing_ctx);
  ofc_free(signing_ctx);
}
#endif

#if OPENSSL_VERSION_NUMBER >= 0x30000000
struct of_security_cipher_ctx *
openssl_smb2_encryption_ctx(OFC_UCHAR *session_key, OFC_SIZET session_key_len,
                            OFC_UINT cipher_algo,
			    OFC_UCHAR *label,
                            OFC_SIZET label_size,
			    OFC_UCHAR *context,
                            OFC_SIZET context_size)
{
  OFC_UINT8 zero = 0;
  OFC_UINT32 len ;
  OFC_UINT32 one;
  
  struct of_security_cipher_ctx *cipher_ctx;

  EVP_MAC *mac;
  EVP_MAC_CTX *macctx;
  OSSL_PARAM params[2];
  size_t digest_len;
  OFC_UINT8 digest[SHA256_DIGEST_LENGTH];
  int rc;

  cipher_ctx = ofc_malloc(sizeof(struct of_security_cipher_ctx));

  cipher_ctx->cipher_algo = cipher_algo;

  digest_len = SHA256_DIGEST_LENGTH;
  cipher_ctx->keylen = OFC_MIN(digest_len, 16);

  OFC_NET_LTON(&one, 0, 1);
  OFC_NET_LTON(&len, 0, (cipher_ctx->keylen * 8));

  mac = EVP_MAC_fetch(OFC_NULL, "HMAC", NULL);
  macctx = EVP_MAC_CTX_new(mac);
  EVP_MAC_free(mac);

  params[0] = OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0);
  params[1] = OSSL_PARAM_construct_end();

  EVP_MAC_init(macctx, session_key, session_key_len, params);
  EVP_MAC_update(macctx, (const unsigned char *) &one, sizeof(one));
  EVP_MAC_update(macctx, (const unsigned char *) label, label_size);
  EVP_MAC_update(macctx, (const unsigned char *) &zero, 1);
  EVP_MAC_update(macctx, (const unsigned char *) context, context_size);
  EVP_MAC_update(macctx, (const unsigned char *) &len, sizeof(len));
  EVP_MAC_final(macctx, digest, &digest_len, digest_len);
  EVP_MAC_CTX_free(macctx);
                                    
  ofc_memcpy(cipher_ctx->key, digest, cipher_ctx->keylen);
#if defined(KEY_DEBUG)
  of_security_print_key("openssl Encryption Key: ",
                        cipher_ctx->key);
#endif

  EVP_CIPHER_CTX *evp_cipher_ctx = EVP_CIPHER_CTX_new();
  if (cipher_ctx->cipher_algo == SMB2_AES_128_CCM)
    {
      EVP_EncryptInit_ex(evp_cipher_ctx,
                         EVP_aes_128_ccm(), OFC_NULL, OFC_NULL, OFC_NULL);
      EVP_CIPHER_CTX_ctrl(evp_cipher_ctx,
                          EVP_CTRL_AEAD_SET_IVLEN, 11,
                          NULL);
    }
  else if (cipher_ctx->cipher_algo == SMB2_AES_128_GCM)
    {
      EVP_EncryptInit_ex(evp_cipher_ctx,
                         EVP_aes_128_gcm(), OFC_NULL, OFC_NULL, OFC_NULL);
      EVP_CIPHER_CTX_ctrl(evp_cipher_ctx,
                          EVP_CTRL_AEAD_SET_IVLEN, 12,
                          NULL);
    }
  else
    ofc_assert(OFC_FALSE, "Invalid Cipher Algorithm");
  
  EVP_CIPHER_CTX_ctrl(evp_cipher_ctx,
                      EVP_CTRL_AEAD_SET_TAG, 16, OFC_NULL);

  cipher_ctx->impl_cipher_ctx = evp_cipher_ctx;

  return (cipher_ctx);
}
#else
struct of_security_cipher_ctx *
openssl_smb2_encryption_ctx(OFC_UCHAR *session_key, OFC_SIZET session_key_len,
                            OFC_UINT cipher_algo,
			    OFC_UCHAR *label,
                            OFC_SIZET label_size,
			    OFC_UCHAR *context,
                            OFC_SIZET context_size)
{
  OFC_UINT8 zero = 0;
  OFC_UINT32 len ;
  OFC_UINT32 one;
  
  struct of_security_cipher_ctx *cipher_ctx;

  HMAC_CTX *macctx;
  unsigned int digest_len;
  OFC_UINT8 digest[SHA256_DIGEST_LENGTH];
  const EVP_MD* md;

  cipher_ctx = ofc_malloc(sizeof(struct of_security_cipher_ctx));

  cipher_ctx->cipher_algo = cipher_algo;

  digest_len = SHA256_DIGEST_LENGTH;
  cipher_ctx->keylen = OFC_MIN(digest_len, 16);

  OFC_NET_LTON(&one, 0, 1);
  OFC_NET_LTON(&len, 0, (cipher_ctx->keylen * 8));

  macctx = HMAC_CTX_new();

  md = EVP_sha256();

  HMAC_Init_ex(macctx, session_key, session_key_len, md, NULL);
  HMAC_Update(macctx, (const unsigned char *) &one, sizeof(one));
  HMAC_Update(macctx, (const unsigned char *) label, label_size);
  HMAC_Update(macctx, (const unsigned char *) &zero, 1);
  HMAC_Update(macctx, (const unsigned char *) context, context_size);
  HMAC_Update(macctx, (const unsigned char *) &len, sizeof(len));
  HMAC_Final(macctx, digest, &digest_len);
  HMAC_CTX_free(macctx);
                                    
  ofc_memcpy(cipher_ctx->key, digest, cipher_ctx->keylen);
#if defined(KEY_DEBUG)
  of_security_print_key("openssl Encryption Key: ",
                        cipher_ctx->key);
#endif

  EVP_CIPHER_CTX *evp_cipher_ctx = EVP_CIPHER_CTX_new();
  if (cipher_ctx->cipher_algo == SMB2_AES_128_CCM)
    {
      EVP_EncryptInit_ex(evp_cipher_ctx,
                         EVP_aes_128_ccm(), OFC_NULL, OFC_NULL, OFC_NULL);
      EVP_CIPHER_CTX_ctrl(evp_cipher_ctx,
                          EVP_CTRL_AEAD_SET_IVLEN, 11,
                          NULL);
    }
  else if (cipher_ctx->cipher_algo == SMB2_AES_128_GCM)
    {
      EVP_EncryptInit_ex(evp_cipher_ctx,
                         EVP_aes_128_gcm(), OFC_NULL, OFC_NULL, OFC_NULL);
      EVP_CIPHER_CTX_ctrl(evp_cipher_ctx,
                          EVP_CTRL_AEAD_SET_IVLEN, 12,
                          NULL);
    }
  else
    ofc_assert(OFC_FALSE, "Invalid Cipher Algorithm");
  
  EVP_CIPHER_CTX_ctrl(evp_cipher_ctx,
		      EVP_CTRL_AEAD_SET_TAG, 16, OFC_NULL);

  cipher_ctx->impl_cipher_ctx = evp_cipher_ctx;

  return (cipher_ctx);
}
#endif

OFC_VOID
openssl_smb2_encrypt(struct of_security_cipher_ctx *cipher_ctx,
                     OFC_UCHAR *iv, OFC_SIZET iv_size,
                     OFC_UINT8 *aead, OFC_SIZET aead_size,
                     OFC_SIZET tag_size,
                     OFC_UINT8 *ptext, OFC_SIZET ptext_size,
                     OFC_UINT8 *ctext, OFC_SIZET ctext_size)
{
  EVP_CIPHER_CTX *evp_cipher_ctx =
    (EVP_CIPHER_CTX *) cipher_ctx->impl_cipher_ctx;
  int evp_ctext_size;
  OFC_UINT8 *tag;

  evp_ctext_size = ctext_size;

  EVP_EncryptInit_ex(evp_cipher_ctx, NULL, NULL,
		     cipher_ctx->key, iv);
  if (cipher_ctx->cipher_algo == SMB2_AES_128_CCM)
    {
      EVP_EncryptUpdate(evp_cipher_ctx,
                        NULL,
                        &evp_ctext_size,
                        NULL,
                        ptext_size);
    }

  EVP_EncryptUpdate(evp_cipher_ctx,
		    NULL,
		    &evp_ctext_size,
		    aead,
		    aead_size);

  EVP_EncryptUpdate(evp_cipher_ctx,
		    ctext,
		    &evp_ctext_size,
		    ptext,
		    ptext_size);

  EVP_EncryptFinal_ex(evp_cipher_ctx,
		      ctext+evp_ctext_size,
		      &evp_ctext_size);

  tag = ctext + (ctext_size - tag_size);
  
  
  if (cipher_ctx->cipher_algo == SMB2_AES_128_CCM)
    {
      EVP_CIPHER_CTX_ctrl(evp_cipher_ctx,
                          EVP_CTRL_CCM_GET_TAG, tag_size, tag);
    }
  else
    {
      EVP_CIPHER_CTX_ctrl(evp_cipher_ctx,
                          EVP_CTRL_GCM_GET_TAG, tag_size, tag);
    }
#if defined(KEY_DEBUG)
  of_security_print_key("openssl encrypt signature:",
                        ctext + ptext_size);
#endif
}

OFC_VOID
openssl_smb2_encrypt_vector(struct of_security_cipher_ctx *cipher_ctx,
                            OFC_UCHAR *iv, OFC_SIZET iv_size,
                            OFC_UINT8 *aead, OFC_SIZET aead_size,
                            OFC_SIZET tag_size,
                            OFC_INT num_elem,
                            OFC_UCHAR **addr, OFC_SIZET *len,
                            OFC_UINT8 *ctext, OFC_SIZET ctext_size)
{
  EVP_CIPHER_CTX *evp_cipher_ctx =
    (EVP_CIPHER_CTX *) cipher_ctx->impl_cipher_ctx;
  int evp_ctext_size;
  OFC_UINT8 *tag;
  int rc;

  OFC_UINT8 *ptext;
  size_t ptext_size = 0;

  OFC_UINT8 *p;

  /*
   * Convert vector to contigous buffer
   */
  for (int i = 0 ; i < num_elem; i++)
    {
      ptext_size += len[i];
    }
  ptext = ofc_malloc(ptext_size);
  p = ptext;
  for (int i = 0; i < num_elem; i++)
    {
      ofc_memcpy(p, addr[i], len[i]);
      p += len[i];
    }

  EVP_EncryptInit_ex(evp_cipher_ctx, NULL, NULL,
		     cipher_ctx->key, iv);

  if (cipher_ctx->cipher_algo == SMB2_AES_128_CCM)
    {
      EVP_EncryptUpdate(evp_cipher_ctx,
                        NULL,
                        &evp_ctext_size,
                        NULL,
                        ptext_size);
    }

  EVP_EncryptUpdate(evp_cipher_ctx,
                    NULL,
                    &evp_ctext_size,
                    aead,
                    aead_size);

  EVP_EncryptUpdate(evp_cipher_ctx,
		    ctext,
		    &evp_ctext_size,
		    ptext, ptext_size);

  ofc_free(ptext);

  EVP_EncryptFinal_ex(evp_cipher_ctx,
                      NULL, &evp_ctext_size);

  tag = ctext + (ctext_size - tag_size);
  
  if (cipher_ctx->cipher_algo == SMB2_AES_128_CCM)
    {
      EVP_CIPHER_CTX_ctrl(evp_cipher_ctx,
                          EVP_CTRL_CCM_GET_TAG, tag_size, tag);
    }
  else
    {
      EVP_CIPHER_CTX_ctrl(evp_cipher_ctx,
                          EVP_CTRL_GCM_GET_TAG, tag_size, tag);
    }

#if defined(KEY_DEBUG)
  of_security_print_key("openssl encrypt vector signature:",
                        ctext + ptext_size);
#endif
}

OFC_VOID
openssl_smb2_encryption_ctx_free(struct of_security_cipher_ctx *cipher_ctx)
{
  EVP_CIPHER_CTX *evp_cipher_ctx;

  evp_cipher_ctx = cipher_ctx->impl_cipher_ctx;
  EVP_CIPHER_CTX_free(evp_cipher_ctx);
  ofc_free(cipher_ctx);
}
  
#if OPENSSL_VERSION_NUMBER >= 0x30000000
struct of_security_cipher_ctx *
openssl_smb2_decryption_ctx(OFC_UCHAR *session_key,
                            OFC_SIZET session_key_len,
                            OFC_UINT cipher_algo,
			    OFC_UCHAR *label,
                            OFC_SIZET label_size,
			    OFC_UCHAR *context,
                            OFC_SIZET context_size)
{
  OFC_UINT8 zero = 0;
  OFC_UINT32 len ;
  OFC_UINT32 one;

  struct of_security_cipher_ctx *cipher_ctx;
  EVP_MAC *mac;
  EVP_MAC_CTX *macctx;
  OSSL_PARAM params[2];
  size_t digest_len;
  OFC_UINT8 digest[SHA256_DIGEST_LENGTH];

  cipher_ctx = ofc_malloc(sizeof(struct of_security_cipher_ctx));

  cipher_ctx->cipher_algo = cipher_algo;

  digest_len = SHA256_DIGEST_LENGTH;
  OFC_NET_LTON(&one, 0, 1);
  OFC_NET_LTON(&len, 0, (16 * 8));

  mac = EVP_MAC_fetch(OFC_NULL, "HMAC", NULL);
  macctx = EVP_MAC_CTX_new(mac);
  EVP_MAC_free(mac);

  params[0] = OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0);
  params[1] = OSSL_PARAM_construct_end();

  EVP_MAC_init(macctx, session_key, session_key_len, params);
  EVP_MAC_update(macctx, (const unsigned char *) &one, sizeof(one));
  EVP_MAC_update(macctx, (const unsigned char *) label, label_size);
  EVP_MAC_update(macctx, (const unsigned char *) &zero, 1);
  EVP_MAC_update(macctx, (const unsigned char *) context, context_size);
  EVP_MAC_update(macctx, (const unsigned char *) &len, sizeof(len));
  EVP_MAC_final(macctx, digest, &digest_len, digest_len); 
  EVP_MAC_CTX_free(macctx);
                                    
  cipher_ctx->keylen = 16;
  ofc_memcpy(cipher_ctx->key, digest, cipher_ctx->keylen);

#if defined(KEY_DEBUG)
  of_security_print_key("openssl Decryption Key: ",
                        decryption_ctx->key);
#endif
  EVP_CIPHER_CTX *evp_cipher_ctx = EVP_CIPHER_CTX_new();
  if (cipher_ctx->cipher_algo == SMB2_AES_128_CCM)
    {
      EVP_DecryptInit_ex(evp_cipher_ctx, EVP_aes_128_ccm,
                         OFC_NULL, OFC_NULL, OFC_NULL);
      EVP_CIPHER_CTX_ctrl(evp_cipher_ctx,
                          EVP_CTRL_AEAD_SET_IVLEN, 11,
                          NULL);

    }
  else if (cipher_ctx->cipher_algo == SMB2_AES_128_GCM)
    {
      EVP_DecryptInit_ex(evp_cipher_ctx, EVP_aes_128_gcm,
                         OFC_NULL, OFC_NULL, OFC_NULL);
      EVP_CIPHER_CTX_ctrl(evp_cipher_ctx,
                          EVP_CTRL_AEAD_SET_IVLEN, 12,
                          NULL);
    }
  else
    ofc_assert(OFC_FALSE, "Invalid Cipher Algorithm");

  cipher_ctx->impl_cipher_ctx = evp_cipher_ctx;
  return (cipher_ctx);
}
#else
struct of_security_cipher_ctx *
openssl_smb2_decryption_ctx(OFC_UCHAR *session_key,
                            OFC_SIZET session_key_len,
                            OFC_UINT cipher_algo,
			    OFC_UCHAR *label,
                            OFC_SIZET label_size,
			    OFC_UCHAR *context,
                            OFC_SIZET context_size)
{
  OFC_UINT8 zero = 0;
  OFC_UINT32 len ;
  OFC_UINT32 one;

  struct of_security_cipher_ctx *cipher_ctx;
  HMAC_CTX *macctx;
  unsigned int digest_len;
  OFC_UINT8 digest[SHA256_DIGEST_LENGTH];
  const EVP_MD *md;

  cipher_ctx = ofc_malloc(sizeof(struct of_security_cipher_ctx));

  cipher_ctx->cipher_algo = cipher_algo;

  digest_len = SHA256_DIGEST_LENGTH;
  OFC_NET_LTON(&one, 0, 1);
  OFC_NET_LTON(&len, 0, (16 * 8));

  macctx = HMAC_CTX_new();

  md = EVP_sha256();

  HMAC_Init_ex(macctx, session_key, session_key_len, md, NULL);
  HMAC_Update(macctx, (const unsigned char *) &one, sizeof(one));
  HMAC_Update(macctx, (const unsigned char *) label, label_size);
  HMAC_Update(macctx, (const unsigned char *) &zero, 1);
  HMAC_Update(macctx, (const unsigned char *) context, context_size);
  HMAC_Update(macctx, (const unsigned char *) &len, sizeof(len));
  HMAC_Final(macctx, digest, &digest_len); 
  HMAC_CTX_free(macctx);
                                    
  cipher_ctx->keylen = 16;
  ofc_memcpy(cipher_ctx->key, digest, cipher_ctx->keylen);

#if defined(KEY_DEBUG)
  of_security_print_key("openssl Decryption Key: ",
                        cipher_ctx->key);
#endif
  EVP_CIPHER_CTX *evp_cipher_ctx = EVP_CIPHER_CTX_new();
  if (cipher_ctx->cipher_algo == SMB2_AES_128_CCM)
    {
      EVP_DecryptInit_ex(evp_cipher_ctx, EVP_aes_128_ccm(),
		     OFC_NULL, OFC_NULL, OFC_NULL);
      EVP_CIPHER_CTX_ctrl(evp_cipher_ctx,
                          EVP_CTRL_AEAD_SET_IVLEN, 11,
                          NULL);
    }
  else if (cipher_ctx->cipher_algo == SMB2_AES_128_GCM)
    {
      EVP_DecryptInit_ex(evp_cipher_ctx, EVP_aes_128_gcm(),
		     OFC_NULL, OFC_NULL, OFC_NULL);
      EVP_CIPHER_CTX_ctrl(evp_cipher_ctx,
                          EVP_CTRL_AEAD_SET_IVLEN, 12,
                          NULL);
    }
  else
    ofc_assert(OFC_FALSE, "Invalid Cipher Algorithm");
  cipher_ctx->impl_cipher_ctx = evp_cipher_ctx;
  return (cipher_ctx);
}
#endif

OFC_BOOL openssl_smb2_decrypt(struct of_security_cipher_ctx *cipher_ctx,
                              OFC_UCHAR *iv, OFC_SIZET iv_size,
                              OFC_UINT8 *aead, OFC_SIZET aead_size,
                              OFC_SIZET tag_size,
                              OFC_UINT8 *ctext, OFC_SIZET ctext_size,
                              OFC_UINT8 *ptext, OFC_SIZET ptext_size)
{
  EVP_CIPHER_CTX *evp_cipher_ctx;

  OFC_UINT8 *tag;
  OFC_UINT rc;
  int evp_ptext_size;
  OFC_BOOL ret = OFC_TRUE;

  ofc_assert(tag_size == 16, "Bad Tag or Key Size");

  evp_ptext_size = ptext_size;
  evp_cipher_ctx =
    (EVP_CIPHER_CTX *) cipher_ctx->impl_cipher_ctx;

  /*
   * Pull tag out of bufer
   */
  ctext_size -= tag_size;
  tag = ctext + ctext_size ;

  if (cipher_ctx->cipher_algo == SMB2_AES_128_CCM)
    {
      EVP_CIPHER_CTX_ctrl(evp_cipher_ctx, EVP_CTRL_CCM_SET_TAG, tag_size,
                          tag);
    }

  EVP_DecryptInit_ex(evp_cipher_ctx, NULL, NULL,
		     cipher_ctx->key, iv);

  if (cipher_ctx->cipher_algo == SMB2_AES_128_CCM)
    {
      EVP_DecryptUpdate(evp_cipher_ctx,
                        NULL,
                        &evp_ptext_size,
                        NULL,
                        ctext_size);
    }

  EVP_DecryptUpdate(evp_cipher_ctx,
		    NULL,
		    &evp_ptext_size,
		    aead, aead_size);
  /*
   * The tag verify occurs on the last decrypt update as per
   * https://wiki.openssl.org/
   */
  if (cipher_ctx->cipher_algo == SMB2_AES_128_CCM)
    {
      rc = EVP_DecryptUpdate(evp_cipher_ctx,
                             ptext,
                             &evp_ptext_size,
                             ctext,
                             ctext_size);
      if (rc <= 0)
        /*
         * verify failed
         */
        ret = OFC_FALSE;
    }
  else
    {
      EVP_DecryptUpdate(evp_cipher_ctx,
                        ptext,
                        &evp_ptext_size,
                        ctext,
                        ctext_size);

      EVP_CIPHER_CTX_ctrl(evp_cipher_ctx, EVP_CTRL_GCM_SET_TAG, tag_size,
                          tag);

      rc = EVP_DecryptFinal_ex(evp_cipher_ctx, ptext + evp_ptext_size,
                               &evp_ptext_size);
      if (rc <= 0)
        ret = OFC_FALSE;
    }
        
#if defined(KEY_DEBUG)
  ofc_printf("openssl decrypt signature verification %s\n",
             ret == OFC_TRUE ? "success" : "failed");
#endif

  return (ret);
}
  
OFC_BOOL
openssl_smb2_decrypt_vector(struct of_security_cipher_ctx *cipher_ctx,
                            OFC_UCHAR *iv, OFC_SIZET iv_size,
                            OFC_UINT8 *aead, OFC_SIZET aead_size,
                            OFC_UINT8 *tag, OFC_SIZET tag_size,
                            OFC_INT num_elem,
                            OFC_UCHAR **addr, OFC_SIZET *len,
                            OFC_UINT8 *ptext, OFC_SIZET ptext_size)
{
  EVP_CIPHER_CTX *evp_cipher_ctx;

  OFC_UINT rc;
  int evp_ptext_size;
  OFC_BOOL ret = OFC_TRUE;
  OFC_UINT8 *ctext;
  size_t ctext_size = 0;
  OFC_UINT8 *p;

  ofc_assert(tag_size == 16, "Bad Tag or Key Size");

  evp_ptext_size = ptext_size;
  evp_cipher_ctx =
    (EVP_CIPHER_CTX *) cipher_ctx->impl_cipher_ctx;

  /*
   * Get size of input
   */
  for (int i = 0 ; i < num_elem; i++)
    {
      ctext_size += len[i];
    }
  ctext = ofc_malloc(ctext_size);
  p = ctext;
  for (int i = 0 ; i < num_elem; i++)
    {
      ofc_memcpy (p, addr[i], len[i]);
      p += len[i];
    }

  if (cipher_ctx->cipher_algo == SMB2_AES_128_CCM)
    {
      EVP_CIPHER_CTX_ctrl(evp_cipher_ctx, EVP_CTRL_CCM_SET_TAG, tag_size,
                          tag);
    }

  EVP_DecryptInit_ex(evp_cipher_ctx, NULL, NULL,
		     cipher_ctx->key, iv);
  if (cipher_ctx->cipher_algo == SMB2_AES_128_CCM)
    {
      EVP_DecryptUpdate(evp_cipher_ctx,
                        NULL,
                        &evp_ptext_size,
                        NULL,
                        ctext_size);
    }
  EVP_DecryptUpdate(evp_cipher_ctx,
		    NULL,
		    &evp_ptext_size,
		    aead, aead_size);

  OFC_OFFT offset = 0;

  /*
   * The tag verify occurs on the last decrypt update as per
   * https://wiki.openssl.org/
   */
  if (cipher_ctx->cipher_algo == SMB2_AES_128_CCM)
    {
      rc = EVP_DecryptUpdate(evp_cipher_ctx,
                             ptext,
                             &evp_ptext_size,
                             ctext, ctext_size);
      if (rc <= 0)
        /*
         * verify failed
         */
        ret = OFC_FALSE;
    }
  else
    {
      EVP_DecryptUpdate(evp_cipher_ctx,
                        ptext,
                        &evp_ptext_size,
                        ctext, ctext_size);
      EVP_CIPHER_CTX_ctrl(evp_cipher_ctx, EVP_CTRL_GCM_SET_TAG, tag_size,
                          tag);

      rc = EVP_DecryptFinal_ex(evp_cipher_ctx, ptext + evp_ptext_size,
                               &evp_ptext_size);
      if (rc <= 0)
        ret = OFC_FALSE;
    }

  ofc_free(ctext);

#if defined(KEY_DEBUG)
  ofc_printf("openssl decrypt vector signature verification %s\n",
             ret == OFC_TRUE ? "success" : "failed");
#endif
  return (ret);
}

OFC_VOID
openssl_smb2_decryption_ctx_free(struct of_security_cipher_ctx *cipher_ctx)
{
  EVP_CIPHER_CTX *evp_cipher_ctx;

  evp_cipher_ctx = cipher_ctx->impl_cipher_ctx;
  EVP_CIPHER_CTX_free(evp_cipher_ctx);
  ofc_free(cipher_ctx);
}

OFC_VOID openssl_smb2_rand_bytes(OFC_UCHAR *output, OFC_SIZET output_size)
{
  RAND_bytes(output, output_size);
}


