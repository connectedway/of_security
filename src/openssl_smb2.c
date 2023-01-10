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
#endif



#if OPENSSL_VERSION_NUMBER >= 0x30000000
struct of_security_signing_ctx *
openssl_smb2_signing_ctx(OFC_UCHAR *session_key,
                         OFC_SIZET session_key_len)
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
  
#if 0
  of_security_print_key("Session Key: ", session_key);
#endif

  EVP_MAC_init(macctx, session_key, session_key_len, params);
  EVP_MAC_update(macctx, (const unsigned char *) &one, sizeof(one));
  EVP_MAC_update(macctx, (const unsigned char *) "SMB2AESCMAC", 12);
  EVP_MAC_update(macctx, (const unsigned char *) &zero, 1);
  EVP_MAC_update(macctx, (const unsigned char *) "SmbSign", 8);
  EVP_MAC_update(macctx, (const unsigned char *) &len, sizeof(len));

  EVP_MAC_final(macctx, digest, &digest_len, digest_len);
  EVP_MAC_CTX_free(macctx);

  signing_ctx->keylen = OFC_MIN(signing_key_len, digest_len);
  ofc_memcpy(signing_ctx->key, digest, signing_ctx->keylen);
#if 0
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
                         OFC_SIZET session_key_len)
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

#if 0
  of_security_print_key("Session Key: ", session_key);
#endif

  md = EVP_sha256();
  HMAC_Init_ex(macctx, session_key, session_key_len, md, NULL);
  
  HMAC_Update(macctx, (const unsigned char *) &one, sizeof(one));
  HMAC_Update(macctx, (const unsigned char *) "SMB2AESCMAC", 12);
  HMAC_Update(macctx, (const unsigned char *) &zero, 1);
  HMAC_Update(macctx, (const unsigned char *) "SmbSign", 8);
  HMAC_Update(macctx, (const unsigned char *) &len, sizeof(len));
	      
  HMAC_Final(macctx, digest, &digest_len);
  HMAC_CTX_free(macctx);

  signing_ctx->keylen = OFC_MIN(signing_key_len, digest_len);
  ofc_memcpy(signing_ctx->key, digest, signing_ctx->keylen);
#if 0
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
#if 0
  of_security_print_key("openssl sign: ", digest);
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
#if 0
  of_security_print_key("openssl sign: ", digest);
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
#if 0
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

#if 0
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
openssl_smb2_encryption_ctx(OFC_UCHAR *session_key, OFC_SIZET session_key_len)
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

  digest_len = SHA256_DIGEST_LENGTH;
  cipher_ctx->keylen = OFC_MIN(digest_len, 16);

  OFC_NET_LTON(&one, 0, 1);
  OFC_NET_LTON(&len, 0, (cipher_ctx->keylen * 8));

  mac = EVP_MAC_fetch(OFC_NULL, "HMAC", NULL);
  macctx = EVP_MAC_CTX_new(mac);
  EVP_MAC_free(mac);

  params[0] = OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0);
  params[1] = OSSL_PARAM_construct_end();

#if 0
  of_security_print_key("Session Key: ", session_key);
#endif

  EVP_MAC_init(macctx, session_key, session_key_len, params);
  EVP_MAC_update(macctx, (const unsigned char *) &one, sizeof(one));
  EVP_MAC_update(macctx, (const unsigned char *) "SMB2AESCCM", 11);
  EVP_MAC_update(macctx, (const unsigned char *) &zero, 1);
  EVP_MAC_update(macctx, (const unsigned char *) "ServerIn ", 10);
  EVP_MAC_update(macctx, (const unsigned char *) &len, sizeof(len));
  EVP_MAC_final(macctx, digest, &digest_len, digest_len);
  EVP_MAC_CTX_free(macctx);
                                    
  ofc_memcpy(cipher_ctx->key, digest, cipher_ctx->keylen);
#if 0
  of_security_print_key("openssl Encryption Key: ",
                        cipher_ctx->key);
#endif

  EVP_CIPHER_CTX *evp_cipher_ctx = EVP_CIPHER_CTX_new();

  EVP_EncryptInit_ex(evp_cipher_ctx,
                     EVP_aes_128_ccm(), OFC_NULL, OFC_NULL, OFC_NULL);
  EVP_CIPHER_CTX_ctrl(evp_cipher_ctx,
                      EVP_CTRL_CCM_SET_IVLEN, 11,
                      NULL);
  EVP_CIPHER_CTX_ctrl(evp_cipher_ctx,
                      EVP_CTRL_CCM_SET_TAG, 16, OFC_NULL);

  cipher_ctx->impl_cipher_ctx = evp_cipher_ctx;

  return (cipher_ctx);
}
#else
struct of_security_cipher_ctx *
openssl_smb2_encryption_ctx(OFC_UCHAR *session_key, OFC_SIZET session_key_len)
{
  OFC_UINT8 zero = 0;
  OFC_UINT32 len ;
  OFC_UINT32 one;
  
  struct of_security_cipher_ctx *cipher_ctx;

  HMAC_CTX *macctx;
  unsigned int digest_len;
  OFC_UINT8 digest[SHA256_DIGEST_LENGTH];
  int rc;
  const EVP_MD* md;

  cipher_ctx = ofc_malloc(sizeof(struct of_security_cipher_ctx));

  digest_len = SHA256_DIGEST_LENGTH;
  cipher_ctx->keylen = OFC_MIN(digest_len, 16);

  OFC_NET_LTON(&one, 0, 1);
  OFC_NET_LTON(&len, 0, (cipher_ctx->keylen * 8));

  macctx = HMAC_CTX_new();

  md = EVP_sha256();

#if 0
  of_security_print_key("Session Key: ", session_key);
#endif

  HMAC_Init_ex(macctx, session_key, session_key_len, md, NULL);
  HMAC_Update(macctx, (const unsigned char *) &one, sizeof(one));
  HMAC_Update(macctx, (const unsigned char *) "SMB2AESCCM", 11);
  HMAC_Update(macctx, (const unsigned char *) &zero, 1);
  HMAC_Update(macctx, (const unsigned char *) "ServerIn ", 10);
  HMAC_Update(macctx, (const unsigned char *) &len, sizeof(len));
  HMAC_Final(macctx, digest, &digest_len);
  HMAC_CTX_free(macctx);
                                    
  ofc_memcpy(cipher_ctx->key, digest, cipher_ctx->keylen);
#if 0
  of_security_print_key("openssl Encryption Key: ",
                        cipher_ctx->key);
#endif

  EVP_CIPHER_CTX *evp_cipher_ctx = EVP_CIPHER_CTX_new();

  EVP_EncryptInit_ex(evp_cipher_ctx,
                     EVP_aes_128_ccm(), OFC_NULL, OFC_NULL, OFC_NULL);
  EVP_CIPHER_CTX_ctrl(evp_cipher_ctx,
                      EVP_CTRL_CCM_SET_IVLEN, 11,
                      NULL);
  EVP_CIPHER_CTX_ctrl(evp_cipher_ctx,
                      EVP_CTRL_CCM_SET_TAG, 16, OFC_NULL);

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
  EVP_EncryptUpdate(evp_cipher_ctx,
                    NULL,
                    &evp_ctext_size,
                    NULL,
                    ptext_size);
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
                      NULL, &evp_ctext_size);

  tag = ctext + (ctext_size - tag_size);
  
  EVP_CIPHER_CTX_ctrl(evp_cipher_ctx,
                      EVP_CTRL_CCM_GET_TAG, tag_size, tag);

#if 0
  of_security_print_key("openssl encrypt signature :", signature);
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
  size_t inlen = 0;
  size_t outlen;

  /*
   * Get size of input
   */
  for (int i = 0 ; i < num_elem; i++)
    {
      inlen += len[i];
    }

  evp_ctext_size = ctext_size;

  EVP_EncryptInit_ex(evp_cipher_ctx, NULL, NULL,
                     cipher_ctx->key, iv);
  EVP_EncryptUpdate(evp_cipher_ctx,
                    NULL,
                    &evp_ctext_size,
                    NULL,
                    inlen);
  EVP_EncryptUpdate(evp_cipher_ctx,
                    NULL,
                    &evp_ctext_size,
                    aead,
                    aead_size);

  OFC_OFFT offset = 0;
  for (int i = 0 ; i < num_elem; i++)
    {
      EVP_EncryptUpdate(evp_cipher_ctx,
			ctext+offset,
			&evp_ctext_size,
			addr[i],
			len[i]);
      offset += evp_ctext_size;
    }
  EVP_EncryptFinal_ex(evp_cipher_ctx,
                      NULL, &evp_ctext_size);

  tag = ctext + (ctext_size - tag_size);
  
  EVP_CIPHER_CTX_ctrl(evp_cipher_ctx,
                      EVP_CTRL_CCM_GET_TAG, tag_size, tag);

#if 0
  of_security_print_key("openssl encrypt signature :", signature);
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
                            OFC_SIZET session_key_len)
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

  digest_len = SHA256_DIGEST_LENGTH;
  OFC_NET_LTON(&one, 0, 1);
  OFC_NET_LTON(&len, 0, (16 * 8));

  mac = EVP_MAC_fetch(OFC_NULL, "HMAC", NULL);
  macctx = EVP_MAC_CTX_new(mac);
  EVP_MAC_free(mac);

  params[0] = OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0);
  params[1] = OSSL_PARAM_construct_end();

#if 0
  of_security_print_key("Session Key: ", session_key);
#endif

  EVP_MAC_init(macctx, session_key, session_key_len, params);
  EVP_MAC_update(macctx, (const unsigned char *) &one, sizeof(one));
  EVP_MAC_update(macctx, (const unsigned char *) "SMB2AESCCM", 11);
  EVP_MAC_update(macctx, (const unsigned char *) &zero, 1);
  EVP_MAC_update(macctx, (const unsigned char *) "ServerOut", 10);
  EVP_MAC_update(macctx, (const unsigned char *) &len, sizeof(len));
  EVP_MAC_final(macctx, digest, &digest_len, digest_len); 
  EVP_MAC_CTX_free(macctx);
                                    
  cipher_ctx->keylen = 16;
  ofc_memcpy(cipher_ctx->key, digest, cipher_ctx->keylen);

#if 0
  of_security_print_key("openssl Decryption Key: ",
                        decryption_ctx->key);
#endif
  EVP_CIPHER_CTX *evp_cipher_ctx = EVP_CIPHER_CTX_new();
  EVP_DecryptInit_ex(evp_cipher_ctx, EVP_aes_128_ccm(),
                     OFC_NULL, OFC_NULL, OFC_NULL);
  EVP_CIPHER_CTX_ctrl(evp_cipher_ctx,
                      EVP_CTRL_AEAD_SET_IVLEN, 11,
                      NULL);
  cipher_ctx->impl_cipher_ctx = evp_cipher_ctx;
  return (cipher_ctx);
}
#else
struct of_security_cipher_ctx *
openssl_smb2_decryption_ctx(OFC_UCHAR *session_key,
                            OFC_SIZET session_key_len)
{
  OFC_UINT8 zero = 0;
  OFC_UINT32 len ;
  OFC_UINT32 one;

  struct of_security_cipher_ctx *cipher_ctx;
  HMAC_CTX *macctx;
  unsigned int digest_len;
  OFC_UINT8 digest[SHA256_DIGEST_LENGTH];
  int rc;
  const EVP_MD *md;

  cipher_ctx = ofc_malloc(sizeof(struct of_security_cipher_ctx));

  digest_len = SHA256_DIGEST_LENGTH;
  OFC_NET_LTON(&one, 0, 1);
  OFC_NET_LTON(&len, 0, (16 * 8));

  macctx = HMAC_CTX_new();

  md = EVP_sha256();
#if 0
  of_security_print_key("Session Key: ", session_key);
#endif

  HMAC_Init_ex(macctx, session_key, session_key_len, md, NULL);
  HMAC_Update(macctx, (const unsigned char *) &one, sizeof(one));
  HMAC_Update(macctx, (const unsigned char *) "SMB2AESCCM", 11);
  HMAC_Update(macctx, (const unsigned char *) &zero, 1);
  HMAC_Update(macctx, (const unsigned char *) "ServerOut", 10);
  HMAC_Update(macctx, (const unsigned char *) &len, sizeof(len));
  HMAC_Final(macctx, digest, &digest_len); 
  HMAC_CTX_free(macctx);
                                    
  cipher_ctx->keylen = 16;
  ofc_memcpy(cipher_ctx->key, digest, cipher_ctx->keylen);

#if 0
  of_security_print_key("openssl Decryption Key: ",
                        decryption_ctx->key);
#endif
  EVP_CIPHER_CTX *evp_cipher_ctx = EVP_CIPHER_CTX_new();
  EVP_DecryptInit_ex(evp_cipher_ctx, EVP_aes_128_ccm(),
                     OFC_NULL, OFC_NULL, OFC_NULL);
  EVP_CIPHER_CTX_ctrl(evp_cipher_ctx,
                      EVP_CTRL_AEAD_SET_IVLEN, 11,
                      NULL);
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
  OFC_BOOL ret;

  ofc_assert(tag_size == 16, "Bad Tag or Key Size");

  evp_ptext_size = ptext_size;
  evp_cipher_ctx =
    (EVP_CIPHER_CTX *) cipher_ctx->impl_cipher_ctx;

  tag = ctext + ctext_size;
  EVP_CIPHER_CTX_ctrl(evp_cipher_ctx, EVP_CTRL_AEAD_SET_TAG, tag_size, tag);

  EVP_DecryptInit_ex(evp_cipher_ctx, NULL, NULL,
                     cipher_ctx->key, iv);
  EVP_DecryptUpdate(evp_cipher_ctx,
                    NULL,
                    &evp_ptext_size,
                    NULL,
                    ctext_size);
  EVP_DecryptUpdate(evp_cipher_ctx,
                    NULL,
                    &evp_ptext_size,
                    aead, aead_size);
  /*
   * The tag verify occurs on the last decrypt update as per
   * https://wiki.openssl.org/
   */
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
  size_t inlen = 0;
  size_t outlen;
  OFC_BOOL ret = OFC_TRUE;

  ofc_assert(tag_size == 16, "Bad Tag or Key Size");

  evp_ptext_size = ptext_size;
  evp_cipher_ctx =
    (EVP_CIPHER_CTX *) cipher_ctx->impl_cipher_ctx;

  /*
   * Get size of input
   */
  for (int i = 0 ; i < num_elem; i++)
    {
      inlen += len[i];
    }

  EVP_CIPHER_CTX_ctrl(evp_cipher_ctx, EVP_CTRL_AEAD_SET_TAG, tag_size, tag);

  EVP_DecryptInit_ex(evp_cipher_ctx, NULL, NULL,
                     cipher_ctx->key, iv);
  EVP_DecryptUpdate(evp_cipher_ctx,
                    NULL,
                    &evp_ptext_size,
                    NULL,
                    inlen);
  EVP_DecryptUpdate(evp_cipher_ctx,
                    NULL,
                    &evp_ptext_size,
                    aead, aead_size);

  evp_ptext_size = 0;
  OFC_OFFT offset = 0;
  rc = 1;

  for (int i = 0 ; i < num_elem && rc > 0; i++)
    {
      /*
       * The tag verify occurs on the last decrypt update as per
       * https://wiki.openssl.org/
       */
      rc = EVP_DecryptUpdate(evp_cipher_ctx,
			     ptext+offset,
			     &evp_ptext_size,
			     addr[i],
			     len[i]);
      offset += evp_ptext_size;
    }

  if (rc <= 0)
    /*
     * verify failed
     */
    ret = OFC_FALSE;
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


