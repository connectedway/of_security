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
#include "of_security/mbedtls_smb2.h"

#include <mbedtls/md.h>
#include <mbedtls/cmac.h>
#include <mbedtls/cipher.h>
#include <mbedtls/error.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ccm.h>
#include <mbedtls/gcm.h>
#include <mbedtls/sha512.h>

#if defined(__linux__)
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#endif

OFC_INT mbedtls_sha512_vector(OFC_SIZET num_elem, const OFC_UCHAR *addr[],
                              const OFC_SIZET *len, OFC_UCHAR *mac)
{
  mbedtls_sha512_context ctx;
    
  mbedtls_sha512_init(&ctx);

#if 0
  mbedtls_sha512_starts_ret(&ctx, 0);
#else
  mbedtls_sha512_starts(&ctx, 0);
#endif

  for (OFC_INT i = 0 ; i < num_elem ; i++)
    {
#if 0
      mbedtls_sha512_update_ret(&ctx, addr[i], len[i]);
#else
      mbedtls_sha512_update(&ctx, addr[i], len[i]);
#endif
    }
#if 0
  mbedtls_sha512_finish_ret(&ctx, mac);
#else
  mbedtls_sha512_finish(&ctx, mac);
#endif
  return (0);
}

struct of_security_signing_ctx *
mbedtls_smb2_signing_ctx(OFC_UCHAR *session_key,
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
  const OFC_SIZET digest_len = 32;
  OFC_UINT8 digest[digest_len];
  const OFC_ULONG signing_key_len = 16;
  mbedtls_md_context_t mbedtls_ctx;

  int rc;

  signing_ctx = ofc_malloc(sizeof (struct of_security_signing_ctx));

  OFC_NET_LTON(&one, 0, 1);
  OFC_NET_LTON(&len, 0, (signing_key_len * 8));

  mbedtls_md_init(&mbedtls_ctx);
  mbedtls_md_setup(&mbedtls_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                   1);
  mbedtls_md_hmac_starts(&mbedtls_ctx, (const unsigned char *) session_key,
                         session_key_len);

  mbedtls_md_hmac_update(&mbedtls_ctx, (const unsigned char *) &one,
                         sizeof(one));
  mbedtls_md_hmac_update(&mbedtls_ctx, 
                         (const unsigned char *) label, label_size);
  mbedtls_md_hmac_update(&mbedtls_ctx, 
                         (const unsigned char *) &zero, 1);
  mbedtls_md_hmac_update(&mbedtls_ctx, 
                         (const unsigned char *) context, context_size);
  mbedtls_md_hmac_update(&mbedtls_ctx,
                         (const unsigned char *) &len, sizeof(len));
  mbedtls_md_hmac_finish(&mbedtls_ctx, digest);
  mbedtls_md_free(&mbedtls_ctx);

  signing_ctx->keylen = OFC_MIN(signing_key_len, digest_len);
  ofc_memcpy(signing_ctx->key, digest, signing_ctx->keylen);
    
#if defined(KEY_DEBUG)
  of_security_print_key("mbedtls Signing Key: ", signing_ctx->key);
#endif

  mbedtls_cipher_context_t *mbedtls_cipher_ctx;
  mbedtls_cipher_ctx = ofc_malloc(sizeof(mbedtls_cipher_context_t));
  
  mbedtls_cipher_init (mbedtls_cipher_ctx);

  rc = mbedtls_cipher_setup(mbedtls_cipher_ctx,
                            mbedtls_cipher_info_from_string("AES-128-ECB"));
  if (rc != 0)
    ofc_log(OFC_LOG_WARN, mbedtls_high_level_strerr(rc));

  rc = mbedtls_cipher_cmac_starts(mbedtls_cipher_ctx,
                             (const unsigned char *) signing_ctx->key,
                                  signing_ctx->keylen * 8);
  if (rc != 0)
    ofc_log(OFC_LOG_WARN, mbedtls_high_level_strerr(rc));

  rc = mbedtls_cipher_cmac_reset(mbedtls_cipher_ctx);
  if (rc != 0)
    ofc_log(OFC_LOG_WARN, mbedtls_high_level_strerr(rc));

  signing_ctx->impl_signing_ctx = mbedtls_cipher_ctx;

  return (signing_ctx);
}

OFC_VOID
mbedtls_smb2_sign_vector(struct of_security_signing_ctx *signing_ctx,
                         OFC_INT num_elem,
                         OFC_UINT8 **ptext_vec,
                         OFC_SIZET *ptext_size_vec,
                         OFC_UINT8 *digest, OFC_SIZET digest_len)
{
  mbedtls_cipher_context_t *mbedtls_cipher_ctx =
    signing_ctx->impl_signing_ctx;
  OFC_UINT8 mac[16];
  int rc;
  int i;

  rc = mbedtls_cipher_cmac_reset(mbedtls_cipher_ctx);
  if (rc != 0)
    ofc_log(OFC_LOG_WARN, mbedtls_high_level_strerr(rc));

  for (i = 0 ; i < num_elem && rc == 0; i++)
    {
      rc = mbedtls_cipher_cmac_update(mbedtls_cipher_ctx,
                                      ptext_vec[i], ptext_size_vec[i]);
    }

  if (rc != 0)
    ofc_log(OFC_LOG_WARN, mbedtls_high_level_strerr(rc));
  rc = mbedtls_cipher_cmac_finish(mbedtls_cipher_ctx, mac);
  if (rc != 0)
    ofc_log(OFC_LOG_WARN, mbedtls_high_level_strerr(rc));
#if defined(KEY_DEBUG)
  of_security_print_key("mbedtls sign: ", mac);
#endif
  ofc_memcpy(digest, mac, digest_len);
}

OFC_VOID mbedtls_smb2_sign(struct of_security_signing_ctx *signing_ctx,
                           OFC_UINT8 *ptext,
                           OFC_SIZET ptext_size,
                           OFC_UINT8 *digest, OFC_SIZET digest_len)
{
  mbedtls_cipher_context_t *mbedtls_cipher_ctx =
    signing_ctx->impl_signing_ctx;
  OFC_UINT8 mac[16];
  int rc;

  rc = mbedtls_cipher_cmac_reset(mbedtls_cipher_ctx);
  if (rc != 0)
    ofc_log(OFC_LOG_WARN, mbedtls_high_level_strerr(rc));

  rc = mbedtls_cipher_cmac_update(mbedtls_cipher_ctx, ptext, ptext_size);
  if (rc != 0)
    ofc_log(OFC_LOG_WARN, mbedtls_high_level_strerr(rc));
  rc = mbedtls_cipher_cmac_finish(mbedtls_cipher_ctx, mac);
  if (rc != 0)
    ofc_log(OFC_LOG_WARN, mbedtls_high_level_strerr(rc));
#if defined(KEY_DEBUG)
  of_security_print_key("mbedtls sign: ", mac);
#endif
  ofc_memcpy(digest, mac, digest_len);
}

OFC_VOID
mbedtls_smb2_signing_ctx_free(struct of_security_signing_ctx *signing_ctx)
{
  mbedtls_cipher_context_t *mbedtls_cipher_ctx =
    signing_ctx->impl_signing_ctx;
  
  mbedtls_cipher_free(mbedtls_cipher_ctx);
  ofc_free(mbedtls_cipher_ctx);
  ofc_free(signing_ctx);
}

struct of_security_cipher_ctx *
mbedtls_smb2_encryption_ctx(OFC_UCHAR *session_key, OFC_SIZET session_key_len,
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

  mbedtls_md_context_t mbedtls_ctx;

  const OFC_SIZET digest_len = 32;
  OFC_UINT8 digest[digest_len];
  int rc;

  cipher_ctx = ofc_malloc(sizeof(struct of_security_cipher_ctx));

  cipher_ctx->cipher_algo = cipher_algo;

  cipher_ctx->keylen = OFC_MIN(digest_len, 16);

  OFC_NET_LTON(&one, 0, 1);
  OFC_NET_LTON(&len, 0, (cipher_ctx->keylen * 8));

  mbedtls_md_init(&mbedtls_ctx);
  mbedtls_md_setup(&mbedtls_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                   1);
  mbedtls_md_hmac_starts(&mbedtls_ctx, (const unsigned char *) session_key,
                         session_key_len);

  mbedtls_md_hmac_update(&mbedtls_ctx, (const unsigned char *) &one,
                         sizeof(one));
  mbedtls_md_hmac_update(&mbedtls_ctx, 
                         (const unsigned char *) label, label_size);
  mbedtls_md_hmac_update(&mbedtls_ctx, 
                         (const unsigned char *) &zero, 1);
  mbedtls_md_hmac_update(&mbedtls_ctx, 
                         (const unsigned char *) context, context_size);
  mbedtls_md_hmac_update(&mbedtls_ctx,
                         (const unsigned char *) &len, sizeof(len));
  mbedtls_md_hmac_finish(&mbedtls_ctx, digest);
  mbedtls_md_free(&mbedtls_ctx);
                                    
  ofc_memcpy(cipher_ctx->key,
             digest,
             cipher_ctx->keylen);

#if defined(KEY_DEBUG)
  of_security_print_key("mbedtls Encryption Key: ", cipher_ctx->key);
#endif

  if (cipher_ctx->cipher_algo == SMB2_AES_128_CCM)
    {
      mbedtls_ccm_context *mbedtls_ccm_ctx;
      mbedtls_ccm_ctx = ofc_malloc(sizeof(mbedtls_ccm_context));
  
      mbedtls_ccm_init(mbedtls_ccm_ctx);
      mbedtls_ccm_setkey(mbedtls_ccm_ctx, MBEDTLS_CIPHER_ID_AES,
                         (const unsigned char *) cipher_ctx->key,
                         cipher_ctx->keylen * 8);

      cipher_ctx->impl_cipher_ctx = mbedtls_ccm_ctx;
    }
  else
    {
      mbedtls_gcm_context *mbedtls_gcm_ctx;
      mbedtls_gcm_ctx = ofc_malloc(sizeof(mbedtls_gcm_context));
  
      mbedtls_gcm_init(mbedtls_gcm_ctx);
      mbedtls_gcm_setkey(mbedtls_gcm_ctx, MBEDTLS_CIPHER_ID_AES,
                         (const unsigned char *) cipher_ctx->key,
                         cipher_ctx->keylen * 8);

      cipher_ctx->impl_cipher_ctx = mbedtls_gcm_ctx;
    }
  return (cipher_ctx);
}

OFC_VOID
mbedtls_smb2_encrypt(struct of_security_cipher_ctx *cipher_ctx,
                     OFC_UCHAR *iv, OFC_SIZET iv_size,
                     OFC_UINT8 *aead, OFC_SIZET aead_size,
                     OFC_SIZET tag_size,
                     OFC_UINT8 *ptext, OFC_SIZET ptext_size,
                     OFC_UINT8 *ctext, OFC_SIZET ctext_size)
{
  size_t outlen = 0;
  if (cipher_ctx->cipher_algo == SMB2_AES_128_CCM)
    {
      mbedtls_ccm_context *mbedtls_ccm_ctx;
  
      mbedtls_ccm_ctx = cipher_ctx->impl_cipher_ctx;
      mbedtls_ccm_starts(mbedtls_ccm_ctx, MBEDTLS_CCM_ENCRYPT, iv, iv_size);
      mbedtls_ccm_set_lengths(mbedtls_ccm_ctx, aead_size, ptext_size, tag_size);
      mbedtls_ccm_update_ad(mbedtls_ccm_ctx, aead, aead_size);

      mbedtls_ccm_update(mbedtls_ccm_ctx, ptext, ptext_size,
                         ctext+outlen, ptext_size, &outlen);

      mbedtls_ccm_finish(mbedtls_ccm_ctx, ctext+outlen, tag_size);
    }
  else
    {
      mbedtls_gcm_context *mbedtls_gcm_ctx;
  
      mbedtls_gcm_ctx = cipher_ctx->impl_cipher_ctx;
      mbedtls_gcm_starts(mbedtls_gcm_ctx, MBEDTLS_GCM_ENCRYPT, iv, iv_size);
      mbedtls_gcm_update_ad(mbedtls_gcm_ctx, aead, aead_size);

      mbedtls_gcm_update(mbedtls_gcm_ctx, ptext, ptext_size,
                         ctext+outlen, ptext_size, &outlen);

      mbedtls_gcm_finish(mbedtls_gcm_ctx, 
                         ctext+outlen, ptext_size-outlen,
                         &outlen,
                         ctext+ptext_size, tag_size);
    }

#if defined(KEY_DEBUG)
  of_security_print_key("mbedtls encrypt signature:",
                        ctext + ptext_size);
#endif
}

OFC_VOID
mbedtls_smb2_encrypt_vector(struct of_security_cipher_ctx *cipher_ctx,
                            OFC_UCHAR *iv, OFC_SIZET iv_size,
                            OFC_UINT8 *aead, OFC_SIZET aead_size,
                            OFC_SIZET tag_size,
                            OFC_INT num_elem,
                            OFC_UCHAR **addr, OFC_SIZET *len,
                            OFC_UINT8 *ctext, OFC_SIZET ctext_size)
{
  size_t mbedtls_ctext_size = ctext_size;
  size_t inlen = 0;
  size_t outlen;
  int rc;
  
  if (cipher_ctx->cipher_algo == SMB2_AES_128_CCM)
    {
      mbedtls_ccm_context *mbedtls_ccm_ctx;
      mbedtls_ccm_ctx = cipher_ctx->impl_cipher_ctx;
      /*
       * Get size of input
       */
      for (int i = 0 ; i < num_elem; i++)
        {
          inlen += len[i];
        }

      rc = mbedtls_ccm_starts(mbedtls_ccm_ctx, MBEDTLS_CCM_ENCRYPT, iv, iv_size);
      rc = mbedtls_ccm_set_lengths(mbedtls_ccm_ctx, aead_size, inlen, tag_size);
      rc = mbedtls_ccm_update_ad(mbedtls_ccm_ctx, aead, aead_size);

      outlen = 0;
      OFC_OFFT offset = outlen;
      for (int i = 0 ; i < num_elem; i++)
        {
          rc = mbedtls_ccm_update(mbedtls_ccm_ctx, addr[i], len[i],
                                  ctext+offset, len[i], &outlen);
          offset += outlen;
        }
      rc = mbedtls_ccm_finish(mbedtls_ccm_ctx, ctext+offset, tag_size);
    }
  else
    {
      mbedtls_gcm_context *mbedtls_gcm_ctx;
      mbedtls_gcm_ctx = cipher_ctx->impl_cipher_ctx;
      /*
       * Get size of input
       */
      for (int i = 0 ; i < num_elem; i++)
        {
          inlen += len[i];
        }

      rc = mbedtls_gcm_starts(mbedtls_gcm_ctx, MBEDTLS_GCM_ENCRYPT, iv, iv_size);
      rc = mbedtls_gcm_update_ad(mbedtls_gcm_ctx, aead, aead_size);

      outlen = 0;
      OFC_OFFT offset = outlen;
      for (int i = 0 ; i < num_elem; i++)
        {
          rc = mbedtls_gcm_update(mbedtls_gcm_ctx, addr[i], len[i],
                                  ctext+offset, len[i], &outlen);
          offset += outlen;
        }

      rc = mbedtls_gcm_finish(mbedtls_gcm_ctx, 
                              ctext+offset, ctext_size-offset,
                              &outlen,
                              ctext+inlen, tag_size);
    }

#if defined(KEY_DEBUG)
  of_security_print_key("mbedtls encrypt vector signature:",
                        ctext + inlen);
#endif
}

OFC_VOID
mbedtls_smb2_encryption_ctx_free(struct of_security_cipher_ctx *cipher_ctx)
{

  if (cipher_ctx->cipher_algo == SMB2_AES_128_CCM)
    {
      mbedtls_ccm_context *mbedtls_ccm_ctx =
        cipher_ctx->impl_cipher_ctx;

      mbedtls_ccm_free(mbedtls_ccm_ctx);
      ofc_free(mbedtls_ccm_ctx);
    }
  else
    {
      mbedtls_gcm_context *mbedtls_gcm_ctx =
        cipher_ctx->impl_cipher_ctx;

      mbedtls_gcm_free(mbedtls_gcm_ctx);
      ofc_free(mbedtls_gcm_ctx);
    }

  ofc_free(cipher_ctx);
}
  
struct of_security_cipher_ctx *
mbedtls_smb2_decryption_ctx(OFC_UCHAR *session_key,
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

  mbedtls_md_context_t mbedtls_ctx;
  const OFC_SIZET digest_len = 32;
  OFC_UINT8 digest[digest_len];
  int rc;

  cipher_ctx = ofc_malloc(sizeof(struct of_security_cipher_ctx));

  cipher_ctx->cipher_algo = cipher_algo;

  cipher_ctx->keylen = OFC_MIN(digest_len, 16);

  OFC_NET_LTON(&one, 0, 1);
  OFC_NET_LTON(&len, 0, (cipher_ctx->keylen * 8));

  mbedtls_md_init(&mbedtls_ctx);
  mbedtls_md_setup(&mbedtls_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                   1);
  mbedtls_md_hmac_starts(&mbedtls_ctx, (const unsigned char *) session_key,
                         session_key_len);

  mbedtls_md_hmac_update(&mbedtls_ctx, (const unsigned char *) &one,
                         sizeof(one));
  mbedtls_md_hmac_update(&mbedtls_ctx, 
                         (const unsigned char *) label, label_size);
  mbedtls_md_hmac_update(&mbedtls_ctx, 
                         (const unsigned char *) &zero, 1);
  mbedtls_md_hmac_update(&mbedtls_ctx, 
                         (const unsigned char *) context, context_size);
  mbedtls_md_hmac_update(&mbedtls_ctx,
                         (const unsigned char *) &len, sizeof(len));
                                    
  mbedtls_md_hmac_finish(&mbedtls_ctx, digest);
  mbedtls_md_free(&mbedtls_ctx);

  ofc_memcpy(cipher_ctx->key,
             digest,
             cipher_ctx->keylen);

#if defined(KEY_DEBUG)
  of_security_print_key("mbedtls Decryption Key: ", cipher_ctx->key);
#endif

  if (cipher_ctx->cipher_algo == SMB2_AES_128_CCM)
    {
      mbedtls_ccm_context *mbedtls_ccm_ctx;
      mbedtls_ccm_ctx = ofc_malloc(sizeof(mbedtls_ccm_context));
  
      mbedtls_ccm_init (mbedtls_ccm_ctx);
      mbedtls_ccm_setkey (mbedtls_ccm_ctx, MBEDTLS_CIPHER_ID_AES,
                          (const unsigned char *) cipher_ctx->key,
                          cipher_ctx->keylen * 8);

      cipher_ctx->impl_cipher_ctx = mbedtls_ccm_ctx;
    }
  else
    {
      mbedtls_gcm_context *mbedtls_gcm_ctx;
      mbedtls_gcm_ctx = ofc_malloc(sizeof(mbedtls_gcm_context));
  
      mbedtls_gcm_init (mbedtls_gcm_ctx);
      mbedtls_gcm_setkey (mbedtls_gcm_ctx, MBEDTLS_CIPHER_ID_AES,
                          (const unsigned char *) cipher_ctx->key,
                          cipher_ctx->keylen * 8);

      cipher_ctx->impl_cipher_ctx = mbedtls_gcm_ctx;
    }
  return (cipher_ctx);
}

OFC_BOOL mbedtls_smb2_decrypt(struct of_security_cipher_ctx *cipher_ctx,
                              OFC_UCHAR *iv, OFC_SIZET iv_size,
                              OFC_UINT8 *aead, OFC_SIZET aead_size,
                              OFC_SIZET tag_size,
                              OFC_UINT8 *ctext, OFC_SIZET ctext_size,
                              OFC_UINT8 *ptext, OFC_SIZET ptext_size)
{
  size_t outlen = 0;
  OFC_UINT8 tag[16];
  size_t inlen = ctext_size - tag_size;
  OFC_BOOL ret = OFC_TRUE;

  if (cipher_ctx->cipher_algo == SMB2_AES_128_CCM)
    {
      mbedtls_ccm_context *mbedtls_ccm_ctx;
      mbedtls_ccm_ctx = cipher_ctx->impl_cipher_ctx;

      mbedtls_ccm_starts(mbedtls_ccm_ctx, MBEDTLS_CCM_DECRYPT, iv, iv_size);
      mbedtls_ccm_set_lengths(mbedtls_ccm_ctx, aead_size, inlen, tag_size);
      mbedtls_ccm_update_ad(mbedtls_ccm_ctx, aead, aead_size);

      mbedtls_ccm_update(mbedtls_ccm_ctx, ctext, inlen,
                         ptext+outlen, ptext_size, &outlen);
      mbedtls_ccm_finish(mbedtls_ccm_ctx, tag, tag_size);
    }
  else
    {
      mbedtls_gcm_context *mbedtls_gcm_ctx;
      mbedtls_gcm_ctx = cipher_ctx->impl_cipher_ctx;

      mbedtls_gcm_starts(mbedtls_gcm_ctx, MBEDTLS_GCM_DECRYPT, iv, iv_size);
      mbedtls_gcm_update_ad(mbedtls_gcm_ctx, aead, aead_size);

      mbedtls_gcm_update(mbedtls_gcm_ctx, ctext, inlen,
                         ptext+outlen, ptext_size, &outlen);

      mbedtls_gcm_finish(mbedtls_gcm_ctx, 
                         ptext+outlen, ptext_size-outlen,
                         &outlen,
                         tag, tag_size);
    }

#if defined(KEY_DEBUG)
  of_security_print_key("mbedtls decrypt signature:",
                        tag);
#endif
  if (ofc_memcmp(ctext+inlen, tag, 16) != 0)
    ret = OFC_FALSE;
  return (ret);
}
  
OFC_BOOL
mbedtls_smb2_decrypt_vector(struct of_security_cipher_ctx *cipher_ctx,
                            OFC_UCHAR *iv, OFC_SIZET iv_size,
                            OFC_UINT8 *aead, OFC_SIZET aead_size,
                            OFC_UINT8 *tag, OFC_SIZET tag_size,
                            OFC_INT num_elem,
                            OFC_UCHAR **addr, OFC_SIZET *len,
                            OFC_UINT8 *ptext, OFC_SIZET ptext_size)
{
  size_t inlen = 0;
  size_t outlen = 0;
  OFC_UINT8 tag_check[16];
  OFC_BOOL ret = OFC_TRUE;

  if (cipher_ctx->cipher_algo == SMB2_AES_128_CCM)
    {
      mbedtls_ccm_context *mbedtls_ccm_ctx;
      mbedtls_ccm_ctx = cipher_ctx->impl_cipher_ctx;

      /*
       * Get size of input
       */
      for (int i = 0 ; i < num_elem; i++)
        {
          inlen += len[i];
        }

      mbedtls_ccm_starts(mbedtls_ccm_ctx, MBEDTLS_CCM_DECRYPT, iv, iv_size);

      mbedtls_ccm_set_lengths(mbedtls_ccm_ctx, aead_size, inlen, tag_size);
      mbedtls_ccm_update_ad(mbedtls_ccm_ctx, aead, aead_size);
      for (int i = 0 ; i < num_elem; i++)
        {
          mbedtls_ccm_update(mbedtls_ccm_ctx, addr[i], len[i],
                             ptext+outlen, len[i], &outlen);
        }
      mbedtls_ccm_finish(mbedtls_ccm_ctx, tag_check, tag_size);
    }
  else
    {
      mbedtls_gcm_context *mbedtls_gcm_ctx;
      mbedtls_gcm_ctx = cipher_ctx->impl_cipher_ctx;

      /*
       * Get size of input
       */
      for (int i = 0 ; i < num_elem; i++)
        {
          inlen += len[i];
        }

      mbedtls_gcm_starts(mbedtls_gcm_ctx, MBEDTLS_GCM_DECRYPT, iv, iv_size);

      mbedtls_gcm_update_ad(mbedtls_gcm_ctx, aead, aead_size);
      for (int i = 0 ; i < num_elem; i++)
        {
          mbedtls_gcm_update(mbedtls_gcm_ctx, addr[i], len[i],
                             ptext+outlen, len[i], &outlen);
        }

      mbedtls_gcm_finish(mbedtls_gcm_ctx, 
                         ptext+outlen, ptext_size-outlen,
                         &outlen,
                         tag_check, tag_size);
    }
    
#if defined(KEY_DEBUG)
  of_security_print_key("mbedtls decrypt vector signature:",
                        tag_check);
#endif
  if (ofc_memcmp(tag_check, tag, 16) != 0)
    ret = OFC_FALSE;
  return (ret);
}

OFC_VOID
mbedtls_smb2_decryption_ctx_free(struct of_security_cipher_ctx *cipher_ctx)
{
  if (cipher_ctx->cipher_algo == SMB2_AES_128_CCM)
    {
      mbedtls_ccm_context *mbedtls_ccm_ctx =
        cipher_ctx->impl_cipher_ctx;

      mbedtls_ccm_free(mbedtls_ccm_ctx);
      ofc_free(mbedtls_ccm_ctx);
    }
  else
    {
      mbedtls_gcm_context *mbedtls_gcm_ctx =
        cipher_ctx->impl_cipher_ctx;

      mbedtls_gcm_free(mbedtls_gcm_ctx);
      ofc_free(mbedtls_gcm_ctx);
    }
    
  ofc_free(cipher_ctx);
}


/*
 * Workaround for qemuarm64
 * qemu arm has bug in it and will hang when trying to get random
 */
int my_mbedtls_entropy_func(void *data, unsigned char *output, size_t len)
{
  int ret = 0;
#if defined(__linux__)
  char name[64];

  if (gethostname(name, sizeof(name)) != 0)
    ret = MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
  else
    {
      if (ofc_strncmp(name, "qemuarm64", strlen("qemuarm64")) == 0)
	{
	  FILE *file;
	  size_t read_len;

	  file = fopen( "/dev/urandom", "rb" );
	  if( file == NULL )
	    {
	      ret = MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
	    }
	  else
	    {
	      /* Ensure no stdio buffering of secrets, 
	       * as such buffers cannot be wiped. */
	      read_len = fread( output, 1, len, file );
	      if( read_len != len )
		ret = MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
	      fclose( file );
	    }
	}
      else
	{
	  ret = mbedtls_entropy_func(data, output, len);
	}
    }
#else
  ret = mbedtls_entropy_func(data, output, len);
#endif
  return (ret);
}

OFC_VOID mbedtls_smb2_rand_bytes(OFC_UCHAR *output, OFC_SIZET output_size)
{
  static OFC_BOOL rng_init = OFC_FALSE;
  static mbedtls_entropy_context entropy;
  static mbedtls_ctr_drbg_context ctr_drbg;
  static char *personalization = "openfiles";

  if (rng_init == OFC_FALSE)
    {
      rng_init = OFC_TRUE;
      mbedtls_entropy_init(&entropy);
      mbedtls_ctr_drbg_init (&ctr_drbg);
      mbedtls_ctr_drbg_seed(&ctr_drbg, my_mbedtls_entropy_func, &entropy,
                            (const unsigned char *) personalization,
                            ofc_strlen(personalization));
    }

  mbedtls_ctr_drbg_random(&ctr_drbg, output, output_size);
}

