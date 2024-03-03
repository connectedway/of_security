/* Copyright (c) 2021 Connected Way, LLC. All rights reserved.
 * Use of this source code is governed by a Creative Commons 
 * Attribution-NoDerivatives 4.0 International license that can be
 * found in the LICENSE file.
 */

#include "ofc/types.h"
#include "ofc/heap.h"
#include "ofc/libc.h"
#include "ofc/net_internal.h"

#include "of_security/security_smb2.h"
#if defined(OF_MBEDTLS)
#include "of_security/mbedtls_smb2.h"
#endif
#if defined(OF_OPENSSL)
#include "of_security/openssl_smb2.h"
#endif
#if defined(OF_GNUTLS)
#include "of_security/gnutls_smb2.h"
#endif

OFC_VOID of_security_print_key(char *heading, OFC_UCHAR *key)
{
  ofc_printf("%s: "
             "0x%02x 0x%02x 0x%02x 0x%02x "
             "0x%02x 0x%02x 0x%02x 0x%02x "
             "0x%02x 0x%02x 0x%02x 0x%02x "
             "0x%02x 0x%02x 0x%02x 0x%02x\n",
             heading,
             key[0], key[1], key[2], key[3],
             key[4], key[5], key[6], key[7],
             key[8], key[9], key[10], key[11],
             key[12], key[13], key[14], key[15]);
}

/*
 * sha512_vector works inplace.  Implying that only one method
 * can be used.
 */
OFC_INT sha512_vector(OFC_SIZET num_elem, const OFC_UCHAR *addr[],
                      const OFC_SIZET *len, OFC_UCHAR *mac)
{
  OFC_INT ret;
#if 0
  OFC_UCHAR *mac_temp;
  mac_temp = ofc_malloc(SHA512_MAC_LEN);
#if defined(OF_MBEDTLS)
  ret = mbedtls_sha512_vector(num_elem, addr, len, mac_temp);
  of_security_print_key("mbedtls sha512: ", mac_temp);
#endif
#if defined(OF_OPENSSL)
  ret = openssl_sha512_vector(num_elem, addr, len, mac_temp);
  of_security_print_key("openssl sha512: ", mac_temp);
#endif
#if defined(OF_GNUTLS)
  ret = gnutls_sha512_vector(num_elem, addr, len, mac_temp);
  of_security_print_key("gnutls sha512: ", mac_temp);
#endif
  ofc_free(mac_temp);
#else
#if defined(OF_MBEDTLS)
  ret = mbedtls_sha512_vector(num_elem, addr, len, mac);
#elif defined(OF_OPENSSL)
  ret = openssl_sha512_vector(num_elem, addr, len, mac);
#elif defined(OF_GNUTLS)
  ret = gnutls_sha512_vector(num_elem, addr, len, mac);
#endif
#endif  
  return (ret);
}  

struct signing_ctx_wrapper
{
  struct of_security_signing_ctx *openssl;
  struct of_security_signing_ctx *mbedtls;
  struct of_security_signing_ctx *gnutls;
};

OFC_VOID *smb2_signing_ctx(OFC_UCHAR *session_key,
                           OFC_SIZET session_key_len,
                           OFC_UCHAR *label,
                           OFC_SIZET label_size,
                           OFC_UCHAR *context,
                           OFC_SIZET context_size)
{
  struct signing_ctx_wrapper *ctx;

  ctx = ofc_malloc(sizeof(struct signing_ctx_wrapper));

#if defined(OF_MBEDTLS)
  ctx->mbedtls = mbedtls_smb2_signing_ctx(session_key, session_key_len,
                                          label, label_size,
                                          context, context_size);
#endif
#if defined(OF_OPENSSL)
  ctx->openssl = openssl_smb2_signing_ctx(session_key, session_key_len,
                                          label, label_size,
                                          context, context_size);
#endif
#if defined(OF_GNUTLS)
  ctx->gnutls = gnutls_smb2_signing_ctx(session_key, session_key_len,
                                       label, label_size,
                                       context, context_size);
#endif
  return (ctx);
}

OFC_VOID smb2_sign_vector(OFC_VOID *signing_ctx,
                          OFC_INT num_elem,
                          OFC_UINT8 **ptext_vec,
                          OFC_SIZET *ptext_size_vec,
                          OFC_UINT8 *digest, OFC_SIZET digest_len)
{
  struct signing_ctx_wrapper *ctx = signing_ctx;

#if defined(OF_MBEDTLS)
  mbedtls_smb2_sign_vector(ctx->mbedtls,
                           num_elem, ptext_vec, ptext_size_vec,
                           digest, digest_len);
#endif
#if defined(OF_OPENSSL)
  openssl_smb2_sign_vector(ctx->openssl,
                           num_elem, ptext_vec, ptext_size_vec,
                           digest, digest_len);
#endif
#if defined(OF_GNUTLS)
  gnutls_smb2_sign_vector(ctx->openssl,
                          num_elem, ptext_vec, ptext_size_vec,
                          digest, digest_len);
#endif
}

OFC_VOID smb2_sign(OFC_VOID *signing_ctx,
                   OFC_UINT8 *ptext,
                   OFC_SIZET ptext_size,
                   OFC_UINT8 *digest, OFC_SIZET digest_len)
{
  struct signing_ctx_wrapper *ctx = signing_ctx;

#if defined(OF_MBEDTLS)
  mbedtls_smb2_sign(ctx->mbedtls, ptext, ptext_size, digest, digest_len);
#endif
#if defined(OF_OPENSSL)
  openssl_smb2_sign(ctx->openssl, ptext, ptext_size, digest, digest_len);
#endif
#if defined(OF_GNUTLS)
  gnutls_smb2_sign(ctx->gnutls, ptext, ptext_size, digest, digest_len);
#endif
}

OFC_VOID smb2_signing_ctx_free(OFC_VOID *signing_ctx)
{
  struct signing_ctx_wrapper *ctx = signing_ctx;

#if defined(OF_OPENSSL)
  openssl_smb2_signing_ctx_free(ctx->openssl);
#endif
#if defined(OF_GNUTLS)
  gnutls_smb2_signing_ctx_free(ctx->gnutls);
#endif
#if defined(OF_MBEDTLS)
  mbedtls_smb2_signing_ctx_free(ctx->mbedtls);
#endif
  ofc_free(ctx);
}

struct cipher_ctx_wrapper
{
  struct of_security_cipher_ctx *openssl;
  struct of_security_cipher_ctx *mbedtls;
  struct of_security_cipher_ctx *gnutls;
};

OFC_VOID *
smb2_encryption_ctx(OFC_UCHAR *session_key,
		    OFC_SIZET session_key_len,
		    OFC_UINT cipher_algo,
		    OFC_UCHAR *label,
                    OFC_SIZET label_size,
		    OFC_UCHAR *context,
                    OFC_SIZET context_size)
{
  struct cipher_ctx_wrapper *ctx =
    ofc_malloc(sizeof(struct cipher_ctx_wrapper));

#if defined(OF_OPENSSL)
  ctx->openssl = openssl_smb2_encryption_ctx(session_key, session_key_len,
                                             cipher_algo,
                                             label, label_size,
                                             context, context_size);
#endif
#if defined(OF_GNUTLS)
  ctx->gnutls = gnutls_smb2_encryption_ctx(session_key, session_key_len,
                                           cipher_algo,
                                           label, label_size,
                                           context, context_size);
#endif
#if defined(OF_MBEDTLS)
  ctx->mbedtls = mbedtls_smb2_encryption_ctx(session_key, session_key_len,
                                             cipher_algo,
                                             label, label_size,
                                             context, context_size);
#endif
  return (ctx);
}

OFC_VOID smb2_encrypt(OFC_VOID *cipher_ctx,
                      OFC_UCHAR *iv, OFC_SIZET iv_size,
                      OFC_UINT8 *aead, OFC_SIZET aead_size,
                      OFC_SIZET tag_size,
                      OFC_UINT8 *ptext, OFC_SIZET ptext_size,
                      OFC_UINT8 *ctext, OFC_SIZET ctext_size)
{
  struct cipher_ctx_wrapper *ctx = cipher_ctx;
#if defined(OF_OPENSSL)
  openssl_smb2_encrypt(ctx->openssl, iv, iv_size, aead, aead_size, tag_size,
                       ptext, ptext_size, ctext, ctext_size);
#endif
#if defined(OF_GNUTLS)
  gnutls_smb2_encrypt(ctx->gnutls, iv, iv_size, aead, aead_size, tag_size,
                      ptext, ptext_size, ctext, ctext_size);
#endif
#if defined(OF_MBEDTLS)
  mbedtls_smb2_encrypt(ctx->mbedtls, iv, iv_size, aead, aead_size, tag_size,
                       ptext, ptext_size, ctext, ctext_size);
#endif
}

OFC_VOID smb2_encrypt_vector(OFC_VOID *cipher_ctx,
                             OFC_UCHAR *iv, OFC_SIZET iv_size,
                             OFC_UINT8 *aead, OFC_SIZET aead_size,
                             OFC_SIZET tag_size,
                             OFC_INT num_elem,
                             OFC_UINT8 **addr, OFC_SIZET *len,
                             OFC_UINT8 *ctext, OFC_SIZET ctext_size)
{
  struct cipher_ctx_wrapper *ctx = cipher_ctx;
#if defined(OF_OPENSSL)
  openssl_smb2_encrypt_vector(ctx->openssl, iv, iv_size, aead, aead_size,
                              tag_size,
                              num_elem, addr, len,
                              ctext, ctext_size);
#endif
#if defined(OF_GNUTLS)
  gnutls_smb2_encrypt_vector(ctx->gnutls, iv, iv_size, aead, aead_size,
                             tag_size,
                             num_elem, addr, len,
                             ctext, ctext_size);
#endif
#if defined(OF_MBEDTLS)
  mbedtls_smb2_encrypt_vector(ctx->mbedtls, iv, iv_size, aead, aead_size,
                              tag_size,
                              num_elem, addr, len,
                              ctext, ctext_size);
#endif
}

OFC_VOID smb2_encryption_ctx_free(OFC_VOID *cipher_ctx)
{
  struct cipher_ctx_wrapper *ctx = cipher_ctx;

#if defined(OF_OPENSSL)
  openssl_smb2_encryption_ctx_free(ctx->openssl);
#endif
#if defined(OF_GNUTLS)
  gnutls_smb2_encryption_ctx_free(ctx->gnutls);
#endif
#if defined(OF_MBEDTLS)
  mbedtls_smb2_encryption_ctx_free(ctx->mbedtls);
#endif
  ofc_free(ctx);
}
  
OFC_VOID *
smb2_decryption_ctx(OFC_UCHAR *session_key,
		    OFC_SIZET session_key_len,
		    OFC_UINT cipher_algo,
		    OFC_UCHAR *label,
                    OFC_SIZET label_size,
		    OFC_UCHAR *context,
                    OFC_SIZET context_size)
{
  struct cipher_ctx_wrapper *ctx =
    ofc_malloc(sizeof(struct cipher_ctx_wrapper));
#if defined(OF_OPENSSL)
  ctx->openssl = openssl_smb2_decryption_ctx(session_key, session_key_len,
                                             cipher_algo,
                                             label, label_size,
                                             context, context_size);
#endif
#if defined(OF_GNUTLS)
  ctx->gnutls = gnutls_smb2_decryption_ctx(session_key, session_key_len,
                                             cipher_algo,
                                             label, label_size,
                                             context, context_size);
#endif
#if defined(OF_MBEDTLS)
  ctx->mbedtls = mbedtls_smb2_decryption_ctx(session_key, session_key_len,
                                             cipher_algo,
                                             label, label_size,
                                             context, context_size);
#endif
  return (ctx);
}

OFC_BOOL smb2_decrypt(OFC_VOID *cipher_ctx,
                      OFC_UCHAR *iv, OFC_SIZET iv_size,
                      OFC_UINT8 *aead, OFC_SIZET aead_size,
                      OFC_SIZET tag_size,
                      OFC_UINT8 *ctext, OFC_SIZET ctext_size,
                      OFC_UINT8 *ptext, OFC_SIZET ptext_size)
{
  struct cipher_ctx_wrapper *ctx = cipher_ctx;
  OFC_BOOL ret;

#if defined(OF_OPENSSL)
  ret = openssl_smb2_decrypt(ctx->openssl, iv, iv_size, aead, aead_size,
                             tag_size,
                             ctext, ctext_size, ptext, ptext_size);
#endif
#if defined(OF_GNUTLS)
  ret = gnutls_smb2_decrypt(ctx->gnutls, iv, iv_size, aead, aead_size,
                            tag_size,
                            ctext, ctext_size, ptext, ptext_size);
#endif
#if defined(OF_MBEDTLS)
  ret = mbedtls_smb2_decrypt(ctx->mbedtls, iv, iv_size, aead, aead_size,
                             tag_size,
                             ctext, ctext_size, ptext, ptext_size);
#endif
  return (ret);
}
  
OFC_BOOL smb2_decrypt_vector(OFC_VOID *cipher_ctx,
                             OFC_UCHAR *iv, OFC_SIZET iv_size,
                             OFC_UINT8 *aead, OFC_SIZET aead_size,
                             OFC_UINT8 *tag, OFC_SIZET tag_size,
                             OFC_INT num_elem,
                             OFC_UCHAR **addr, OFC_SIZET *len,
                             OFC_UINT8 *ptext, OFC_SIZET ptext_size)
{
  struct cipher_ctx_wrapper *ctx = cipher_ctx;
  OFC_BOOL ret;

#if defined(OF_OPENSSL)
  ret = openssl_smb2_decrypt_vector(ctx->openssl, iv, iv_size, aead, aead_size,
                                    tag, tag_size,
                                    num_elem, addr, len,
                                    ptext, ptext_size);
#endif
#if defined(OF_GNUTLS)
  ret = gnutls_smb2_decrypt_vector(ctx->gnutls, iv, iv_size, aead, aead_size,
                                   tag, tag_size,
                                   num_elem, addr, len,
                                   ptext, ptext_size);
#endif
#if defined(OF_MBEDTLS)
  ret = mbedtls_smb2_decrypt_vector(ctx->mbedtls, iv, iv_size, aead, aead_size,
                                    tag, tag_size,
                                    num_elem, addr, len,
                                    ptext, ptext_size);
#endif
  return (ret);
}
  
OFC_VOID smb2_decryption_ctx_free(OFC_VOID *cipher_ctx)
{
  struct cipher_ctx_wrapper *ctx = cipher_ctx;

#if defined(OF_OPENSSL)
  openssl_smb2_decryption_ctx_free(ctx->openssl);
#endif
#if defined(OF_GNUTLS)
  gnutls_smb2_decryption_ctx_free(ctx->gnutls);
#endif
#if defined(OF_MBEDTLS)
  mbedtls_smb2_decryption_ctx_free(ctx->mbedtls);
#endif
  ofc_free(ctx);
}

OFC_VOID smb2_rand_bytes(OFC_UCHAR *output, OFC_SIZET output_size)
{
#if defined(OF_MBEDTLS)
  mbedtls_smb2_rand_bytes(output, output_size);
#elif defined(OF_OPENSSL)
  openssl_smb2_rand_bytes(output, output_size);
#elif defined(OF_GNUTLS)
  gnutls_smb2_rand_bytes(output, output_size);
#endif
}

