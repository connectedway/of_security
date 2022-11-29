/* Copyright (c) 2021 Connected Way, LLC. All rights reserved.
 * Use of this source code is governed by a Creative Commons 
 * Attribution-NoDerivatives 4.0 International license that can be
 * found in the LICENSE file.
 */

#include "ofc/types.h"
#include "ofc/libc.h"
#include "ofc/net_internal.h"

#if defined(OF_MBEDTLS)
#include "of_security/mbedtls_smb2.h"
#elif defined(OF_OPENSSL)
#include "of_security/openssl_smb2.h"
#elif defined(OF_GNUTLS)
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

struct of_security_signing_ctx *smb2_signing_ctx(OFC_UCHAR *session_key,
                                                 OFC_SIZET session_key_len)
{
#if defined(OF_MBEDTLS)
  return(mbedtls_smb2_signing_ctx(session_key, session_key_len));
#elif defined(OF_OPENSSL)
  return (openssl_smb2_signing_ctx(session_key, session_key_len));
#elif defined(OF_GNUTLS)
  return (gnutls_smb2_signing_ctx(session_key, session_key_len));
#endif
}

OFC_VOID smb2_sign_vector(struct of_security_signing_ctx *signing_ctx,
                          OFC_INT num_elem,
                          OFC_UINT8 **ptext_vec,
                          OFC_SIZET *ptext_size_vec,
                          OFC_UINT8 *digest, OFC_SIZET digest_len)
{
#if defined(OF_MBEDTLS)
  mbedtls_smb2_sign_vector(signing_ctx,
                           num_elem, ptext_vec, ptext_size_vec,
                           digest, digest_len);
#elif defined(OF_OPENSSL)
  openssl_smb2_sign_vector(signing_ctx,
                           num_elem, ptext_vec, ptext_size_vec,
                           digest, digest_len);
#elif defined(OF_GNUTLS)
  gnutls_smb2_sign_vector(signing_ctx,
                          num_elem, ptext_vec, ptext_size_vec,
                          digest, digest_len);
#endif
}

OFC_VOID smb2_sign(struct of_security_signing_ctx *signing_ctx,
                   OFC_UINT8 *ptext,
                   OFC_SIZET ptext_size,
                   OFC_UINT8 *digest, OFC_SIZET digest_len)
{
#if defined(OF_MBEDTLS)
  mbedtls_smb2_sign(signing_ctx, ptext, ptext_size, digest, digest_len);
#elif defined(OF_OPENSSL)
  openssl_smb2_sign(signing_ctx, ptext, ptext_size, digest, digest_len);
#elif defined(OF_GNUTLS)
  gnutls_smb2_sign(signing_ctx, ptext, ptext_size, digest, digest_len);
#endif
}

OFC_VOID smb2_signing_ctx_free(struct of_security_signing_ctx *signing_ctx)
{
#if defined(OF_MBEDTLS)
  mbedtls_smb2_signing_ctx_free(signing_ctx);
#elif defined(OF_OPENSSL)
  openssl_smb2_signing_ctx_free(signing_ctx);
#elif defined(OF_GNUTLS)
  gnutls_smb2_signing_ctx_free(signing_ctx);
#endif
}

struct of_security_cipher_ctx *smb2_encryption_ctx(OFC_UCHAR *session_key,
                                                   OFC_SIZET session_key_len)
{
#if defined(OF_MBEDTLS)
  return (mbedtls_smb2_encryption_ctx(session_key, session_key_len));
#elif defined(OF_OPENSSL)
  return (openssl_smb2_encryption_ctx(session_key, session_key_len));
#elif defined(OF_GNUTLS)
  return (gnutls_smb2_encryption_ctx(session_key, session_key_len));
#endif
}

OFC_VOID smb2_encrypt(struct of_security_cipher_ctx *cipher_ctx,
                      OFC_UCHAR *iv, OFC_SIZET iv_size,
                      OFC_UINT8 *aead, OFC_SIZET aead_size,
                      OFC_SIZET tag_size,
                      OFC_UINT8 *ptext, OFC_SIZET ptext_size,
                      OFC_UINT8 *ctext, OFC_SIZET ctext_size)
{
#if defined(OF_MBEDTLS)
  mbedtls_smb2_encrypt(cipher_ctx, iv, iv_size, aead, aead_size, tag_size,
                       ptext, ptext_size, ctext, ctext_size);
#elif defined(OF_OPENSSL)
  openssl_smb2_encrypt(cipher_ctx, iv, iv_size, aead, aead_size, tag_size,
                       ptext, ptext_size, ctext, ctext_size);
#elif defined(OF_GNUTLS)
  gnutls_smb2_encrypt(cipher_ctx, iv, iv_size, aead, aead_size, tag_size,
                      ptext, ptext_size, ctext, ctext_size);
#endif
}

OFC_VOID smb2_encrypt_vector(struct of_security_cipher_ctx *cipher_ctx,
                             OFC_UCHAR *iv, OFC_SIZET iv_size,
                             OFC_UINT8 *aead, OFC_SIZET aead_size,
                             OFC_SIZET tag_size,
                             OFC_INT num_elem,
                             OFC_UINT8 **addr, OFC_SIZET *len,
                             OFC_UINT8 *ctext, OFC_SIZET ctext_size)
{
#if defined(OF_MBEDTLS)
  mbedtls_smb2_encrypt_vector(cipher_ctx, iv, iv_size, aead, aead_size,
                              tag_size,
                              num_elem, addr, len,
                              ctext, ctext_size);
#elif defined(OF_OPENSSL)
  openssl_smb2_encrypt_vector(cipher_ctx, iv, iv_size, aead, aead_size,
                              tag_size,
                              num_elem, addr, len,
                              ctext, ctext_size);
#elif defined(OF_GNUTLS)
  gnutls_smb2_encrypt_vector(cipher_ctx, iv, iv_size, aead, aead_size,
                             tag_size,
                             num_elem, addr, len,
                             ctext, ctext_size);
#endif
}

OFC_VOID smb2_encryption_ctx_free(struct of_security_cipher_ctx *cipher_ctx)
{
#if defined(OF_MBEDTLS)
  mbedtls_smb2_encryption_ctx_free(cipher_ctx);
#elif defined(OF_OPENSSL)
  openssl_smb2_encryption_ctx_free(cipher_ctx);
#elif defined(OF_GNUTLS)
  gnutls_smb2_encryption_ctx_free(cipher_ctx);
#endif
}
  
struct of_security_cipher_ctx *smb2_decryption_ctx(OFC_UCHAR *session_key,
                                                   OFC_SIZET session_key_len)
{
#if defined(OF_MBEDTLS)
  return (mbedtls_smb2_decryption_ctx(session_key, session_key_len));
#elif defined(OF_OPENSSL)
  return (openssl_smb2_decryption_ctx(session_key, session_key_len));
#elif defined(OF_GNUTLS)
  return (gnutls_smb2_decryption_ctx(session_key, session_key_len));
#endif
}

OFC_VOID smb2_decrypt(struct of_security_cipher_ctx *cipher_ctx,
                      OFC_UCHAR *iv, OFC_SIZET iv_size,
                      OFC_UINT8 *aead, OFC_SIZET aead_size,
                      OFC_SIZET tag_size,
                      OFC_UINT8 *ctext, OFC_SIZET ctext_size,
                      OFC_UINT8 *ptext, OFC_SIZET ptext_size)
{
#if defined(OF_MBEDTLS)
  mbedtls_smb2_decrypt(cipher_ctx, iv, iv_size, aead, aead_size, tag_size,
                       ctext, ctext_size, ptext, ptext_size);
#elif defined(OF_OPENSSL)
  openssl_smb2_decrypt(cipher_ctx, iv, iv_size, aead, aead_size, tag_size,
                       ctext, ctext_size, ptext, ptext_size);
#elif defined(OF_GNUTLS)
  gnutls_smb2_decrypt(cipher_ctx, iv, iv_size, aead, aead_size, tag_size,
                      ctext, ctext_size, ptext, ptext_size);
#endif
}
  
OFC_VOID smb2_decrypt_vector(struct of_security_cipher_ctx *cipher_ctx,
                             OFC_UCHAR *iv, OFC_SIZET iv_size,
                             OFC_UINT8 *aead, OFC_SIZET aead_size,
                             OFC_UINT8 *tag, OFC_SIZET tag_size,
                             OFC_INT num_elem,
                             OFC_UCHAR **addr, OFC_SIZET *len,
                             OFC_UINT8 *ptext, OFC_SIZET ptext_size)
{
#if defined(OF_MBEDTLS)
  mbedtls_smb2_decrypt_vector(cipher_ctx, iv, iv_size, aead, aead_size,
                              tag, tag_size,
                              num_elem, addr, len,
                              ptext, ptext_size);
#elif defined(OF_OPENSSL)
  openssl_smb2_decrypt_vector(cipher_ctx, iv, iv_size, aead, aead_size,
                              tag, tag_size,
                              num_elem, addr, len,
                              ptext, ptext_size);
#elif defined(OF_GNUTLS)
  gnutls_smb2_decrypt_vector(cipher_ctx, iv, iv_size, aead, aead_size,
                             tag, tag_size,
                             num_elem, addr, len,
                             ptext, ptext_size);
#endif
}
  
OFC_VOID smb2_decryption_ctx_free(struct of_security_cipher_ctx *cipher_ctx)
{
#if defined(OF_MBEDTLS)
  mbedtls_smb2_decryption_ctx_free(cipher_ctx);
#elif defined(OF_OPENSSL)
  openssl_smb2_decryption_ctx_free(cipher_ctx);
#elif defined(OF_GNUTLS)
  gnutls_smb2_decryption_ctx_free(cipher_ctx);
#endif
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

