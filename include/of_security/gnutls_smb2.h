
#if !defined(__OF_GNUTLS__)
#define __OF_GNUTLS__

#if defined(OF_GNUTLS)

#if defined(__cplusplus)
extern "C"
{
#endif
  struct of_security_signing_ctx *
  gnutls_smb2_signing_ctx(OFC_UCHAR *session_key,
                          OFC_SIZET session_key_len);

  OFC_VOID gnutls_smb2_sign(struct of_security_signing_ctx *signing_ctx,
                            OFC_UINT8 *ptext,
                            OFC_SIZET ptext_size,
                            OFC_UINT8 *digest, OFC_SIZET digest_len);

  OFC_VOID
  gnutls_smb2_signing_ctx_free(struct of_security_signing_ctx *signing_ctx);

  struct of_security_cipher_ctx *
  gnutls_smb2_encryption_ctx(OFC_UCHAR *session_key,
                             OFC_SIZET session_key_len);

  OFC_VOID
  gnutls_smb2_encrypt(struct of_security_cipher_ctx *cipher_ctx,
                      OFC_UCHAR *iv, OFC_SIZET iv_size,
                       OFC_UINT8 *aead, OFC_SIZET aead_size,
                       OFC_SIZET tag_size,
                       OFC_UINT8 *ptext, OFC_SIZET ptext_size,
                       OFC_UINT8 *ctext, OFC_SIZET ctext_size);

  OFC_VOID
  gnutls_smb2_encryption_ctx_free(struct of_security_cipher_ctx *cipher_ctx);

  struct of_security_cipher_ctx *
  gnutls_smb2_decryption_ctx(OFC_UCHAR *session_key,
                             OFC_SIZET session_key_len);

  OFC_VOID gnutls_smb2_decrypt(struct of_security_cipher_ctx *cipher_ctx,
                               OFC_UCHAR *iv, OFC_SIZET iv_size,
                               OFC_UINT8 *aead, OFC_SIZET aead_size,
                               OFC_SIZET tag_size,
                               OFC_UINT8 *ctext, OFC_SIZET ctext_size,
                               OFC_UINT8 *ptext, OFC_SIZET ptext_size);

  OFC_VOID
  gnutls_smb2_decryption_ctx_free(struct of_security_cipher_ctx *cipher_ctx);

  OFC_VOID gnutls_smb2_rand_bytes(OFC_UCHAR *output, OFC_SIZET output_size);
#if defined(__cplusplus)
}
#endif

#endif
#endif