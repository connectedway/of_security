#if !defined(__SECURITY_SMB_H__)
#define __SECURITY_SMB_H__

#define SMB2_KEY_LENGTH 16

struct of_security_cipher_ctx
{
  OFC_VOID *impl_cipher_ctx;
  OFC_UINT8 key[SMB2_KEY_LENGTH];
  OFC_SIZET keylen;
};

struct of_security_signing_ctx
{
  OFC_VOID *impl_signing_ctx;
  OFC_UINT8 key[SMB2_KEY_LENGTH];
  OFC_SIZET keylen;
};

#if defined(__cplusplus)
extern "C"
{
#endif
  struct of_security_signing_ctx *smb2_signing_ctx(OFC_UCHAR *session_key,
                                                   OFC_SIZET session_key_len);

  OFC_VOID smb2_sign(struct of_security_signing_ctx *signing_ctx,
                     OFC_UINT8 *ptext,
                     OFC_SIZET ptext_size,
                     OFC_UINT8 *digest, OFC_SIZET digest_len);

  OFC_VOID smb2_sign_vector(struct of_security_signing_ctx *signing_ctx,
                            OFC_INT num_elem,
                            OFC_UINT8 **ptext_vec,
                            OFC_SIZET *ptext_size_vec,
                            OFC_UINT8 *digest, OFC_SIZET digest_len);

  OFC_VOID smb2_signing_ctx_free(struct of_security_signing_ctx *signing_ctx);

  struct of_security_cipher_ctx *
  smb2_encryption_ctx(OFC_UCHAR *session_key,
                      OFC_SIZET session_key_len);

  OFC_VOID smb2_encrypt(struct of_security_cipher_ctx *cipher_ctx,
                        OFC_UCHAR *iv, OFC_SIZET iv_size,
                        OFC_UINT8 *aead, OFC_SIZET aead_size,
                        OFC_SIZET tag_size,
                        OFC_UINT8 *ptext, OFC_SIZET ptext_size,
                        OFC_UINT8 *ctext, OFC_SIZET ctext_size);

  OFC_VOID smb2_encrypt_vector(struct of_security_cipher_ctx *cipher_ctx,
                               OFC_UCHAR *iv, OFC_SIZET iv_size,
                               OFC_UINT8 *aead, OFC_SIZET aead_size,
                               OFC_SIZET tag_size,
                               OFC_INT num_elem,
                               OFC_UCHAR **addr, OFC_SIZET *len,
                               OFC_UINT8 *ctext, OFC_SIZET ctext_size);

  OFC_VOID smb2_encryption_ctx_free(struct of_security_cipher_ctx *cipher_ctx);

  struct of_security_cipher_ctx *
  smb2_decryption_ctx(OFC_UCHAR *session_key,
                      OFC_SIZET session_key_len);

  OFC_BOOL smb2_decrypt(struct of_security_cipher_ctx *cipher_ctx,
                        OFC_UCHAR *iv, OFC_SIZET iv_size,
                        OFC_UINT8 *aead, OFC_SIZET aead_size,
                        OFC_SIZET tag_size,
                        OFC_UINT8 *ctext, OFC_SIZET ctext_size,
                        OFC_UINT8 *ptext, OFC_SIZET ptext_size);

  OFC_BOOL smb2_decrypt_vector(struct of_security_cipher_ctx *cipher_ctx,
                               OFC_UCHAR *iv, OFC_SIZET iv_size,
                               OFC_UINT8 *aead, OFC_SIZET aead_size,
                               OFC_UINT8 *tag, OFC_SIZET tag_size,
                               OFC_INT num_elem,
                               OFC_UCHAR **addr, OFC_SIZET *len,
                               OFC_UINT8 *ptext, OFC_SIZET ptext_size);
  OFC_VOID
  smb2_decryption_ctx_free(struct of_security_cipher_ctx *cipher_ctx);

  OFC_VOID smb2_rand_bytes(OFC_UCHAR *output, OFC_SIZET output_size);

  OFC_VOID of_security_print_key(char *heading, OFC_UCHAR *key);
#if defined(__cplusplus)
}
#endif

#endif
