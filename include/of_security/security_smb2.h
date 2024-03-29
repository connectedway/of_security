#if !defined(__SECURITY_SMB_H__)
#define __SECURITY_SMB_H__

#define SMB2_KEY_LENGTH 16
#define SHA512_MAC_LEN 64
#undef KEY_DEBUG

struct of_security_cipher_ctx
{
  OFC_VOID *impl_cipher_ctx;
  OFC_UINT cipher_algo;
  OFC_UINT8 key[SMB2_KEY_LENGTH];
  OFC_SIZET keylen;
};

struct of_security_signing_ctx
{
  OFC_VOID *impl_signing_ctx;
  OFC_UINT8 key[SMB2_KEY_LENGTH];
  OFC_SIZET keylen;
};

#define SMB2_AES_128_CCM 0
#define SMB2_AES_128_GCM 1

#if defined(__cplusplus)
extern "C"
{
#endif
  OFC_INT sha512_vector(OFC_SIZET num_elem, const OFC_UCHAR *addr[],
                        const OFC_SIZET *len, OFC_UCHAR *mac);
  OFC_VOID *smb2_signing_ctx(OFC_UCHAR *session_key,
                             OFC_SIZET session_key_len,
                             OFC_UCHAR *label,
                             OFC_SIZET label_size,
                             OFC_UCHAR *context,
                             OFC_SIZET context_size);

  OFC_VOID smb2_sign(OFC_VOID *signing_ctx,
                     OFC_UINT8 *ptext,
                     OFC_SIZET ptext_size,
                     OFC_UINT8 *digest, OFC_SIZET digest_len);

  OFC_VOID smb2_sign_vector(OFC_VOID *signing_ctx,
                            OFC_INT num_elem,
                            OFC_UINT8 **ptext_vec,
                            OFC_SIZET *ptext_size_vec,
                            OFC_UINT8 *digest, OFC_SIZET digest_len);

  OFC_VOID smb2_signing_ctx_free(OFC_VOID *signing_ctx);

  OFC_VOID *
  smb2_encryption_ctx(OFC_UCHAR *session_key,
                      OFC_SIZET session_key_len,
                      OFC_UINT cipher_algo,
                      OFC_UCHAR *label,
                      OFC_SIZET label_size,
                      OFC_UCHAR *context,
                      OFC_SIZET context_size);

  OFC_VOID smb2_encrypt(OFC_VOID *cipher_ctx,
                        OFC_UCHAR *iv, OFC_SIZET iv_size,
                        OFC_UINT8 *aead, OFC_SIZET aead_size,
                        OFC_SIZET tag_size,
                        OFC_UINT8 *ptext, OFC_SIZET ptext_size,
                        OFC_UINT8 *ctext, OFC_SIZET ctext_size);

  OFC_VOID smb2_encrypt_vector(OFC_VOID *cipher_ctx,
                               OFC_UCHAR *iv, OFC_SIZET iv_size,
                               OFC_UINT8 *aead, OFC_SIZET aead_size,
                               OFC_SIZET tag_size,
                               OFC_INT num_elem,
                               OFC_UCHAR **addr, OFC_SIZET *len,
                               OFC_UINT8 *ctext, OFC_SIZET ctext_size);

  OFC_VOID smb2_encryption_ctx_free(OFC_VOID *cipher_ctx);

  OFC_VOID *
  smb2_decryption_ctx(OFC_UCHAR *session_key,
                      OFC_SIZET session_key_len,
                      OFC_UINT cipher_algo,
                      OFC_UCHAR *label,
                      OFC_SIZET label_size,
                      OFC_UCHAR *context,
                      OFC_SIZET context_size);
  OFC_BOOL smb2_decrypt(OFC_VOID *cipher_ctx,
                        OFC_UCHAR *iv, OFC_SIZET iv_size,
                        OFC_UINT8 *aead, OFC_SIZET aead_size,
                        OFC_SIZET tag_size,
                        OFC_UINT8 *ctext, OFC_SIZET ctext_size,
                        OFC_UINT8 *ptext, OFC_SIZET ptext_size);

  OFC_BOOL smb2_decrypt_vector(OFC_VOID *cipher_ctx,
                               OFC_UCHAR *iv, OFC_SIZET iv_size,
                               OFC_UINT8 *aead, OFC_SIZET aead_size,
                               OFC_UINT8 *tag, OFC_SIZET tag_size,
                               OFC_INT num_elem,
                               OFC_UCHAR **addr, OFC_SIZET *len,
                               OFC_UINT8 *ptext, OFC_SIZET ptext_size);
  OFC_VOID
  smb2_decryption_ctx_free(OFC_VOID *cipher_ctx);

  OFC_VOID smb2_rand_bytes(OFC_UCHAR *output, OFC_SIZET output_size);

  OFC_VOID of_security_print_key(char *heading, OFC_UCHAR *key);
#if defined(__cplusplus)
}
#endif

#endif
