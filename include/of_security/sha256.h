#if !defined(__SHA256_H__)
#define __SHA256_H__

#define SHA256_MAC_LEN 32

#if defined(__cplusplus)
extern "C"
{
#endif
  OFC_INT hmac_sha256_vector(const OFC_UCHAR *key, OFC_SIZET key_len, 
                             OFC_SIZET num_elem, const OFC_UCHAR *addr[], 
                             const OFC_SIZET *len, OFC_UCHAR *mac);
  OFC_INT hmac_sha256(const OFC_UCHAR *key, OFC_SIZET key_len, 
		       const OFC_UCHAR *data, OFC_SIZET data_len, 
		       OFC_UCHAR *mac) ;

#if defined(__cplusplus)
}
#endif

#endif
