/* saslutil.c
 * Rob Siemborski
 * Tim Martin
 * $Id: saslutil.c,v 1.51 2010/12/01 14:25:53 mel Exp $
 */
/* 
 * Copyright (c) 1998-2003 Carnegie Mellon University.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "Carnegie Mellon University" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For permission or any other legal
 *    details, please contact  
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Computing Services
 *     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#define LIBSASL_EXPORTS

#include "of_security/saslint.h"
#include "of_security/saslutil.h"

#include "of_smb/config.h"
#include "ofc/time.h"
#include "ofc/framework.h"

/*  Contains:
 *
 * sasl_decode64 
 * sasl_encode64
 * sasl_mkchal
 * sasl_utf8verify
 * sasl_randcreate
 * sasl_randfree
 * sasl_randseed
 * sasl_rand
 * sasl_churn
 * sasl_erasebuffer
 */

//char *encode_table;
//char *decode_table;

#define RPOOL_SIZE 3
struct sasl_rand_s {
    unsigned short pool[RPOOL_SIZE];
    /* since the init time might be really bad let's make this lazy */
    int initialized; 
};

#define CHAR64(c)  (((c) < 0 || (c) > 127) ? -1 : index_64[(c)])

static char basis_64[] =
   "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/???????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????";

static char index_64[128] = {
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,62, -1,-1,-1,63,
    52,53,54,55, 56,57,58,59, 60,61,-1,-1, -1,-1,-1,-1,
    -1, 0, 1, 2,  3, 4, 5, 6,  7, 8, 9,10, 11,12,13,14,
    15,16,17,18, 19,20,21,22, 23,24,25,-1, -1,-1,-1,-1,
    -1,26,27,28, 29,30,31,32, 33,34,35,36, 37,38,39,40,
    41,42,43,44, 45,46,47,48, 49,50,51,-1, -1,-1,-1,-1
};

/* base64 encode
 *  in      -- input data
 *  inlen   -- input data length
 *  out     -- output buffer (will be NUL terminated)
 *  outmax  -- max size of output buffer
 * result:
 *  outlen  -- gets actual length of output buffer (optional)
 * 
 * Returns SASL_OK on success, SASL_BUFOVER if result won't fit
 */

int of_security_encode64(const char *_in,
		       unsigned inlen,
		       char *_out,
		       unsigned outmax,
		       unsigned *outlen)
{
    const unsigned char *in = (const unsigned char *)_in;
    unsigned char *out = (unsigned char *)_out;
    unsigned char oval;
    unsigned olen;

    /* check params */
    if ((inlen > 0) && (in == OFC_NULL)) return SASL_BADPARAM;
    
    /* Will it fit? */
    olen = (inlen + 2) / 3 * 4;
    if (outlen) {
	*outlen = olen;
    }
    if (outmax <= olen) {
	return SASL_BUFOVER;
    }

    /* Do the work... */
    while (inlen >= 3) {
      /* user provided max buffer size; make sure we don't go over it */
        *out++ = basis_64[in[0] >> 2];
        *out++ = basis_64[((in[0] << 4) & 0x30) | (in[1] >> 4)];
        *out++ = basis_64[((in[1] << 2) & 0x3c) | (in[2] >> 6)];
        *out++ = basis_64[in[2] & 0x3f];
        in += 3;
        inlen -= 3;
    }
    if (inlen > 0) {
      /* user provided max buffer size; make sure we don't go over it */
        *out++ = basis_64[in[0] >> 2];
        oval = (in[0] << 4) & 0x30;
        if (inlen > 1) oval |= in[1] >> 4;
        *out++ = basis_64[oval];
        *out++ = (inlen < 2) ? '=' : basis_64[(in[1] << 2) & 0x3c];
        *out++ = '=';
    }

    *out = '\0';
    
    return SASL_OK;
}

/* base64 decode
 *  in     -- input data
 *  inlen  -- length of input data
 *  out    -- output data (may be same as in, must have enough space)
 *  outmax  -- max size of output buffer
 * result:
 *  outlen -- actual output length
 *
 * returns:
 * SASL_BADPROT on bad base64,
 * SASL_BUFOVER if result won't fit,
 * SASL_CONTINUE on a partial block,
 * SASL_OK on success
 */

int of_security_decode64(const char *in,
		       unsigned inlen,
		       char *out,
		       unsigned outmax,  /* size of the buffer, not counting the NUL */
		       unsigned *outlen)
{
    unsigned len = 0;
    unsigned j;
    int c[4];
    int saw_equal = 0;

    /* check parameters */
    if (out == OFC_NULL) return SASL_FAIL;

    if (inlen > 0 && *in == '\r') return SASL_FAIL;

    while (inlen > 3) {
        /* No data is valid after an '=' character */
        if (saw_equal) {
            return SASL_BADPROT;
        }

	for (j = 0; j < 4; j++) {
	    c[j] = in[0];
	    in++;
	    inlen--;
	}

        if (CHAR64(c[0]) == -1 || CHAR64(c[1]) == -1) return SASL_BADPROT;
        if (c[2] != '=' && CHAR64(c[2]) == -1) return SASL_BADPROT;
        if (c[3] != '=' && CHAR64(c[3]) == -1) return SASL_BADPROT;
        /* No data is valid after a '=' character, unless it is another '=' */
        if (c[2] == '=' && c[3] != '=') return SASL_BADPROT;
        if (c[2] == '=' || c[3] == '=') {
            saw_equal = 1;
        }

        *out++ = (CHAR64(c[0]) << 2) | (CHAR64(c[1]) >> 4);
        if (++len >= outmax) return SASL_BUFOVER;
        if (c[2] != '=') {
            *out++ = ((CHAR64(c[1]) << 4) & 0xf0) | (CHAR64(c[2]) >> 2);
            if (++len >= outmax) return SASL_BUFOVER;
            if (c[3] != '=') {
                *out++ = ((CHAR64(c[2]) << 6) & 0xc0) | CHAR64(c[3]);
                if (++len >= outmax) return SASL_BUFOVER;
            }
        }
    }

    *out = '\0'; /* NUL terminate the output string */

    if (outlen) *outlen = len;

    if (inlen != 0) {
        if (saw_equal) {
            /* Unless there is CRLF at the end? */
            return SASL_BADPROT;
        } else {
	    return (SASL_CONTINUE);
        }
    }

    return SASL_OK;
}

/* make a challenge string (NUL terminated)
 *  buf      -- buffer for result
 *  maxlen   -- max length of result
 *  hostflag -- 0 = don't include hostname, 1 = include hostname
 * returns final length or 0 if not enough space
 */

int of_security_mkchal(sasl_conn_t *conn,
		     char *buf,
		     unsigned maxlen,
		     unsigned hostflag)
{
  sasl_rand_t *pool = OFC_NULL;
  unsigned long randnum;
  int ret;
  OFC_MSTIME now ;
  unsigned len;

  len = 4			/* <.>\0 */
    + (2 * 20);			/* 2 numbers, 20 => max size of 64bit
				 * ulong in base 10 */
  if (hostflag && conn->serverFQDN)
    len += (unsigned) ofc_strlen(conn->serverFQDN) + 1 /* for the @ */;

  if (maxlen < len)
    return 0;

  ret = of_security_randcreate(&pool);
  if(ret != SASL_OK) return 0; /* xxx sasl return code? */

  of_security_rand(pool, (char *)&randnum, sizeof(randnum));
  of_security_randfree(&pool);

  now = ofc_time_get_now() ;

  if (hostflag && conn->serverFQDN)
    ofc_snprintf(buf,maxlen, "<%lu.%lu@%s>", randnum, now, conn->serverFQDN);
  else
    ofc_snprintf(buf,maxlen, "<%lu.%lu>", randnum, now);

  return (int) ofc_strlen(buf);
}

/* 
 * To see why this is really bad see RFC 1750
 *
 * unfortunatly there currently is no way to make 
 * cryptographically secure pseudo random numbers
 * without specialized hardware etc...
 * thus, this is for nonce use only
 */

static void getranddata(unsigned short ret[RPOOL_SIZE])
{
    long curtime;
    
    ofc_memset(ret, 0, RPOOL_SIZE*sizeof(unsigned short));

    /* if all else fails just use time() */
    curtime = (long) ofc_time_get_now() ; /* better be at least 32 bits */
    
    ret[0] ^= (unsigned short) (curtime >> 16);
    ret[1] ^= (unsigned short) (curtime & 0xFFFF);
    ret[2] ^= (unsigned short) (curtime & 0xFFFF);
    
    return;
}

int of_security_randcreate(sasl_rand_t **rpool)
{
  (*rpool)=sasl_ALLOC(sizeof(sasl_rand_t));
  if ((*rpool) == OFC_NULL) return SASL_NOMEM;

  /* init is lazy */
  (*rpool)->initialized = 0;

  return SASL_OK;
}

void of_security_randfree(sasl_rand_t **rpool)
{
    sasl_FREE(*rpool);
}

void of_security_randseed (sasl_rand_t *rpool, const char *seed, unsigned len)
{
    /* is it acceptable to just use the 1st 3 char's given??? */
    unsigned int lup;

    /* check params */
    if (seed == OFC_NULL) return;
    if (rpool == OFC_NULL) return;

    rpool->initialized = 1;

    if (len > sizeof(unsigned short)*RPOOL_SIZE)
      len = sizeof(unsigned short)*RPOOL_SIZE;

    for (lup = 0; lup < len; lup += 2)
	rpool->pool[lup/2] = (seed[lup] << 8) + seed[lup + 1];
}

static OFC_ULONG m_w = 36939 ;
static OFC_ULONG m_z = 18000 ;

OFC_ULONG of_security_get_random(OFC_VOID)
{
  m_z = 36969 * (m_z & 0xFFFF) + (m_z >> 16) ;
  m_w = 18000 * (m_w & 0xFFFF) + (m_w >> 16) ;
  return (m_z << 16) + m_w ;
}

static void randinit(sasl_rand_t *rpool)
{
    unsigned int i ;

    if (!rpool) return;
    
    if (!rpool->initialized) {
	getranddata(rpool->pool);
	rpool->initialized = 1;
	{
	  unsigned int *foo = (unsigned int *) rpool->pool ;
	  for (i = 0 ; i < (*foo & 0xFF) ; i++)
	    of_security_get_random() ;
	}
    }
}

void of_security_rand (sasl_rand_t *rpool, char *buf, unsigned len)
{
    unsigned int lup;

    /* check params */
    if (!rpool || !buf) return;
    
    /* init if necessary */
    randinit(rpool);

    for (lup = 0; lup < len; lup++) {
      buf[lup] = (char) (of_security_get_random() >> 8);
    }
}

/* this function is just a bad idea all around, since we're not trying to
   implement a true random number generator */
void of_security_churn (sasl_rand_t *rpool, const char *data, unsigned len)
{
    unsigned int lup;
    
    /* check params */
    if (!rpool || !data) return;
    
    /* init if necessary */
    randinit(rpool);
    
    for (lup=0; lup<len; lup++)
	rpool->pool[lup % RPOOL_SIZE] ^= data[lup];
}

void of_security_erasebuffer(char *buf, unsigned len) {
    ofc_memset(buf, 0, len);
}

/* Lowercase string in place */
char *of_security_strlower (
  char *val
)
{
    int i;

    if (val == OFC_NULL) {
	return (OFC_NULL);
    }

/* don't use tolower(), as it is locale dependent */

    for (i = 0; val[i] != '\0'; i++) {
	if (val[i] >= 'A' && val[i] <= 'Z') {
	    val[i] = val[i] - 'A' + 'a';
	}
    }

    return (val);
}

/* A version of gethostname that tries hard to return a FQDN */
int of_security_get_fqhostname(
  char *name,  
  int namelen,
  int abort_if_no_fqdn
)
{
    OFC_LPTSTR node ;
    OFC_LPSTR cnode ;

    node = ofc_framework_get_host_name() ;
    cnode = ofc_tstr2cstr(node) ;
    ofc_free (node) ;

    ofc_strncpy (name, cnode, namelen) ;
    of_security_strlower (name);
    ofc_free (cnode) ;

    return (0);
}
