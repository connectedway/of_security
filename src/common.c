/* common.c - Functions that are common to server and clinet
 * Rob Siemborski
 * Tim Martin
 * $Id: common.c,v 1.133 2011/09/01 14:12:53 mel Exp $
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

#include "of_security/sasl.h"
#include "of_security/saslutil.h"
#include "of_security/saslplug.h"
#include "of_security/saslint.h"
#include "of_security/md5.h"

#include "ofc/types.h"
#include "ofc/libc.h"
#include "ofc/net.h"

static const char *implementation_string = "Open Files SASL";

#define	VSTR0(maj, min, step)	#maj "." #min "." #step
#define	VSTR(maj, min, step)	VSTR0(maj, min, step)
#define	SASL_VERSION_STRING	VSTR(SASL_VERSION_MAJOR, SASL_VERSION_MINOR, \
				SASL_VERSION_STEP)

#define PACKAGE "of-security"
#define VERSION "2.1.25"

/* It turns out to be convenient to have a shared sasl_utils_t */
LIBSASL_VAR const sasl_utils_t *of_security_global_utils = OFC_NULL;

/* Should be a null-terminated array that lists the available mechanisms */
static char **global_mech_list = OFC_NULL;

static void *free_mutex = OFC_NULL;

int (*of_security_client_cleanup_hook)(void) = OFC_NULL;
int (*of_security_server_cleanup_hook)(void) = OFC_NULL;
int (*of_security_client_idle_hook)(sasl_conn_t *conn) = OFC_NULL;
int (*of_security_server_idle_hook)(sasl_conn_t *conn) = OFC_NULL;

sasl_allocation_utils_t of_security_allocation_utils={
  (sasl_malloc_t *)  &ofc_malloc,
  (sasl_calloc_t *)  &ofc_calloc,
  (sasl_realloc_t *) &ofc_realloc,
  (sasl_free_t *) &ofc_free
};
int of_security_allocation_locked = 0;

#define SASL_ENCODEV_EXTRA  4096

static int _sasl_global_getopt(void *context,
			       const char *plugin_name,
			       const char *option,
			       const char ** result,
			       unsigned *len);
 
/* Intenal mutex functions do as little as possible (no thread protection) */
static void *sasl_mutex_alloc(void)
{
  return (void *)0x1;
}

static int sasl_mutex_lock(void *mutex)
{
    return SASL_OK;
}

static int sasl_mutex_unlock(void *mutex)
{
    return SASL_OK;
}

static void sasl_mutex_free(void *mutex)
{
    return;
}

sasl_mutex_utils_t of_security_mutex_utils={
  &sasl_mutex_alloc,
  &sasl_mutex_lock,
  &sasl_mutex_unlock,
  &sasl_mutex_free
};

void of_security_set_mutex(sasl_mutex_alloc_t *n,
			 sasl_mutex_lock_t *l,
			 sasl_mutex_unlock_t *u,
			 sasl_mutex_free_t *d)
{
    /* Disallow mutex function changes once sasl_client_init
       and/or sasl_server_init is called */
    if (of_security_server_cleanup_hook || of_security_client_cleanup_hook) {
	return;
    }

    of_security_mutex_utils.alloc=n;
    of_security_mutex_utils.lock=l;
    of_security_mutex_utils.unlock=u;
    of_security_mutex_utils.free=d;
}

/* copy a string to malloced memory */
int of_security_strdup(const char *in, char **out, OFC_SIZET *outlen)
{
  OFC_SIZET len = ofc_strlen(in);
  if (outlen) *outlen = len;
  *out=sasl_ALLOC((unsigned) len + 1);
  if (! *out) return SASL_NOMEM;
  ofc_strcpy((char *) *out, in);
  return SASL_OK;
}

/* adds a string to the buffer; reallocing if need be */
int of_security_add_string(char **out, OFC_SIZET *alloclen,
			  OFC_SIZET *outlen, const char *add)
{
  OFC_SIZET addlen;

  if (add==OFC_NULL) add = "(null)";

  addlen=ofc_strlen(add); /* only compute once */
  if (of_security_buf_alloc(out, alloclen, (*outlen)+addlen)!=SASL_OK)
    return SASL_NOMEM;

  ofc_strncpy(*out + *outlen, add, addlen);
  *outlen += addlen;

  return SASL_OK;
}

/* a simpler way to set plugin path or configuration file path
 * without the need to set sasl_getpath_t callback.
 *
 * This function can be called before sasl_server_init/sasl_client_init.
 *
 * Don't call this function without locking in a multithreaded application.
 */  
int of_security_set_path (int path_type, char * path)
{
  return (SASL_FAIL) ;
}

/* return the version of the cyrus sasl library as compiled,
 * using 32 bits: high byte is major version, second byte is minor version,
 * low 16 bits are step #.
 * Patch version is not available using this function,
 * use sasl_version_info() instead.
 */
void of_security_version(const char **implementation, int *version) 
{
    if(implementation) *implementation = implementation_string;
    /* NB: the format is not the same as in SASL_VERSION_FULL */
    if(version) *version = (SASL_VERSION_MAJOR << 24) | 
		           (SASL_VERSION_MINOR << 16) |
		           (SASL_VERSION_STEP);
}

/* Extended version of sasl_version above */
void of_security_version_info (const char **implementation, 
			     const char **version_string,
			     int *version_major, int *version_minor, 
			     int *version_step,
			     int *version_patch)
{
    if (implementation) *implementation = implementation_string;
    if (version_string) *version_string = SASL_VERSION_STRING;
    if (version_major) *version_major = SASL_VERSION_MAJOR;
    if (version_minor) *version_minor = SASL_VERSION_MINOR;
    if (version_step) *version_step = SASL_VERSION_STEP;
    /* Version patch is always 0 for CMU SASL */
    if (version_patch) *version_patch = 0;
}

/* security-encode a regular string.  Mostly a wrapper for sasl_encodev */
/* output is only valid until next call to sasl_encode or sasl_encodev */
int of_security_encode(sasl_conn_t *conn, const char *input,
		     unsigned inputlen,
		     const char **output, unsigned *outputlen)
{
    int result;
    OFC_IOVEC tmp;

    if(!conn) return SASL_BADPARAM;
    if(!input || !inputlen || !output || !outputlen)
	PARAMERROR(conn);
    
    /* maxoutbuf checking is done in sasl_encodev */

    /* Note: We are casting a const pointer here, but it's okay
     * because we believe people downstream of us are well-behaved, and the
     * alternative is an absolute mess, performance-wise. */
    tmp.iov_base = (void *)input;
    tmp.iov_len = inputlen;
    
    result = of_security_encodev(conn, &tmp, 1, output, outputlen);

    RETURN(conn, result);
}

/* Internal function that doesn't do any verification */
static int
_sasl_encodev (sasl_conn_t *conn,
	       const OFC_IOVEC *invec,
               unsigned numiov,
               int * p_num_packets,     /* number of packets generated so far */
	       const char **output,     /* previous output, if *p_num_packets > 0 */
               unsigned *outputlen)
{
    int result;
    char * new_buf;

    if (*p_num_packets == 1) {
        /* This is the second call to this function,
           so we need to allocate a new output buffer
           and copy existing data there. */
      conn->multipacket_encoded_data.curlen = *outputlen;
        if (conn->multipacket_encoded_data.data == OFC_NULL) {
            conn->multipacket_encoded_data.reallen = 
                 conn->multipacket_encoded_data.curlen + SASL_ENCODEV_EXTRA;
            conn->multipacket_encoded_data.data =
                 sasl_ALLOC(conn->multipacket_encoded_data.reallen + 1);

            if (conn->multipacket_encoded_data.data == OFC_NULL) {
                MEMERROR(conn);
            }
        } else {
            /* A buffer left from a previous sasl_encodev call.
               Make sure it is big enough. */
            if (conn->multipacket_encoded_data.curlen >
                conn->multipacket_encoded_data.reallen) {
                conn->multipacket_encoded_data.reallen = 
                    conn->multipacket_encoded_data.curlen + SASL_ENCODEV_EXTRA;

	        new_buf = sasl_REALLOC(conn->multipacket_encoded_data.data,
                            conn->multipacket_encoded_data.reallen + 1);
                if (new_buf == OFC_NULL) {
                    MEMERROR(conn);
                }
                conn->multipacket_encoded_data.data = new_buf;
            }
        }

        ofc_memcpy (conn->multipacket_encoded_data.data,
                *output,
                *outputlen);
    }

    result = conn->oparams.encode(conn->context,
                                  invec,
                                  numiov,
				  output,
                                  outputlen);

    if (*p_num_packets > 0 && result == SASL_OK) {
        /* Is the allocated buffer big enough? If not, grow it. */
      if ((conn->multipacket_encoded_data.curlen + (OFC_SIZET) *outputlen) >
             conn->multipacket_encoded_data.reallen) {
            conn->multipacket_encoded_data.reallen =
                conn->multipacket_encoded_data.curlen + *outputlen;
	    new_buf = sasl_REALLOC(conn->multipacket_encoded_data.data,
                        conn->multipacket_encoded_data.reallen + 1);
            if (new_buf == OFC_NULL) {
                MEMERROR(conn);
            }
            conn->multipacket_encoded_data.data = new_buf;
        }

        /* Append new data to the end of the buffer */
        ofc_memcpy (conn->multipacket_encoded_data.data +
                conn->multipacket_encoded_data.curlen,
                *output,
                *outputlen);
        conn->multipacket_encoded_data.curlen += *outputlen;

        *output = conn->multipacket_encoded_data.data;
        *outputlen = (unsigned)conn->multipacket_encoded_data.curlen;
    }

    (*p_num_packets)++;

    RETURN(conn, result);
}

/* security-encode an iovec */
/* output is only valid until the next call to sasl_encode or sasl_encodev */
int of_security_encodev(sasl_conn_t *conn,
		      const OFC_IOVEC *invec,
		      unsigned numiov,
		      const char **output,
		      unsigned *outputlen)
{
    int result = SASL_OK;
    unsigned i;
    unsigned j;
    OFC_SIZET total_size = 0;
    OFC_IOVEC *cur_invec = OFC_NULL;
    OFC_IOVEC last_invec;
    unsigned cur_numiov;
    char * next_buf = OFC_NULL;
    OFC_SIZET remainder_len;
    unsigned index_offset;
    unsigned allocated = 0;
    /* Number of generated SASL packets */
    int num_packets = 0;

    if (!conn) return SASL_BADPARAM;
    if (! invec || ! output || ! outputlen || numiov < 1) {
	PARAMERROR(conn);
    }

    if (!conn->props.maxbufsize) {
	of_security_seterror(conn, 0,
		      "called sasl_encode[v] with application that does not support security layers");
	return SASL_TOOWEAK;
    }

    /* If oparams.encode is OFC_NULL, this means there is no SASL security
       layer in effect, so no SASL framing is needed. */
    if (conn->oparams.encode == OFC_NULL)  {
	result = of_security_iovec_to_buf(invec, numiov, &conn->encode_buf);
	if (result != SASL_OK) INTERROR(conn, result);
       
	*output = conn->encode_buf->data;
	*outputlen = (unsigned) conn->encode_buf->curlen;

        RETURN(conn, result);
    }

    /* This might be better to check on a per-plugin basis, but I think
     * it's cleaner and more effective here.  It also encourages plugins
     * to be honest about what they accept */

    last_invec.iov_base = OFC_NULL;
    remainder_len = 0;
    next_buf = OFC_NULL;
    i = 0;
    while (i < numiov) {
      if ((total_size + invec[i].iov_len) >
	  (OFC_SIZET) conn->oparams.maxoutbuf) {

            /* CLAIM: total_size < conn->oparams.maxoutbuf */
            
            /* Fit as many bytes in last_invec, so that we have conn->oparams.maxoutbuf
               bytes in total. */
            last_invec.iov_len = conn->oparams.maxoutbuf - total_size;
            /* Point to the first byte of the current record. */
            last_invec.iov_base = invec[i].iov_base;

            /* Note that total_size < conn->oparams.maxoutbuf */
            /* The total size of the iov is bigger then the other end can accept.
               So we allocate a new iov that contains just enough. */

            /* +1 --- for the tail record */
            cur_numiov = i + 1;

            /* +1 --- just in case we need the head record */
            if ((cur_numiov + 1) > allocated) {
                OFC_IOVEC *new_invec;

                allocated = cur_numiov + 1;
                new_invec = sasl_REALLOC (cur_invec, sizeof(OFC_IOVEC) * allocated);
                if (new_invec == OFC_NULL) {
                    if (cur_invec != OFC_NULL) {
                        sasl_FREE(cur_invec);
                    }
                    MEMERROR(conn);
                }
                cur_invec = new_invec;
            }

            if (next_buf != OFC_NULL) {
                cur_invec[0].iov_base = next_buf;
                cur_invec[0].iov_len = (long)remainder_len;
                cur_numiov++;
                index_offset = 1;
            } else {
                index_offset = 0;
            }

            if (i > 0) {
                /* Copy all previous chunks */
                /* NOTE - The starting index in invec is always 0 */
                for (j = 0; j < i; j++) {
                    cur_invec[j + index_offset] = invec[j];
                }
            }

            /* Initialize the last record */
            cur_invec[i + index_offset] = last_invec;

            result = _sasl_encodev (conn,
	                            cur_invec,
                                    cur_numiov,
                                    &num_packets,
	                            output,
                                    outputlen);

            if (result != SASL_OK) {
                goto cleanup;
            }

            /* Point to the first byte that wouldn't fit into
               the conn->oparams.maxoutbuf buffer. */
            /* Note, if next_buf points to the very end of the IOV record,
               it will be reset to OFC_NULL below */
            /* Note, that some platforms define iov_base as "void *",
               thus the typecase below */
            next_buf = (char *) last_invec.iov_base + last_invec.iov_len;
            /* Note - remainder_len is how many bytes left to be encoded in
               the current IOV slot. */
            remainder_len = (total_size + invec[i].iov_len) - conn->oparams.maxoutbuf;

            /* Skip all consumed IOV records */
            invec += i + 1;
            numiov = numiov - (i + 1);
            i = 0;

            while (remainder_len > (OFC_SIZET) conn->oparams.maxoutbuf) {
                last_invec.iov_base = next_buf;
                last_invec.iov_len = conn->oparams.maxoutbuf;

                /* Note, if next_buf points to the very end of the IOV record,
                   it will be reset to OFC_NULL below */
                /* Note, that some platforms define iov_base as "void *",
                   thus the typecase below */
                next_buf = (char *) last_invec.iov_base + last_invec.iov_len;
                remainder_len = remainder_len - conn->oparams.maxoutbuf;

                result = _sasl_encodev (conn,
	                                &last_invec,
                                        1,
                                        &num_packets,
	                                output,
                                        outputlen);
                if (result != SASL_OK) {
                    goto cleanup;
                }
            }

	    total_size = remainder_len;

            if (remainder_len == 0) {
                /* Just clear next_buf */
                next_buf = OFC_NULL;
            }
        } else {
	    total_size += invec[i].iov_len;
            i++;
        }
    }

    /* CLAIM - The remaining data is shorter then conn->oparams.maxoutbuf. */

    /* Force encoding of any partial buffer. Might not be optimal on the wire. */
    if (next_buf != OFC_NULL) {
        last_invec.iov_base = next_buf;
        last_invec.iov_len = (long)remainder_len;

        result = _sasl_encodev (conn,
	                        &last_invec,
                                1,
                                &num_packets,
	                        output,
                                outputlen);

        if (result != SASL_OK) {
            goto cleanup;
        }
    }

    if (numiov > 0) {
        result = _sasl_encodev (conn,
	                        invec,
                                numiov,
                                &num_packets,
	                        output,
                                outputlen);
    }

cleanup:
    if (cur_invec != OFC_NULL) {
        sasl_FREE(cur_invec);
    }

    RETURN(conn, result);
}
 
/* output is only valid until next call to sasl_decode */
int of_security_decode(sasl_conn_t *conn,
		     const char *input, unsigned inputlen,
		     const char **output, unsigned *outputlen)
{
    int result;

    if(!conn) return SASL_BADPARAM;
    if(!input || !output || !outputlen)
	PARAMERROR(conn);

    if(!conn->props.maxbufsize) {
	of_security_seterror(conn, 0,
		      "called sasl_decode with application that does not support security layers");
	RETURN(conn, SASL_TOOWEAK);
    }

    if(conn->oparams.decode == OFC_NULL)
    {
	/* Since we know how long the output is maximally, we can
	 * just allocate it to begin with, and never need another
         * allocation! */

	/* However, if they pass us more than they actually can take,
	 * we cannot help them... */
	if(inputlen > conn->props.maxbufsize) {
	    of_security_seterror(conn, 0,
			  "input too large for default sasl_decode");
	    RETURN(conn,SASL_BUFOVER);
	}

	if(!conn->decode_buf)
	    conn->decode_buf = sasl_ALLOC(conn->props.maxbufsize + 1);
	if(!conn->decode_buf)	
	    MEMERROR(conn);
	
	ofc_memcpy (conn->decode_buf, input, inputlen);
	conn->decode_buf[inputlen] = '\0';
	*output = conn->decode_buf;
	*outputlen = inputlen;
	
        return SASL_OK;
    } else {
        result = conn->oparams.decode(conn->context, input, inputlen,
                                      output, outputlen);

	/* OFC_NULL an empty buffer (for misbehaved applications) */
	if (*outputlen == 0) *output = OFC_NULL;

        RETURN(conn, result);
    }

    INTERROR(conn, SASL_FAIL);
}


void
of_security_set_alloc(sasl_malloc_t *m,
		    sasl_calloc_t *c,
		    sasl_realloc_t *r,
		    sasl_free_t *f)
{
  if (of_security_allocation_locked++)  return;

  of_security_allocation_utils.malloc=m;
  of_security_allocation_utils.calloc=c;
  of_security_allocation_utils.realloc=r;
  of_security_allocation_utils.free=f;
}

void of_security_common_done(void)
{
    /* NOTE - the caller will need to reinitialize the values,
       if it is going to call sasl_client_init/sasl_server_init again. */
    of_security_canonuser_free();
    
    sasl_MUTEX_FREE(free_mutex);
    free_mutex = OFC_NULL;
    
    of_security_free_utils(&of_security_global_utils);
    
    if (global_mech_list) {
	sasl_FREE(global_mech_list);
	global_mech_list = OFC_NULL;
    }
}

/* This function is for backward compatibility */
void of_security_done(void)
{
    if (of_security_server_cleanup_hook && 
	of_security_server_cleanup_hook() == SASL_OK) {
	of_security_server_idle_hook = OFC_NULL;
	of_security_server_cleanup_hook = OFC_NULL;
    }
    
    if (of_security_client_cleanup_hook && 
	of_security_client_cleanup_hook() == SASL_OK) {
	of_security_client_idle_hook = OFC_NULL;	
	of_security_client_cleanup_hook = OFC_NULL;
    }
    
    if (of_security_server_cleanup_hook || of_security_client_cleanup_hook) {
	return;
    }

    of_security_common_done();
}

/* fills in the base sasl_conn_t info */
int of_security_conn_init(sasl_conn_t *conn,
			 const char *service,
			 unsigned int flags,
			 enum Sasl_conn_type type,
			 int (*idle_hook)(sasl_conn_t *conn),
			 const char *serverFQDN,
			 const char *iplocalport,
			 const char *ipremoteport,
			 const sasl_callback_t *callbacks,
			 const sasl_global_callbacks_t *global_callbacks) {
  int result = SASL_OK;

  conn->type = type;

  result = of_security_strdup(service, &conn->service, OFC_NULL);
  if (result != SASL_OK) 
      MEMERROR(conn);

  ofc_memset(&conn->oparams, 0, sizeof(sasl_out_params_t));
  ofc_memset(&conn->external, 0, sizeof(_sasl_external_properties_t));

  conn->flags = flags;

  result = of_security_setprop(conn, SASL_IPLOCALPORT, iplocalport);
  if(result != SASL_OK)
      RETURN(conn, result);
  
  result = of_security_setprop(conn, SASL_IPREMOTEPORT, ipremoteport);
  if(result != SASL_OK)
      RETURN(conn, result);
  
  conn->encode_buf = OFC_NULL;
  conn->context = OFC_NULL;
  conn->secret = OFC_NULL;
  conn->idle_hook = idle_hook;
  conn->callbacks = callbacks;
  conn->global_callbacks = global_callbacks;

  ofc_memset(&conn->props, 0, sizeof(conn->props));

  /* Start this buffer out as an empty string */
  conn->error_code = SASL_OK;
  conn->errdetail_buf = conn->error_buf = OFC_NULL;
  conn->errdetail_buf_len = conn->error_buf_len = 150;

  result = of_security_buf_alloc(&conn->error_buf, &conn->error_buf_len, 150);     
  if(result != SASL_OK) MEMERROR(conn);
  result = of_security_buf_alloc(&conn->errdetail_buf, 
			   &conn->errdetail_buf_len, 150);
  if(result != SASL_OK) MEMERROR(conn);
  
  conn->error_buf[0] = '\0';
  conn->errdetail_buf[0] = '\0';
  
  conn->decode_buf = OFC_NULL;

  if(serverFQDN) {
      result = of_security_strdup(serverFQDN, &conn->serverFQDN, OFC_NULL);
      of_security_strlower (conn->serverFQDN);
  } else if (conn->type == SASL_CONN_SERVER) {
      /* We can fake it because we *are* the server */
      char name[OFC_MAX_PATH];
      ofc_memset(name, 0, sizeof(name));
      if (of_security_get_fqhostname (name, OFC_MAX_PATH, 0) != 0) {
        return (SASL_FAIL);
      }
      
      result = of_security_strdup(name, &conn->serverFQDN, OFC_NULL);
  } else {
      conn->serverFQDN = OFC_NULL;
  }
  

  if(result != SASL_OK) MEMERROR( conn );

  RETURN(conn, SASL_OK);
}

int of_security_common_init(sasl_global_callbacks_t *global_callbacks)
{
    int result;

    /* The last specified global callback always wins */
    if (of_security_global_utils != OFC_NULL) {
	sasl_utils_t * global_utils = (sasl_utils_t *)of_security_global_utils;
	global_utils->getopt = &_sasl_global_getopt;
	global_utils->getopt_context = global_callbacks;
    }

    /* Do nothing if we are already initialized */
    if (free_mutex) {
	return SASL_OK;
    }

    /* Setup the global utilities */
    if(!of_security_global_utils) {
	of_security_global_utils = 
	  of_security_alloc_utils(OFC_NULL, global_callbacks);
	if(of_security_global_utils == OFC_NULL) return SASL_NOMEM;
    }

    /* Init the canon_user plugin */
    result = of_security_canonuser_add_plugin("INTERNAL", 
					    of_security_internal_canonuser_init);
    if(result != SASL_OK) return result;    

    if (!free_mutex) {
	free_mutex = sasl_MUTEX_ALLOC();
    }
    if (!free_mutex) return SASL_FAIL;

    return SASL_OK;
}

/* dispose connection state, sets it to OFC_NULL
 *  checks for pointer to OFC_NULL
 */
void of_security_dispose(sasl_conn_t **pconn)
{
  int result;

  if (! pconn) return;
  if (! *pconn) return;

  /* serialize disposes. this is necessary because we can't
     dispose of conn->mutex if someone else is locked on it */
  result = sasl_MUTEX_LOCK(free_mutex);
  if (result!=SASL_OK) return;
  
  /* *pconn might have become OFC_NULL by now */
  if (! (*pconn)) return;

  (*pconn)->destroy_conn(*pconn);
  sasl_FREE(*pconn);
  *pconn=OFC_NULL;

  sasl_MUTEX_UNLOCK(free_mutex);
}

void of_security_conn_dispose(sasl_conn_t *conn) {
  if (conn->serverFQDN)
      sasl_FREE(conn->serverFQDN);

  if (conn->external.auth_id)
      sasl_FREE(conn->external.auth_id);

  if(conn->encode_buf) {
      if(conn->encode_buf->data) sasl_FREE(conn->encode_buf->data);
      sasl_FREE(conn->encode_buf);
  }

  if(conn->error_buf)
      sasl_FREE(conn->error_buf);
  
  if(conn->errdetail_buf)
      sasl_FREE(conn->errdetail_buf);

  if(conn->decode_buf)
      sasl_FREE(conn->decode_buf);

  if(conn->mechlist_buf)
      sasl_FREE(conn->mechlist_buf);

  if(conn->service)
      sasl_FREE(conn->service);

  if (conn->multipacket_encoded_data.data) {
      sasl_FREE(conn->multipacket_encoded_data.data);
  }

  /* oparams sub-members should be freed by the plugin, in so much
   * as they were allocated by the plugin */
}


/* get property from SASL connection state
 *  propnum       -- property number
 *  pvalue        -- pointer to value
 * returns:
 *  SASL_OK       -- no error
 *  SASL_NOTDONE  -- property not available yet
 *  SASL_BADPARAM -- bad property number or SASL context is OFC_NULL
 */
int of_security_getprop(sasl_conn_t *conn, int propnum, const void **pvalue)
{
  int result = SASL_OK;
  sasl_getopt_t *getopt;
  void *context;
  
  if (! conn) return SASL_BADPARAM;
  if (! pvalue) PARAMERROR(conn);

  switch(propnum)
  {
  case SASL_SSF:
      *(sasl_ssf_t **)pvalue= &conn->oparams.mech_ssf;
      break;      
  case SASL_MAXOUTBUF:
      *(unsigned **)pvalue = &conn->oparams.maxoutbuf;
      break;
  case SASL_GETOPTCTX:
      result = of_security_getcallback(conn, SASL_CB_GETOPT, 
				      (sasl_callback_ft *)&getopt, &context);
      if(result != SASL_OK) break;
      
      *(void **)pvalue = context;
      break;
  case SASL_CALLBACK:
      *(const sasl_callback_t **)pvalue = conn->callbacks;
      break;
  case SASL_IPLOCALPORT:
      if(conn->got_ip_local)
	  *(const char **)pvalue = conn->iplocalport;
      else {
	  *(const char **)pvalue = OFC_NULL;
	  result = SASL_NOTDONE;
      }
      break;
  case SASL_IPREMOTEPORT:
      if(conn->got_ip_remote)
	  *(const char **)pvalue = conn->ipremoteport;
      else {
	  *(const char **)pvalue = OFC_NULL;
	  result = SASL_NOTDONE;
      }	  
      break;
  case SASL_USERNAME:
      if(! conn->oparams.user)
	  result = SASL_NOTDONE;
      else
	  *((const char **)pvalue) = conn->oparams.user;
      break;
  case SASL_AUTHUSER:
      if(! conn->oparams.authid)
	  result = SASL_NOTDONE;
      else
	  *((const char **)pvalue) = conn->oparams.authid;
      break;
  case SASL_APPNAME:
      /* Currently we only support server side contexts, but we should
         be able to extend this to support client side contexts as well */
      if(conn->type != SASL_CONN_SERVER) result = SASL_BADPROT;
      else
	  *((const char **)pvalue) = ((sasl_server_conn_t *)conn)->sparams->appname;
      break;
  case SASL_SERVERFQDN:
      *((const char **)pvalue) = conn->serverFQDN;
      break;
  case SASL_DEFUSERREALM:
      if(conn->type != SASL_CONN_SERVER) result = SASL_BADPROT;
      else
	  *((const char **)pvalue) = ((sasl_server_conn_t *)conn)->user_realm;
      break;
  case SASL_SERVICE:
      *((const char **)pvalue) = conn->service;
      break;
  case SASL_AUTHSOURCE: /* name of plugin (not name of mech) */
      if(conn->type == SASL_CONN_CLIENT) {
	  if(!((sasl_client_conn_t *)conn)->mech) {
	      result = SASL_NOTDONE;
	      break;
	  }
	  *((const char **)pvalue) =
	      ((sasl_client_conn_t *)conn)->mech->m.plugname;
      } else if (conn->type == SASL_CONN_SERVER) {
	  if(!((sasl_server_conn_t *)conn)->mech) {
	      result = SASL_NOTDONE;
	      break;
	  }
	  *((const char **)pvalue) =
	      ((sasl_server_conn_t *)conn)->mech->m.plugname;
      } else {
	  result = SASL_BADPARAM;
      }
      break;
  case SASL_MECHNAME: /* name of mech */
      if(conn->type == SASL_CONN_CLIENT) {
	  if(!((sasl_client_conn_t *)conn)->mech) {
	      result = SASL_NOTDONE;
	      break;
	  }
	  *((const char **)pvalue) =
	      ((sasl_client_conn_t *)conn)->mech->m.plug->mech_name;
      } else if (conn->type == SASL_CONN_SERVER) {
	  if(!((sasl_server_conn_t *)conn)->mech) {
	      result = SASL_NOTDONE;
	      break;
	  }
	  *((const char **)pvalue) =
	      ((sasl_server_conn_t *)conn)->mech->m.plug->mech_name;
      } else {
	  result = SASL_BADPARAM;
      }
      
      if(!(*pvalue) && result == SASL_OK) result = SASL_NOTDONE;
      break;
  case SASL_PLUGERR:
      *((const char **)pvalue) = conn->error_buf;
      break;
  case SASL_DELEGATEDCREDS:
      /* We can't really distinguish between "no delegated credentials"
         and "authentication not finished" */
      if(! conn->oparams.client_creds)
	  result = SASL_NOTDONE;
      else
	  *((const char **)pvalue) = conn->oparams.client_creds;
      break;
  case SASL_GSS_PEER_NAME:
      if(! conn->oparams.gss_peer_name)
	  result = SASL_NOTDONE;
      else
	  *((const char **)pvalue) = conn->oparams.gss_peer_name;
      break;
  case SASL_GSS_LOCAL_NAME:
      if(! conn->oparams.gss_peer_name)
	  result = SASL_NOTDONE;
      else
	  *((const char **)pvalue) = conn->oparams.gss_local_name;
      break;
  case SASL_SSF_EXTERNAL:
      *((const sasl_ssf_t **)pvalue) = &conn->external.ssf;
      break;
  case SASL_AUTH_EXTERNAL:
      *((const char **)pvalue) = conn->external.auth_id;
      break;
  case SASL_SEC_PROPS:
      *((const sasl_security_properties_t **)pvalue) = &conn->props;
      break;
  case SASL_GSS_CREDS:
      if(conn->type == SASL_CONN_CLIENT)
	  *(void **)pvalue = (void *) 
              ((sasl_client_conn_t *)conn)->cparams->gss_creds;
      else
	  *(void **)pvalue = (void *)
              ((sasl_server_conn_t *)conn)->sparams->gss_creds;
      break;
  case SASL_HTTP_REQUEST: {
      if (conn->type == SASL_CONN_SERVER)
	  *(const sasl_http_request_t **)pvalue =
	      ((sasl_server_conn_t *)conn)->sparams->http_request;
      else
	  *(const sasl_http_request_t **)pvalue =
	      ((sasl_client_conn_t *)conn)->cparams->http_request;
      break;
  }
  default: 
      result = SASL_BADPARAM;
  }

  if(result == SASL_BADPARAM) {
      PARAMERROR(conn);
  } else if(result == SASL_NOTDONE) {
      of_security_seterror(conn, SASL_NOLOG,
		    "Information that was requested is not yet available.");
      RETURN(conn, result);
  } else if(result != SASL_OK) {
      INTERROR(conn, result);
  } else
      RETURN(conn, result); 
}

/* set property in SASL connection state
 * returns:
 *  SASL_OK       -- value set
 *  SASL_BADPARAM -- invalid property or value
 */
int of_security_setprop(sasl_conn_t *conn, int propnum, const void *value)
{
  int result = SASL_OK;
  char *str;

  /* make sure the sasl context is valid */
  if (!conn)
    return SASL_BADPARAM;

  switch(propnum)
  {
  case SASL_SSF_EXTERNAL:
      conn->external.ssf = *((sasl_ssf_t *)value);
      if(conn->type == SASL_CONN_SERVER) {
	((sasl_server_conn_t*)conn)->sparams->external_ssf =
	  conn->external.ssf;
      } else {
	((sasl_client_conn_t*)conn)->cparams->external_ssf =
	  conn->external.ssf;
      }
      break;

  case SASL_AUTH_EXTERNAL:
      if(value && ofc_strlen(value)) {
	  result = of_security_strdup(value, &str, OFC_NULL);
	  if(result != SASL_OK) MEMERROR(conn);
      } else {
	  str = OFC_NULL;
      }

      if(conn->external.auth_id)
	  sasl_FREE(conn->external.auth_id);

      conn->external.auth_id = str;

      break;

  case SASL_DEFUSERREALM:
      if(conn->type != SASL_CONN_SERVER) {
	of_security_seterror(conn, 0, "Tried to set realm on non-server connection");
	result = SASL_BADPROT;
	break;
      }

      if(value && ofc_strlen(value)) {
	  result = of_security_strdup(value, &str, OFC_NULL);
	  if(result != SASL_OK) MEMERROR(conn);
      } else {
	  PARAMERROR(conn);
      }

      if(((sasl_server_conn_t *)conn)->user_realm)
      	  sasl_FREE(((sasl_server_conn_t *)conn)->user_realm);

      ((sasl_server_conn_t *)conn)->user_realm = str;
      ((sasl_server_conn_t *)conn)->sparams->user_realm = str;

      break;

  case SASL_SEC_PROPS:
  {
      sasl_security_properties_t *props = (sasl_security_properties_t *)value;

      if(props->maxbufsize == 0 && props->min_ssf != 0) {
	  of_security_seterror(conn, 0,
			"Attempt to disable security layers (maxoutbuf == 0) with min_ssf > 0");
	  RETURN(conn, SASL_TOOWEAK);
      }

      conn->props = *props;

      if(conn->type == SASL_CONN_SERVER) {
	((sasl_server_conn_t*)conn)->sparams->props = *props;
      } else {
	((sasl_client_conn_t*)conn)->cparams->props = *props;
      }

      break;
  }
      
  case SASL_IPREMOTEPORT:
  {
      const char *ipremoteport = (const char *)value;
      if(!value) {
	  conn->got_ip_remote = 0; 
      } else if (of_security_ipfromstring(ipremoteport, OFC_NULL, 0)
		 != SASL_OK) {
	  of_security_seterror(conn, 0, "Bad IPREMOTEPORT value");
	  RETURN(conn, SASL_BADPARAM);
      } else {
	  ofc_strcpy(conn->ipremoteport, ipremoteport);
	  conn->got_ip_remote = 1;
      }
      
      if(conn->got_ip_remote) {
	  if(conn->type == SASL_CONN_CLIENT) {
	      ((sasl_client_conn_t *)conn)->cparams->ipremoteport
		  = conn->ipremoteport;
	      ((sasl_client_conn_t *)conn)->cparams->ipremlen =
		  (unsigned) ofc_strlen(conn->ipremoteport);
	  } else if (conn->type == SASL_CONN_SERVER) {
	      ((sasl_server_conn_t *)conn)->sparams->ipremoteport
		  = conn->ipremoteport;
	      ((sasl_server_conn_t *)conn)->sparams->ipremlen =
		  (unsigned) ofc_strlen(conn->ipremoteport);
	  }
      } else {
	  if(conn->type == SASL_CONN_CLIENT) {
	      ((sasl_client_conn_t *)conn)->cparams->ipremoteport
		  = OFC_NULL;
	      ((sasl_client_conn_t *)conn)->cparams->ipremlen = 0;
	  } else if (conn->type == SASL_CONN_SERVER) {
	      ((sasl_server_conn_t *)conn)->sparams->ipremoteport
		  = OFC_NULL;	      
	      ((sasl_server_conn_t *)conn)->sparams->ipremlen = 0;
	  }
      }

      break;
  }

  case SASL_IPLOCALPORT:
  {
      const char *iplocalport = (const char *)value;
      if(!value) {
	  conn->got_ip_local = 0;	  
      } else if (of_security_ipfromstring(iplocalport, OFC_NULL, 0)
		 != SASL_OK) {
	  of_security_seterror(conn, 0, "Bad IPLOCALPORT value");
	  RETURN(conn, SASL_BADPARAM);
      } else {
	  ofc_strcpy(conn->iplocalport, iplocalport);
	  conn->got_ip_local = 1;
      }

      if(conn->got_ip_local) {
	  if(conn->type == SASL_CONN_CLIENT) {
	      ((sasl_client_conn_t *)conn)->cparams->iplocalport
		  = conn->iplocalport;
	      ((sasl_client_conn_t *)conn)->cparams->iploclen
		  = (unsigned) ofc_strlen(conn->iplocalport);
	  } else if (conn->type == SASL_CONN_SERVER) {
	      ((sasl_server_conn_t *)conn)->sparams->iplocalport
		  = conn->iplocalport;
	      ((sasl_server_conn_t *)conn)->sparams->iploclen
		  = (unsigned) ofc_strlen(conn->iplocalport);
	  }
      } else {
	  if(conn->type == SASL_CONN_CLIENT) {
	      ((sasl_client_conn_t *)conn)->cparams->iplocalport
		  = OFC_NULL;
	      ((sasl_client_conn_t *)conn)->cparams->iploclen = 0;
	  } else if (conn->type == SASL_CONN_SERVER) {
	      ((sasl_server_conn_t *)conn)->sparams->iplocalport
		  = OFC_NULL;
	      ((sasl_server_conn_t *)conn)->sparams->iploclen = 0;
	  }
      }
      break;
  }

  case SASL_APPNAME:
      /* Currently we only support server side contexts, but we should
         be able to extend this to support client side contexts as well */
      if(conn->type != SASL_CONN_SERVER) {
	of_security_seterror(conn, 0, "Tried to set application name on non-server connection");
	result = SASL_BADPROT;
	break;
      }

      if(((sasl_server_conn_t *)conn)->appname) {
      	  sasl_FREE(((sasl_server_conn_t *)conn)->appname);
	  ((sasl_server_conn_t *)conn)->appname = OFC_NULL;
      }

      if(value && ofc_strlen(value)) {
	  result = of_security_strdup(value,
				&(((sasl_server_conn_t *)conn)->appname),
				OFC_NULL);
	  if(result != SASL_OK) MEMERROR(conn);
	  ((sasl_server_conn_t *)conn)->sparams->appname =
              ((sasl_server_conn_t *)conn)->appname;
	  ((sasl_server_conn_t *)conn)->sparams->applen =
	      (unsigned) ofc_strlen(((sasl_server_conn_t *)conn)->appname);
      } else {
	  ((sasl_server_conn_t *)conn)->sparams->appname = OFC_NULL;
	  ((sasl_server_conn_t *)conn)->sparams->applen = 0;
      }
      break;

  case SASL_GSS_CREDS:
      if(conn->type == SASL_CONN_CLIENT)
          ((sasl_client_conn_t *)conn)->cparams->gss_creds = value;
      else
          ((sasl_server_conn_t *)conn)->sparams->gss_creds = value;
      break;

  case SASL_CHANNEL_BINDING: {
    const struct sasl_channel_binding *cb = (const struct sasl_channel_binding *)value;

    if (conn->type == SASL_CONN_SERVER)
        ((sasl_server_conn_t *)conn)->sparams->cbinding = cb;
    else
        ((sasl_client_conn_t *)conn)->cparams->cbinding = cb;
    break;
  }

  case SASL_HTTP_REQUEST: {
      const sasl_http_request_t *req = (const sasl_http_request_t *)value;

      if (conn->type == SASL_CONN_SERVER)
	  ((sasl_server_conn_t *)conn)->sparams->http_request = req;
      else
	  ((sasl_client_conn_t *)conn)->cparams->http_request = req;
      break;
  }

  default:
      of_security_seterror(conn, 0, "Unknown parameter type");
      result = SASL_BADPARAM;
  }
  
  RETURN(conn, result);
}

/* this is apparently no longer a user function */
static int sasl_usererr(int saslerr)
{
    /* Hide the difference in a username failure and a password failure */
    if (saslerr == SASL_NOUSER)
	return SASL_BADAUTH;

    /* otherwise return the error given; no transform necessary */
    return saslerr;
}

const char *of_security_errstring(int saslerr,
				const char *langlist,
				const char **outlang)
{
  if (outlang) *outlang="en-us";

  switch(saslerr)
    {
    case SASL_CONTINUE: return "another step is needed in authentication";
    case SASL_OK:       return "successful result";
    case SASL_FAIL:     return "generic failure";
    case SASL_NOMEM:    return "no memory available";
    case SASL_BUFOVER:  return "overflowed buffer";
    case SASL_NOMECH:   return "no mechanism available";
    case SASL_BADPROT:  return "bad protocol / cancel";
    case SASL_NOTDONE:  return "can't request information until later in exchange";
    case SASL_BADPARAM: return "invalid parameter supplied";
    case SASL_TRYAGAIN: return "transient failure (e.g., weak key)";
    case SASL_BADMAC:   return "integrity check failed";
    case SASL_NOTINIT:  return "SASL library is not initialized";
                             /* -- client only codes -- */
    case SASL_INTERACT:   return "needs user interaction";
    case SASL_BADSERV:    return "server failed mutual authentication step";
    case SASL_WRONGMECH:  return "mechanism doesn't support requested feature";
                             /* -- server only codes -- */
    case SASL_BADAUTH:    return "authentication failure";
    case SASL_NOAUTHZ:    return "authorization failure";
    case SASL_TOOWEAK:    return "mechanism too weak for this user";
    case SASL_ENCRYPT:    return "encryption needed to use mechanism";
    case SASL_TRANS:      return "One time use of a plaintext password will enable requested mechanism for user";
    case SASL_EXPIRED:    return "passphrase expired, has to be reset";
    case SASL_DISABLED:   return "account disabled";
    case SASL_NOUSER:     return "user not found";
    case SASL_BADVERS:    return "version mismatch with plug-in";
    case SASL_UNAVAIL:    return "remote authentication server unavailable";
    case SASL_NOVERIFY:   return "user exists, but no verifier for user";
    case SASL_PWLOCK:     return "passphrase locked";
    case SASL_NOCHANGE:   return "requested change was not needed";
    case SASL_WEAKPASS:   return "passphrase is too weak for security policy";
    case SASL_NOUSERPASS: return "user supplied passwords are not permitted";
    case SASL_NEED_OLD_PASSWD: return "sasl_setpass needs old password in order "
				"to perform password change";
    case SASL_CONSTRAINT_VIOLAT: return "sasl_setpass can't store a property because "
			        "of a constraint violation";
    case SASL_BADBINDING: return "channel binding failure";

    default:   return "undefined error!";
    }

}

/* Return the sanitized error detail about the last error that occured for 
 * a connection */
const char *of_security_errdetail(sasl_conn_t *conn) 
{
    unsigned need_len;
    const char *errstr;
    char leader[128];

    if(!conn) return OFC_NULL;
    
    errstr = of_security_errstring(conn->error_code, OFC_NULL, OFC_NULL);
    ofc_snprintf(leader,128,"SASL(%d): %s: ",
		  sasl_usererr(conn->error_code), errstr);
    
    need_len = (unsigned) (ofc_strlen(leader) + ofc_strlen(conn->error_buf) + 12);
    of_security_buf_alloc(&conn->errdetail_buf, &conn->errdetail_buf_len, need_len);

    ofc_snprintf(conn->errdetail_buf, need_len, "%s%s", leader, conn->error_buf);
   
    return conn->errdetail_buf;
}


/* Note that this needs the global callbacks, so if you don't give getcallbacks
 * a sasl_conn_t, you're going to need to pass it yourself (or else we couldn't
 * have client and server at the same time */
static int _sasl_global_getopt(void *context,
			       const char *plugin_name,
			       const char *option,
			       const char ** result,
			       unsigned *len)
{
  const sasl_global_callbacks_t * global_callbacks;
  const sasl_callback_t *callback;

  global_callbacks = (const sasl_global_callbacks_t *) context;

  if (global_callbacks && global_callbacks->callbacks) {
      for (callback = global_callbacks->callbacks;
	   callback->id != SASL_CB_LIST_END;
	   callback++) {
	if (callback->id == SASL_CB_GETOPT) {
	  if (!callback->proc) return SASL_FAIL;
	  if (((sasl_getopt_t *)(callback->proc))(callback->context,
						  plugin_name,
						  option,
						  result,
						  len)
	      == SASL_OK)
	    return SASL_OK;
	}
      }
  }
  
  return SASL_FAIL;
}

static int
_sasl_conn_getopt(void *context,
		  const char *plugin_name,
		  const char *option,
		  const char ** result,
		  unsigned *len)
{
  sasl_conn_t * conn;
  const sasl_callback_t *callback;

  if (! context)
    return SASL_BADPARAM;

  conn = (sasl_conn_t *) context;

  if (conn->callbacks)
    for (callback = conn->callbacks;
	 callback->id != SASL_CB_LIST_END;
	 callback++)
      if (callback->id == SASL_CB_GETOPT
	  && (((sasl_getopt_t *)(callback->proc))(callback->context,
						  plugin_name,
						  option,
						  result,
						  len)
	      == SASL_OK))
	return SASL_OK;

  /* If we made it here, we didn't find an appropriate callback
   * in the connection's callback list, or the callback we did
   * find didn't return SASL_OK.  So we attempt to use the
   * global callback for this connection... */
  return _sasl_global_getopt((void *)conn->global_callbacks,
			     plugin_name,
			     option,
			     result,
			     len);
}

#ifdef HAVE_SYSLOG
/* this is the default logging */
static int _sasl_syslog(void *context,
			int priority,
			const char *message)
{
    int syslog_priority;
    sasl_server_conn_t *sconn;

    if (context) {
	if (((sasl_conn_t *)context)->type == SASL_CONN_SERVER) {
	    sconn = (sasl_server_conn_t *)context;
	    if (sconn->sparams->log_level < priority) 
		return SASL_OK;
	}
    }

    /* set syslog priority */
    switch(priority) {
    case SASL_LOG_NONE:
	return SASL_OK;
	break;
    case SASL_LOG_ERR:
	syslog_priority = LOG_ERR;
	break;
    case SASL_LOG_WARN:
	syslog_priority = LOG_WARNING;
	break;
    case SASL_LOG_NOTE:
    case SASL_LOG_FAIL:
	syslog_priority = LOG_NOTICE;
	break;
    case SASL_LOG_PASS:
    case SASL_LOG_TRACE:
    case SASL_LOG_DEBUG:
    default:
	syslog_priority = LOG_DEBUG;
	break;
    }
    
    /* do the syslog call. Do not need to call openlog? */
    syslog(syslog_priority | LOG_AUTH, "%s", message);
    
    return SASL_OK;
}
#endif				/* HAVE_SYSLOG */

static int
_sasl_getsimple(void *context,
		int id,
		const char ** result,
		OFC_SIZET *len)
{
  sasl_conn_t *conn;

  if (! context || ! result) return SASL_BADPARAM;

  conn = (sasl_conn_t *)context;

  switch(id) {
  case SASL_CB_AUTHNAME:
    return SASL_FAIL;
  case SASL_CB_TIMESTAMP:
    return SASL_FAIL;
  case SASL_CB_GETREALM:
    return SASL_FAIL;
  default:
    return SASL_BADPARAM;
  }
}

static int
_sasl_verifyfile(void *context,
		 char *file,
		 int type)
{
  /* always say ok */
  return SASL_OK;
}


static int
_sasl_proxy_policy(sasl_conn_t *conn,
		   void *context,
		   const char *requested_user, unsigned rlen,
		   const char *auth_identity, unsigned alen,
		   const char *def_realm,
		   unsigned urlen,
		   struct propctx *propctx)
{
    if (!conn)
	return SASL_BADPARAM;

    if (!requested_user || *requested_user == '\0')
	return SASL_OK;

    if (!auth_identity || !requested_user || rlen != alen ||
	(ofc_memcmp(auth_identity, requested_user, rlen) != 0)) {
	of_security_seterror(conn, 0,
		      "Requested identity not authenticated identity");
	RETURN(conn, SASL_BADAUTH);
    }

    return SASL_OK;
}

int of_security_getcallback(sasl_conn_t * conn,
			   unsigned long callbackid,
			   sasl_callback_ft *pproc,
			   void **pcontext)
{
  const sasl_callback_t *callback;

  if (!pproc || !pcontext)
      PARAMERROR(conn);

  /* Some callbacks are always provided by the library */
  switch (callbackid) {
  case SASL_CB_LIST_END:
    /* Nothing ever gets to provide this */
      INTERROR(conn, SASL_FAIL);
  case SASL_CB_GETOPT:
      if (conn) {
	  *pproc = (sasl_callback_ft)&_sasl_conn_getopt;
	  *pcontext = conn;
      } else {
	  *pproc = (sasl_callback_ft)&_sasl_global_getopt;
	  *pcontext = OFC_NULL;
      }
      return SASL_OK;
  }

  /* If it's not always provided by the library, see if there's
   * a version provided by the application for this connection... */
  if (conn && conn->callbacks) {
    for (callback = conn->callbacks; callback->id != SASL_CB_LIST_END;
	 callback++) {
	if (callback->id == callbackid) {
	    *pproc = callback->proc;
	    *pcontext = callback->context;
	    if (callback->proc) {
		return SASL_OK;
	    } else {
		return SASL_INTERACT;
	    }
	}
    }
  }

  /* And, if not for this connection, see if there's one
   * for all {server,client} connections... */
  if (conn && conn->global_callbacks && conn->global_callbacks->callbacks) {
      for (callback = conn->global_callbacks->callbacks;
	   callback->id != SASL_CB_LIST_END;
	   callback++) {
	  if (callback->id == callbackid) {
	      *pproc = callback->proc;
	      *pcontext = callback->context;
	      if (callback->proc) {
		  return SASL_OK;
	      } else {
		  return SASL_INTERACT;
	      }
	  }
      }
  }

  /* Otherwise, see if the library provides a default callback. */
  switch (callbackid) {
#ifdef HAVE_SYSLOG
  case SASL_CB_LOG:
    *pproc = (sasl_callback_ft)&_sasl_syslog;
    *pcontext = conn;
    return SASL_OK;
#endif /* HAVE_SYSLOG */
  case SASL_CB_GETPATH:
    return SASL_FAIL;
  case SASL_CB_GETCONFPATH:
    return SASL_FAIL;
  case SASL_CB_AUTHNAME:
    *pproc = (sasl_callback_ft)&_sasl_getsimple;
    *pcontext = conn;
    return SASL_OK;
  case SASL_CB_TIMESTAMP:
    *pproc = (sasl_callback_ft)&_sasl_getsimple;
    *pcontext = conn;
    return SASL_OK;
  case SASL_CB_GETREALM:
    *pproc = (sasl_callback_ft)&_sasl_getsimple;
    *pcontext = conn;
    return SASL_OK;
  case SASL_CB_VERIFYFILE:
    *pproc = (sasl_callback_ft)&_sasl_verifyfile;
    *pcontext = OFC_NULL;
    return SASL_OK;
  case SASL_CB_PROXY_POLICY:
    *pproc = (sasl_callback_ft)&_sasl_proxy_policy;
    *pcontext = OFC_NULL;
    return SASL_OK;
  }

  /* Unable to find a callback... */
  *pproc = OFC_NULL;
  *pcontext = OFC_NULL;
  of_security_seterror(conn, SASL_NOLOG, "Unable to find a callback: %d", callbackid);
  RETURN(conn,SASL_FAIL);
}


/*
 * This function is typically called from a plugin.
 * It creates a string from the formatting and varargs given
 * and calls the logging callback (syslog by default)
 *
 * %m will parse the value in the next argument as an errno string
 * %z will parse the next argument as a SASL error code.
 */

void
of_security_log (sasl_conn_t *conn,
		int level,
		const char *fmt,
		...)
{
  char *out=(char *) sasl_ALLOC(250);
  OFC_SIZET alloclen=100; /* current allocated length */
  OFC_SIZET outlen=0; /* current length of output buffer */
  OFC_SIZET formatlen;
  OFC_SIZET pos=0; /* current position in format string */
  int result;
  sasl_log_t *log_cb;
  void *log_ctx;
  
  int ival;
  unsigned int uval;
  char *cval;
  va_list ap; /* varargs thing */

  if(!fmt) goto done;
  if(!out) return;
  
  formatlen = ofc_strlen(fmt);

  /* See if we have a logging callback... */
  result = of_security_getcallback(conn, SASL_CB_LOG, 
				  (sasl_callback_ft *)&log_cb, &log_ctx);
  if (result == SASL_OK && ! log_cb)
    result = SASL_FAIL;
  if (result != SASL_OK) goto done;
  
  va_start(ap, fmt); /* start varargs */

  while(pos<formatlen)
  {
    if (fmt[pos]!='%') /* regular character */
    {
      result = of_security_buf_alloc(&out, &alloclen, outlen+1);
      if (result != SASL_OK) goto done;
      out[outlen]=fmt[pos];
      outlen++;
      pos++;

    } else { /* formating thing */
      int done=0;
      char frmt[10];
      int frmtpos=1;
      char tempbuf[21];
      frmt[0]='%';
      pos++;

      while (done==0)
      {
	switch(fmt[pos])
	  {
	  case 's': /* need to handle this */
	    cval = va_arg(ap, char *); /* get the next arg */
	    result = of_security_add_string(&out, &alloclen,
					   &outlen, cval);
	      
	    if (result != SASL_OK) /* add the string */
		goto done;

	    done=1;
	    break;

	  case '%': /* double % output the '%' character */
	    result = of_security_buf_alloc(&out,&alloclen,outlen+1);
	    if (result != SASL_OK)
		goto done;
	    
	    out[outlen]='%';
	    outlen++;
	    done=1;
	    break;

	  case 'm': /* insert the errno string */
	    result = of_security_add_string(&out, &alloclen, &outlen, "err") ;
	    if (result != SASL_OK)
		goto done;
	    
	    done=1;
	    break;

	  case 'z': /* insert the sasl error string */
	    result = of_security_add_string
	      (&out, &alloclen, &outlen,
	       (char *) of_security_errstring(va_arg(ap, int),
					    OFC_NULL,OFC_NULL));
	    if (result != SASL_OK)
		goto done;
	    
	    done=1;
	    break;

	  case 'c':
	    frmt[frmtpos++]=fmt[pos];
	    frmt[frmtpos]=0;
	    tempbuf[0] = (char) va_arg(ap, int); /* get the next arg */
	    tempbuf[1]='\0';
	    
	    /* now add the character */
	    result = of_security_add_string(&out, &alloclen, &outlen, tempbuf);
	    if (result != SASL_OK)
		goto done;
		
	    done=1;
	    break;

	  case 'd':
	  case 'i':
	    frmt[frmtpos++]=fmt[pos];
	    frmt[frmtpos]=0;
	    ival = va_arg(ap, int); /* get the next arg */

	    ofc_snprintf(tempbuf,20,frmt,ival); /* have snprintf do the work */
	    /* now add the string */
	    result = of_security_add_string(&out, &alloclen, &outlen, tempbuf);
	    if (result != SASL_OK)
		goto done;

	    done=1;
	    break;

	  case 'o':
	  case 'u':
	  case 'x':
	  case 'X':
	    frmt[frmtpos++]=fmt[pos];
	    frmt[frmtpos]=0;
	    uval = va_arg(ap, unsigned int); /* get the next arg */

	    ofc_snprintf(tempbuf,20,frmt,uval); /* have snprintf do the work */
	    /* now add the string */
	    result = of_security_add_string(&out, &alloclen, &outlen, tempbuf);
	    if (result != SASL_OK)
		goto done;

	    done=1;
	    break;

	  default: 
	    frmt[frmtpos++]=fmt[pos]; /* add to the formating */
	    frmt[frmtpos]=0;	    
	    if (frmtpos>9) 
	      done=1;
	  }
	pos++;
	if (pos>formatlen)
	  done=1;
      }

    }
  }

  /* put 0 at end */
  result = of_security_buf_alloc(&out, &alloclen, outlen+1);
  if (result != SASL_OK) goto done;
  out[outlen]=0;

  va_end(ap);    

  /* send log message */
  result = log_cb(log_ctx, level, out);

 done:
  if(out) sasl_FREE(out);
}



/* Allocate and Init a sasl_utils_t structure */
sasl_utils_t *
of_security_alloc_utils(sasl_conn_t *conn,
		  sasl_global_callbacks_t *global_callbacks)
{
  sasl_utils_t *utils;
  /* set util functions - need to do rest*/
  utils=sasl_ALLOC(sizeof(sasl_utils_t));
  if (utils==OFC_NULL)
    return OFC_NULL;

  utils->conn = conn;

  of_security_randcreate(&utils->rpool);

  if (conn) {
    utils->getopt = &_sasl_conn_getopt;
    utils->getopt_context = conn;
  } else {
    utils->getopt = &_sasl_global_getopt;
    utils->getopt_context = global_callbacks;
  }

  utils->malloc=of_security_allocation_utils.malloc;
  utils->calloc=of_security_allocation_utils.calloc;
  utils->realloc=of_security_allocation_utils.realloc;
  utils->free=of_security_allocation_utils.free;

  utils->mutex_alloc = of_security_mutex_utils.alloc;
  utils->mutex_lock = of_security_mutex_utils.lock;
  utils->mutex_unlock = of_security_mutex_utils.unlock;
  utils->mutex_free = of_security_mutex_utils.free;
  
  utils->MD5Init  = &of_security_MD5Init;
  utils->MD5Update= &of_security_MD5Update;
  utils->MD5Final = &of_security_MD5Final;
  utils->hmac_md5 = &of_security_hmac_md5;
  utils->hmac_md5_init = &of_security_hmac_md5_init;
  utils->hmac_md5_final = &of_security_hmac_md5_final;
  utils->hmac_md5_precalc = &of_security_hmac_md5_precalc;
  utils->hmac_md5_import = &of_security_hmac_md5_import;
  utils->mkchal = &of_security_mkchal;
  utils->utf8verify = &of_security_utf8verify;
  utils->rand=&of_security_rand;
  utils->churn=&of_security_churn;  
  utils->checkpass=OFC_NULL;
  
  utils->encode64=&of_security_encode64;
  utils->decode64=&of_security_decode64;
  
  utils->erasebuffer=&of_security_erasebuffer;

  utils->getprop=&of_security_getprop;
  utils->setprop=&of_security_setprop;

  utils->getcallback=&of_security_getcallback;

  utils->log=&of_security_log;

  utils->seterror=&of_security_seterror;

#ifndef macintosh
  /* Aux Property Utilities */
  utils->prop_new=&of_security_prop_new;
  utils->prop_dup=&of_security_prop_dup;
  utils->prop_request=&of_security_prop_request;
  utils->prop_get=&of_security_prop_get;
  utils->prop_getnames=&of_security_prop_getnames;
  utils->prop_clear=&of_security_prop_clear;
  utils->prop_dispose=&of_security_prop_dispose;
  utils->prop_format=&of_security_prop_format;
  utils->prop_set=&of_security_prop_set;
  utils->prop_setvals=&of_security_prop_setvals;
  utils->prop_erase=&of_security_prop_erase;
  utils->auxprop_store=&of_security_auxprop_store;
#endif

  /* Spares */
  utils->spare_fptr = OFC_NULL;
  utils->spare_fptr1 = utils->spare_fptr2 = OFC_NULL;
  
  return utils;
}

int
of_security_free_utils(const sasl_utils_t ** utils)
{
    sasl_utils_t *nonconst;

    if(!utils) return SASL_BADPARAM;
    if(!*utils) return SASL_OK;

    /* I wish we could avoid this cast, it's pretty gratuitous but it
     * does make life easier to have it const everywhere else. */
    nonconst = (sasl_utils_t *)(*utils);

    of_security_randfree(&(nonconst->rpool));
    sasl_FREE(nonconst);

    *utils = OFC_NULL;
    return SASL_OK;
}

int of_security_idle(sasl_conn_t *conn)
{
  if (! conn) {
    if (of_security_server_idle_hook
	&& of_security_server_idle_hook(OFC_NULL))
      return 1;
    if (of_security_client_idle_hook
	&& of_security_client_idle_hook(OFC_NULL))
      return 1;
    return 0;
  }

  if (conn->idle_hook)
    return conn->idle_hook(conn);

  return 0;
}

static const sasl_callback_t *
_sasl_find_callback_by_type (const sasl_callback_t *callbacks,
                             unsigned long id)
{
    if (callbacks) {
        while (callbacks->id != SASL_CB_LIST_END) {
            if (callbacks->id == id) {
	        return callbacks;
            } else {
	        ++callbacks;
            }
        }
    }
    return OFC_NULL;
}

const sasl_callback_t *
of_security_find_getpath_callback(const sasl_callback_t *callbacks)
{
  callbacks = _sasl_find_callback_by_type (callbacks, SASL_CB_GETPATH);
  if (callbacks != OFC_NULL) {
    return callbacks;
  } else {
    return OFC_NULL ;
  }
}

const sasl_callback_t *
of_security_find_getconfpath_callback(const sasl_callback_t *callbacks)
{
  callbacks = _sasl_find_callback_by_type (callbacks, SASL_CB_GETCONFPATH);
  if (callbacks != OFC_NULL) {
    return callbacks;
  } else {
    return OFC_NULL ;
  }
}

const sasl_callback_t *
of_security_find_verifyfile_callback(const sasl_callback_t *callbacks)
{
  static const sasl_callback_t default_verifyfile_cb = {
    SASL_CB_VERIFYFILE,
    (sasl_callback_ft)&_sasl_verifyfile,
    OFC_NULL
  };

  callbacks = _sasl_find_callback_by_type (callbacks, SASL_CB_VERIFYFILE);
  if (callbacks != OFC_NULL) {
    return callbacks;
  } else {
    return &default_verifyfile_cb;
  }
}

/* Basically a conditional call to realloc(), if we need more */
int of_security_buf_alloc(char **rwbuf, OFC_SIZET *curlen, OFC_SIZET newlen) 
{
    if(!(*rwbuf)) {
	*rwbuf = sasl_ALLOC((unsigned)newlen);
	if (*rwbuf == OFC_NULL) {
	    *curlen = 0;
	    return SASL_NOMEM;
	}
	*curlen = newlen;
    } else if(*rwbuf && *curlen < newlen) {
	OFC_SIZET needed = 2*(*curlen);

	while(needed < newlen)
	    needed *= 2;

        /* WARN - We will leak the old buffer on failure */
	*rwbuf = sasl_REALLOC(*rwbuf, (unsigned)needed);
	
	if (*rwbuf == OFC_NULL) {
	    *curlen = 0;
	    return SASL_NOMEM;
	}
	*curlen = needed;
    } 

    return SASL_OK;
}

/* for the mac os x cfm glue: this lets the calling function
   get pointers to the error buffer without having to touch the sasl_conn_t struct */
void of_security_get_errorbuf(sasl_conn_t *conn, char ***bufhdl, 
			     OFC_SIZET **lenhdl)
{
	*bufhdl = &conn->error_buf;
	*lenhdl = &conn->error_buf_len;
}

/* convert an iovec to a single buffer */
int of_security_iovec_to_buf(const OFC_IOVEC *vec,
		       unsigned numiov, buffer_info_t **output) 
{
    unsigned i;
    int ret;
    buffer_info_t *out;
    char *pos;

    if (!vec || !output) return SASL_BADPARAM;

    if (!(*output)) {
	*output = sasl_ALLOC(sizeof(buffer_info_t));
	if (!*output) return SASL_NOMEM;
	ofc_memset(*output,0,sizeof(buffer_info_t));
    }

    out = *output;
    
    out->curlen = 0;
    for (i = 0; i < numiov; i++) {
	out->curlen += vec[i].iov_len;
    }

    ret = of_security_buf_alloc(&out->data, &out->reallen, out->curlen);

    if (ret != SASL_OK) return SASL_NOMEM;
    
    ofc_memset(out->data, 0, out->reallen);
    pos = out->data;
    
    for (i = 0; i < numiov; i++) {
	ofc_memcpy (pos, vec[i].iov_base, vec[i].iov_len);
	pos += vec[i].iov_len;
    }

    return SASL_OK;
}


int of_security_ipfromstring(const char *addr,
			    OFC_SOCKADDR *out, OFC_SIZET outlen) 
{
  OFC_CHAR *p ;

  if (out != OFC_NULL)
    {
      out->sin_port = 0 ;
      ofc_pton(addr, &out->sin_addr) ;
      p = ofc_strchr (addr, ';') ;
      if (p != OFC_NULL)
	{
	  p++ ;
	  out->sin_port = (OFC_UINT16) ofc_strtol (p, OFC_NULL, 10) ;
	}
    }

  return SASL_OK;
}

int of_security_build_mechlist(void) 
{
    int count = 0;
    sasl_string_list_t *clist = OFC_NULL, *slist = OFC_NULL, *olist = OFC_NULL;
    sasl_string_list_t *p, *q, **last, *p_next;

    clist = of_security_client_mechs();
    slist = of_security_server_mechs();

    if(!clist) {
	olist = slist;
    } else {
	int flag;
	
	/* append slist to clist, and set olist to clist */
	for(p = slist; p; p = p_next) {
	    flag = 0;
	    p_next = p->next;

	    last = &clist;
	    for(q = clist; q; q = q->next) {
		if(!ofc_strcmp(q->d, p->d)) {
		    /* They match, set the flag */
		    flag = 1;
		    break;
		}
		last = &(q->next);
	    }

	    if(!flag) {
		*last = p;
		p->next = OFC_NULL;
	    } else {
		sasl_FREE(p);
	    }
	}

	olist = clist;
    }

    if(!olist) {
	/* This is not going to be very useful */
	return SASL_FAIL;
    }

    for (p = olist; p; p = p->next) count++;
    
    if(global_mech_list) {
	sasl_FREE(global_mech_list);
	global_mech_list = OFC_NULL;
    }
    
    global_mech_list = sasl_ALLOC((count + 1) * sizeof(char *));
    if(!global_mech_list) return SASL_NOMEM;
    
    ofc_memset(global_mech_list, 0, (count + 1) * sizeof(char *));
    
    count = 0;
    for (p = olist; p; p = p_next) {
	p_next = p->next;

	global_mech_list[count++] = (char *) p->d;

    	sasl_FREE(p);
    }

    return SASL_OK;
}

const char ** of_security_global_listmech(void) 
{
    return (const char **)global_mech_list;
}

int of_security_listmech(sasl_conn_t *conn,
		       const char *user,
		       const char *prefix,
		       const char *sep,
		       const char *suffix,
		       const char **result,
		       unsigned *plen,
		       int *pcount)
{
    if(!conn) {
	return SASL_BADPARAM;
    } else if(conn->type == SASL_CONN_SERVER) {
	RETURN(conn, of_security_server_listmech(conn, user, prefix, sep, suffix,
					   result, plen, pcount));
    } else if (conn->type == SASL_CONN_CLIENT) {
	RETURN(conn, of_security_client_listmech(conn, prefix, sep, suffix,
						result, plen, pcount));
    }
    
    PARAMERROR(conn);
}

int of_security_is_equal_mech(const char *req_mech,
			     const char *plug_mech,
			     OFC_SIZET req_mech_len,
			     int *plus)
{
    OFC_SIZET n;

    if (req_mech_len > 5 &&
        ofc_strcasecmp(&req_mech[req_mech_len - 5], "-PLUS") == 0) {
        n = req_mech_len - 5;
        *plus = 1;
    } else {
        n = req_mech_len;
        *plus = 0;
    }

    return (ofc_strncasecmp(req_mech, plug_mech, n) == 0);
}
