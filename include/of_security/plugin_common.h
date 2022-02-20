
/* Generic SASL plugin utility functions
 * Rob Siemborski
 * $Id: plugin_common.h,v 1.21 2006/01/17 12:18:21 mel Exp $
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

#ifndef _PLUGIN_COMMON_H_
#define _PLUGIN_COMMON_H_

#include "of_security/sasl.h"
#include "of_security/saslutil.h"
#include "of_security/saslplug.h"

#define PLUG_API extern

#define SASL_CLIENT_PLUG_INIT( x ) \
extern sasl_client_plug_init_t x##_client_plug_init; \
PLUG_API int sasl_client_plug_init(const sasl_utils_t *utils, \
                         int maxversion, int *out_version, \
			 sasl_client_plug_t **pluglist, \
                         int *plugcount) { \
        return x##_client_plug_init(utils, maxversion, out_version, \
				     pluglist, plugcount); \
}

#define SASL_SERVER_PLUG_INIT( x ) \
extern sasl_server_plug_init_t x##_server_plug_init; \
PLUG_API int sasl_server_plug_init(const sasl_utils_t *utils, \
                         int maxversion, int *out_version, \
			 sasl_server_plug_t **pluglist, \
                         int *plugcount) { \
        return x##_server_plug_init(utils, maxversion, out_version, \
				     pluglist, plugcount); \
}

#define SASL_AUXPROP_PLUG_INIT( x ) \
extern sasl_auxprop_init_t x##_auxprop_plug_init; \
PLUG_API int sasl_auxprop_plug_init(const sasl_utils_t *utils, \
                           int maxversion, int *out_version, \
                           sasl_auxprop_plug_t **plug, \
                           const char *plugname) {\
        return x##_auxprop_plug_init(utils, maxversion, out_version, \
                                     plug, plugname); \
}

#define SASL_CANONUSER_PLUG_INIT( x ) \
extern sasl_canonuser_init_t x##_canonuser_plug_init; \
PLUG_API int sasl_canonuser_init(const sasl_utils_t *utils, \
                           int maxversion, int *out_version, \
                           sasl_canonuser_plug_t **plug, \
                           const char *plugname) {\
        return x##_canonuser_plug_init(utils, maxversion, out_version, \
                                     plug, plugname); \
}

/* note: msg cannot include additional variables, so if you want to
 * do a printf-format string, then you need to call seterror yourself */
#define SETERROR( utils, msg ) (utils)->seterror( (utils)->conn, 0, (msg) )

#ifndef MEMERROR
#define MEMERROR( utils ) \
    (utils)->seterror( (utils)->conn, 0, \
                       "Out of Memory in " __FILE__ " near line %d", __LINE__ )
#endif

#ifndef PARAMERROR
#define PARAMERROR( utils ) \
    (utils)->seterror( (utils)->conn, 0, \
                       "Parameter Error in " __FILE__ " near line %d", __LINE__ )
#endif

#ifndef SASLINT_H
typedef struct buffer_info 
{
    char *data;
    unsigned curlen;   /* Current length of data in buffer */
    unsigned reallen;  /* total length of buffer (>= curlen) */
} buffer_info_t;
#endif

#ifdef __cplusplus
extern "C" {
#endif

OFC_INT of_security_plug_iovec_to_buf(const sasl_utils_t *utils, 
				 const OFC_IOVEC *vec,
				 OFC_UINT numiov, buffer_info_t **output);
int of_security_plug_buf_alloc(const sasl_utils_t *utils, char **rwbuf,
		    unsigned *curlen, unsigned newlen);
int of_security_plug_strdup(const sasl_utils_t * utils, const char *in,
	         char **out, int *outlen);
void _plug_free_string(const sasl_utils_t *utils, char **str);
void _plug_free_secret(const sasl_utils_t *utils, sasl_secret_t **secret);

#define of_security_plug_get_userid(utils, result, prompt_need) \
	of_security_plug_get_simple(utils, SASL_CB_USER, 0, result, prompt_need)
#define of_security_plug_get_timestamp(utils, result, prompt_need) \
	of_security_plug_get_simple(utils, SASL_CB_TIMESTAMP, 1, result, prompt_need)
#define of_security_plug_get_authid(utils, result, prompt_need) \
	of_security_plug_get_simple(utils, SASL_CB_AUTHNAME, 1, result, prompt_need)
#define of_security_plug_get_domain(utils, result, prompt_need) \
	of_security_plug_get_simple(utils, SASL_CB_GETREALM, 1, result, prompt_need)
int of_security_plug_get_simple(const sasl_utils_t *utils, unsigned int id, int required,
			  char **result, sasl_interact_t **prompt_need);

int of_security_plug_get_password(const sasl_utils_t *utils, sasl_secret_t **secret,
			    unsigned int *iscopy, 
			    sasl_interact_t **prompt_need);

int of_security_plug_challenge_prompt(const sasl_utils_t *utils, unsigned int id,
			   const char *challenge, const char *promptstr,
			   const char **result, sasl_interact_t **prompt_need);

int of_security_plug_get_realm(const sasl_utils_t *utils, const char **availrealms,
		    const char **realm, sasl_interact_t **prompt_need);

int of_security_plug_make_prompts(const sasl_utils_t *utils,
		       sasl_interact_t **prompts_res,
		       const char *user_prompt, const char *user_def,
		       const char *auth_prompt, const char *auth_def,
		       const char *pass_prompt, const char *pass_def,
		       const char *echo_chal,
		       const char *echo_prompt, const char *echo_def,
		       const char *realm_chal,
		       const char *realm_prompt, const char *realm_def,
		       const char *timestamp_prompt,
		       const char *timestamp_def);

typedef struct decode_context {
    const sasl_utils_t *utils;
    OFC_UINT needsize;	/* How much of the 4-byte size do we need? */
    OFC_CHAR sizebuf[4];		/* Buffer to accumulate the 4-byte size */
    OFC_UINT size;		/* Absolute size of the encoded packet */
    OFC_CHAR *buffer;		/* Buffer to accumulate an encoded packet */
    OFC_UINT cursize;	/* Amount of packet data in the buffer */
    OFC_UINT in_maxbuf;	/* Maximum allowed size of an incoming encoded packet */
} decode_context_t;

OFC_VOID of_security_plug_decode_init(decode_context_t *text,
		       const sasl_utils_t *utils, OFC_UINT in_maxbuf);

OFC_INT of_security_plug_decode(decode_context_t *text,
		 const OFC_CHAR *input, OFC_UINT inputlen,
		 OFC_CHAR **output, OFC_UINT *outputsize, OFC_UINT *outputlen,
		 OFC_INT (*decode_pkt)(OFC_VOID *rock,
				   const OFC_CHAR *input, OFC_UINT inputlen,
				   OFC_CHAR **output, OFC_UINT *outputlen),
		 OFC_VOID *rock);

OFC_VOID of_security_plug_decode_free(decode_context_t *text);

int of_security_plug_parseuser(const sasl_utils_t *utils,
		    char **user, char **realm, const char *user_realm, 
		    const char *serverFQDN, const char *input);

int of_security_plug_make_fulluser(const sasl_utils_t *utils,
			char **fulluser, const char * useronly, const char *realm);

char * of_security_plug_get_error_message (const sasl_utils_t *utils, int error);
void of_security_plug_snprintf_os_info (char * osbuf, int osbuf_len);

#ifdef __cplusplus
}
#endif

#endif /* _PLUGIN_COMMON_H_ */
