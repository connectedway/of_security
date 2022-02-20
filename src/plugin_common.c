/* Generic SASL plugin utility functions
 * Rob Siemborski
 * $Id: plugin_common.c,v 1.22 2011/09/01 14:12:18 mel Exp $
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

#include "of_security/sasl.h"
#include "of_security/saslutil.h"
#include "of_security/saslplug.h"
#include "of_security/plugin_common.h"

#include "ofc/libc.h"
#include "ofc/net.h"
#include "ofc/net_internal.h"
#include "ofc/heap.h"

OFC_INT of_security_plug_iovec_to_buf(const sasl_utils_t *utils, 
				 const OFC_IOVEC *vec,
				 OFC_UINT numiov, buffer_info_t **output) 
{
    OFC_UINT i;
    OFC_INT ret;
    buffer_info_t *out;
    OFC_CHAR *pos;

    if(!utils || !vec || !output) {
	if(utils) PARAMERROR( utils );
	return SASL_BADPARAM;
    }
    
    if(!(*output)) {
	*output = utils->malloc(sizeof(buffer_info_t));
	if(!*output) {
	    MEMERROR(utils);
	    return SASL_NOMEM;
	}
	ofc_memset(*output,0,sizeof(buffer_info_t));
    }

    out = *output;
    
    out->curlen = 0;
    for(i=0; i<numiov; i++)
	out->curlen += vec[i].iov_len;

    ret = of_security_plug_buf_alloc(utils, &out->data, &out->reallen, out->curlen);

    if(ret != SASL_OK) {
	MEMERROR(utils);
	return SASL_NOMEM;
    }
    
    ofc_memset(out->data, 0, out->reallen);
    pos = out->data;
    
    for(i=0; i<numiov; i++) {
	ofc_memcpy(pos, vec[i].iov_base, vec[i].iov_len);
	pos += vec[i].iov_len;
    }

    return SASL_OK;
}

/* Basically a conditional call to realloc(), if we need more */
int of_security_plug_buf_alloc(const sasl_utils_t *utils, char **rwbuf,
			 unsigned *curlen, unsigned newlen) 
{
    if(!utils || !rwbuf || !curlen) {
	PARAMERROR(utils);
	return SASL_BADPARAM;
    }

    if(!(*rwbuf)) {
	*rwbuf = utils->malloc(newlen);
	if (*rwbuf == OFC_NULL) {
	    *curlen = 0;
	    MEMERROR(utils);
	    return SASL_NOMEM;
	}
	*curlen = newlen;
    } else if(*rwbuf && *curlen < newlen) {
	OFC_SIZET needed = 2*(*curlen);

	while(needed < (OFC_SIZET) newlen)
	    needed *= 2;

	*rwbuf = utils->realloc(*rwbuf, needed);
	if (*rwbuf == OFC_NULL) {
	    *curlen = 0;
	    MEMERROR(utils);
	    return SASL_NOMEM;
	}
	*curlen = (unsigned) needed;
    } 

    return SASL_OK;
}

/* 
 * Trys to find the prompt with the lookingfor id in the prompt list
 * Returns it if found. OFC_NULL otherwise
 */
sasl_interact_t *of_security_plug_find_prompt(sasl_interact_t **promptlist,
					unsigned int lookingfor)
{
    sasl_interact_t *prompt;

    if (promptlist && *promptlist) {
	for (prompt = *promptlist; prompt->id != SASL_CB_LIST_END; ++prompt) {
	    if (prompt->id==lookingfor)
		return prompt;
	}
    }

    return OFC_NULL;
}

/*
 * Retrieve the simple string given by the callback id.
 */
int of_security_plug_get_simple(const sasl_utils_t *utils, 
			  unsigned int id, int required,
			  char **result, sasl_interact_t **prompt_need)
{

    int ret = SASL_FAIL;
    sasl_getsimple_t *simple_cb;
    void *simple_context;
    sasl_interact_t *prompt;

    *result = OFC_NULL;

    /* see if we were given the result in the prompt */
    prompt = of_security_plug_find_prompt(prompt_need, id);
    if (prompt != OFC_NULL) {
	/* We prompted, and got.*/
	
	if (required && !prompt->result) {
	    SETERROR(utils, "Unexpectedly missing a prompt result");
	    return SASL_BADPARAM;
	}

	*result = prompt->result;
	return SASL_OK;
    }
  
    /* Try to get the callback... */
    ret = utils->getcallback(utils->conn, id, (sasl_callback_ft *)&simple_cb, &simple_context);

    if (ret == SASL_FAIL && !required)
	return SASL_OK;

    if (ret == SASL_OK && simple_cb) {
	ret = simple_cb(simple_context, id, result, OFC_NULL);
	if (ret != SASL_OK)
	    return ret;

	if (required && !*result) {
	    PARAMERROR(utils);
	    return SASL_BADPARAM;
	}
    }
  
    return ret;
}

/*
 * Retrieve the user password.
 */
int of_security_plug_get_password(const sasl_utils_t *utils, sasl_secret_t **password,
		       unsigned int *iscopy, sasl_interact_t **prompt_need)
{
    int ret = SASL_FAIL;
    sasl_getsecret_t *pass_cb;
    void *pass_context;
    sasl_interact_t *prompt;

    *password = OFC_NULL;
    *iscopy = 0;

    /* see if we were given the password in the prompt */
    prompt = of_security_plug_find_prompt(prompt_need, SASL_CB_PASS);
    if (prompt != OFC_NULL) {
	/* We prompted, and got.*/
	
	if (!prompt->result) {
	    SETERROR(utils, "Unexpectedly missing a prompt result");
	    return SASL_BADPARAM;
	}
      
	/* copy what we got into a secret_t */
	*password = (sasl_secret_t *) utils->malloc(sizeof(sasl_secret_t) +
						    prompt->len + 1);
	if (!*password) {
	    MEMERROR(utils);
	    return SASL_NOMEM;
	}
      
	(*password)->len=prompt->len;
	ofc_memcpy((*password)->data, prompt->result, prompt->len);
	(*password)->data[(*password)->len]=0;
	ofc_free (prompt->result) ;
	*iscopy = 1;

	return SASL_OK;
    }

    /* Try to get the callback... */
    ret = utils->getcallback(utils->conn, SASL_CB_PASS,
			     (sasl_callback_ft *)&pass_cb, &pass_context);

    if (ret == SASL_OK && pass_cb) {
	ret = pass_cb(utils->conn, pass_context, SASL_CB_PASS, password);
	if (ret != SASL_OK)
	    return ret;

	if (!*password) {
	    PARAMERROR(utils);
	    return SASL_BADPARAM;
	}
    }

    return ret;
}

/*
 * Make the requested prompts. (prompt==OFC_NULL means we don't want it)
 */
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
			    const char *timestamp_def)
{
    int num = 1;
    int alloc_size;
    sasl_interact_t *prompts;

    if (user_prompt) num++;
    if (auth_prompt) num++;
    if (pass_prompt) num++;
    if (echo_prompt) num++;
    if (realm_prompt) num++;
    if (timestamp_prompt) num++;

    if (num == 1) {
	SETERROR( utils, "make_prompts() called with no actual prompts" );
	return SASL_FAIL;
    }

    alloc_size = sizeof(sasl_interact_t)*num;
    prompts = utils->malloc(alloc_size);
    if (!prompts) {
	MEMERROR( utils );
	return SASL_NOMEM;
    }
    ofc_memset(prompts, 0, alloc_size);
  
    *prompts_res = prompts;

    if (user_prompt) {
	(prompts)->id = SASL_CB_USER;
	(prompts)->challenge = "Authorization Name";
	(prompts)->prompt = user_prompt;
	(prompts)->defresult = user_def;

	prompts++;
    }

    if (timestamp_prompt) {
	(prompts)->id = SASL_CB_TIMESTAMP;
	(prompts)->challenge = "Timestamp";
	(prompts)->prompt = timestamp_prompt;
	(prompts)->defresult = timestamp_def;

	prompts++;
    }

    if (auth_prompt) {
	(prompts)->id = SASL_CB_AUTHNAME;
	(prompts)->challenge = "Authentication Name";
	(prompts)->prompt = auth_prompt;
	(prompts)->defresult = auth_def;

	prompts++;
    }

    if (pass_prompt) {
	(prompts)->id = SASL_CB_PASS;
	(prompts)->challenge = "Password";
	(prompts)->prompt = pass_prompt;
	(prompts)->defresult = pass_def;

	prompts++;
    }

    if (echo_prompt) {
	(prompts)->id = SASL_CB_ECHOPROMPT;
	(prompts)->challenge = echo_chal;
	(prompts)->prompt = echo_prompt;
	(prompts)->defresult = echo_def;

	prompts++;
    }

    if (realm_prompt) {
	(prompts)->id = SASL_CB_GETREALM;
	(prompts)->challenge = realm_chal;
	(prompts)->prompt = realm_prompt;
	(prompts)->defresult = realm_def;

	prompts++;
    }

    /* add the ending one */
    (prompts)->id = SASL_CB_LIST_END;
    (prompts)->challenge = OFC_NULL;
    (prompts)->prompt = OFC_NULL;
    (prompts)->defresult = OFC_NULL;

    return SASL_OK;
}

/* returns the realm we should pretend to be in */
int of_security_plug_parseuser(const sasl_utils_t *utils,
		    char **user, char **realm, const char *user_realm, 
		    const char *serverFQDN, const char *input)
{
    int ret;
    char *r;

    ret = SASL_OK ;
    if(!user || !serverFQDN) {
	PARAMERROR( utils );
	return SASL_BADPARAM;
    }

    r = ofc_strchr(input, '@');
    if (!r) {
	/* hmmm, the user didn't specify a realm */
      
	if(user_realm && user_realm[0]) {
	  *realm = ofc_strdup (user_realm) ;
	} else {
	    /* Default to serverFQDN */
	  *realm = ofc_strdup (serverFQDN) ;
	}
	
	if (ret == SASL_OK) {
	  *user = ofc_strdup (input) ;
	}
    } else {
	r++;
	*realm = ofc_strdup (r) ;
	*--r = '\0';
	*user = utils->malloc(r - input + 1);
	if (*user) {
	    ofc_strncpy(*user, input, r - input +1);
	} else {
	    MEMERROR( utils );
	    ret = SASL_NOMEM;
	}
	*r = '@';
    }

    return ret;
}

OFC_VOID of_security_plug_decode_init(decode_context_t *text,
			    const sasl_utils_t *utils, OFC_UINT in_maxbuf)
{
    ofc_memset(text, 0, sizeof(decode_context_t));

    text->utils = utils;
    text->needsize = 4;
    text->in_maxbuf = in_maxbuf;
}

/*
 * Decode as much of the input as possible (possibly none),
 * using decode_pkt() to decode individual packets.
 */
OFC_INT of_security_plug_decode(decode_context_t *text,
		 const OFC_CHAR *input, OFC_UINT inputlen,
		 OFC_CHAR **output,		/* output buffer */
		 OFC_UINT *outputsize,	/* current size of output buffer */
		 OFC_UINT *outputlen,	/* length of data in output buffer */
		 OFC_INT (*decode_pkt)(OFC_VOID *rock,
				   const OFC_CHAR *input, OFC_UINT inputlen,
				   OFC_CHAR **output, OFC_UINT *outputlen),
		 OFC_VOID *rock)
{
    OFC_UINT tocopy;
    OFC_UINT diff;
    OFC_CHAR *tmp;
    OFC_UINT tmplen;
    OFC_INT ret;
    
    *outputlen = 0;

    while (inputlen) { /* more input */
	if (text->needsize) { /* need to get the rest of the 4-byte size */

	    /* copy as many bytes (up to 4) as we have into size buffer */
	    tocopy = (inputlen > text->needsize) ? text->needsize : inputlen;
	    ofc_memcpy(text->sizebuf + 4 - text->needsize, input, tocopy);
	    text->needsize -= tocopy;
	
	    input += tocopy;
	    inputlen -= tocopy;
	
	    if (!text->needsize) { /* we have the entire 4-byte size */
		ofc_memcpy(&(text->size), text->sizebuf, 4);
		text->size = OFC_NET_NTOL(&text->size,0) ;
	
		if (!text->size) /* should never happen */
		    return SASL_FAIL;
	    
		if (text->size > text->in_maxbuf) {
		    text->utils->log(OFC_NULL, SASL_LOG_ERR, 
				     "encoded packet size too big (%d > %d)",
				     text->size, text->in_maxbuf);
		    return SASL_FAIL;
		}
	    
		if (!text->buffer)
		    text->buffer = text->utils->malloc(text->in_maxbuf);
		if (text->buffer == OFC_NULL) return SASL_NOMEM;

		text->cursize = 0;
	    } else {
		/* We do NOT have the entire 4-byte size...
		 * wait for more data */
		return SASL_OK;
	    }
	}

	diff = text->size - text->cursize; /* bytes needed for full packet */

	if (inputlen < diff) {	/* not a complete packet, need more input */
	    ofc_memcpy(text->buffer + text->cursize, input, inputlen);
	    text->cursize += inputlen;
	    return SASL_OK;
	}

	/* copy the rest of the packet */
	ofc_memcpy(text->buffer + text->cursize, input, diff);
	input += diff;
	inputlen -= diff;

	/* decode the packet (no need to free tmp) */
	ret = decode_pkt(rock, text->buffer, text->size, &tmp, &tmplen);
	if (ret != SASL_OK) return ret;

	/* append the decoded packet to the output */
	ret = of_security_plug_buf_alloc(text->utils, output, outputsize,
			      *outputlen + tmplen + 1); /* +1 for NUL */
	if (ret != SASL_OK) return ret;

	ofc_memcpy(*output + *outputlen, tmp, tmplen);
	*outputlen += tmplen;

	/* protect stupid clients */
	*(*output + *outputlen) = '\0';

	/* reset for the next packet */
	text->needsize = 4;
    }

    return SASL_OK;    
}

OFC_VOID of_security_plug_decode_free(decode_context_t *text)
{
    if (text->buffer) text->utils->free(text->buffer);
}

