/* SASL server API implementation
 * Rob Siemborski
 * Tim Martin
 * $Id: sasldb.c,v 1.17 2009/03/10 14:37:03 mel Exp $
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

/* sasldb stuff */

#include "ofc/libc.h"
#include "ofc/heap.h"
#include "ofc/persist.h"
#include "of_smb/persist.h"

#include "of_security/sasl.h"
#include "of_security/saslutil.h"
#include "of_security/saslplug.h"

#include "of_security/plugin_common.h"

static int of_security_db_getdata(const sasl_utils_t *utils,
			   sasl_conn_t *conn,
			   const char *authid,
			   const char *realm,
			   const char *propName,
			   char *out,
			   const OFC_SIZET max_out,
			   OFC_SIZET *out_len)
{
  OFC_CHAR *cstrPass ;
  OFC_CHAR *cstrUser ;
  OFC_CTCHAR *tstrPass ;
  OFC_CTCHAR *tstrUser ;
  int ret ;

  cstrPass = OFC_NULL ;

#if defined(OF_SMB_SERVER)
  if (ofc_strcmp (propName, "userPassword") == 0)
    {
      of_smb_persist_auth_username(&tstrUser);
      cstrUser = ofc_tstr2cstr (tstrUser) ;
      if (ofc_strcmp (authid, cstrUser) == 0)
	{
	  of_smb_persist_auth_server(&tstrPass) ;
	  cstrPass = ofc_tstr2cstr (tstrPass) ;
	}
      ofc_free(cstrUser) ;
    }
#endif
  
  if (cstrPass != OFC_NULL)
    {
      *out_len = OFC_MIN(max_out, ofc_strlen (cstrPass)) ;
      ofc_strncpy (out, cstrPass, *out_len) ;
      ofc_free(cstrPass) ;
      ret = SASL_OK ;
    }
  else
    ret = SASL_NOUSER ;
  return (ret) ;
}

static int of_security_db_putdata(const sasl_utils_t *utils,
			   sasl_conn_t *conn,
			   const char *authid,
			   const char *realm,
			   const char *propName,
			   const char *data,
			   OFC_SIZET data_len)
{
    return SASL_OK;
}

static int of_security_check_db(const sasl_utils_t *utils,
			  sasl_conn_t *conn)
{
    return SASL_OK;
}

static int of_security_db_auxprop_lookup(void *glob_context,
				  sasl_server_params_t *sparams,
				  unsigned flags,
				  const char *user,
				  unsigned ulen) 
{
    char *userid = OFC_NULL;
    char *realm = OFC_NULL;
    const char *user_realm = OFC_NULL;
    int ret;
    const struct propval *to_fetch, *cur;
    char value[8192];
    OFC_SIZET value_len;
    char *user_buf;
    int verify_against_hashed_password;
    int saw_user_password = 0;

    if (!sparams || !user) return SASL_BADPARAM;

    user_buf = sparams->utils->malloc(ulen + 1);
    if(!user_buf) {
	ret = SASL_NOMEM;
	goto done;
    }

    ofc_memcpy(user_buf, user, ulen);
    user_buf[ulen] = '\0';

    if(sparams->user_realm) {
	user_realm = sparams->user_realm;
    } else {
	user_realm = sparams->serverFQDN;
    }

    ret = of_security_plug_parseuser(sparams->utils, &userid, &realm, user_realm,
			  sparams->serverFQDN, user_buf);
    if(ret != SASL_OK) goto done;

    to_fetch = sparams->utils->prop_get(sparams->propctx);
    if (!to_fetch) {
	ret = SASL_NOMEM;
	goto done;
    }

    verify_against_hashed_password = flags & SASL_AUXPROP_VERIFY_AGAINST_HASH;

    /* Use a fake value to signal that we have no property to lookup */
    ret = SASL_CONTINUE;
    for(cur = to_fetch; cur->name; cur++) {
	int cur_ret;
	const char *realname = cur->name;
	
	/* Only look up properties that apply to this lookup! */
	if(cur->name[0] == '*' && (flags & SASL_AUXPROP_AUTHZID)) continue;
	if(!(flags & SASL_AUXPROP_AUTHZID)) {
	    if(cur->name[0] != '*') continue;
	    else realname = cur->name + 1;
	}
	
	/* If it's there already, we want to see if it needs to be
	 * overridden. userPassword is a special case, because it's value
	   is always present if SASL_AUXPROP_VERIFY_AGAINST_HASH is specified.
	   When SASL_AUXPROP_VERIFY_AGAINST_HASH is set, we just clear userPassword. */
	if (cur->values && !(flags & SASL_AUXPROP_OVERRIDE) &&
	    (verify_against_hashed_password == 0 ||
	     ofc_strcasecmp(realname, SASL_AUX_PASSWORD_PROP) != 0)) {
	    continue;
	} else if (cur->values) {
	    sparams->utils->prop_erase(sparams->propctx, cur->name);
	}

	if (ofc_strcasecmp(realname, SASL_AUX_PASSWORD_PROP) == 0) {
	    saw_user_password = 1;
	}

	cur_ret = of_security_db_getdata(sparams->utils,
			      sparams->utils->conn, userid, realm,
			      realname, value, sizeof(value), &value_len);

	/* Assumption: cur_ret is never SASL_CONTINUE */

	/* If this is the first property we've tried to fetch ==>
	   always set the global error code.
	   If we had SASL_NOUSER ==> any other error code overrides it
	   (including SASL_NOUSER). */
	if (ret == SASL_CONTINUE || ret == SASL_NOUSER) {
	    ret = cur_ret;
	} else if (ret == SASL_OK) {
	    /* Any error code other than SASL_NOUSER overrides SASL_OK.
	       (And SASL_OK overrides SASL_OK as well) */
	    if (cur_ret != SASL_NOUSER) {
		ret = cur_ret;
	    }
	}
	/* Any other global error code is left as is */

	if (cur_ret != SASL_OK) {
	    if (cur_ret != SASL_NOUSER) {
		/* No point in continuing if we hit any serious error */
		break;
	    }
	    /* We didn't find it, leave it as not found */
	    continue;
	}

	sparams->utils->prop_set(sparams->propctx, cur->name,
				 value, (unsigned) value_len);
    }

    /* [Keep in sync with LDAPDB, SQL]
       If ret is SASL_CONTINUE, it means that no properties were requested
       (or maybe some were requested, but they already have values and
       SASL_AUXPROP_OVERRIDE flag is not set).
       Always return SASL_OK in this case. */
    if (ret == SASL_CONTINUE) {
        ret = SASL_OK;
    }

    if (flags & SASL_AUXPROP_AUTHZID) {
	/* This is a lie, but the caller can't handle
	   when we return SASL_NOUSER for authorization identity lookup. */
	if (ret == SASL_NOUSER) {
	    ret = SASL_OK;
	}
    } else {
	if (ret == SASL_NOUSER && saw_user_password == 0) {
	    /* Verify user existence by checking presence of
	       the userPassword attribute */
	    ret = of_security_db_getdata(sparams->utils,
				  sparams->utils->conn,
				  userid,
				  realm,
				  SASL_AUX_PASSWORD_PROP,
				  value,
				  sizeof(value),
				  &value_len);
	}
    }

 done:
    if (userid) sparams->utils->free(userid);
    if (realm)  sparams->utils->free(realm);
    if (user_buf) sparams->utils->free(user_buf);

    return ret;
}

static int of_security_db_auxprop_store(void *glob_context,
				sasl_server_params_t *sparams,
				struct propctx *ctx,
				const char *user,
				unsigned ulen) 
{
    char *userid = OFC_NULL;
    char *realm = OFC_NULL;
    const char *user_realm = OFC_NULL;
    int ret = SASL_FAIL;
    const struct propval *to_store, *cur;
    char *user_buf;

    /* just checking if we are enabled */
    if(!ctx) return SASL_OK;
    
    if(!sparams || !user) return SASL_BADPARAM;

    user_buf = sparams->utils->malloc(ulen + 1);
    if(!user_buf) {
	ret = SASL_NOMEM;
	goto done;
    }

    ofc_memcpy(user_buf, user, ulen);
    user_buf[ulen] = '\0';

    if(sparams->user_realm) {
	user_realm = sparams->user_realm;
    } else {
	user_realm = sparams->serverFQDN;
    }

    ret = of_security_plug_parseuser(sparams->utils, &userid, &realm, user_realm,
			  sparams->serverFQDN, user_buf);
    if(ret != SASL_OK) goto done;

    to_store = sparams->utils->prop_get(ctx);
    if(!to_store) {
	ret = SASL_BADPARAM;
	goto done;
    }

    ret = SASL_OK;
    for (cur = to_store; cur->name; cur++) {
	const char * value = (cur->values && cur->values[0]) ? cur->values[0] : OFC_NULL;

	if (cur->name[0] == '*') {
	    continue;
	}

	/* WARN: We only support one value right now. */
	ret = of_security_db_putdata(sparams->utils,
			      sparams->utils->conn,
			      userid,
			      realm,
			      cur->name,
			      value,
			      value ? ofc_strlen(value) : 0);

	if (value == OFC_NULL && ret == SASL_NOUSER) {
	    /* Deleting something which is not there is not an error */
	    ret = SASL_OK;
	}

	if (ret != SASL_OK) {
	    /* We've already failed, no point in continuing */
	    break;
	}
    }

 done:
    if (userid) sparams->utils->free(userid);
    if (realm)  sparams->utils->free(realm);
    if (user_buf) sparams->utils->free(user_buf);

    return ret;
}

static sasl_auxprop_plug_t of_security_db_auxprop_plugin = {
    0,           		/* Features */
    0,           		/* spare */
    OFC_NULL,        		/* glob_context */
    OFC_NULL,			/* auxprop_free */
    of_security_db_auxprop_lookup,	/* auxprop_lookup */
    "of_security_db",			/* name */
    of_security_db_auxprop_store	/* auxprop_store */
};

int of_security_db_auxprop_plug_init(const sasl_utils_t *utils,
                             int max_version,
                             int *out_version,
                             sasl_auxprop_plug_t **plug,
                             const char *plugname)
{
    if(!out_version || !plug) return SASL_BADPARAM;

    /* Do we have database support? */
    /* Note that we can use a NULL sasl_conn_t because our
     * sasl_utils_t is "blessed" with the global callbacks */
    if(of_security_check_db(utils, OFC_NULL) != SASL_OK)
	return SASL_NOMECH;

    /* Check if libsasl API is older than ours. If it is, fail */
    if(max_version < SASL_AUXPROP_PLUG_VERSION) return SASL_BADVERS;
    
    *out_version = SASL_AUXPROP_PLUG_VERSION;

    *plug = &of_security_db_auxprop_plugin;

    return SASL_OK;
}
