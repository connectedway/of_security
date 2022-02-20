/* SASL server API implementation
 * Rob Siemborski
 * Tim Martin
 * $Id: checkpw.c,v 1.79 2009/05/08 00:43:44 murch Exp $
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

/* checkpw stuff */

#include "of_security/sasl.h"
#include "of_security/saslutil.h"
#include "of_security/saslplug.h"
#include "of_security/saslint.h"

/* we store the following secret to check plaintext passwords:
 *
 * <salt> \0 <secret>
 *
 * where <secret> = MD5(<salt>, "sasldb", <pass>)
 */
static int of_security_make_plain_secret(const char *salt, 
				   const char *passwd, size_t passlen,
				   sasl_secret_t **secret)
{
    MD5_CTX ctx;
    unsigned sec_len = 16 + 1 + 16; /* salt + "\0" + hash */

    *secret = (sasl_secret_t *) sasl_ALLOC(sizeof(sasl_secret_t) +
					   sec_len * sizeof(char));
    if (*secret == NULL) {
	return SASL_NOMEM;
    }

    of_security_MD5Init(&ctx);
    of_security_MD5Update(&ctx, (const unsigned char *) salt, 16);
    of_security_MD5Update(&ctx, (const unsigned char *) "sasldb", 6);
    of_security_MD5Update(&ctx, (const unsigned char *) passwd, (unsigned int) passlen);
    ofc_memcpy((*secret)->data, salt, 16);
    (*secret)->data[16] = '\0';
    of_security_MD5Final((*secret)->data + 17, &ctx);
    (*secret)->len = sec_len;
    
    return SASL_OK;
}

/* verify user password using auxprop plugins
 */
static int auxprop_verify_password(sasl_conn_t *conn,
				   const char *userstr,
				   const char *passwd,
				   const char *service,
				   const char *user_realm)
{
    int ret = SASL_FAIL;
    int result = SASL_OK;
    sasl_server_conn_t *sconn = (sasl_server_conn_t *)conn;
    const char *password_request[] = { SASL_AUX_PASSWORD,
				       "*cmusaslsecretPLAIN",
				       NULL };
    struct propval auxprop_values[3];
    
    if (!conn || !userstr)
	return SASL_BADPARAM;

    /* We need to clear any previous results and re-canonify to 
     * ensure correctness */

    of_security_prop_clear (sconn->sparams->propctx, 0);
	
    /* ensure its requested */
    result = of_security_prop_request(sconn->sparams->propctx, password_request);

    if(result != SASL_OK) return result;

    result = of_security_canon_user_lookup (conn,
				      userstr,
				      0,
				      SASL_CU_AUTHID | SASL_CU_AUTHZID,
				      &(conn->oparams));
    if(result != SASL_OK) return result;
    
    result = of_security_prop_getnames(sconn->sparams->propctx, password_request,
			   auxprop_values);
    if (result < 0) {
	return result;
    }

    /* Verify that the returned <name>s are correct.
       But we defer checking for NULL values till after we verify
       that a passwd is specified. */
    if (!auxprop_values[0].name && !auxprop_values[1].name) {
	return SASL_NOUSER;
    }
        
    /* It is possible for us to get useful information out of just
     * the lookup, so we won't check that we have a password until now */
    if(!passwd) {
	ret = SASL_BADPARAM;
	goto done;
    }

    if ((!auxprop_values[0].values || !auxprop_values[0].values[0])
	&& (!auxprop_values[1].values || !auxprop_values[1].values[0])) {
	return SASL_NOUSER;
    }
        
    /* At the point this has been called, the username has been canonified
     * and we've done the auxprop lookup.  This should be easy. */
    if(auxprop_values[0].name
       && auxprop_values[0].values
       && auxprop_values[0].values[0]
       && !ofc_strcmp(auxprop_values[0].values[0], passwd)) {
	/* We have a plaintext version and it matched! */
	return SASL_OK;
    } else if(auxprop_values[1].name
	      && auxprop_values[1].values
	      && auxprop_values[1].values[0]) {
	const char *db_secret = auxprop_values[1].values[0];
	sasl_secret_t *construct;
	
	ret = of_security_make_plain_secret(db_secret, passwd,
				      ofc_strlen(passwd),
				      &construct);
	if (ret != SASL_OK) {
	    goto done;
	}

	if (!ofc_memcmp(db_secret, construct->data, construct->len)) {
	    /* password verified! */
	    ret = SASL_OK;
	} else {
	    /* passwords do not match */
	    ret = SASL_BADAUTH;
	}

	sasl_FREE(construct);
    } else {
	/* passwords do not match */
	ret = SASL_BADAUTH;
    }

    /* erase the plaintext password */
    sconn->sparams->utils->prop_erase(sconn->sparams->propctx,
				      password_request[0]);

 done:
    /* We're not going to erase the property here because other people
     * may want it */
    return ret;
}

/* Verify user password using auxprop plugins. Allow verification against a hashed password,
 * or non-retrievable password. Don't use cmusaslsecretPLAIN attribute.
 *
 * This function is similar to auxprop_verify_password().
 */
static int auxprop_verify_password_hashed(sasl_conn_t *conn,
					  const char *userstr,
					  const char *passwd,
					  const char *service,
					  const char *user_realm)
{
    int ret = SASL_FAIL;
    int result = SASL_OK;
    sasl_server_conn_t *sconn = (sasl_server_conn_t *)conn;
    const char *password_request[] = { SASL_AUX_PASSWORD,
				       NULL };
    struct propval auxprop_values[2];
    unsigned extra_cu_flags = 0;

    if (!conn || !userstr)
	return SASL_BADPARAM;

    /* We need to clear any previous results and re-canonify to 
     * ensure correctness */

    of_security_prop_clear(sconn->sparams->propctx, 0);
	
    /* ensure its requested */
    result = of_security_prop_request(sconn->sparams->propctx, password_request);

    if (result != SASL_OK) return result;

    /* We need to pass "password" down to the auxprop_lookup */
    /* NB: We don't support binary passwords */
    if (passwd != NULL) {
	of_security_prop_set (sconn->sparams->propctx,
		  SASL_AUX_PASSWORD,
		  passwd,
		  -1);
	extra_cu_flags = SASL_CU_VERIFY_AGAINST_HASH;
    }

    result = of_security_canon_user_lookup (conn,
				      userstr,
				      0,
				      SASL_CU_AUTHID | SASL_CU_AUTHZID | extra_cu_flags,
				      &(conn->oparams));

    if (result != SASL_OK) return result;
    
    result = of_security_prop_getnames(sconn->sparams->propctx, password_request,
			   auxprop_values);
    if (result < 0) {
	return result;
    }

    /* Verify that the returned <name>s are correct.
       But we defer checking for NULL values till after we verify
       that a passwd is specified. */
    if (!auxprop_values[0].name && !auxprop_values[1].name) {
	return SASL_NOUSER;
    }
        
    /* It is possible for us to get useful information out of just
     * the lookup, so we won't check that we have a password until now */
    if (!passwd) {
	ret = SASL_BADPARAM;
	goto done;
    }

    if ((!auxprop_values[0].values || !auxprop_values[0].values[0])) {
	return SASL_NOUSER;
    }

    /* At the point this has been called, the username has been canonified
     * and we've done the auxprop lookup.  This should be easy. */

    /* NB: Note that if auxprop_lookup failed to verify the password,
       then the userPassword property value would be NULL */
    if (auxprop_values[0].name
        && auxprop_values[0].values
        && auxprop_values[0].values[0]
        && !ofc_strcmp(auxprop_values[0].values[0], passwd)) {
	/* We have a plaintext version and it matched! */
	return SASL_OK;
    } else {
	/* passwords do not match */
	ret = SASL_BADAUTH;
    }

 done:
    /* We're not going to erase the property here because other people
     * may want it */
    return ret;
}

#ifdef DO_SASL_CHECKAPOP
int of_security_auxprop_verify_apop(sasl_conn_t *conn,
			      const char *userstr,
			      const char *challenge,
			      const char *response,
				   const char *user_realm)
{
    int ret = SASL_BADAUTH;
    char *userid = NULL;
    char *realm = NULL;
    unsigned char digest[16];
    char digeststr[33];
    const char *password_request[] = { SASL_AUX_PASSWORD, NULL };
    struct propval auxprop_values[2];
    sasl_server_conn_t *sconn = (sasl_server_conn_t *)conn;
    MD5_CTX ctx;
    int i;

    if (!conn || !userstr || !challenge || !response)
       PARAMERROR(conn)

    /* We've done the auxprop lookup already (in our caller) */
    /* sadly, APOP has no provision for storing secrets */
    ret = of_security_prop_getnames(sconn->sparams->propctx, password_request,
			auxprop_values);
    if(ret < 0) {
	of_security_seterror(conn, 0, "could not perform password lookup");
	goto done;
    }
    
    if(!auxprop_values[0].name ||
       !auxprop_values[0].values ||
       !auxprop_values[0].values[0]) {
	of_security_seterror(conn, 0, "could not find password");
	ret = SASL_NOUSER;
	goto done;
    }
    
    of_security_MD5Init(&ctx);
    of_security_MD5Update(&ctx, challenge, ofc_strlen(challenge));
    of_security_MD5Update(&ctx, auxprop_values[0].values[0],
			 ofc_strlen(auxprop_values[0].values[0]));
    of_security_MD5Final(digest, &ctx);

    /* erase the plaintext password */
    sconn->sparams->utils->prop_erase(sconn->sparams->propctx,
				      password_request[0]);

    /* convert digest from binary to ASCII hex */
    for (i = 0; i < 16; i++)
      ofc_sprintf(digeststr + (i*2), "%02x", digest[i]);

    if (!ofc_strncasecmp(digeststr, response, 32)) {
      /* password verified! */
      ret = SASL_OK;
    } else {
      /* passwords do not match */
      ret = SASL_BADAUTH;
    }

 done:
    if (ret == SASL_BADAUTH) of_security_seterror(conn, SASL_NOLOG,
					   "login incorrect");
    if (userid) sasl_FREE(userid);
    if (realm)  sasl_FREE(realm);

    return ret;
}
#endif /* DO_SASL_CHECKAPOP */

#ifdef HAVE_ALWAYSTRUE
static int always_true(sasl_conn_t *conn,
		       const char *userstr,
		       const char *passwd,
		       const char *service,
		       const char *user_realm)
{
    _sasl_log(conn, SASL_LOG_WARN, "AlwaysTrue Password Verifier Verified: %s",
	      userstr);
    return SASL_OK;
}
#endif

struct sasl_verify_password_s of_security_verify_password[] = {
    { "auxprop", &auxprop_verify_password },
    { "auxprop-hashed", &auxprop_verify_password_hashed },
#ifdef HAVE_ALWAYSTRUE
    { "alwaystrue", &always_true },
#endif
    { NULL, NULL }
};
