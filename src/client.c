/* SASL client API implementation
 * Rob Siemborski
 * Tim Martin
 * $Id: client.c,v 1.86 2011/09/01 14:12:53 mel Exp $
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

/* SASL Headers */
#define LIBSASL_EXPORTS

#include "ofc/config.h"
#include "of_security/sasl.h"
#include "of_security/saslplug.h"
#include "of_security/saslutil.h"
#include "of_security/saslint.h"

static cmech_list_t *cmechlist; /* global var which holds the list */
sasl_global_callbacks_t of_security_global_callbacks_client; 
static int _sasl_client_active = 0;
extern sasl_client_plug_init_t of_security_ntlm_client_plug_init; ;
#if defined(OFC_KERBEROS)
extern sasl_client_plug_init_t of_security_kerberos_client_plug_init; ;
#endif
extern sasl_client_plug_init_t of_security_gssapiv2_client_plug_init; ;

static int init_mechlist()
{
  cmechlist->utils=of_security_alloc_utils(OFC_NULL, 
					  &of_security_global_callbacks_client);
  if (cmechlist->utils==OFC_NULL)
    return SASL_NOMEM;

  cmechlist->mech_list=OFC_NULL;
  cmechlist->mech_length=0;

  return SASL_OK;
}

int of_security_client_done(void)
{
    int result = SASL_CONTINUE;

    if (of_security_server_cleanup_hook == OFC_NULL && 
	of_security_client_cleanup_hook == OFC_NULL) {
	return SASL_NOTINIT;
    }

    if (of_security_client_cleanup_hook) {
	result = of_security_client_cleanup_hook();
	
	if (result == SASL_OK) {
	    of_security_client_idle_hook = OFC_NULL;	
	    of_security_client_cleanup_hook = OFC_NULL;
	} else {
	    return result;
	}
    }
    
    if (of_security_server_cleanup_hook || of_security_client_cleanup_hook) {
	return result;
    }
    
    of_security_common_done();

    return SASL_OK;
}

static int client_done(void) {
    cmechanism_t *cm;
    cmechanism_t *cprevm;

    if (!_sasl_client_active) {
	return SASL_NOTINIT;
    } else {
	_sasl_client_active--;
    }

    if(_sasl_client_active) {
	/* Don't de-init yet! Our refcount is nonzero. */
	return SASL_CONTINUE;
    }

    cm = cmechlist->mech_list; /* m point to beginning of the list */
    while (cm != OFC_NULL) {
	cprevm = cm;
	cm = cm->next;

	if (cprevm->m.plug->mech_free) {
	    cprevm->m.plug->mech_free(cprevm->m.plug->glob_context,
				      cmechlist->utils);
	}

	sasl_FREE(cprevm->m.plugname);
	sasl_FREE(cprevm);    
    }
    of_security_free_utils(&cmechlist->utils);
    sasl_FREE(cmechlist);

    cmechlist = OFC_NULL;

    return SASL_OK;
}

/* This is nearly identical to the version in server.c.
   Keep in sync. */
static int mech_compare(const sasl_client_plug_t *a,
			const sasl_client_plug_t *b)
{
    unsigned sec_diff;
    unsigned features_diff;

    /* XXX  the following is fairly arbitrary, but its independent
       of the order in which the plugins are loaded
    */
    sec_diff = a->security_flags ^ b->security_flags;
    if (sec_diff & a->security_flags & SASL_SEC_NOANONYMOUS) return 1;
    if (sec_diff & b->security_flags & SASL_SEC_NOANONYMOUS) return -1;
    if (sec_diff & a->security_flags & SASL_SEC_NOPLAINTEXT) return 1;
    if (sec_diff & b->security_flags & SASL_SEC_NOPLAINTEXT) return -1;
    if (sec_diff & a->security_flags & SASL_SEC_MUTUAL_AUTH) return 1;
    if (sec_diff & b->security_flags & SASL_SEC_MUTUAL_AUTH) return -1;
    if (sec_diff & a->security_flags & SASL_SEC_NOACTIVE) return 1;
    if (sec_diff & b->security_flags & SASL_SEC_NOACTIVE) return -1;
    if (sec_diff & a->security_flags & SASL_SEC_NODICTIONARY) return 1;
    if (sec_diff & b->security_flags & SASL_SEC_NODICTIONARY) return -1;
    if (sec_diff & a->security_flags & SASL_SEC_FORWARD_SECRECY) return 1;
    if (sec_diff & b->security_flags & SASL_SEC_FORWARD_SECRECY) return -1;

    features_diff = a->features ^ b->features;
    if (features_diff & a->features & SASL_FEAT_CHANNEL_BINDING) return 1;
    if (features_diff & b->features & SASL_FEAT_CHANNEL_BINDING) return -1;

    if (a->max_ssf > b->max_ssf) return 1;
    if (a->max_ssf < b->max_ssf) return -1;
  
    return 0;
}

int of_security_client_add_plugin(const char *plugname,
				sasl_client_plug_init_t *entry_point)
{
    int plugcount;
    sasl_client_plug_t *pluglist;
    cmechanism_t *mech, *mp;
    int result;
    int version;
    int lupe;

    if (!plugname || !entry_point) return SASL_BADPARAM;

    result = entry_point(cmechlist->utils,
			 SASL_CLIENT_PLUG_VERSION,
			 &version,
			 &pluglist,
			 &plugcount);

    if (result != SASL_OK)
    {
	of_security_log(OFC_NULL, SASL_LOG_WARN,
		       "entry_point failed in sasl_client_add_plugin for %s",
		       plugname);
	return result;
    }

    if (version != SASL_CLIENT_PLUG_VERSION)
    {
	of_security_log(OFC_NULL, SASL_LOG_WARN,
		       "version conflict in sasl_client_add_plugin for %s", plugname);
	return SASL_BADVERS;
    }

    for (lupe=0; lupe < plugcount; lupe++, pluglist++)
    {
	mech = sasl_ALLOC(sizeof(cmechanism_t));
	if (!mech) return SASL_NOMEM;

	mech->m.plug = pluglist;
	if (of_security_strdup(plugname, &mech->m.plugname, 
			      OFC_NULL) != SASL_OK) {
	    sasl_FREE(mech);
	    return SASL_NOMEM;
	}
	mech->m.version = version;

	/* sort mech_list by relative "strength" */
	mp = cmechlist->mech_list;
	if (!mp || mech_compare(pluglist, mp->m.plug) >= 0) {
	    /* add mech to head of list */
	    mech->next = cmechlist->mech_list;
	    cmechlist->mech_list = mech;
	} else {
	    /* find where to insert mech into list */
	    while (mp->next &&
		   mech_compare(pluglist, mp->next->m.plug) <= 0) mp = mp->next;
	    mech->next = mp->next;
	    mp->next = mech;
	}

	cmechlist->mech_length++;
    }
    return SASL_OK;
}

static int
client_idle(sasl_conn_t *conn)
{
  cmechanism_t *m;
  if (! cmechlist)
    return 0;

  for (m = cmechlist->mech_list;
       m;
       m = m->next)
    if (m->m.plug->idle
	&&  m->m.plug->idle(m->m.plug->glob_context,
			  conn,
			  conn ? ((sasl_client_conn_t *)conn)->cparams : OFC_NULL))
      return 1;
  return 0;
}

/* initialize the SASL client drivers
 *  callbacks      -- base callbacks for all client connections
 * returns:
 *  SASL_OK        -- Success
 *  SASL_NOMEM     -- Not enough memory
 *  SASL_BADVERS   -- Mechanism version mismatch
 *  SASL_BADPARAM  -- error in config file
 *  SASL_NOMECH    -- No mechanisms available
 *  ...
 */

int of_security_client_init(const sasl_callback_t *callbacks)
{
  int ret;
  /* lock allocation type */
  of_security_allocation_locked++;
  
  if(_sasl_client_active) {
      /* We're already active, just increase our refcount */
      /* xxx do something with the callback structure? */
      _sasl_client_active++;
      return SASL_OK;
  }

  of_security_global_callbacks_client.callbacks = callbacks;
  of_security_global_callbacks_client.appname = OFC_NULL;

  cmechlist=sasl_ALLOC(sizeof(cmech_list_t));
  if (cmechlist==OFC_NULL) return SASL_NOMEM;

  /* We need to call client_done if we fail now */
  _sasl_client_active = 1;

  /* load plugins */
  ret=init_mechlist();  
  if (ret!=SASL_OK) {
      client_done();
      return ret;
  }

  ret = of_security_common_init(&of_security_global_callbacks_client);

#if defined(OFC_KERBEROS)
  if (ret == SASL_OK)
    {
      ret = of_security_client_add_plugin ("kerberos", of_security_kerberos_client_plug_init) ;
    }
#endif

  if (ret == SASL_OK)
    {
      ret = of_security_client_add_plugin ("ntlm", of_security_ntlm_client_plug_init) ;
    }

  if (ret == SASL_OK)
    {
      ret = of_security_client_add_plugin ("gssapi", 
					 of_security_gssapiv2_client_plug_init);
    }

  if (ret == SASL_OK) {
      of_security_client_cleanup_hook = &client_done;
      of_security_client_idle_hook = &client_idle;

      ret = of_security_build_mechlist();
  } else {
      client_done();
  }
      
  return ret;
}

static void client_dispose(sasl_conn_t *pconn)
{
  sasl_client_conn_t *c_conn=(sasl_client_conn_t *) pconn;

  if (c_conn->mech && c_conn->mech->m.plug->mech_dispose) {
    c_conn->mech->m.plug->mech_dispose(pconn->context,
				     c_conn->cparams->utils);
  }

  pconn->context = OFC_NULL;

  if (c_conn->clientFQDN)
      sasl_FREE(c_conn->clientFQDN);

  if (c_conn->cparams) {
      of_security_free_utils(&(c_conn->cparams->utils));
      sasl_FREE(c_conn->cparams);
  }

  if (c_conn->mech_list != cmechlist->mech_list) {
      /* free connection-specific mech_list */
      cmechanism_t *m, *prevm;

      m = c_conn->mech_list; /* m point to beginning of the list */

      while (m) {
	  prevm = m;
	  m = m->next;
	  sasl_FREE(prevm);    
      }
  }

  of_security_conn_dispose(pconn);
}

/* initialize a client exchange based on the specified mechanism
 *  service       -- registered name of the service using SASL (e.g. "imap")
 *  serverFQDN    -- the fully qualified domain name of the server
 *  iplocalport   -- client IPv4/IPv6 domain literal string with port
 *                    (if NULL, then mechanisms requiring IPaddr are disabled)
 *  ipremoteport  -- server IPv4/IPv6 domain literal string with port
 *                    (if NULL, then mechanisms requiring IPaddr are disabled)
 *  prompt_supp   -- list of client interactions supported
 *                   may also include sasl_getopt_t context & call
 *                   NULL prompt_supp = user/pass via SASL_INTERACT only
 *                   NULL proc = interaction supported via SASL_INTERACT
 *  secflags      -- security flags (see above)
 * in/out:
 *  pconn         -- connection negotiation structure
 *                   pointer to NULL => allocate new
 *                   non-NULL => recycle storage and go for next available mech
 *
 * Returns:
 *  SASL_OK       -- success
 *  SASL_NOMECH   -- no mechanism meets requested properties
 *  SASL_NOMEM    -- not enough memory
 */
int of_security_client_new(const char *service,
			 const char *serverFQDN,
			 const char *iplocalport,
			 const char *ipremoteport,
			 const sasl_callback_t *prompt_supp,
			 unsigned flags,
			 sasl_conn_t **pconn)
{
  int result;
  char name[OFC_MAX_PATH];
  sasl_client_conn_t *conn;
  sasl_utils_t *utils;
  sasl_getopt_t *getopt;
  void *context;
  const char *mlist = OFC_NULL;
  int plus = 0;

  if (_sasl_client_active == 0) return SASL_NOTINIT;
  
  /* Remember, serverFQDN, iplocalport and ipremoteport can be OFC_NULL and be valid! */
  if (!pconn || !service)
    return SASL_BADPARAM;

  *pconn=sasl_ALLOC(sizeof(sasl_client_conn_t));
  if (*pconn==OFC_NULL) {
      of_security_log(OFC_NULL, SASL_LOG_ERR,
		     "Out of memory allocating connection context");
      return SASL_NOMEM;
  }
  ofc_memset(*pconn, 0, sizeof(sasl_client_conn_t));

  (*pconn)->destroy_conn = &client_dispose;

  conn = (sasl_client_conn_t *)*pconn;
  
  conn->mech = OFC_NULL;

  conn->cparams=sasl_ALLOC(sizeof(sasl_client_params_t));
  if (conn->cparams==OFC_NULL) 
      MEMERROR(*pconn);
  ofc_memset(conn->cparams,0,sizeof(sasl_client_params_t));

  result = of_security_conn_init(*pconn, service, flags, SASL_CONN_CLIENT,
				&client_idle, serverFQDN,
				iplocalport, ipremoteport,
				prompt_supp, &of_security_global_callbacks_client);
  if (result != SASL_OK) RETURN(*pconn, result);
  
  utils = of_security_alloc_utils(*pconn, &of_security_global_callbacks_client);
  if (utils == OFC_NULL) {
      MEMERROR(*pconn);
  }
  
  utils->conn= *pconn;
  conn->cparams->utils = utils;

  if(of_security_getcallback(*pconn, SASL_CB_GETOPT, 
			    (sasl_callback_ft *)&getopt, 
			    &context) == SASL_OK) {
    getopt(context, OFC_NULL, "client_mech_list", &mlist, OFC_NULL);
  }

  /* if we have a client_mech_list, create ordered list of
     available mechanisms for this conn */
  if (mlist) {
      const char *cp;
      cmechanism_t *mptr, *tail = OFC_NULL;
      cmechanism_t *new;

      while (*mlist) {
	  /* find end of current mech name */
	  for (cp = mlist; *cp && !OFC_ISSPACE((int) *cp); cp++);

	  /* search for mech name in loaded plugins */
	  for (mptr = cmechlist->mech_list; mptr; mptr = mptr->next) {
	      const sasl_client_plug_t *plug = mptr->m.plug;

	      if (of_security_is_equal_mech(mlist, 
					   plug->mech_name, 
					   (OFC_SIZET) (cp - mlist), 
					   &plus)) {
		  /* found a match */
		  break;
	      }
	  }
	  if (mptr) {
	      new = sasl_ALLOC(sizeof(cmechanism_t));
	      if (!new) {
		  result = SASL_NOMEM;
		  goto failed_client_new;
	      }
	      ofc_memcpy(&new->m, &mptr->m, sizeof(client_sasl_mechanism_t));
	      new->next = OFC_NULL;

	      if (!conn->mech_list) {
		  conn->mech_list = new;
		  tail = conn->mech_list;
	      } else {
		  tail->next = new;
		  tail = new;
	      }
	      conn->mech_length++;
	  }

	  /* find next mech name */
	  mlist = cp;
	  while (*mlist && OFC_ISSPACE((int) *mlist)) mlist++;
      }
  } else {
      conn->mech_list = cmechlist->mech_list;
      conn->mech_length = cmechlist->mech_length;
  }

  if (conn->mech_list == OFC_NULL) {
      of_security_seterror(*pconn, 0, "No worthy mechs found");
      result = SASL_NOMECH;
      goto failed_client_new;
  }

  /* Setup the non-lazy parts of cparams, the rest is done in
   * sasl_client_start */
  conn->cparams->canon_user = &of_security_canon_user_lookup;
  conn->cparams->flags = flags;
  conn->cparams->prompt_supp = (*pconn)->callbacks;
  
  /* get the clientFQDN (serverFQDN was set in _sasl_conn_init) */
  ofc_memset(name, 0, sizeof(name));
  if (of_security_get_fqhostname (name, OFC_MAX_PATH, 0) != 0) {
      return (SASL_FAIL);
  }

  result = of_security_strdup(name, &conn->clientFQDN, OFC_NULL);

  if (result == SASL_OK) return SASL_OK;

failed_client_new:
  /* result isn't SASL_OK */
  of_security_conn_dispose(*pconn);
  sasl_FREE(*pconn);
  *pconn = OFC_NULL;
  of_security_log(OFC_NULL, SASL_LOG_ERR, "Out of memory in sasl_client_new");
  return result;
}

static int have_prompts(sasl_conn_t *conn,
			const sasl_client_plug_t *mech)
{
  static const unsigned long default_prompts[] = {
    SASL_CB_AUTHNAME,
    SASL_CB_PASS,
    SASL_CB_GETREALM,
    SASL_CB_TIMESTAMP,
    SASL_CB_LIST_END
  };

  const unsigned long *prompt;
  sasl_callback_ft pproc;
  void *pcontext;
  int result;

  for (prompt = (mech->required_prompts
		 ? mech->required_prompts :
		 default_prompts);
       *prompt != SASL_CB_LIST_END;
       prompt++) {
    result = of_security_getcallback(conn, *prompt, &pproc, &pcontext);
    if (result != SASL_OK && result != SASL_INTERACT)
      return 0;			/* we don't have this required prompt */
  }

  return 1; /* we have all the prompts */
}

static int
_mech_plus_p(const char *mech, OFC_SIZET len)
{
    return (len > 5 && ofc_strncasecmp(&mech[len - 5], "-PLUS", 5) == 0);
}

/*
 * Order PLUS mechanisms first. Returns NUL separated list of
 * *count items.
 */
static int
_sasl_client_order_mechs(const sasl_utils_t *utils,
			 const char *mechs,
			 int has_cb_data,
			 char **ordered_mechs,
			 OFC_SIZET *count,
			 int *server_can_cb)
{
    char *list, *listp;
    OFC_SIZET i, mechslen, start;

    *count = 0;
    *server_can_cb = 0;

    if (mechs == OFC_NULL || mechs[0] == '\0')
        return SASL_NOMECH;

    mechslen = ofc_strlen(mechs);

    listp = list = utils->malloc(mechslen + 1);
    if (list == OFC_NULL)
	return SASL_NOMEM;

    /* As per RFC 4422:
     * SASL mechanism allowable characters are "AZ-_"
     * separators can be any other characters and of any length
     * even variable lengths between.
     *
     * But for convenience we accept lowercase ASCII.
     *
     * Apps should be encouraged to simply use space or comma space
     * though
     */
#define ismechchar(c)   (OFC_ISALNUM((c)) || (c) == '_' || (c) == '-')
    do {
        for (i = start = 0; i <= mechslen; i++) {
	    if (!ismechchar(mechs[i])) {
                const char *mechp = &mechs[start];
		OFC_SIZET len = i - start;

		if (len != 0 &&
                    _mech_plus_p(mechp, len) == has_cb_data) {
		    ofc_memcpy(listp, mechp, len);
		    listp[len] = '\0';
		    listp += len + 1;
		    (*count)++;
		    if (*server_can_cb == 0 && has_cb_data)
			*server_can_cb = 1;
		}
		start = ++i;
	    }
	}
	if (has_cb_data)
	    has_cb_data = 0;
	else
	    break;
    } while (1);

    if (*count == 0) {
        utils->free(list);
        return SASL_NOMECH;
    }

    *ordered_mechs = list;

    return SASL_OK;
}

static INLINE int
_sasl_cbinding_disp(sasl_client_params_t *cparams,
                    int mech_nego,
                    int server_can_cb,
                    sasl_cbinding_disp_t *cbindingdisp)
{
    /*
     * If negotiating mechanisms, then we fail immediately if the
     * client requires channel binding and the server does not
     * advertise support. Otherwise we send "y" (which later will
     * become "p" if we select a supporting mechanism).
     *
     * If the client explicitly selected a mechanism, then we only
     * send channel bindings if they're marked critical.
     */

    *cbindingdisp = SASL_CB_DISP_NONE;

    if (SASL_CB_PRESENT(cparams)) {
        if (mech_nego) {
	    if (!server_can_cb && SASL_CB_CRITICAL(cparams)) {
	        return SASL_NOMECH;
	    } else {
                *cbindingdisp = SASL_CB_DISP_WANT;
	    }
        } else if (SASL_CB_CRITICAL(cparams)) {
            *cbindingdisp = SASL_CB_DISP_USED;
        }
    }

    return SASL_OK;
}

/* select a mechanism for a connection
 *  mechlist      -- mechanisms server has available (punctuation ignored)
 *  secret        -- optional secret from previous session
 * output:
 *  prompt_need   -- on SASL_INTERACT, list of prompts needed to continue
 *  clientout     -- the initial client response to send to the server
 *  mech          -- set to mechanism name
 *
 * Returns:
 *  SASL_OK       -- success
 *  SASL_NOMEM    -- not enough memory
 *  SASL_NOMECH   -- no mechanism meets requested properties
 *  SASL_INTERACT -- user interaction needed to fill in prompt_need list
 */

/*
 * SASL mechanism allowable characters are "AZ-_"
 * separators can be any other characters and of any length
 * even variable lengths between.
 *
 * But for convenience we accept lowercase ASCII.
 *
 * Apps should be encouraged to simply use space or comma space
 * though
 */
int of_security_client_start(sasl_conn_t *conn,
			   const char *mechlist,
			   sasl_interact_t **prompt_need,
			   const char **clientout,
			   unsigned *clientoutlen,
			   const char **mech)
{
    sasl_client_conn_t *c_conn = (sasl_client_conn_t *) conn;
    char *ordered_mechs = OFC_NULL, *name;
    cmechanism_t *m = OFC_NULL, *bestm = OFC_NULL;
    OFC_SIZET i, list_len, name_len;
    sasl_ssf_t bestssf = 0, minssf = 0;
    int result, server_can_cb = 0;
    sasl_cbinding_disp_t cbindingdisp;
    sasl_cbinding_disp_t cur_cbindingdisp;
    sasl_cbinding_disp_t best_cbindingdisp = SASL_CB_DISP_NONE;

    if (_sasl_client_active == 0) return SASL_NOTINIT;

    if (!conn) return SASL_BADPARAM;

    /* verify parameters */
    if (mechlist == OFC_NULL) {
	PARAMERROR(conn);
    }

    /* if prompt_need != OFC_NULL we've already been here
       and just need to do the continue step again */

    /* do a step */
    /* FIXME: Hopefully they only give us our own prompt_need back */
    if (prompt_need && *prompt_need != OFC_NULL) {
	goto dostep;
    }

    if (conn->props.min_ssf < conn->external.ssf) {
	minssf = 0;
    } else {
	minssf = conn->props.min_ssf - conn->external.ssf;
    }

    /* Order mechanisms so -PLUS are preferred */
    result = _sasl_client_order_mechs(c_conn->cparams->utils,
				      mechlist,
				      SASL_CB_PRESENT(c_conn->cparams),
				      &ordered_mechs,
				      &list_len,
				      &server_can_cb);
    if (result != 0)
	goto done;
  
    /*
     * Determine channel binding disposition based on whether we
     * are doing mechanism negotiation and whether server supports
     * channel bindings.
     */
    result = _sasl_cbinding_disp(c_conn->cparams,
				 (list_len > 1),
                                 server_can_cb,
				 &cbindingdisp);
    if (result != 0)
	goto done;

    for (i = 0, name = ordered_mechs; i < list_len; i++) {

	name_len = ofc_strlen(name);

	/* for each mechanism in client's list */
	for (m = c_conn->mech_list; m != OFC_NULL; m = m->next) {
	    int myflags, plus;

	    if (!of_security_is_equal_mech(name, 
					  m->m.plug->mech_name, 
					  name_len, &plus)) {
		continue;
	    }

	    /* Do we have the prompts for it? */
	    if (!have_prompts(conn, m->m.plug))
		break;

	    /* Is it strong enough? */
	    if (minssf > m->m.plug->max_ssf)
		break;

	    /* Does it meet our security properties? */
	    myflags = conn->props.security_flags;
	    
	    /* if there's an external layer this is no longer plaintext */
	    if ((conn->props.min_ssf <= conn->external.ssf) && 
		(conn->external.ssf > 1)) {
		myflags &= ~SASL_SEC_NOPLAINTEXT;
	    }

	    if (((myflags ^ m->m.plug->security_flags) & myflags) != 0) {
		break;
	    }

	    /* Can we meet it's features? */
	    if (cbindingdisp == SASL_CB_DISP_USED &&
		!(m->m.plug->features & SASL_FEAT_CHANNEL_BINDING)) {
		break;
	    }

	    if ((m->m.plug->features & SASL_FEAT_NEEDSERVERFQDN)
		&& !conn->serverFQDN) {
		break;
	    }

	    /* Can it meet our features? */
	    if ((conn->flags & SASL_NEED_PROXY) &&
		!(m->m.plug->features & SASL_FEAT_ALLOWS_PROXY)) {
		break;
	    }

	    if ((conn->flags & SASL_NEED_HTTP) &&
		!(m->m.plug->features & SASL_FEAT_SUPPORTS_HTTP)) {
		break;
	    }

	    /* compare security flags, only take new mechanism if it has
	     * all the security flags of the previous one.
	     *
	     * From the mechanisms we ship with, this yields the order:
	     *
	     * SRP
	     * GSSAPI + KERBEROS_V4
	     * DIGEST + OTP
	     * CRAM + EXTERNAL
	     * PLAIN + LOGIN + ANONYMOUS
	     *
	     * This might be improved on by comparing the numeric value of
	     * the bitwise-or'd security flags, which splits DIGEST/OTP,
	     * CRAM/EXTERNAL, and PLAIN/LOGIN from ANONYMOUS, but then we
	     * are depending on the numeric values of the flags (which may
	     * change, and their ordering could be considered dumb luck.
	     */

	    if (bestm &&
		((m->m.plug->security_flags ^ bestm->m.plug->security_flags) &
		 bestm->m.plug->security_flags)) {
		break;
	    }

	    if (SASL_CB_PRESENT(c_conn->cparams) && plus) {
		cur_cbindingdisp = SASL_CB_DISP_USED;
	    } else {
		cur_cbindingdisp = cbindingdisp;
	    }

	    if (bestm && (best_cbindingdisp > cur_cbindingdisp)) {
		break;
	    }

#ifdef PREFER_MECH
	    if (ofc_strcasecmp(m->m.plug->mech_name, PREFER_MECH) &&
		bestm && m->m.plug->max_ssf <= bestssf) {
		/* this mechanism isn't our favorite, and it's no better
		   than what we already have! */
		break;
	    }
#else
	    if (bestm && m->m.plug->max_ssf <= bestssf) {
		/* this mechanism is no better than what we already have! */
		break;
	    }
#endif

	    if (mech) {
		*mech = m->m.plug->mech_name;
	    }

	    best_cbindingdisp = cur_cbindingdisp;
	    bestssf = m->m.plug->max_ssf;
	    bestm = m;
	    break;
	}
	name += ofc_strlen(name) + 1;
    }

    if (bestm == OFC_NULL) {
	of_security_seterror(conn, 0, "No worthy mechs found");
	result = SASL_NOMECH;
	goto done;
    }

    /* make (the rest of) cparams */
    c_conn->cparams->service = conn->service;
    c_conn->cparams->servicelen = (unsigned) ofc_strlen(conn->service);
    
    if (conn->serverFQDN) {
	c_conn->cparams->serverFQDN = conn->serverFQDN; 
	c_conn->cparams->slen = (unsigned) ofc_strlen(conn->serverFQDN);
    }

    c_conn->cparams->clientFQDN = c_conn->clientFQDN; 
    c_conn->cparams->clen = (unsigned) ofc_strlen(c_conn->clientFQDN);

    c_conn->cparams->external_ssf = conn->external.ssf;
    c_conn->cparams->props = conn->props;
    c_conn->cparams->cbindingdisp = best_cbindingdisp;
    c_conn->mech = bestm;

    /* init that plugin */
    result = c_conn->mech->m.plug->mech_new(c_conn->mech->m.plug->glob_context,
					  c_conn->cparams,
					  &(conn->context));
    if (result != SASL_OK) goto done;

    /* do a step -- but only if we can do a client-send-first */
 dostep:
    if(clientout) {
        if(c_conn->mech->m.plug->features & SASL_FEAT_SERVER_FIRST) {
            *clientout = OFC_NULL;
            *clientoutlen = 0;
            result = SASL_CONTINUE;
        } else {
            result = of_security_client_step(conn, OFC_NULL, 0, prompt_need,
					   clientout, clientoutlen);
        }
    }
    else
	result = SASL_CONTINUE;

 done:
    if (ordered_mechs != OFC_NULL)
	c_conn->cparams->utils->free(ordered_mechs);
    RETURN(conn, result);
}

/* do a single authentication step.
 *  serverin    -- the server message received by the client, MUST have a NUL
 *                 sentinel, not counted by serverinlen
 * output:
 *  prompt_need -- on SASL_INTERACT, list of prompts needed to continue
 *  clientout   -- the client response to send to the server
 *
 * returns:
 *  SASL_OK        -- success
 *  SASL_INTERACT  -- user interaction needed to fill in prompt_need list
 *  SASL_BADPROT   -- server protocol incorrect/cancelled
 *  SASL_BADSERV   -- server failed mutual auth
 */

int of_security_client_step(sasl_conn_t *conn,
			  const char *serverin,
			  unsigned serverinlen,
			  sasl_interact_t **prompt_need,
			  const char **clientout,
			  unsigned *clientoutlen)
{
  sasl_client_conn_t *c_conn= (sasl_client_conn_t *) conn;
  int result;

  if (_sasl_client_active == 0) return SASL_NOTINIT;
  if (!conn) return SASL_BADPARAM;

  /* check parameters */
  if ((serverin==OFC_NULL) && (serverinlen>0))
      PARAMERROR(conn);

  /* Don't do another step if the plugin told us that we're done */
  if (conn->oparams.doneflag) {
      of_security_log(conn, SASL_LOG_ERR, 
		     "attempting client step after doneflag");
      return SASL_FAIL;
  }

  if(clientout) *clientout = OFC_NULL;
  if(clientoutlen) *clientoutlen = 0;

  /* do a step */
  result = c_conn->mech->m.plug->mech_step(conn->context,
					 c_conn->cparams,
					 serverin,
					 serverinlen,
					 prompt_need,
					 clientout, clientoutlen,
					 &conn->oparams);

  if (result == SASL_OK) {
      /* So we're done on this end, but if both
       * 1. the mech does server-send-last
       * 2. the protocol does not
       * we need to return no data */
      if(!*clientout && !(conn->flags & SASL_SUCCESS_DATA)) {
	  *clientout = "";
	  *clientoutlen = 0;
      }
      
      if(!conn->oparams.maxoutbuf) {
	  conn->oparams.maxoutbuf = conn->props.maxbufsize;
      }

      if(conn->oparams.user == OFC_NULL || conn->oparams.authid == OFC_NULL) {
	  of_security_seterror(conn, 0,
			"mech did not call canon_user for both authzid and authid");
	  result = SASL_BADPROT;
      }
  }  

  RETURN(conn,result);
}

int of_security_target_name(sasl_conn_t *conn,
			  OFC_TCHAR *name,
			  size_t name_len)
{
  sasl_client_conn_t *c_conn= (sasl_client_conn_t *) conn;
  int result;

  if (_sasl_client_active == 0) return SASL_NOTINIT;
  if (!conn) return SASL_BADPARAM;

  /* obtain the key */
  if (c_conn->mech->m.plug->mech_target_name != NULL)
    result = c_conn->mech->m.plug->mech_target_name(conn->context,
						    name, name_len) ;
  else
    result = SASL_FAIL ;

  RETURN(conn,result);
}

int of_security_client_key(sasl_conn_t *conn,
                           unsigned char session_key[SASL_KEY_LENGTH])
{
  sasl_client_conn_t *c_conn= (sasl_client_conn_t *) conn;
  int result;

  if (_sasl_client_active == 0) return SASL_NOTINIT;
  if (!conn) return SASL_BADPARAM;

  /* obtain the key */
  if (c_conn->mech->m.plug->mech_session_key != NULL)
    result = c_conn->mech->m.plug->mech_session_key(conn->context,
						    session_key);
  else
    result = SASL_FAIL ;

  RETURN(conn,result);
}

int of_security_mech_list_mic(sasl_conn_t *conn,
			    const OFC_UCHAR *mechlist, 
			    OFC_SIZET length,
			    unsigned char mic[SASL_KEY_LENGTH])
{
  sasl_client_conn_t *c_conn= (sasl_client_conn_t *) conn;
  int result;

  if (_sasl_client_active == 0) return SASL_NOTINIT;
  if (!conn) return SASL_BADPARAM;

  /* obtain the key */
  if (c_conn->mech->m.plug->mech_mech_list_mic != NULL)
    result = c_conn->mech->m.plug->mech_mech_list_mic(conn->context,
						      mechlist,
						      length,
						      mic) ;
  else
    result = SASL_FAIL ;

  RETURN(conn,result);
}

/* returns the length of all the mechanisms
 * added up 
 */

static unsigned mech_names_len(cmechanism_t *mech_list)
{
  cmechanism_t *listptr;
  unsigned result = 0;

  for (listptr = mech_list;
       listptr;
       listptr = listptr->next)
    result += (unsigned) ofc_strlen(listptr->m.plug->mech_name);

  return result;
}


int of_security_client_listmech(sasl_conn_t *conn,
			       const char *prefix,
			       const char *sep,
			       const char *suffix,
			       const char **result,
			       unsigned *plen,
			       int *pcount)
{
    sasl_client_conn_t *c_conn = (sasl_client_conn_t *)conn;
    cmechanism_t *m = OFC_NULL;
    sasl_ssf_t minssf = 0;
    int ret;
    OFC_SIZET resultlen;
    int flag;
    const char *mysep;

    if (_sasl_client_active == 0) return SASL_NOTINIT;
    if (!conn) return SASL_BADPARAM;
    if (conn->type != SASL_CONN_CLIENT) PARAMERROR(conn);
    
    if (! result)
	PARAMERROR(conn);
    
    if (plen != OFC_NULL)
	*plen = 0;
    if (pcount != OFC_NULL)
	*pcount = 0;

    if (sep) {
	mysep = sep;
    } else {
	mysep = " ";
    }

    if (conn->props.min_ssf < conn->external.ssf) {
	minssf = 0;
    } else {
	minssf = conn->props.min_ssf - conn->external.ssf;
    }

    if (!c_conn->mech_list || c_conn->mech_length <= 0) {
	INTERROR(conn, SASL_NOMECH);
    }

    resultlen = (prefix ? ofc_strlen(prefix) : 0)
	+ (ofc_strlen(mysep) * (c_conn->mech_length - 1))
	+ mech_names_len(c_conn->mech_list)
	+ (suffix ? ofc_strlen(suffix) : 0)
	+ 1;
    ret = of_security_buf_alloc(&conn->mechlist_buf,
			  &conn->mechlist_buf_len,
			  resultlen);
    if (ret != SASL_OK) MEMERROR(conn);

    if (prefix) {
	ofc_strcpy (conn->mechlist_buf,prefix);
    } else {
	*(conn->mechlist_buf) = '\0';
    }

    flag = 0;
    for (m = c_conn->mech_list; m != OFC_NULL; m = m->next) {
	    /* do we have the prompts for it? */
	    if (!have_prompts(conn, m->m.plug)) {
		continue;
	    }

	    /* is it strong enough? */
	    if (minssf > m->m.plug->max_ssf) {
		continue;
	    }

	    /* does it meet our security properties? */
	    if (((conn->props.security_flags ^ m->m.plug->security_flags)
		 & conn->props.security_flags) != 0) {
		continue;
	    }

	    /* Can we meet it's features? */
	    if ((m->m.plug->features & SASL_FEAT_NEEDSERVERFQDN)
		&& !conn->serverFQDN) {
		continue;
	    }

	    /* Can it meet our features? */
	    if ((conn->flags & SASL_NEED_PROXY) &&
		!(m->m.plug->features & SASL_FEAT_ALLOWS_PROXY)) {
		continue;
	    }

	    /* Okay, we like it, add it to the list! */

	    if (pcount != OFC_NULL)
		(*pcount)++;

	    /* print seperator */
	    if (flag) {
		ofc_strcat(conn->mechlist_buf, mysep);
	    } else {
		flag = 1;
	    }
	    
	    /* now print the mechanism name */
	    ofc_strcat(conn->mechlist_buf, m->m.plug->mech_name);
    }
    
  if (suffix)
      ofc_strcat(conn->mechlist_buf,suffix);

  if (plen!=OFC_NULL)
      *plen = (unsigned) ofc_strlen(conn->mechlist_buf);

  *result = conn->mechlist_buf;

  return SASL_OK;
}

sasl_string_list_t *of_security_client_mechs(void) 
{
  cmechanism_t *listptr;
  sasl_string_list_t *retval = OFC_NULL, *next=OFC_NULL;

  if(!_sasl_client_active) return OFC_NULL;

  /* make list */
  for (listptr = cmechlist->mech_list; listptr; listptr = listptr->next) {
      next = sasl_ALLOC(sizeof(sasl_string_list_t));

      if(!next && !retval) return OFC_NULL;
      else if(!next) {
	  next = retval->next;
	  do {
	      sasl_FREE(retval);
	      retval = next;
	      next = retval->next;
	  } while(next);
	  return OFC_NULL;
      }
      
      next->d = listptr->m.plug->mech_name;

      if(!retval) {
	  next->next = OFC_NULL;
	  retval = next;
      } else {
	  next->next = retval;
	  retval = next;
      }
  }

  return retval;
}




/* It would be nice if we can show other information like Author, Company, Year, plugin version */
static void
_sasl_print_mechanism (
  client_sasl_mechanism_t *m,
  sasl_info_callback_stage_t stage,
  void *rock)
{
    char delimiter;

    if (stage == SASL_INFO_LIST_START) {
	ofc_printf ("List of client plugins follows\n");
	return;
    } else if (stage == SASL_INFO_LIST_END) {
	return;
    }

    /* Process the mechanism */
    ofc_printf ("Plugin \"%s\" ", m->plugname);

    /* There is no delay loading for client side plugins */
    ofc_printf ("[loaded]");

    ofc_printf (", \tAPI version: %d\n", m->version);

    if (m->plug != OFC_NULL) {
	ofc_printf ("\tSASL mechanism: %s, best SSF: %d\n",
		m->plug->mech_name,
		m->plug->max_ssf);

	ofc_printf ("\tsecurity flags:");
	
	delimiter = ' ';
	if (m->plug->security_flags & SASL_SEC_NOANONYMOUS) {
	    ofc_printf ("%cNO_ANONYMOUS", delimiter);
	    delimiter = '|';
	}

	if (m->plug->security_flags & SASL_SEC_NOPLAINTEXT) {
	    ofc_printf ("%cNO_PLAINTEXT", delimiter);
	    delimiter = '|';
	}
	
	if (m->plug->security_flags & SASL_SEC_NOACTIVE) {
	    ofc_printf ("%cNO_ACTIVE", delimiter);
	    delimiter = '|';
	}

	if (m->plug->security_flags & SASL_SEC_NODICTIONARY) {
	    ofc_printf ("%cNO_DICTIONARY", delimiter);
	    delimiter = '|';
	}

	if (m->plug->security_flags & SASL_SEC_FORWARD_SECRECY) {
	    ofc_printf ("%cFORWARD_SECRECY", delimiter);
	    delimiter = '|';
	}

	if (m->plug->security_flags & SASL_SEC_PASS_CREDENTIALS) {
	    ofc_printf ("%cPASS_CREDENTIALS", delimiter);
	    delimiter = '|';
	}

	if (m->plug->security_flags & SASL_SEC_MUTUAL_AUTH) {
	    ofc_printf ("%cMUTUAL_AUTH", delimiter);
	    delimiter = '|';
	}



	ofc_printf ("\n\tfeatures:");
	
	delimiter = ' ';
	if (m->plug->features & SASL_FEAT_WANT_CLIENT_FIRST) {
	    ofc_printf ("%cWANT_CLIENT_FIRST", delimiter);
	    delimiter = '|';
	}

	if (m->plug->features & SASL_FEAT_SERVER_FIRST) {
	    ofc_printf ("%cSERVER_FIRST", delimiter);
	    delimiter = '|';
	}

	if (m->plug->features & SASL_FEAT_ALLOWS_PROXY) {
	    ofc_printf ("%cPROXY_AUTHENTICATION", delimiter);
	    delimiter = '|';
	}

	if (m->plug->features & SASL_FEAT_NEEDSERVERFQDN) {
	    ofc_printf ("%cNEED_SERVER_FQDN", delimiter);
	    delimiter = '|';
	}

	if (m->plug->features & SASL_FEAT_GSS_FRAMING) {
	    ofc_printf ("%cGSS_FRAMING", delimiter);
	    delimiter = '|';
	}

	if (m->plug->features & SASL_FEAT_CHANNEL_BINDING) {
	    ofc_printf ("%cCHANNEL_BINDING", delimiter);
	    delimiter = '|';
	}

	if (m->plug->features & SASL_FEAT_SUPPORTS_HTTP) {
	    ofc_printf ("%cSUPPORTS_HTTP", delimiter);
	    delimiter = '|';
	}
    }

/* Delay loading is not supported for the client side plugins:
    if (m->f) {
	printf ("\n\twill be loaded from \"%s\"", m->f);
    }
 */

    ofc_printf ("\n");
}


/* Dump information about available client plugins */
int of_security_client_plugin_info (
  const char *c_mech_list,		/* space separated mechanism list or OFC_NULL for ALL */
  sasl_client_info_callback_t *info_cb,
  void *info_cb_rock
)
{
    cmechanism_t *m;
    client_sasl_mechanism_t plug_data;
    char * cur_mech;
    char * mech_list = OFC_NULL;
    char * p;

    if (info_cb == OFC_NULL) {
	info_cb = _sasl_print_mechanism;
    }

    if (cmechlist != OFC_NULL) {
	info_cb (OFC_NULL, SASL_INFO_LIST_START, info_cb_rock);

	if (c_mech_list == OFC_NULL) {
	    m = cmechlist->mech_list; /* m point to beginning of the list */

	    while (m != OFC_NULL) {
		ofc_memcpy (&plug_data, &m->m, sizeof(plug_data));

		info_cb (&plug_data, SASL_INFO_LIST_MECH, info_cb_rock);
	    
		m = m->next;
	    }
	} else {
            mech_list = ofc_strdup (c_mech_list);

	    cur_mech = mech_list;

	    while (cur_mech != OFC_NULL) {
		p = ofc_strchr (cur_mech, ' ');
		if (p != OFC_NULL) {
		    *p = '\0';
		    p++;
		}

		m = cmechlist->mech_list; /* m point to beginning of the list */

		while (m != OFC_NULL) {
		    if (ofc_strcasecmp (cur_mech, m->m.plug->mech_name) == 0) {
			ofc_memcpy (&plug_data, &m->m, sizeof(plug_data));

			info_cb (&plug_data, SASL_INFO_LIST_MECH, info_cb_rock);
		    }
	    
		    m = m->next;
		}

		cur_mech = p;
	    }
	    ofc_free(mech_list);
	}

	info_cb (OFC_NULL, SASL_INFO_LIST_END, info_cb_rock);

	return (SASL_OK);
    }

    return (SASL_NOTINIT);
}
