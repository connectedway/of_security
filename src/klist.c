/* -*- mode: c; c-basic-offset: 2; indent-tabs-mode: nil -*- */
/* clients/klist/klist.c - List contents of credential cache or keytab */
/*
 * Copyright 1990 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */

#if defined(__APPLE__)
//#include <GSS/GSS.h>
#define KERBEROS_APPLE_DEPRECATED(x)
#include <Kerberos/Kerberos.h>
#endif

#if defined(__linux__)
#include <krb5.h>
#include <com_err.h>
#endif

#include <ofc/types.h>
#include <ofc/time.h>
#include <ofc/process.h>
#include <ofc/file.h>
#include <ofc/libc.h>
#include <ofc/heap.h>

static krb5_boolean is_local_tgt(krb5_principal princ, krb5_data *realm);
static int check_ccache(krb5_context context, krb5_ccache cache,
                        krb5_timestamp *exp);

#if 0
void list_all_ccaches(void);
#endif
static int list_ccache(void);

#define DEFAULT 0
#define CCACHE 1
#define KEYTAB 2

#if defined(__APPLE__) || defined(__linux__)
/* Return true if a comes after b. */
static inline krb5_boolean
ts_after(krb5_timestamp a, krb5_timestamp b)
{
    return (uint32_t)a > (uint32_t)b;
}

/* Some data comparison and conversion functions.  */
static inline int
data_eq(krb5_data d1, krb5_data d2)
{
    return (d1.length == d2.length && (d1.length == 0 ||
                                       !ofc_memcmp(d1.data, d2.data, d1.length)));
}

static inline int
data_eq_string (krb5_data d, const char *s)
{
    return (d.length == ofc_strlen(s) &&
            (d.length == 0 || !ofc_memcmp(d.data, s, d.length)));
}

#endif

#if 0
void
list_all_ccaches()
{
    krb5_error_code ret;
    krb5_ccache cache;
    krb5_cccol_cursor cursor;

    OFC_FILETIME filetime ;
    OFC_ULONG tv_sec ;
    OFC_ULONG tv_nsec ;
    krb5_timestamp now;

    ofc_time_get_file_time(&filetime);
    file_time_to_epoch_time(&filetime, &tv_sec, &tv_nsec) ;
    now = (int) (tv_sec);

    ret = krb5_init_context(&context);
    if (ret) {
        ofc_process_crash ("while initializing krb5");
    }

    ret = krb5_cccol_cursor_new(context, &cursor);
    if (ret) {
      ofc_process_crash("while listing ccache collection");
    }

    while ((ret = krb5_cccol_cursor_next(context, cursor, &cache)) == 0 &&
           cache != NULL) {
        list_ccache(cache) ;
        krb5_cc_close(context, cache);
    }
    krb5_cccol_cursor_free(context, &cursor);

    krb5_free_context (context) ;

}
#endif
int kinit(const char *principal, const char *password)
{
  krb5_context ctx = NULL;
  krb5_ccache out_cc = NULL;
  krb5_principal me = NULL;
  krb5_get_init_creds_opt *options = NULL;
  krb5_creds my_creds;
  int ret;

  ret = krb5_init_context(&ctx);
  if (ret)
    {
      ofc_printf("Unable to Initialize KRB5 context for Authentication\n");
    }
  else
    {
      ret = krb5_cc_default(ctx, &out_cc);
      if (ret)
        {
          ofc_printf("Unable to get the default cache\n");
        }
      else
        {
          ret = krb5_get_init_creds_opt_alloc (ctx, &options);
          if (ret)
            {
              ofc_printf("Unable to get initial credential options\n");
            }
          else
            {
              ret = krb5_get_init_creds_opt_set_out_ccache(ctx,
                                                           options,
                                                           out_cc);
              if (ret)
                {
                  ofc_printf("Unable to set output cache\n");
                }
              else
                {
                  ret = krb5_parse_name_flags(ctx, principal, 0, &me);
                  if (ret)
                    {
                      ofc_printf("Unable to parse principal\n");
                    }
                  else
                    {
                      ofc_memset(&my_creds, 0, sizeof(my_creds));
                      ret = krb5_get_init_creds_password(ctx,
                                                         &my_creds,
                                                         me,
                                                         password,
                                                         NULL,
                                                         NULL,
                                                         0,
                                                         NULL,
                                                         options);
                      if (ret)
                        {
                          ofc_printf("Unable to Authenticate\n");
                        }
                      else
                        {
                          krb5_free_cred_contents(ctx, &my_creds);
                        }
                      krb5_free_principal(ctx, me);
                    }
                }
              krb5_get_init_creds_opt_free(ctx, options);
            }
          krb5_cc_close(ctx, out_cc);
        }
      krb5_free_context(ctx);
    }
  return (ret);
}

int
destroy_ccache(OFC_VOID)
{
  krb5_context ctx = NULL;
  krb5_error_code ret;
  krb5_ccache cache;

  ret = krb5_init_context(&ctx);
  if (ret)
    {
      ofc_process_crash ("while initializing krb5");
    }

  ret = krb5_cc_default(ctx, &cache);
  if (ret)
    {
      ofc_printf("Unable to get the default cache\n");
    }
  else
    {
      ret = krb5_cc_destroy (ctx, cache) ;
    }
    krb5_free_context(ctx);
    return (ret);
}

#if 0
void kadd_princ (const char *princ_name, const char *password)
{
    krb5_error_code ret;
    krb5_context context ;
    krb5_principal princ ;
    krb5_ccache cache;

    ret = krb5_init_context(&context);
    if (ret) {
        ofc_process_crash ("while initializing Kerberos 5 library");
    }
    
    if (princ_name != NULL) {
        ret = krb5_parse_name(context, princ_name, &princ);
        if (ret) {
            ofc_process_crash ("while parsing principal name %s") ;
        }
        ret = krb5_cc_cache_match(context, princ, &cache);
        if (ret) {
            ret = krb5_cc_new_unique(context, "API", NULL, &cache);
            if (ret)
                ofc_process_crash ("while finding cache") ;
        }
        krb5_free_principal(context, princ);
    }
}
#endif

/*
 * kcache_active
 *
 * Returns 0 if the cache has an active login
 * Returns 1 if this routine failed or if no active loging found
 * If it does, the realm will contain the name of the realm that is active.
 * the realm should be freed when no longer needed
 */
OFC_CHAR *kcache_active(OFC_VOID)
{
  krb5_context ctx = NULL;
  krb5_ccache ccache = NULL;
  krb5_error_code ret;
  krb5_principal princ = NULL;
  char *princname = NULL ;
  int expired = 1;
  krb5_timestamp exp ;
  OFC_CHAR *realmp;
  OFC_CHAR *realm = OFC_NULL;

  ret = krb5_init_context(&ctx);
  if (ret)
    {
      ofc_printf("Unable to Initialize KRB5 context for Authentication\n");
    }
  else
    {
      ret = krb5_cc_default(ctx, &ccache);
      if (ret)
        {
          ofc_printf("Unable to get the default cache\n");
        }
      else
        {
          ret = krb5_cc_get_principal(ctx, ccache, &princ);
          if (ret)
            {
              /* Uninitialized cache file, probably. */
              ofc_printf("Unable to get principal\n");
            }
          else
            {
              ret = krb5_unparse_name(ctx, princ, &princname);
              if (ret)
                {
                  ofc_printf("Unable to unparse principal\n");
                }
              else
                {
                  expired = check_ccache(ctx, ccache, &exp);

                  if (!expired)
                    {
                      realmp = ofc_strchr(princname, '@');
                      if (realmp != OFC_NULL)
                        {
                          realm = ofc_strdup(realmp + 1);
                        }
                    }
                  krb5_free_unparsed_name(ctx, princname);
                }
              krb5_free_principal(ctx, princ);
            }
          krb5_cc_close(ctx, ccache);
        }
      krb5_free_context(ctx);
    }
  return (realm);
}  

OFC_CHAR *kcache_active_user(OFC_VOID)
{
  krb5_context ctx = NULL;
  krb5_ccache ccache = NULL;
  krb5_error_code ret;
  krb5_principal princ = NULL;
  char *princname = NULL ;
  int expired = 1;
  krb5_timestamp exp ;
  OFC_CHAR *userp;
  OFC_CHAR *user = OFC_NULL;

  ret = krb5_init_context(&ctx);
  if (ret)
    {
      ofc_printf("Unable to Initialize KRB5 context for Authentication\n");
    }
  else
    {
      ret = krb5_cc_default(ctx, &ccache);
      if (ret)
        {
          ofc_printf("Unable to get the default cache\n");
        }
      else
        {
          ret = krb5_cc_get_principal(ctx, ccache, &princ);
          if (ret)
            {
              /* Uninitialized cache file, probably. */
              ofc_printf("Unable to get principal\n");
            }
          else
            {
              ret = krb5_unparse_name(ctx, princ, &princname);
              if (ret)
                {
                  ofc_printf("Unable to unparse principal\n");
                }
              else
                {
                  expired = check_ccache(ctx, ccache, &exp);

                  if (!expired)
                    {
                      userp = ofc_strchr(princname, '@');
                      if (userp != OFC_NULL)
                        {
                          int len = userp - princname;
                          user = ofc_malloc(len+1);
                          ofc_strncpy(user, princname, len);
                          user[len] = '\0';
                        }
                    }
                  krb5_free_unparsed_name(ctx, princname);
                }
              krb5_free_principal(ctx, princ);
            }
          krb5_cc_close(ctx, ccache);
        }
      krb5_free_context(ctx);
    }
  return (user);
}  

#if 0
static int
list_ccache(void)
{
  krb5_context ctx = NULL;
  krb5_ccache ccache = NULL;
  krb5_error_code ret;
  krb5_principal princ = NULL;
  char *princname = NULL ;
  char *ccname = NULL;
  int expired, status = 1;
  krb5_timestamp exp ;
  OFC_FILETIME ft ;
  OFC_WORD fat_date ;
  OFC_WORD fat_time ;
  OFC_UINT16 month ;
  OFC_UINT16 day ;
  OFC_UINT16 year ;
  OFC_UINT16 hour ;
  OFC_UINT16 min ;
  OFC_UINT16 sec ;
  const char *def_ccname ;
  int def_cache ;
  OFC_CHAR *realmp;
  OFC_CHAR *str_realm;

  ret = krb5_init_context(&ctx);
  if (ret)
    {
      ofc_printf("Unable to Initialize KRB5 context for Authentication\n");
    }
  else
    {
      ret = krb5_cc_default(ctx, &ccache);
      if (ret)
        {
          ofc_printf("Unable to get the default cache\n");
        }
      else
        {
          def_ccname = krb5_cc_default_name(ctx);

          ret = krb5_cc_get_principal(ctx, ccache, &princ);
          if (ret)                    /* Uninitialized cache file, probably. */
            {
              ofc_printf("Unable to get principal\n");
            }
          else
            {
              ret = krb5_unparse_name(ctx, princ, &princname);
              if (ret)
                {
                  ofc_printf("Unable to unparse principal\n");
                }
              else
                {
#if defined(__APPLE__)
                  ccname = ofc_saprintf ("%s:%s",
                                         krb5_cc_get_type (ctx, ccache),
                                         krb5_cc_get_name (ctx, ccache)) ;
                  ret = 0;
#else
                  ret = krb5_cc_get_full_name(ctx, ccache, &ccname);
#endif
                  if (ret)
                    {
                      ofc_printf("Unable to get full name for cache\n");
                    }
                  else
                    {
                      def_cache = 0 ;
                      if (ofc_strcmp (ccname, def_ccname) == 0)
                        def_cache = 1 ;
                      expired = check_ccache(ctx, ccache, &exp);

                      epoch_time_to_file_time (exp, 0, &ft) ;
                      ofc_file_time_to_dos_date_time (&ft, &fat_date, &fat_time);
                      ofc_dos_date_time_to_elements(fat_date, fat_time,
                                                    &month, &day, &year,
                                                    &hour, &min, &sec) ;

                      realmp = ofc_strchr(princname, '@');
                      if (realmp != OFC_NULL)
                        {
                          str_realm = ofc_strdup(realmp + 1);

                          ofc_printf("Realm %s : active: %s\n",
                                     str_realm,
                                     expired ? "no": "yes");
                          ofc_free(str_realm);
                        }
                                                                        
                      ofc_printf ("%c %s : %s : %02d/%02d/%04d %02d:%02d:%02d GMT : %s\n",
                                  def_cache ? '*' : ' ', ccname, princname, month, day, year, hour, min, sec, expired ? "expired" : "active") ;

                      status = 0;
#if defined(__APPLE__)
                      ofc_free (ccname) ;
#else
                      krb5_free_string(ctx, ccname);
#endif
                    }
                  krb5_free_unparsed_name(ctx, princname);
                }
              krb5_free_principal(ctx, princ);
            }
          krb5_cc_close(ctx, ccache);
        }
      krb5_free_context(ctx);
    }
  return (ret);
}
#endif

/* Return 0 if cache is accessible, present, and unexpired; return 1 if not. */
static int
check_ccache(krb5_context ctx, krb5_ccache cache, krb5_timestamp *exp)
{
    krb5_error_code ret;
    krb5_cc_cursor cur;
    krb5_creds creds;
    krb5_principal princ;
    krb5_boolean found_tgt, found_current_tgt;

    if (krb5_cc_get_principal(ctx, cache, &princ) != 0)
        return 1;
    if (krb5_cc_start_seq_get(ctx, cache, &cur) != 0)
        return 1;
    found_tgt = found_current_tgt = FALSE;
    *exp = 0 ;

    OFC_FILETIME filetime ;
    OFC_ULONG tv_sec ;
    OFC_ULONG tv_nsec ;
    krb5_timestamp now;

    ofc_time_get_file_time(&filetime);
    file_time_to_epoch_time(&filetime, &tv_sec, &tv_nsec) ;
    now = (int) (tv_sec);

    while ((ret = krb5_cc_next_cred(ctx, cache, &cur, &creds)) == 0)
        {
            if (*exp == 0 || ts_after (*exp, creds.times.endtime))
                *exp = creds.times.endtime ;
            if (is_local_tgt(creds.server, &princ->realm))
                {
                    found_tgt = TRUE;
                    if (ts_after(creds.times.endtime, now))
                        found_current_tgt = TRUE;
                }
            krb5_free_cred_contents(ctx, &creds);
        }
    krb5_free_principal(ctx, princ);
    if (ret != KRB5_CC_END)
        return 1;
    if (krb5_cc_end_seq_get(ctx, cache, &cur) != 0)
        return 1;

    /* If the cache contains at least one local TGT, require that it be
     * current.  Otherwise accept any current cred. */
    if (found_tgt)
        return found_current_tgt ? 0 : 1;

    return 1;
}

/* Return true if princ is the local krbtgt principal for local_realm. */
static krb5_boolean
is_local_tgt(krb5_principal princ, krb5_data *realm)
{
    return princ->length == 2 && data_eq(princ->realm, *realm) &&
        data_eq_string(princ->data[0], KRB5_TGS_NAME) &&
        data_eq(princ->data[1], *realm);
}

