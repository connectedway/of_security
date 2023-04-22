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

krb5_timestamp now;
unsigned int timestamp_width;

krb5_context context;

static krb5_boolean is_local_tgt(krb5_principal princ, krb5_data *realm);
static int check_ccache(krb5_ccache cache, krb5_timestamp *exp);

void list_all_ccaches(void);
static int list_ccache(krb5_ccache);

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

void
list_all_ccaches()
{
    krb5_error_code ret;
    krb5_ccache cache;
    krb5_cccol_cursor cursor;

    OFC_FILETIME filetime ;
    OFC_ULONG tv_sec ;
    OFC_ULONG tv_nsec ;

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

void
destroy_ccache(const char *princ_name)
{
  krb5_error_code ret;
  krb5_ccache cache;
  krb5_principal princ;

  ret = krb5_init_context(&context);
  if (ret)
    {
      ofc_process_crash ("while initializing krb5");
    }

  if (princ_name != NULL)
    {
      ret = krb5_parse_name(context, princ_name, &princ);
      if (ret)
        {
          ofc_process_crash ("while parsing principal name %s") ;
        }
      ret = krb5_cc_cache_match(context, princ, &cache);
      if (!ret)
        {
          krb5_free_principal(context, princ);

          ret = krb5_cc_destroy (context, cache) ;
          if (ret)
            {
              ofc_process_crash ("while destroying cache") ;
            }
        }
    }
    krb5_free_context(context);
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

#endif

static int
list_ccache(krb5_ccache cache)
{
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

    def_ccname = krb5_cc_default_name(context);

    ret = krb5_cc_get_principal(context, cache, &princ);
    if (ret)                    /* Uninitialized cache file, probably. */
        goto cleanup;
    ret = krb5_unparse_name(context, princ, &princname);
    if (ret)
        goto cleanup;
#if defined(__APPLE__)
    ccname = ofc_saprintf ("%s:%s",
                            krb5_cc_get_type (context, cache),
                            krb5_cc_get_name (context, cache)) ;
#else
    ret = krb5_cc_get_full_name(context, cache, &ccname);
    if (ret)
        goto cleanup;
#endif
    
    def_cache = 0 ;
    if (ofc_strcmp (ccname, def_ccname) == 0)
       def_cache = 1 ;
    expired = check_ccache(cache, &exp);

    epoch_time_to_file_time (exp, 0, &ft) ;
    ofc_file_time_to_dos_date_time (&ft, &fat_date, &fat_time);
    ofc_dos_date_time_to_elements(fat_date, fat_time,
                                   &month, &day, &year, &hour, &min, &sec) ;

    ofc_printf ("%c %s : %s : %02d/%02d/%04d %02d:%02d:%02d GMT : %s\n",
                 def_cache ? '*' : ' ', ccname, princname, month, day, year, hour, min, sec, expired ? "expired" : "active") ;

    status = 0;

cleanup:
    krb5_free_principal(context, princ);
    krb5_free_unparsed_name(context, princname);
#if defined(__APPLE__)
    ofc_free (ccname) ;
#else
    krb5_free_string(context, ccname);
#endif
    return status;
}

/* Return 0 if cache is accessible, present, and unexpired; return 1 if not. */
static int
check_ccache(krb5_ccache cache, krb5_timestamp *exp)
{
    krb5_error_code ret;
    krb5_cc_cursor cur;
    krb5_creds creds;
    krb5_principal princ;
    krb5_boolean found_tgt, found_current_tgt;

    if (krb5_cc_get_principal(context, cache, &princ) != 0)
        return 1;
    if (krb5_cc_start_seq_get(context, cache, &cur) != 0)
        return 1;
    found_tgt = found_current_tgt = FALSE;
    *exp = 0 ;
    while ((ret = krb5_cc_next_cred(context, cache, &cur, &creds)) == 0)
        {
            if (*exp == 0 || ts_after (*exp, creds.times.endtime))
                *exp = creds.times.endtime ;
            if (is_local_tgt(creds.server, &princ->realm))
                {
                    found_tgt = TRUE;
                    if (ts_after(creds.times.endtime, now))
                        found_current_tgt = TRUE;
                }
            krb5_free_cred_contents(context, &creds);
        }
    krb5_free_principal(context, princ);
    if (ret != KRB5_CC_END)
        return 1;
    if (krb5_cc_end_seq_get(context, cache, &cur) != 0)
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

