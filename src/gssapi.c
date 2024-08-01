/* Copyright (c) 2021 Connected Way, LLC. All rights reserved.
 * Use of this source code is governed by a Creative Commons 
 * Attribution-NoDerivatives 4.0 International license that can be
 * found in the LICENSE file.
 */
/*
 * Portions of this code for der enconding/decoding have been leveraged 
 * from the bind code base that carries the following copyrights
 */

/*
 * Copyright (C) 2006-2011  Internet Systems Consortium, Inc. ("ISC")
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

#define OFC_PARAM_SPNEGO_MECHLISTMIC
/* 
 * GSSAPI/SPNEGO SASL plugin
 */
#include "ofc/config.h"
#include "ofc/types.h"
#include "ofc/socket.h"
#include "ofc/net.h"
#include "ofc/libc.h"
#include "ofc/time.h"
#include "ofc/heap.h"
#include "ofc/file.h"

#include "of_security/saslint.h"
#include "of_security/sasl.h"
#include "of_security/saslplug.h"

#include "of_security/plugin_common.h"

#include "of_smb/config.h"

/*****************************  Common Section  *****************************/

typedef OFC_UINT32 OM_uint32 ;

typedef struct gss_buffer_desc_struct {
  OFC_SIZET length ;
  OFC_VOID *value ;
} gss_buffer_desc, *gss_buffer_t ;

typedef struct gss_OID_desc_struct {
  OFC_UINT32 length ;
  OFC_UINT *elements ;
} gss_OID_desc, *gss_OID ;

typedef struct oid_struct {
  OFC_UINT length ;
  OFC_UCHAR *elements ;
} oid ;

typedef gss_OID_desc MechType;

static const oid gss_mech_ntlmssp_oid =
  { 10, (OFC_UCHAR *) "\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a" } ;

static const OFC_UINT ntlmssp_elements[] = 
  { 1, 3, 6, 1, 4, 1, 311, 2, 2, 10 };

static const gss_OID_desc gss_mech_ntlmssp_gss_oid =
  { sizeof(ntlmssp_elements)/sizeof(OFC_UINT), 
    (OFC_UINT *) ntlmssp_elements } ;

static const oid gss_mech_krb5_oid =
  { 9, (OFC_UCHAR *) "\x2a\x86\x48\x86\xf7\x12\x01\x02\x02" } ;

#if defined(OFC_KERBEROS)
static const OFC_UINT krb5_elements[] = 
  { 1, 2, 840, 113554, 1, 2, 2};

static const gss_OID_desc gss_mech_krb5_gss_oid =
  { sizeof(krb5_elements)/sizeof(OFC_UINT), 
    (OFC_UINT *) krb5_elements } ;
#endif

static oid gss_mech_spnego_oid =
  { 6, (OFC_UCHAR *) "\x2b\x06\x01\x05\x05\x02" } ;

enum {
    SASL_SPNEGO_STATE_NEG_TOKEN_INIT = 1,
    SASL_SPNEGO_STATE_NEG_TOKEN_TARG = 2,
    SASL_SPNEGO_STATE_NEG_TOKEN_COMP = 3,
    SASL_SPNEGO_STATE_AUTHNEG = 4
};

#define NTLM_SESSKEY_LENGTH 16

#define GSS_C_NO_BUFFER ((gss_buffer_t) 0)

/*
 * Flag bits for context-level services.
 */
#define GSS_C_DELEG_FLAG 1
#define GSS_C_MUTUAL_FLAG 2
#define GSS_C_REPLAY_FLAG 4
#define GSS_C_SEQUENCE_FLAG 8
#define GSS_C_CONF_FLAG 16
#define GSS_C_INTEG_FLAG 32
#define	GSS_C_ANON_FLAG 64
#define GSS_C_PROT_READY_FLAG 128
#define GSS_C_TRANS_FLAG 256

typedef struct MechTypeList {
	OFC_UINT len;
	MechType *val;
} MechTypeList;

typedef struct ContextFlags {
	unsigned int delegFlag:1;
	unsigned int mutualFlag:1;
	unsigned int replayFlag:1;
	unsigned int sequenceFlag:1;
	unsigned int anonFlag:1;
	unsigned int confFlag:1;
	unsigned int integFlag:1;
} ContextFlags;

typedef struct octet_string {
	OFC_SIZET length;
        const OFC_VOID *data;
} octet_string;

typedef struct NegTokenInit {
	MechTypeList mechTypes;
	ContextFlags *reqFlags;
	octet_string *mechToken;
        char *negHint ;
#if defined(OFC_PARAM_SPNEGO_MECHLISTMIC)
	octet_string *mechListMIC;
#endif
} NegTokenInit;

enum neg_state {
	accept_completed = 0,
	accept_incomplete = 1,
	reject = 2,
	request_mic = 3
} ;

typedef struct NegTokenResp {
	OFC_UINT *negState ;
	MechType *supportedMech;
	octet_string *responseToken;
#if defined(OFC_PARAM_SPNEGO_MECHLISTMIC)
	octet_string *mechListMIC;
#endif
} NegTokenResp;

typedef enum asn1_error_number{
  ASN1_BAD_TIMEFORMAT = 1859794432,
  ASN1_MISSING_FIELD = 1859794433,
  ASN1_MISPLACED_FIELD = 1859794434,
  ASN1_TYPE_MISMATCH = 1859794435,
  ASN1_OVERFLOW = 1859794436,
  ASN1_OVERRUN = 1859794437,
  ASN1_BAD_ID = 1859794438,
  ASN1_BAD_LENGTH = 1859794439,
  ASN1_BAD_FORMAT = 1859794440,
  ASN1_PARSE_ERROR = 1859794441,
  ASN1_EXTRA_DATA = 1859794442,
  ASN1_BAD_CHARACTER = 1859794443,
  ASN1_MIN_CONSTRAINT = 1859794444,
  ASN1_MAX_CONSTRAINT = 1859794445,
  ASN1_EXACT_CONSTRAINT = 1859794446,
  ASN1_INDEFINITE = -589242643
} asn1_error_number;



typedef enum {
	ASN1_C_UNIV = 0, ASN1_C_APPL = 1,
	ASN1_C_CONTEXT = 2, ASN1_C_PRIVATE = 3
} Der_class;

typedef enum {
	PRIM = 0, CONS = 1
} Der_type;

enum {
	UT_Boolean = 1,
	UT_Integer = 2,
	UT_BitString = 3,
	UT_OctetString = 4,
	UT_Null = 5,
	UT_OID = 6,
        UT_Enumerated = 10,
	UT_Sequence = 16,
	UT_Set = 17,
	UT_PrintableString = 19,
	UT_IA5String = 22,
	UT_UTCTime = 23,
	UT_GeneralizedTime = 24,
	UT_VisibleString = 26,
	UT_GeneralString = 27
};

static OFC_SIZET len_unsigned(OFC_UINT val)
{
  OFC_SIZET ret = 0;

  do {
    ++ret;
    val /= 256;
  } while (val);
  return (ret);
}

static OFC_SIZET length_len(OFC_SIZET len)
{
  if (len < 128U)
    return (1);
  else
    return (len_unsigned((OFC_UINT)len) + 1);
}

static OFC_VOID free_oid(gss_OID k)
{
  ofc_free(k->elements);
  k->elements = OFC_NULL;
}

static OFC_VOID gssapi_encap_length(OFC_SIZET data_len,
				     OFC_SIZET *len,
				     OFC_SIZET *total_len,
				     const oid *mech)
{
  OFC_SIZET len_len;

  *len = 1 + 1 + mech->length + data_len;

  len_len = length_len(*len);

  *total_len = 1 + len_len + *len;
}

static OFC_INT der_put_unsigned(OFC_UCHAR *p, 
				 OFC_SIZET len, 
				 OFC_UINT val, 
				 OFC_SIZET *size)
{
  OFC_UCHAR *base = p;
  OFC_INT result ;

  if (val) 
    {
      while (len > 0U && val) 
	{
	  *p-- = val % 256;
	  val /= 256;
	  --len;
	}
      if (val != 0)
	result = SASL_BUFOVER ;
      else
	{
	  *size = base - p;
	  result = SASL_OK ;
	}
    } 
  else if (len < 1U)
    result = SASL_BUFOVER ;
  else
    {
      *p = 0;
      *size = 1;
      result = SASL_OK ;
    }
  return (result) ;
}

static OFC_INT
der_put_int(OFC_UCHAR *p, OFC_SIZET len, OFC_INT val, OFC_SIZET *size)
{
  OFC_UCHAR *base = p;
  OFC_INT result ;

  result = SASL_OK ;
  if (val >= 0) 
    {
      do 
	{
	  if (len < 1U)
	    result = SASL_BUFOVER ;
	  else
	    {
	      *p-- = val % 256;
	      len--;
	      val /= 256;
	    } 
	}
      while ((result == SASL_OK) && (val));

      if (result == SASL_OK)
	{
	  if (p[1] >= 128) 
	    {
	      if (len < 1U)
		result = SASL_BUFOVER ;
	      else
		{
		  *p-- = 0;
		  len--;
		}
	    } 
	}
    }
  else 
    {
      val = ~val;
      do 
	{
	  if (len < 1U)
	    result = SASL_BUFOVER ;
	  else
	    {
	      *p-- = ~(val % 256);
	      len--;
	      val /= 256;
	    } 
	}
      while ((result == SASL_OK) && val);

      if (result == SASL_OK)
	{
	  if (p[1] < 128) 
	    {
	      if (len < 1U)
		result = SASL_BUFOVER ;
	      else
		{
		  *p-- = 0xff;
		  len--;
		}
	    }
	}
    }

  if (result == SASL_OK)
    *size = base - p;
  return (result);
}

static OFC_INT der_put_length(OFC_UCHAR *p, 
			       OFC_SIZET len, 
			       OFC_SIZET val, 
			       OFC_SIZET *size)
{
  OFC_INT result ;

  if (len < 1U)
    result = SASL_BUFOVER ;
  else
    {
      if (val < 128U) 
	{
	  *p = (OFC_UCHAR) val;
	  *size = 1;
	  result = SASL_OK ;
	}
      else
	{
	  OFC_SIZET l;
	  OFC_INT e;

	  e = der_put_unsigned(p, len - 1, (OFC_UINT) val, &l);
	  if (e)
	    result = e ;
	  else
	    {
	      p -= l;
	      *p = 0x80 | (OFC_UCHAR) l;
	      *size = l + 1;
	      result = SASL_OK ;
	    }
	}
    }
  return (result) ;
}

static OFC_INT der_get_unsigned(const OFC_UCHAR *p, 
				 OFC_SIZET len,
				 OFC_UINT *ret, 
				 OFC_SIZET *size)
{
  OFC_UINT val = 0;
  OFC_SIZET oldlen = len;

  while (len--)
    val = val * 256 + *p++;
  *ret = val;
  if (size)
    *size = oldlen;
  return (SASL_OK);
}

static OFC_INT der_get_length(const OFC_UCHAR *p, OFC_SIZET len,
			       OFC_SIZET *val, OFC_SIZET *size)
{
  OFC_SIZET v;
  OFC_INT result ;

  if (len <= 0U)
    result = SASL_BUFOVER ;
  else
    {
      --len;
      v = *p++;
      if (v < 128U) 
	{
	  *val = v;
	  if (size)
	    *size = 1;
	  result = SASL_OK ;
	} 
      else 
	{
	  OFC_INT e;
	  OFC_SIZET l;
	  OFC_UINT tmp;

	  if (v == 0x80U) 
	    {
	      *val = ASN1_INDEFINITE;
	      if (size)
		*size = 1;
	      result = SASL_OK ;
	    }
	  else
	    {
	      v &= 0x7F;
	      if (len < v)
		result = SASL_BUFOVER ;
	      else
		{
		  e = der_get_unsigned(p, v, &tmp, &l);
		  if (e != SASL_OK)
		    result = e ;
		  else
		    {
		      *val = tmp;
		      if (size)
			*size = l + 1;
		      result = SASL_OK ;
		    }
		}
	    }
	}
    }
  return (result) ;
}

static OFC_INT
der_put_octet_string(OFC_UCHAR *p, OFC_SIZET len,
		     const octet_string *data, OFC_SIZET *size)
{
  OFC_INT result ;

  if (len < data->length)
    result = SASL_BUFOVER ;
  else
    {
      p -= data->length;
      len -= data->length;

      ofc_memcpy(p + 1, data->data, data->length);
      *size = data->length;
      result = SASL_OK ;
    }
  return (result) ;
}

static OFC_INT
der_put_general_string(OFC_UCHAR *p, OFC_SIZET len,
		       const char *data, OFC_SIZET *size)
{
  OFC_INT result ;
  OFC_SIZET slen ;

  slen = ofc_strlen (data) ;
  if (len < slen)
    result = SASL_BUFOVER ;
  else
    {
      p -= slen ;
      len -= slen ;

      ofc_memcpy(p + 1, data, slen);
      *size = slen;
      result = SASL_OK ;
    }
  return (result) ;
}

static OFC_INT
der_get_octet_string(const OFC_UCHAR *p, OFC_SIZET len,
		     octet_string *data, OFC_SIZET *size)
{
  OFC_INT result ;
  OFC_CHAR *temp ;

  temp = ofc_malloc(len) ;
  if (temp == OFC_NULL && len != 0U)
    result = SASL_NOMEM ;
  else
    {
      ofc_memcpy(temp, p, len);
      data->length = len;
      data->data = temp ;
      if (size)
	*size = len;
      result = SASL_OK ;
    }
  return (result) ;
}

static OFC_INT
der_put_tag(OFC_UCHAR *p, OFC_SIZET len, Der_class class, 
	    Der_type type, OFC_INT tag, OFC_SIZET *size)
{
  OFC_INT result ;

  if (len < 1U)
    result = SASL_BUFOVER ;
  else
    {
      *p = (class << 6) | (type << 5) | tag;	/* XXX */
      *size = 1;
      result = SASL_OK ;
    }
  return (result) ;
}

static OFC_INT
der_put_length_and_tag(OFC_UCHAR *p, OFC_SIZET len, OFC_SIZET len_val,
		       Der_class class, Der_type type, OFC_INT tag, 
		       OFC_SIZET *size)
{
  OFC_SIZET retsize = 0 ;
  OFC_SIZET l;
  OFC_INT e;
  OFC_INT result ;

  e = der_put_length(p, len, len_val, &l);
  if (e != SASL_OK)
    result = e ;
  else
    {
      p -= l;
      len -= l;
      retsize += l;
      e = der_put_tag(p, len, class, type, tag, &l);
      if (e != SASL_OK)
	result = e ;
      else
	{
	  p -= l;
	  len -= l;
	  retsize += l;
	  *size = retsize;
	  result = SASL_OK ;
	}
    }
  return (result) ;
}

static OFC_INT
der_put_oid(OFC_UCHAR *p, OFC_SIZET len,
	    const gss_OID_desc *data, OFC_SIZET *size)
{
  OFC_UCHAR *base = p;
  OFC_INT n;

  OFC_INT result = SASL_OK;
  for (n = data->length - 1; (n >= 2) && (result == SASL_OK) ; --n) 
    {
      OFC_UINT u = (OFC_UINT) data->elements[n];

      if (len < 1U)
	result = SASL_BUFOVER ;
      else
	{
	  *p-- = u % 128;
	  u /= 128;
	  --len;
	  while (u > 0 && (result == SASL_OK)) 
	    {
	      if (len < 1U)
		result = SASL_BUFOVER ;
	      else
		{
		  *p-- = 128 + u % 128;
		  u /= 128;
		  --len;
		}
	    }
	}
    }

  if ((result == SASL_OK) && (len < 1U))
    result = SASL_BUFOVER ;
  else
    {
      *p-- = 40 * data->elements[0] + data->elements[1];
      *size = base - p;
    }

  return (result) ;
}

static OFC_INT der_get_oid(const OFC_UCHAR *p, OFC_SIZET len,
			    gss_OID data, OFC_SIZET *size)
{
  OFC_INT n;
  OFC_SIZET oldlen = len;
  OFC_INT result ;

  if (len < 1U)
    result = SASL_BUFOVER ;
  else
    {
      data->elements = ofc_malloc((len+1) * sizeof(data->elements[0]));
      if (data->elements == OFC_NULL)
	result = SASL_NOMEM ;
      else
	{
	  data->elements[0] = (*p) / 40;
	  data->elements[1] = (*p) % 40;
	  --len;
	  ++p;
	  for (n = 2; len > 0U; ++n) 
	    {
	      OFC_UINT u = 0, u1;
	      do 
		{
		  --len;
		  u1 = u * 128 + (*p++ % 128);
		  if (u1 < u)
		    {
		      free_oid(data);
		      return (SASL_BUFOVER);
		    }
		  u = u1;
		} 
	      while (len > 0U && p[-1] & 0x80);
	      data->elements[n] = u;
	    }
	  if (n > 2 && p[-1] & 0x80) 
	    {
	      free_oid(data);
	      result = SASL_BUFOVER ;
	    }
	  else
	    {
	      data->length = n;
	      if (size)
		*size = oldlen;
	      result = SASL_OK ;
	    }
	}
    }
  return (result) ;
}

static OFC_INT
der_get_tag(const OFC_UCHAR *p, OFC_SIZET len,
	    Der_class *class, Der_type *type,
	    OFC_INT *tag, OFC_SIZET *size)
{
  OFC_INT result ;

  if (len < 1U)
    result = SASL_BUFOVER ;
  else
    {
      *class = (Der_class) (((*p) >> 6) & 0x03);
      *type = (Der_type) (((*p) >> 5) & 0x01);
      *tag = (*p) & 0x1F;
      if (size)
	*size = 1;
      result = SASL_OK ;
    }
  return (result) ;
}

static OFC_INT
der_match_tag(const OFC_UCHAR *p, OFC_SIZET len,
	      Der_class class, Der_type type,
	      OFC_INT tag, OFC_SIZET *size)
{
  OFC_SIZET l;
  Der_class thisclass;
  Der_type thistype;
  OFC_INT thistag;
  OFC_INT e;
  OFC_INT result ;

  e = der_get_tag(p, len, &thisclass, &thistype, &thistag, &l);
  if (e != SASL_OK)
    result = e ;
  else if (class != thisclass || type != thistype)
    result = SASL_BADMAC ;
  else if (tag > thistag)
    result = SASL_BADMAC ;
  else if (tag < thistag)
    result = SASL_BADMAC ;
  else 
    {
      if (size)
	*size = l;
      result = SASL_OK ;
    }
  return (result) ;
}

static OFC_INT
der_match_tag_and_length(const OFC_UCHAR *p, OFC_SIZET len,
			 Der_class class, Der_type type, OFC_INT tag,
			 OFC_SIZET *length_ret, OFC_SIZET *size)
{
  OFC_SIZET l, retsize = 0;
  OFC_INT e;
  OFC_INT result ;

  e = der_match_tag(p, len, class, type, tag, &l);
  if (e != SASL_OK)
    result = e ;
  else
    {
      p += l;
      len -= l;
      retsize += l;
      e = der_get_length(p, len, length_ret, &l);
      if (e != SASL_OK)
	result = e ;
      else
	{
	  /* p += l; */
	  len -= l;
	  retsize += l;
	  if (size)
	    *size = retsize;
	  result = SASL_OK ;
	}
    }
  return (result) ;
}

static OFC_INT
der_get_int(const OFC_UCHAR *p, OFC_SIZET len,
	    OFC_INT *ret, OFC_SIZET *size)
{
  OFC_INT val = 0;
  OFC_SIZET oldlen = len;

  if (len > 0U) 
    {
      val = (OFC_CHAR)*p++;
      while (--len)
	val = val * 256 + *p++;
    }
  *ret = val;
  if (size)
    *size = oldlen;
  return (0);
}

static OFC_UCHAR *gssapi_mech_make_header(OFC_UCHAR *p,
					   OFC_SIZET len,
					   const oid * mech)
{
  OFC_INT e;
  OFC_SIZET len_len, foo;
  OFC_UCHAR *ret ;

  *p++ = 0x60;
  len_len = length_len(len);
  e = der_put_length(p + len_len - 1, len_len, len, &foo);
  if ((e != SASL_OK) || (foo != len_len))
    ret = OFC_NULL ;
  else
    {
      p += len_len;
      *p++ = 0x06;
      *p++ = mech->length;
      ofc_memcpy(p, mech->elements, mech->length);
      p += mech->length;
      ret = p ;
    }
  return (ret);
}

static OM_uint32 of_security_gss_release_buffer(gss_buffer_t buffer)
{
  ofc_free (buffer->value) ;
  buffer->length = 0 ;
  return (SASL_OK) ;
}

static OFC_INT gssapi_spnego_encapsulate(OFC_UCHAR *buf,
					  OFC_SIZET buf_size,
					  gss_buffer_t output_token,
					  const oid* mech)
{
  OFC_SIZET len, outer_len ;
  OFC_UCHAR *p ;

  OFC_INT result ;

  gssapi_encap_length(buf_size, &len, &outer_len, mech);

  output_token->length = outer_len;
  output_token->value = ofc_malloc(outer_len);
  if (output_token->value == OFC_NULL) 
    {
      result = SASL_NOMEM ;
    }
  else
    {
      p = gssapi_mech_make_header(output_token->value, len, mech);
      if (p == OFC_NULL) 
	{
	  if (output_token->length != 0U)
	    of_security_gss_release_buffer(output_token);
	  result = SASL_FAIL ;
	}
      else
	{
	  ofc_memcpy(p, buf, buf_size);
	  result = SASL_OK ;
	}
    }
  return (result) ;
}

static OFC_INT gssapi_spnego_encapsulate_len(OFC_UCHAR *buf,
					      OFC_SIZET buf_size,
					      gss_buffer_t output_token)
{
  OFC_UCHAR *p ;

  OFC_INT result ;

  output_token->length = buf_size ;
  output_token->value = ofc_malloc(buf_size) ;
  if (output_token->value == OFC_NULL) 
    {
      result = SASL_NOMEM ;
    }
  else
    {
      p = output_token->value ;
      if (p == OFC_NULL) 
	{
	  if (output_token->length != 0U)
	    of_security_gss_release_buffer(output_token);
	  result = SASL_FAIL ;
	}
      else
	{
	  ofc_memcpy(p, buf, buf_size);
	  result = SASL_OK ;
	}
    }
  return (result) ;
}

static OFC_INT gssapi_verify_mech_header(OFC_UCHAR ** str,
					   OFC_SIZET total_len,
					   oid * mech)
{
  OFC_SIZET len, len_len, mech_len, foo;
  OFC_INT e;
  OFC_UCHAR *p = *str;
  OFC_UINT32 ret ;

  if (total_len < 1U)
    ret = SASL_BADMAC ;
  else
    {
      if (*p++ != 0x60)
	ret = SASL_BADMAC ;
      else
	{
	  e = der_get_length(p, total_len - 1, &len, &len_len);
	  if ((e != SASL_OK) || 1 + len_len + len != total_len)
	    ret = SASL_BADMAC ;
	  else
	    {
	      p += len_len;
	      if (*p++ != 0x06)
		ret = SASL_BADMAC ;
	      else
		{
		  e = der_get_length(p, total_len - 1 - len_len - 1,
				     &mech_len, &foo);
		  if (e != SASL_OK)
		    ret = SASL_BADMAC ;
		  else
		    {
		      p += foo;
		      if (mech_len != mech->length)
			ret = SASL_NOMECH ;
		      else
			{
			  if (ofc_memcmp(p, 
					  mech->elements, mech->length) != 0)
			    ret = SASL_NOMECH ;
			  else
			    {
			      p += mech_len;
			      *str = p;
			      ret = SASL_OK ;
			    }
			}
		    }
		}
	    }
	}
    }
  return (ret) ;
}

static OFC_INT gssapi_spnego_decapsulate(gss_buffer_t input_token_buffer,
					  OFC_UCHAR **buf,
					  OFC_SIZET *buf_len,
					  oid * mech)
{
  OFC_UCHAR *p ;
  OFC_UINT32 ret ;

  p = input_token_buffer->value;
  ret = gssapi_verify_mech_header(&p,
				  input_token_buffer->length,
				  mech);
  if (ret == SASL_OK) 
    {
      *buf_len = input_token_buffer->length - 
	(p - (OFC_UCHAR *) input_token_buffer->value);
      *buf = p;
    }
  else
    {
      /* 
       * If there is no gssapi header, just ignore it.  Not all implementations
       * put a gssapi wrapper
       */
      *buf_len = input_token_buffer->length ;
      *buf = input_token_buffer->value ;
      ret = SASL_NOMECH ;
    }
  return (ret) ;
}

static OFC_INT
encode_enumerated(OFC_UCHAR *p, OFC_SIZET len, const OFC_VOID *data, 
		  OFC_SIZET *size)
{
  OFC_UINT num = *(const OFC_UINT *)data;
  OFC_SIZET retsize = 0;
  OFC_SIZET l;
  OFC_INT e;
  OFC_INT result ;

  result = SASL_OK ;
  e = der_put_int(p, len, num, &l);
  if (e)
    result = e ;
  else
    {
      p -= l;
      len -= l;
      retsize += l;

      e = der_put_length_and_tag(p, len, l, 
				 ASN1_C_UNIV, PRIM, UT_Enumerated, &l);
      if (e)
	result = e ;
      else
	{
	  p -= l;
	  len -= l;
	  retsize += l;
	  *size = retsize;
	}
    }
  return (result) ;
}

static OFC_INT
encode_octet_string(OFC_UCHAR *p, OFC_SIZET len,
		    const octet_string *k, OFC_SIZET *size)
{
  OFC_SIZET retsize = 0;
  OFC_SIZET l;
  OFC_INT e;
  OFC_INT result ;

  e = der_put_octet_string(p, len, k, &l);
  if (e != SASL_OK)
    result = e ;
  else
    {
      p -= l;
      len -= l;
      retsize += l;
      e = der_put_length_and_tag(p, len, l, 
				 ASN1_C_UNIV, PRIM, UT_OctetString, &l);
      if (e != SASL_OK)
	result = e ;
      else
	{
	  p -= l;
	  len -= l;
	  retsize += l;
	  *size = retsize;
	  result = SASL_OK ;
	}
    }
  return (result) ;
}

static OFC_INT
encode_general_string(OFC_UCHAR *p, OFC_SIZET len,
		    const char *k, OFC_SIZET *size)
{
  OFC_SIZET retsize = 0;
  OFC_SIZET l;
  OFC_INT e;
  OFC_INT result ;

  e = der_put_general_string(p, len, k, &l);
  if (e != SASL_OK)
    result = e ;
  else
    {
      p -= l;
      len -= l;
      retsize += l;
      e = der_put_length_and_tag(p, len, l, 
				 ASN1_C_UNIV, PRIM, UT_GeneralString, &l);
      if (e != SASL_OK)
	result = e ;
      else
	{
	  p -= l;
	  len -= l;
	  retsize += l;
	  *size = retsize;
	  result = SASL_OK ;
	}
    }
  return (result) ;
}

/* oid descriptor is unencoded.  So it should really be of uints */
static OFC_INT
encode_oid(OFC_UCHAR *p, OFC_SIZET len,
	   const gss_OID_desc *k, OFC_SIZET *size)
{
  OFC_SIZET retsize = 0;
  OFC_SIZET l;
  OFC_INT e;
  OFC_INT result ;

  e = der_put_oid(p, len, k, &l);
  if (e != SASL_OK)
    result = e ;
  else
    {
      p -= l;
      len -= l;
      retsize += l;
      e = der_put_length_and_tag(p, len, l, ASN1_C_UNIV, PRIM, UT_OID, &l);
      if (e != SASL_OK)
	result = e ;
      else
	{
	  p -= l;
	  len -= l;
	  retsize += l;
	  *size = retsize;
	  result = SASL_OK ;
	}
    }
  return (result) ;
}

static OFC_INT 
encode_MechType(OFC_UCHAR *p, OFC_SIZET len, const MechType * data, 
		OFC_SIZET * size)
{
  OFC_SIZET retsize = 0;
  OFC_SIZET l;
  OFC_INT i, e;
  OFC_INT result ;

  i = 0;
  e = encode_oid(p, len, data, &l);
  if (e != SASL_OK)
    result = e ;
  else
    {
      p -= l ;
      len -= l ;
      retsize += l ;

      *size = retsize;
      result = SASL_OK ;
    }
  return (result) ;
}

static OFC_INT
encode_MechTypeList(OFC_UCHAR *p, OFC_SIZET len, 
		    const MechTypeList * data, OFC_SIZET * size)
{
  OFC_SIZET retsize = 0;
  OFC_SIZET l;
  OFC_INT i, e;
  OFC_INT result ;

  result = SASL_OK ;
  i = 0;
  for (i = (data)->len - 1; i >= 0; --i) 
    {
      OFC_SIZET oldsize = retsize;

      retsize = 0 ;
      e = encode_MechType(p, len, &(data)->val[i], &l);

      if (e != SASL_OK)
	result = e ;
      else
	{
	  p -= l;
	  len -= l ;
	  retsize += l ;
	  
	  retsize += oldsize;
	}
    }

  if (result == SASL_OK)
    {
      e = der_put_length_and_tag(p, len, retsize, ASN1_C_UNIV, 
				 CONS, UT_Sequence, &l);
      if (e != SASL_OK)
	result = e ;
      else
	{
	  p -= l;
	  len -= l ;
	  retsize += l ;
	  
	  *size = retsize;
	  result = SASL_OK ;
	}
    }

  return (result) ;
}

static OFC_VOID
free_octet_string(octet_string *k)
{
  ofc_free((OFC_VOID*) k->data);
  k->data = OFC_NULL;
}

static OFC_INT
encode_NegHint(OFC_UCHAR *p, OFC_SIZET len, 
	       const char * data, OFC_SIZET * size)
{
  OFC_SIZET retsize = 0;
  OFC_SIZET l;
  OFC_INT i, e;
  OFC_INT result ;

  result = SASL_OK ;
  i = 0;

  retsize = 0 ;
  e = encode_general_string(p, len, data, &l);

  if (e != SASL_OK)
    result = e ;
  else
    {
      p -= l;
      len -= l ;
      retsize += l ;

      e = der_put_length_and_tag(p, len, retsize, 
				 ASN1_C_CONTEXT, CONS, 0, &l);
      if (e != SASL_OK)
	result = e ;
      else
	{
	  p -= l ;
	  len -= l ;
	  retsize += l ;

	  e = der_put_length_and_tag(p, len, retsize, ASN1_C_UNIV, 
				     CONS, UT_Sequence, &l);
	  if (e != SASL_OK)
	    result = e ;
	  else
	    {
	      p -= l;
	      len -= l ;
	      retsize += l ;
	  
	      *size = retsize;
	      result = SASL_OK ;
	    }
	}
    }
  return (result) ;
}

static OFC_INT encode_ContextFlags(OFC_UCHAR *p, 
				    OFC_SIZET len, 
				    const ContextFlags * data, 
				    OFC_SIZET * size)
{
  OFC_SIZET retsize = 0;
  OFC_SIZET l;
  OFC_INT i, e;
  OFC_INT result ;
  OFC_UCHAR c = 0;

  i = 0;

  *p-- = c;
  len--;
  retsize++;
  c = 0;
  *p-- = c;
  len--;
  retsize++;
  c = 0;
  *p-- = c;
  len--;
  retsize++;
  c = 0;
  if (data->integFlag)
    c |= 1 << 1;
  if (data->confFlag)
    c |= 1 << 2;
  if (data->anonFlag)
    c |= 1 << 3;
  if (data->sequenceFlag)
    c |= 1 << 4;
  if (data->replayFlag)
    c |= 1 << 5;
  if (data->mutualFlag)
    c |= 1 << 6;
  if (data->delegFlag)
    c |= 1 << 7;
  *p-- = c;
  *p-- = 0;
  len -= 2;
  retsize += 2;

  e = der_put_length_and_tag(p, len, retsize, 
			     ASN1_C_UNIV, PRIM, UT_BitString, &l);
  if (e != SASL_OK)
    result = e ;
  else
    {
      p -= l ;
      len -= l ;
      retsize += l ;

      *size = retsize;
      result = SASL_OK ;
    }
  return (result) ;
}

static OFC_INT
encode_NegTokenInit(OFC_UCHAR *p, OFC_SIZET len, 
		    const NegTokenInit * data, OFC_SIZET *size)
{
  OFC_SIZET retsize = 0;
  OFC_SIZET l;
  OFC_INT i, e;
  OFC_INT result ;

  result = SASL_OK ;
  i = 0;
  /*
   * We are not utilizing the MIC
   */
#if defined(OFC_PARAM_SPNEGO_MECHLISTMIC)
  if ((data)->mechListMIC) 
    {
      OFC_SIZET oldsize = retsize;
      retsize = 0;
      e = encode_octet_string(p, len, (data)->mechListMIC, &l);

      if (e != SASL_OK)
	result = e ;
      else
	{
	  p -= l;
	  len -= l ;
	  retsize += l ;
	  
	  e = der_put_length_and_tag(p, len, retsize, ASN1_C_CONTEXT, 
				     CONS, 4, &l);
	  if (e != SASL_OK)
	    result = e ;
	  else
	    {
	      p -= l ;
	      len -= l ;
	      retsize += l ;

	      retsize += oldsize;
	    }
	}
    }
#endif

  if ((result == SASL_OK) && (data)->negHint)
    {
      OFC_SIZET oldsize = retsize;
      retsize = 0;
      e = encode_NegHint(p, len, (data)->negHint, &l);
      if (e != SASL_OK)
	result = e ;
      else
	{
	  p -= l ;
	  len -= l ;
	  retsize += l ;
 	  e = der_put_length_and_tag(p, len, retsize, 
				     ASN1_C_CONTEXT, CONS, 3, &l);
	  if (e != SASL_OK)
	    result = e ;
	  else
	    {
	      p -= l ;
	      len -= l ;
	      retsize += l ;

	      retsize += oldsize;
	    }
	}
    }

  if ((result == SASL_OK) && (data)->mechToken) 
    {
      OFC_SIZET oldsize = retsize;
      result = SASL_OK;
      e = encode_octet_string(p, len, (data)->mechToken, &l);

      if (e != SASL_OK)
	result = e ;
      else
	{
	  p -= l ;
	  len -= l ;
	  retsize += l ;

	  e = der_put_length_and_tag(p, len, retsize, 
				     ASN1_C_CONTEXT, CONS, 2, &l);

	  if (e != SASL_OK)
	    result = e ;
	  else
	    {
	      p -= l ;
	      len -= l ;
	      retsize += l ;

	      retsize += oldsize;
	    }
	}
    }

  if ((result == SASL_OK) && ((data)->reqFlags))
    {
      OFC_SIZET oldsize = retsize;
      result = SASL_OK;
      e = encode_ContextFlags(p, len, (data)->reqFlags, &l);
      if (e != SASL_OK)
	result = e ;
      else
	{
	  p -= l ;
	  len -= l ;
	  retsize += l ;

	  e = der_put_length_and_tag(p, len, retsize, 
				     ASN1_C_CONTEXT, CONS, 1, &l);
	  if (e != SASL_OK)
	    result = e ;
	  else
	    {
	      p -= l ;
	      len -= l ;
	      retsize += l ;

	      retsize += oldsize;
	    } 
	}
    }

  if (result == SASL_OK)
    {
      OFC_SIZET oldsize = retsize;
      retsize = 0;
      e = encode_MechTypeList(p, len, &(data)->mechTypes, &l);
      if (e != SASL_OK)
	result = e ;
      else
	{
	  p -= l ;
	  len -= l ;
	  retsize += l ;

	  e = der_put_length_and_tag(p, len, retsize, 
				     ASN1_C_CONTEXT, CONS, 0, &l);
	  if (e != SASL_OK)
	    result = e ;
	  else
	    {
	      p -= l ;
	      len -= l ;
	      retsize += l ;

	      retsize += oldsize;
	    }
	}
    }

  if (result == SASL_OK)
    {
      e = der_put_length_and_tag(p, len, retsize, ASN1_C_UNIV, 
				 CONS, UT_Sequence, &l);
      if (e != SASL_OK)
	result = e ;
      else
	{
	  p -= l ;
	  len -= l ;
	  retsize += l ;

	  *size = retsize;
	  result = SASL_OK ;
	}
    }
  return (result) ;
}

static OFC_INT
decode_enumerated(const OFC_UCHAR *p, OFC_SIZET len, OFC_VOID *num, 
		  OFC_SIZET *size)
{
  OFC_SIZET retsize = 0;
  OFC_SIZET l, reallen;
  OFC_INT e;
  OFC_INT result ;

  e = der_match_tag(p, len, ASN1_C_UNIV, PRIM, UT_Enumerated, &l);
  if (e != SASL_OK)
    result = e ;
  else
    {
      p += l;
      len -= l;
      retsize += l;
      e = der_get_length(p, len, &reallen, &l);
      if (e != SASL_OK)
	result = e ;
      else
	{
	  p += l;
	  len -= l;
	  retsize += l;
	  e = der_get_int(p, reallen, num, &l);
	  if (e != SASL_OK)
	    result = e ;
	  else
	    {
	      p += l;
	      len -= l;
	      retsize += l;
	      if (size)
		*size = retsize ;
	      result = SASL_OK ;
	    }
	}
    }
  return (result) ;
}

static OFC_INT
decode_octet_string(const OFC_UCHAR *p, OFC_SIZET len,
		    octet_string *k, OFC_SIZET *size)
{
  OFC_SIZET retsize = 0;
  OFC_SIZET l;
  OFC_INT e;
  OFC_SIZET slen;
  OFC_INT result ;

  e = der_match_tag(p, len, ASN1_C_UNIV, PRIM, UT_OctetString, &l);
  if (e != SASL_OK)
    result = e ;
  else
    {
      p += l;
      len -= l;
      retsize += l;

      e = der_get_length(p, len, &slen, &l);
      if (e != SASL_OK)
	result = e ;
      else
	{
	  p += l;
	  len -= l;
	  retsize += l;
	  if (len < slen)
	    result = SASL_BUFOVER ;
	  else
	    {
	      e = der_get_octet_string(p, slen, k, &l);
	      if (e != SASL_OK)
		result = e ;
	      else
		{
		  p += l;
		  len -= l;
		  retsize += l;
		  if (size)
		    *size = retsize;
		  result = SASL_OK ;
		}
	    }
	}
    }
  return (result) ;
}

static OFC_INT
decode_oid(const OFC_UCHAR *p, OFC_SIZET len,
	   gss_OID k, OFC_SIZET *size)
{
  OFC_SIZET retsize = 0;
  OFC_SIZET l;
  OFC_INT e;
  OFC_SIZET slen;
  OFC_INT result ;

  e = der_match_tag(p, len, ASN1_C_UNIV, PRIM, UT_OID, &l);
  if (e != SASL_OK)
    result = e ;
  else
    {
      p += l;
      len -= l;
      retsize += l;

      e = der_get_length(p, len, &slen, &l);
      if (e != SASL_OK)
	result = e ;
      else
	{
	  p += l;
	  len -= l;
	  retsize += l;
	  if (len < slen)
	    result = SASL_BUFOVER ;
	  else
	    {
	      e = der_get_oid(p, slen, k, &l);
	      if (e != SASL_OK)
		result = e ;
	      else
		{
		  p += l;
		  len -= l;
		  retsize += l;
		  if (size)
		    *size = retsize;
		  result = SASL_OK ;
		}
	    }
	}
    }
  return (result) ;
}

static OFC_VOID
free_MechType(MechType * data)
{
  free_oid(data);
}

static OFC_INT
decode_MechType(const OFC_UCHAR *p, OFC_SIZET len, 
		MechType * data, OFC_SIZET * size)
{
  OFC_SIZET retsize = 0, reallen;
  OFC_SIZET l;
  OFC_INT e;
  OFC_INT result ;

  ofc_memset(data, 0, sizeof(*data));
  reallen = 0;
  e = decode_oid(p, len, data, &l);
  if (e != SASL_OK)
    result = e ;
  else
    {
      p += l;
      len -= l ;
      retsize += l ;

      if (size)
	*size = retsize;
      result = SASL_OK ;
    }

  if (result != SASL_OK)
    free_MechType(data) ;

  return (result) ;
}

static OFC_VOID
free_MechTypeList(MechTypeList * data)
{
  if (data != OFC_NULL)
    {
      while ((data)->len)
	{
	  free_MechType(&(data)->val[(data)->len - 1]);
	  (data)->len--;
	}
      ofc_free((data)->val);
      (data)->val = OFC_NULL;
    }
}

static OFC_INT
decode_MechTypeList(const OFC_UCHAR *p, OFC_SIZET len, MechTypeList * data, OFC_SIZET * size)
{
  OFC_SIZET reallen;
  OFC_SIZET l;
  OFC_INT e;
  OFC_INT retsize = 0 ;

  OFC_INT result = SASL_OK ;

  ofc_memset(data, '\0', sizeof(*data));
  reallen = 0;
  e = der_match_tag_and_length(p, len, ASN1_C_UNIV, CONS, UT_Sequence, &reallen, &l);

  if (e != SASL_OK)
    result = e ;
  else
    {
      p += l;
      len -= l ;
      retsize += l ;

      if (len < reallen)
	result = SASL_BUFOVER ;
      else
	{
	  OFC_SIZET origlen = len;
	  OFC_INT oldret = retsize ;

	  len = reallen;

	  retsize = 0 ;
	  (data)->len = 0;
	  (data)->val = OFC_NULL;

	  while (retsize < origlen) 
	    {
	      (data)->len++;
	      (data)->val = ofc_realloc((data)->val, sizeof(*((data)->val)) * (data)->len);
	      e = decode_MechType(p, len, &(data)->val[(data)->len - 1], &l);

	      if (e != SASL_OK)
		result = e ;
	      else
		{
		  p += l;
		  len -= l ;
		  retsize += l ;

		  len = origlen - retsize;
		}
	    }
	  if (result == SASL_OK)
	    retsize += oldret;
	}
    }

  if (result == SASL_OK)
    {
      if (size)
	*size = retsize;
    }
  else
    free_MechTypeList(data);

  return (result) ;
}

static OFC_VOID
free_NegTokenInit(NegTokenInit * data)
{
  free_MechTypeList(&(data)->mechTypes);

  if ((data)->reqFlags)
    {
      ofc_free((data)->reqFlags);
      (data)->reqFlags = NULL;
    }
  if ((data)->mechToken)
    {
      free_octet_string((data)->mechToken);
      ofc_free((data)->mechToken);
      (data)->mechToken = NULL;
    }

  if ((data)->negHint)
    {
      ofc_free ((data)->negHint) ;
      (data)->negHint = NULL ;
    }

#if defined(OFC_PARAM_SPNEGO_MECHLISTMIC)
  if ((data)->mechListMIC)
    {
      free_octet_string((data)->mechListMIC);
      ofc_free((data)->mechListMIC);
      (data)->mechListMIC = NULL;
    }
#endif
}

static OFC_VOID
free_NegTokenResp(NegTokenResp * data)
{
  if ((data)->negState) 
    {
      ofc_free((data)->negState);
      (data)->negState = OFC_NULL;
    }
  if ((data)->supportedMech) 
    {
      free_MechType((data)->supportedMech);
      ofc_free((data)->supportedMech);
      (data)->supportedMech = OFC_NULL;
    }
  if ((data)->responseToken) 
    {
      free_octet_string((data)->responseToken);
      ofc_free((data)->responseToken);
      (data)->responseToken = OFC_NULL;
    }
#if defined(OFC_PARAM_SPNEGO_MECHLISTMIC)
  if ((data)->mechListMIC) 
    {
      free_octet_string((data)->mechListMIC);
      ofc_free((data)->mechListMIC);
      (data)->mechListMIC = OFC_NULL;
    }
#endif
}

static OFC_INT
encode_NegTokenResp(OFC_UCHAR *p, OFC_SIZET len, 
		   const NegTokenResp * data, OFC_SIZET * size)
{
  OFC_SIZET retsize = 0;
  OFC_SIZET l;
  OFC_INT i, e;
  OFC_INT result ;

  i = 0;

  result = SASL_OK ;
#if defined(OFC_PARAM_SPNEGO_MECHLISTMIC)
  if ((data)->mechListMIC) 
    {
      OFC_SIZET oldret = retsize;

      retsize = 0;
      e = encode_octet_string(p, len, (data)->mechListMIC, &l);

      if (e != SASL_OK)
	result = e ;
      else
	{
	  p -= l ;
	  len -= l ;
	  retsize += l ;

	  e = der_put_length_and_tag(p, len, retsize, 
				     ASN1_C_CONTEXT, CONS, 3, &l);

	  if (e != SASL_OK)
	    result = e ;
	  else
	    {
	      p -= l ;
	      len -= l ;
	      retsize += l ;

	      retsize += oldret;
	    }
	}
    }
#endif

  if ((result == SASL_OK) && ((data)->responseToken))
    {
      OFC_SIZET oldret = retsize;
      retsize = 0;

      e = encode_octet_string(p, len, (data)->responseToken, &l);
      if (e != SASL_OK)
	result = e ;
      else
	{
	  p -= l ;
	  len -= l ;
	  retsize += l ;

	  e = der_put_length_and_tag(p, len, retsize, 
				     ASN1_C_CONTEXT, CONS, 2, &l);

	  if (e != SASL_OK)
	    result = e ;
	  else
	    {
	      p -= l ;
	      len -= l ;
	      retsize += l ;

	      retsize += oldret;
	    }
	}
    }

  if ((result == SASL_OK) && ((data)->supportedMech)) 
    {
      OFC_SIZET oldret = retsize;
      retsize = 0;

      e = encode_MechType(p, len, (data)->supportedMech, &l);

      if (e != SASL_OK)
	result = e ;
      else
	{
	  p -= l ;
	  len -= l ;
	  retsize += l ;

	  e = der_put_length_and_tag(p, len, retsize, 
				     ASN1_C_CONTEXT, CONS, 1, &l);
	  if (e != SASL_OK)
	    result = e ;
	  else
	    {
	      p -= l ;
	      len -= l ;
	      retsize += l ;

	      retsize += oldret;
	    }
	}
    }

  if ((result == SASL_OK) && ((data)->negState)) 
    {
      OFC_SIZET oldret = retsize;
      retsize = 0;
      e = encode_enumerated(p, len, (data)->negState, &l);
      if (e != SASL_OK)
	result = e ;
      else
	{
	  p -= l ;
	  len -= l ;
	  retsize += l ;

	  e = der_put_length_and_tag(p, len, retsize, 
				     ASN1_C_CONTEXT, CONS, 0, &l);

	  if (e != SASL_OK)
	    result = e ;
	  else
	    {
	      p -= l ;
	      len -= l ;
	      retsize += l ;

	      retsize += oldret;
	    }
	}
    }

  if (result == SASL_OK)
    {
      e = der_put_length_and_tag(p, len, retsize, 
				 ASN1_C_UNIV, CONS, UT_Sequence, &l);
      if (e != SASL_OK)
	result = e ;
      else
	{
	  p -= l ;
	  len -= l ;
	  retsize += l ;

	  *size = retsize;
	}
    }

  return (result) ;
}

/*****************************  Server Section  *****************************/

typedef struct server_context {
  OFC_INT state;

    /* per-step mem management */
  OFC_CHAR *out_buf;
  OFC_UINT out_buf_len;

  sasl_conn_t *pconn ;
  OFC_CHAR *user ;
  OFC_CHAR *authid ;
  OFC_INT use_spnego ;
} server_context_t;

static int 
gssapi_server_mech_new(OFC_VOID *glob_context,
		       sasl_server_params_t *params,
		       const char *challenge,
		       unsigned challen,
		       OFC_VOID **conn_context)
{
    server_context_t *text;
    OFC_INT result ;
    
    text = params->utils->malloc(sizeof(server_context_t));
    if (text == NULL) 
      {
	MEMERROR(params->utils->conn);
	result = SASL_NOMEM ;
      }
    else
      {
	text->state = SASL_SPNEGO_STATE_NEG_TOKEN_INIT ;
	text->out_buf = OFC_NULL ;
	text->user = OFC_NULL ;
	text->authid = OFC_NULL ;
	/*
	 * Create a context for ntlm
	 */
	result = of_security_server_new ("cifs", 
				       params->serverFQDN, OFC_NULL,
				       params->iplocalport, 
				       params->ipremoteport,
				       OFC_NULL, 0, 
				       (sasl_conn_t **) &text->pconn) ;
      
	if (result == SASL_OK)
	  {
	    *conn_context = text;
	  }
      }
    return result ;
}

static OFC_INT
fix_dce(OFC_SIZET reallen, OFC_SIZET *len)
{
  OFC_INT result ;

  if (reallen == ASN1_INDEFINITE)
    result = 1 ;
  else if (*len < reallen)
    result = -1 ;
  else
    {
      *len = reallen;
      result = 0 ;
    }
  return (result) ;
}

static OFC_VOID
free_ContextFlags(ContextFlags * data)
{
  (OFC_VOID) data;
}

static OFC_INT
decode_ContextFlags(const OFC_UCHAR *p, OFC_SIZET len, ContextFlags * data, OFC_SIZET * size)
{
  OFC_SIZET retsize = 0 ;
  OFC_SIZET reallen;
  OFC_SIZET l;
  OFC_INT e;

  OFC_INT result = SASL_OK ;

  ofc_memset(data, '\0', sizeof(*data));
  reallen = 0;

  e = der_match_tag_and_length(p, len, ASN1_C_UNIV, PRIM, UT_BitString, &reallen, &l);
  if (e != SASL_OK)
    result = e ;
  else
    {
      p += l ;
      len -= l ;
      retsize += l ;

      if (len < reallen)
	result = SASL_BUFOVER ;
      else
	{
	  p++;
	  len--;
	  reallen--;
	  retsize++;

	  data->delegFlag = (*p >> 7) & 1;
	  data->mutualFlag = (*p >> 6) & 1;
	  data->replayFlag = (*p >> 5) & 1;
	  data->sequenceFlag = (*p >> 4) & 1;
	  data->anonFlag = (*p >> 3) & 1;
	  data->confFlag = (*p >> 2) & 1;
	  data->integFlag = (*p >> 1) & 1;

	  p += reallen;
	  len -= reallen;
	  retsize += reallen;
	}
    }
  if (result == SASL_OK)
    {
      if (size)
	*size = retsize;
    }
  else
    free_ContextFlags(data);
  return result ;
}

static OFC_INT
decode_NegTokenInit(const OFC_UCHAR *p, OFC_SIZET len, NegTokenInit * data, OFC_SIZET * size)
{
  OFC_SIZET retsize = 0 ;
  OFC_SIZET reallen ;
  OFC_SIZET l;
  OFC_INT e;
  OFC_INT dce_fix;
  OFC_INT result ;

  result = SASL_OK ;

  ofc_memset(data, '\0', sizeof(*data));
  reallen = 0;
  e = der_match_tag_and_length(p, len, ASN1_C_UNIV, CONS, UT_Sequence, &reallen, &l);

  if (e != SASL_OK)
    {
      result = e ;
    }
  else
    {
      p+= l;
      len -= l ;
      retsize += l ;

      if ((dce_fix = fix_dce(reallen, &len)) < 0)
	result = SASL_BADPROT ;
      else
	{
	  OFC_SIZET newlen, oldlen;

	  e = der_match_tag(p, len, ASN1_C_CONTEXT, CONS, 0, &l);
	  if (e != SASL_OK)
	    result = e ;
	  else
	    {
	      p += l;
	      len -= l;
	      retsize += l;
	      e = der_get_length(p, len, &newlen, &l);

	      if (e != SASL_OK)
		{
		  result = e ;
		}
	      else
		{
		  p += l;
		  len -= l ;
		  retsize += l ;

		  oldlen = len ;
		  if ((dce_fix = fix_dce(newlen, &len)) < 0)
		    result = SASL_BADPROT ;
		  else
		    {
		      e = decode_MechTypeList(p, len, &(data)->mechTypes, &l);

		      if (e)
			{
			  result = e ;
			}
		      else
			{
			  p+= l;
			  len -= l ;
			  retsize += l ;

			  if (dce_fix) 
			    {
			      e = der_match_tag_and_length(p, len, (Der_class) 0, (Der_type) 0, 0, &reallen, &l);

			      if (e != SASL_OK)
				{
				  result = e ;
				}
			      else
				{
				  p+= l;
				  len -= l ;
				  retsize += l ;
				}
			    }
			  else 
			    {
			      len = oldlen - newlen;
			    }
			}
		    }
		}
	    }
	  
	  if (result == SASL_OK)
	    {
	      e = der_match_tag(p, len, ASN1_C_CONTEXT, CONS, 1, &l);
	      if (e != SASL_OK)
		(data)->reqFlags = OFC_NULL;
	      else 
		{
		  p += l;
		  len -= l;
		  retsize += l;
		  e = der_get_length(p, len, &newlen, &l);

		  if (e != SASL_OK)
		    {
		      free_NegTokenInit(data);
		      result = e ;
		    }
		  else
		    {
		      p+= l;
		      len -= l ;
		      retsize += l ;

		      oldlen = len;
		      if ((dce_fix = fix_dce(newlen, &len)) < 0)
			result = SASL_BADPROT ;
		      else
			{
			  (data)->reqFlags = ofc_malloc(sizeof(*(data)->reqFlags));
			  if ((data)->reqFlags == NULL)
			    result = SASL_NOMEM ;
			  else
			    e = decode_ContextFlags(p, len, (data)->reqFlags, &l);

			  if (e != SASL_OK)
			    {
			      result = e ;
			    }
			  else
			    {
			      p+= l;
			      len -= l ;
			      retsize += l ;

			      if (dce_fix) 
				{
				  e = der_match_tag_and_length(p, len, (Der_class) 0, (Der_type) 0, 0, &reallen, &l);

				  if (e != SASL_OK)
				    {
				      free_NegTokenInit(data);
				      result = e ;
				    }
				  else
				    {
				      p+= l;
				      len -= l ;
				      retsize += l ;
				    } 
				}
			      else
				len = oldlen - newlen;
			    }
			}
		    }
		}
	    }

	  if (result == SASL_OK)
	    {
	      e = der_match_tag(p, len, ASN1_C_CONTEXT, CONS, 2, &l);
	      if (e)
		(data)->mechToken = OFC_NULL;
	      else 
		{
		  p += l;
		  len -= l;
		  retsize += l;
		  e = der_get_length(p, len, &newlen, &l);

		  if (e != SASL_OK)
		    {
		      result = e ;
		    }
		  else
		    {
		      p+= l;
		      len -= l ;
		      retsize += l ;

		      oldlen = len;
		      if ((dce_fix = fix_dce(newlen, &len)) < 0)
			result = SASL_BADPROT ;
		      else
			{
			  (data)->mechToken = ofc_malloc(sizeof(*(data)->mechToken));
			  if ((data)->mechToken == NULL)
			    result = SASL_NOMEM ;
			  else
			    {
			      e = decode_octet_string(p, len, (data)->mechToken, &l);
			      if (e != SASL_OK)
				{
				  result = e ;
				}
			      else
				{
				  p+= l;
				  len -= l ;
				  retsize += l ;

				  if (dce_fix) 
				    {
				      e = der_match_tag_and_length(p, len, (Der_class) 0, (Der_type) 0, 0, &reallen, &l);

				      if (e != SASL_OK)
					{
					  result = e ;
					}
				      else
					{
					  p+= l;
					  len -= l ;
					  retsize += l ;
					} 
				    }
				  else
				    len = oldlen - newlen;
				}
			    }
			}
		    }
		}
	    }

#if defined(OFC_PARAM_SPNEGO_MECHLISTMIC)
	  if (result == SASL_OK)
	    {
	      e = der_match_tag(p, len, ASN1_C_CONTEXT, CONS, 3, &l);
	      if (e)
		(data)->mechListMIC = NULL;
	      else 
		{
		  p += l;
		  len -= l;
		  retsize += l;
		  e = der_get_length(p, len, &newlen, &l);

		  if (e != SASL_OK)
		    {
		      result = e ;
		    }
		  else
		    {
		      p+= l;
		      len -= l ;
		      retsize += l ;

		      oldlen = len;
		      if ((dce_fix = fix_dce(newlen, &len)) < 0)
			result = SASL_BADPROT ;
		      else
			{
			  (data)->mechListMIC = 
			    ofc_malloc(sizeof(struct octet_string));
			  if ((data)->mechListMIC == OFC_NULL)
			    result = SASL_NOMEM ;
			  else
			    {
			      e = decode_octet_string(p, len, (data)->mechListMIC, &l);

			      if (e != SASL_OK)
				{
				  result = e ;
				}
			      else
				{
				  p+= l;
				  len -= l ;
				  retsize += l ;

				  if (dce_fix) 
				    {
				      e = der_match_tag_and_length(p, len, (Der_class) 0, (Der_type) 0, 0, &reallen, &l);

				      if (e != SASL_OK)
					{
					  result = e ;
					}
				      else
					{
					  p+= l;
					  len -= l ;
					  retsize += l ;
					}
				    } 
				  else
				    len = oldlen - newlen;
				}
			    }
			}
		    }
		}
	    }
#endif

	  if (result == SASL_OK)
	    {
	      if (dce_fix) 
		{
		  e = der_match_tag_and_length(p, len, (Der_class) 0, (Der_type) 0, 0, &reallen, &l);

		  if (e != SASL_OK)
		    {
		      result = e ;
		    }
		  else
		    {
		      p+= l;
		      len -= l ;
		      retsize += l ;
		    }
		}
	    }
	}
    }

  if (result == SASL_OK)
    {
      if (size)
	*size = retsize;
    }
  else
    free_NegTokenInit(data);

  return (result) ;
}

static OFC_INT spnego_init(server_context_t *text,
			    const gss_buffer_t input_token,
			    gss_buffer_t output_token,
			    OM_uint32 *time_rec)
{
  OFC_INT result ;
  NegTokenInit resp;
  OFC_UCHAR *buf;
  OFC_SIZET buf_size;
  gss_buffer_desc sub_token;
  OFC_SIZET len, taglen;
  OFC_CCHAR *sasl_out ;
  OFC_UINT sasl_outlen ;

  text->use_spnego = OFC_TRUE ;
  result = gssapi_spnego_decapsulate (input_token, &buf,
				      &buf_size, &gss_mech_spnego_oid) ;

  if (result == SASL_OK)
    {
      result = der_match_tag_and_length(buf, buf_size,
					ASN1_C_CONTEXT, CONS, 0, 
					&len, &taglen);
      if (result == SASL_OK)
	{
	  if(len > buf_size - taglen)
	    result = SASL_BUFOVER ;
	  else
	    {
	      result = decode_NegTokenInit(buf + taglen, len, &resp, OFC_NULL) ;
	      if (result == SASL_OK)
		{
		  if (resp.mechToken != OFC_NULL) 
		    {
		      sub_token.length = resp.mechToken->length;
		      sub_token.value  = 
			(OFC_VOID *) resp.mechToken->data;
		    } 
		  else 
		    {
		      sub_token.length = 0;
		      sub_token.value  = OFC_NULL;
		    }

		  sasl_out = OFC_NULL ;
		  sasl_outlen = 0 ;

		  result = of_security_server_start (text->pconn, "NTLM", 
						   sub_token.value, (unsigned) sub_token.length,
						   &sasl_out, &sasl_outlen) ;


		  output_token->value = ofc_malloc(sasl_outlen);
		  if (output_token->value == OFC_NULL)
		    {
		      result = SASL_NOMEM ;
		    }
		  else
		    {
		      output_token->length = sasl_outlen ;
		      ofc_memcpy (output_token->value, sasl_out,
				   sasl_outlen) ;
		    }
		  free_NegTokenInit(&resp) ;
		}
	    }
	}
    }
  else
    {
      text->use_spnego = OFC_FALSE ;
      sub_token.length = buf_size ;
      sub_token.value = buf ;
      sasl_out = OFC_NULL ;
      sasl_outlen = 0 ;

      result = of_security_server_start (text->pconn, "NTLM", 
				       sub_token.value,
				       (unsigned) sub_token.length,
				       &sasl_out, &sasl_outlen) ;

      output_token->value = ofc_malloc(sasl_outlen);
      if (output_token->value == OFC_NULL)
	{
	  result = SASL_NOMEM ;
	}
      else
	{
	  output_token->length = sasl_outlen ;
	  ofc_memcpy (output_token->value, sasl_out, sasl_outlen) ;
	}
    }

  return (result) ;
}

static OFC_INT add_mech(MechTypeList * mech_list, const oid *mech);

static OFC_INT spnego_sreply(server_context_t *text,
			      const gss_buffer_t input_token,
			      gss_buffer_t output_token,
			      OM_uint32 *time_rec)
{
  NegTokenResp resp;
  OFC_INT result ;
  OFC_UCHAR *buf = OFC_NULL ;
  OFC_SIZET buf_size;
  OFC_SIZET len ;

  result = SASL_OK ;

  ofc_memset (&resp, 0, sizeof(resp)) ;

#if defined(OFC_PARAM_SPNEGO_MECHLISTMIC)
  MechTypeList mechTypes;
  OFC_UCHAR * bufx ;
  OFC_UCHAR * px ;
  OFC_SIZET lenx ;
  OFC_SIZET lx ;
  OFC_UCHAR *mic ;

  ofc_memset (&mechTypes, '\0', sizeof (MechTypeList)) ;
  mechTypes.len = 0 ;
  mechTypes.val = OFC_NULL ;
  add_mech(&mechTypes, &gss_mech_ntlmssp_oid) ;

  bufx = ofc_malloc(1024) ;
  px = bufx + 1024 - 1 ;
  lenx = 1024 ;
  encode_MechTypeList(px, lenx, &mechTypes, &lx);
  px -= lx ;
  lenx -= lx ;
  px++ ;

  free_MechTypeList(&mechTypes);

  mic = ofc_malloc(16) ;
  of_security_server_mech_list_mic(text->pconn, px, lx, mic) ;
  resp.mechListMIC = 
    ofc_malloc(sizeof(struct octet_string));
  resp.mechListMIC->data = mic ;
  resp.mechListMIC->length = 16 ;

  ofc_free (bufx) ;
#endif

  if (output_token != OFC_NULL && output_token->length != 0U)
    {
      resp.responseToken =
	ofc_malloc(sizeof(struct octet_string));
      if (resp.responseToken == OFC_NULL)
	{
	  result = SASL_NOMEM ;
	}
      else
	{
	  resp.responseToken->length = output_token->length ;
	  resp.responseToken->data = output_token->value ;
	}
    }

  resp.negState = ofc_malloc (sizeof(*resp.negState)) ;
  if (resp.negState == OFC_NULL)
    {
      result = SASL_NOMEM ;
    }
  else
    {
      *(resp.negState) = accept_completed;
    }

  if (result == SASL_OK)
    {
      buf_size = 1024 ;
      buf = ofc_malloc(buf_size) ;

      do
	{
	  OFC_INT nested_result ;

	  nested_result =
	    encode_NegTokenResp(buf + buf_size - 1,
				buf_size,
				&resp, &len) ;

	  if (nested_result != SASL_OK)
	    result = nested_result ;
	  else
	    {
	      OFC_SIZET tmp;

	      nested_result =
		der_put_length_and_tag(buf + buf_size - 
				       len - 1,
				       buf_size - len,
				       len,
				       ASN1_C_CONTEXT,
				       CONS,
				       1,
				       &tmp);
	      if (nested_result != SASL_OK)
		result = nested_result ;
	      else
		len += tmp;
	    }

	  if (result != SASL_OK && result != SASL_CONTINUE) 
	    {
	      if (result == SASL_BUFOVER)
		{
		  OFC_UCHAR *tmp;

		  buf_size *= 2;
		  tmp = ofc_realloc(buf, buf_size);
		  if (tmp == OFC_NULL) 
		    {
		      result = SASL_NOMEM ;
		    }
		  else
		    {
		      buf = tmp;
		      result = SASL_OK ;
		    }
		}
	    }
	}
      while (result == SASL_BUFOVER) ;

      if (result == SASL_OK || result == SASL_CONTINUE)
	{
	  OFC_INT nested_result ;
	  nested_result = 
	    gssapi_spnego_encapsulate_len(buf + buf_size - len, 
					  len,
					  output_token) ;
	  if (nested_result != SASL_OK)
	    result = nested_result ;
	}
      ofc_free (buf) ;
    }

  free_NegTokenResp(&resp) ;
  return (result) ;
}

static OFC_INT spnego_xreply(server_context_t *text,
			      const gss_buffer_t input_token,
			      gss_buffer_t output_token,
			      OM_uint32 *time_rec)
{
  NegTokenResp resp;
  OFC_INT result ;
  OFC_UCHAR *buf = OFC_NULL ;
  OFC_SIZET buf_size;
  OFC_SIZET len ;

  result = SASL_OK ;

  ofc_memset (&resp, 0, sizeof(resp)) ;

  resp.negState = ofc_malloc (sizeof(*resp.negState)) ;
  if (resp.negState == OFC_NULL)
    {
      result = SASL_NOMEM ;
    }
  else
    {
      *(resp.negState) = accept_incomplete;

      resp.supportedMech = 
	ofc_malloc(sizeof(*resp.supportedMech));
      if (resp.supportedMech == OFC_NULL) 
	{
	  result = SASL_NOMEM ;
	}
      else
	{
	  result = der_get_oid(gss_mech_ntlmssp_oid.elements,
			       gss_mech_ntlmssp_oid.length,
			       resp.supportedMech,
			       OFC_NULL);
	  if (result == SASL_OK) 
	    {
	      if (output_token != OFC_NULL && output_token->length != 0U)
		{
		  resp.responseToken =
		    ofc_malloc (sizeof(*resp.responseToken)) ;
		  if (resp.responseToken == OFC_NULL)
		    {
		      result = SASL_NOMEM ;
		    }
		  else
		    {
		      resp.responseToken->length = output_token->length ;
		      resp.responseToken->data = output_token->value ;

		      buf_size = 1024 ;
		      buf = ofc_malloc(buf_size) ;

		      do
			{
			  OFC_INT nested_result ;

			  nested_result =
			    encode_NegTokenResp(buf + buf_size - 1,
						buf_size,
						&resp, &len) ;

			  if (nested_result != SASL_OK)
			    result = nested_result ;
			  else
			    {
			      OFC_SIZET tmp;

			      nested_result =
				der_put_length_and_tag(buf + buf_size - 
						       len - 1,
						       buf_size - len,
						       len,
						       ASN1_C_CONTEXT,
						       CONS,
						       1,
						       &tmp);
			      if (nested_result != SASL_OK)
				result = nested_result ;
			      else
				len += tmp;
			    }

			  if (result != SASL_OK && result != SASL_CONTINUE) 
			    {
			      if (result == SASL_BUFOVER)
				{
				  OFC_UCHAR *tmp;

				  buf_size *= 2;
				  tmp = ofc_realloc(buf, buf_size);
				  if (tmp == OFC_NULL) 
				    {
				      result = SASL_NOMEM ;
				    }
				  else
				    {
				      buf = tmp;
				      result = SASL_OK ;
				    }
				}
			    }
			}
		      while (result == SASL_BUFOVER) ;

		      if (result == SASL_OK || result == SASL_CONTINUE)
			{
			  OFC_INT nested_result ;
			  nested_result = 
			    gssapi_spnego_encapsulate_len(buf + buf_size - len, 
							  len,
							  output_token) ;
			  if (nested_result != SASL_OK)
			    result = nested_result ;
			}
		      ofc_free (buf) ;
		    }
		}
	    }
	}
    }
  free_NegTokenResp(&resp) ;
  return (result) ;
}

static OFC_INT
decode_NegTokenResp(const OFC_UCHAR *p, OFC_SIZET len, 
		    NegTokenResp * data, OFC_SIZET * size)
{
  OFC_SIZET retsize = 0, reallen;
  OFC_SIZET l;
  OFC_INT e;
  OFC_INT result ;
  OFC_INT dce_fix;

  ofc_memset (data, '\0', sizeof(NegTokenResp)) ;
  reallen = 0;
  e = der_match_tag_and_length(p, len, ASN1_C_UNIV, CONS, 
			       UT_Sequence, &reallen, &l);
  /* FORW */
  if (e != SASL_OK)
    result = e ;
  else
    {
      p += l;
      len -= l ;
      retsize += l ;

      if ((dce_fix = fix_dce(reallen, &len)) < 0)
	result = SASL_BADPROT ;
      else
	{
	  OFC_SIZET newlen, oldlen;

	  e = der_match_tag(p, len, ASN1_C_CONTEXT, CONS, 0, &l);
	  if (e != SASL_OK)
	    {
	      (data)->negState = OFC_NULL;
	      result = SASL_OK ;
	    }
	  else 
	    {
	      p += l;
	      len -= l;
	      retsize += l;
	      e = der_get_length(p, len, &newlen, &l);
	      if (e != SASL_OK)
		result = e ;
	      else
		{
		  p += l;
		  len -= l ;
		  retsize += l ;

		  oldlen = len;
		  if ((dce_fix = fix_dce(newlen, &len)) < 0)
		    result = SASL_BADPROT ;
		  else
		    {
		      (data)->negState = 
			ofc_malloc(sizeof(*(data)->negState));
		      if ((data)->negState == OFC_NULL)
			result = SASL_NOMEM ;
		      else
			{
			  e = decode_enumerated(p, len, (data)->negState, &l);
			  if (e != SASL_OK)
			    result = e ;
			  else
			    {
			      p += l;
			      len -= l ;
			      retsize += l ;

			      if (dce_fix) 
				{
				  e = der_match_tag_and_length(p, len, 
							       (Der_class) 0, 
							       (Der_type) 0, 
							       0, &reallen, 
							       &l);
				  if (e != SASL_OK)
				    result = e ;
				  else
				    {
				      p += l;
				      len -= l ;
				      retsize += l ;
				      result = SASL_OK ;
				    } 
				}
			      else
				{
				  len = oldlen - newlen;
				  result = SASL_OK ;
				}
			    }
			}
		    }
		}
	    }
	}
      if (result == SASL_OK)
	{
	  OFC_SIZET newlen, oldlen;

	  e = der_match_tag(p, len, ASN1_C_CONTEXT, CONS, 1, &l);
	  if (e != SASL_OK)
	    (data)->supportedMech = NULL;
	  else 
	    {
	      p += l;
	      len -= l;
	      retsize += l;
	      e = der_get_length(p, len, &newlen, &l);
	      if (e != SASL_OK)
		result = e ;
	      else
		{
		  p += l;
		  len -= l ;
		  retsize += l ;

		  oldlen = len;
		  if ((dce_fix = fix_dce(newlen, &len)) < 0)
		    result = SASL_BADPROT ;
		  else
		    {
		      (data)->supportedMech = 
			ofc_malloc(sizeof(*(data)->supportedMech));
		      if ((data)->supportedMech == OFC_NULL)
			result = SASL_NOMEM ;
		      else
			{
			  e = decode_MechType(p, len, 
					      (data)->supportedMech, &l);
			  if (e != SASL_OK)
			    result = e ;
			  else
			    {
			      p += l;
			      len -= l ;
			      retsize += l ;

			      if (dce_fix) 
				{
				  e = der_match_tag_and_length(p, len, 
							       (Der_class) 0, 
							       (Der_type) 0, 
							       0, &reallen, 
							       &l);
				  if (e != SASL_OK)
				    result = e ;
				  else
				    {
				      p += l;
				      len -= l ;
				      retsize += l ;
				      result = SASL_OK ;
				    }
				}
			      else
				{
				  len = oldlen - newlen;
				  result = SASL_OK ;
				}
			    }
			}
		    }
		}
	    }
	}

      if (result == SASL_OK)
	{
	  OFC_SIZET newlen, oldlen;

	  e = der_match_tag(p, len, ASN1_C_CONTEXT, CONS, 2, &l);
	  if (e != SASL_OK)
	    (data)->responseToken = NULL;
	  else 
	    {
	      p += l;
	      len -= l;
	      retsize += l;
	      e = der_get_length(p, len, &newlen, &l);
	      if (e != SASL_OK)
		result = e ;
	      else
		{
		  p += l;
		  len -= l;
		  retsize += l;

		  oldlen = len;
		  if ((dce_fix = fix_dce(newlen, &len)) < 0)
		    result = SASL_BADPROT ;
		  else
		    {
		      (data)->responseToken = 
			ofc_malloc(sizeof(*(data)->responseToken));
		      if ((data)->responseToken == OFC_NULL)
			result = SASL_NOMEM ;
		      else
			{
			  e = decode_octet_string(p, len, 
						  (data)->responseToken, &l);
			  if (e != SASL_OK)
			    result = e ;
			  else
			    {
			      p += l;
			      len -= l;
			      retsize += l;

			      if (dce_fix) 
				{
				  e = der_match_tag_and_length(p, len, 
							       (Der_class) 0, 
							       (Der_type) 0, 
							       0, &reallen, 
							       &l);

				  if (e != SASL_OK)
				    result = e ;
				  else
				    {
				      p += l;
				      len -= l;
				      retsize += l;
				      result = SASL_OK ;
				    } 
				}
			      else
				{
				  len = oldlen - newlen;
				  result = SASL_OK ;
				}
			    }
			}
		    }
		}
	    }
	}

#if defined(OFC_PARAM_SPNEGO_MECHLISTMIC)
      if (result == SASL_OK)
	{
	  OFC_SIZET newlen, oldlen;

	  e = der_match_tag(p, len, ASN1_C_CONTEXT, CONS, 3, &l);
	  if (e != SASL_OK)
	    (data)->mechListMIC = OFC_NULL;
	  else 
	    {
	      p += l;
	      len -= l;
	      retsize += l;
	      e = der_get_length(p, len, &newlen, &l);
	      if (e != SASL_OK)
		result = e ;
	      else
		{
		  p += l;
		  len -= l;
		  retsize += l;

		  oldlen = len;
		  if ((dce_fix = fix_dce(newlen, &len)) < 0)
		    result = SASL_BADPROT ;
		  else
		    {
		      (data)->mechListMIC = 
			ofc_malloc(sizeof(struct octet_string)) ;

		      if ((data)->mechListMIC == OFC_NULL)
			result = SASL_NOMEM ;
		      else
			{
			  e = decode_octet_string(p, len, 
						  (data)->mechListMIC, &l);
			  if (e != SASL_OK)
			    result = e ;
			  else
			    {
			      p += l;
			      len -= l;
			      retsize += l;

			      if (dce_fix) 
				{
				  e = der_match_tag_and_length(p, len, 
							       (Der_class) 0, 
							       (Der_type) 0, 
							       0, &reallen, 
							       &l);
				  if (e != SASL_OK)
				    result = e ;
				  else
				    {
				      p += l;
				      len -= l;
				      retsize += l;
				      result = SASL_OK ;
				    }
				}
			      else
				{
				  len = oldlen - newlen;
				  result = SASL_OK ;
				}
			    }
			}
		    }
		}
	    }
	}
#endif

      if (result == SASL_OK && dce_fix)
	{
	  e = der_match_tag_and_length(p, len, 
				       (Der_class) 0, (Der_type) 0, 0, 
				       &reallen, &l);
	  if (e != SASL_OK)
	    result = e ;
	  else
	    {
	      p += l;
	      len -= l ;
	      retsize += l ;
	      result = SASL_OK ;
	    }
	}
    }
  if (result == SASL_OK)
    {
      if (size)
	*size = retsize ;
    }
  else
    free_NegTokenResp(data) ;
  return (result) ;
}

static OFC_INT spnego_sarg(server_context_t *text,
			    const gss_buffer_t input_token,
			    gss_buffer_t output_token,
			    OM_uint32 *time_rec)
{
  OFC_INT result ;
  NegTokenResp resp ;
  OFC_UCHAR *buf;
  OFC_SIZET buf_size;
  gss_buffer_desc sub_token;
  OFC_SIZET len, taglen;
  OFC_CCHAR *sasl_out ;
  OFC_UINT sasl_outlen ;

  if (text->use_spnego)
    {
      result = gssapi_spnego_decapsulate (input_token, &buf,
					  &buf_size, &gss_mech_spnego_oid) ;

      if (result == SASL_OK || result == SASL_NOMECH)
	{
	  result = der_match_tag_and_length(buf, buf_size,
					    ASN1_C_CONTEXT, CONS, 1, 
					    &len, &taglen);
	  if (result == SASL_OK)
	    {
	      if(len > buf_size - taglen)
		result = SASL_BUFOVER ;
	      else
		{
		  result = decode_NegTokenResp(buf + taglen, len,
					       &resp, OFC_NULL) ;
		  if (result == SASL_OK)
		    {
		      if (resp.responseToken != OFC_NULL) 
			{
			  sub_token.length = resp.responseToken->length;
			  sub_token.value  = 
			    (OFC_VOID *) resp.responseToken->data;
			} 
		      else 
			{
			  sub_token.length = 0;
			  sub_token.value  = OFC_NULL;
			}

		      sasl_out = OFC_NULL ;
		      sasl_outlen = 0 ;

		      result = of_security_server_step (text->pconn, 
						      sub_token.value,
						      (unsigned) sub_token.length,
						      &sasl_out,
						      &sasl_outlen) ;


		      if (sasl_outlen > 0)
			{
			  output_token->value = ofc_malloc(sasl_outlen);
			  if (output_token->value == OFC_NULL)
			    {
			      result = SASL_NOMEM ;
			    }
			  else
			    {
			      output_token->length = sasl_outlen ;
			      ofc_memcpy (output_token->value, sasl_out,
					   sasl_outlen) ;
			    }
			}
		      free_NegTokenResp(&resp) ;
		    }
		}
	    }
	}
    }
  else
    {
      sasl_out = OFC_NULL ;
      sasl_outlen = 0 ;

      result = of_security_server_step (text->pconn, 
				      input_token->value,
				      (unsigned) input_token->length,
				      &sasl_out,
				      &sasl_outlen) ;

      if (sasl_outlen > 0)
	{
	  output_token->value = ofc_malloc(sasl_outlen);
	  if (output_token->value == OFC_NULL)
	    {
	      result = SASL_NOMEM ;
	    }
	  else
	    {
	      output_token->length = sasl_outlen ;
	      ofc_memcpy (output_token->value, sasl_out,
			   sasl_outlen) ;
	    }
	}
    }
  return (result) ;
}


/*
 * This adds an encoded mechanism to the list.
 */
static OFC_INT add_mech(MechTypeList * mech_list, const oid *mech)
{
  MechType *tmp;
  OFC_INT result;

  tmp = ofc_realloc(mech_list->val, 
			(mech_list->len + 1) * sizeof(MechType));
  if (tmp == OFC_NULL)
    result = SASL_NOMEM ;
  else
    {
      mech_list->val = tmp;
      /*
       * converts encoded oid to unencocoded.
       */
      result = der_get_oid(mech->elements, mech->length,
			   &mech_list->val[mech_list->len], OFC_NULL);
      if (result == SASL_OK)
	mech_list->len++;
    }
  return (result) ;
}

static OFC_INT spnego_server_init(server_context_t *text,
				   gss_buffer_t output_token,
				   OM_uint32 *ret_flags)
{
  NegTokenInit token_init;
  OFC_INT result ;
  OFC_UCHAR *buf = OFC_NULL;
  OFC_SIZET buf_size;
  OFC_SIZET len;

  ofc_memset (&token_init, 0, sizeof(token_init)) ;

  result = add_mech(&token_init.mechTypes, &gss_mech_ntlmssp_oid) ;

  if (result == SASL_OK)
    {
#if 0
      token_init.negHint = ofc_strdup ("not_defined_in_RFC4178@please_ignore") ;
#endif
      buf_size = 1024;
      buf = ofc_malloc(buf_size);

      do 
	{
	  OFC_INT nested_result ;
	  nested_result = encode_NegTokenInit(buf + buf_size - 1,
					      buf_size,
					      &token_init, &len);

	  if (nested_result != SASL_OK) 
	    result = nested_result ;
	  else
	    {
	      OFC_SIZET tmp;

	      nested_result = 
		der_put_length_and_tag(buf + buf_size - 
				       len - 1,
				       buf_size - len,
				       len,
				       ASN1_C_CONTEXT,
				       CONS,
				       0,
				       &tmp);
	      if (nested_result != SASL_OK)
		result = nested_result ;
	      else
		len += tmp;
	    }

	  if (result != SASL_OK && result != SASL_CONTINUE) 
	    {
	      if (result == SASL_BUFOVER)
		{
		  OFC_UCHAR *tmp;

		  buf_size *= 2;
		  tmp = ofc_realloc(buf, buf_size);
		  if (tmp == OFC_NULL) 
		    {
		      result = SASL_NOMEM ;
		    }
		  else
		    {
		      buf = tmp;
		      result = SASL_OK ;
		    }
		}
	    }
	}
      while (result == SASL_BUFOVER) ;

      if (result == SASL_OK || result == SASL_CONTINUE)
	{
	  OFC_INT nested_result ;

	  nested_result = 
	    gssapi_spnego_encapsulate(buf + buf_size - len, len,
				      output_token, 
				      &gss_mech_spnego_oid) ;
	  if (nested_result != SASL_OK)
	    result = nested_result ;
	}
      ofc_free (buf) ;
    }

  free_NegTokenInit (&token_init) ;
  return (result) ;
}

static OFC_INT gssapi_server_mech_step(OFC_VOID *conn_context,
			sasl_server_params_t *params,
			const char *clientin,
			unsigned clientinlen,
			const char **serverout,
			unsigned *serveroutlen,
			sasl_out_params_t *oparams)
{
  server_context_t *text = (server_context_t *)conn_context;

  gss_buffer_t input_token, output_token;
  gss_buffer_desc real_input_token, real_output_token;
  OFC_INT result = SASL_OK ;
  OM_uint32 req_flags = 0, out_req_flags = 0;
	
  input_token = &real_input_token;
  output_token = &real_output_token;
  output_token->value = OFC_NULL; 
  output_token->length = 0;
  input_token->value = OFC_NULL; 
  input_token->length = 0;
    
  *serverout = OFC_NULL ;
  *serveroutlen = 0 ;

  switch (text->state) 
    {
    case SASL_SPNEGO_STATE_NEG_TOKEN_INIT:
      if (clientinlen == 0)
	{
	  input_token = GSS_C_NO_BUFFER;
	  req_flags = GSS_C_INTEG_FLAG ;

	  result = spnego_server_init(text,
				      output_token,
				      &out_req_flags) ;

	  if (result != SASL_OK && result != SASL_CONTINUE)
	    {
	      if (output_token->value)
		of_security_gss_release_buffer(output_token) ;
	    }
	  else
	    {
	      *serveroutlen = (OFC_UINT) output_token->length ;
	      if (output_token->value)
		{
		  if (serverout)
		    {
		      if (text->out_buf) ofc_free (text->out_buf) ;
		      text->out_buf = ofc_malloc (*serveroutlen) ;
		      text->out_buf_len = *serveroutlen ;

		      if (text->out_buf == OFC_NULL)
			{
			  of_security_gss_release_buffer (output_token) ;
			  result = SASL_NOMEM ;
			}
		      else
			{
			  ofc_memcpy (text->out_buf, output_token->value,
				       *serveroutlen) ;
			  *serverout = text->out_buf ;
			  of_security_gss_release_buffer (output_token) ;
			  result = SASL_CONTINUE ;
			}
		    }
		}
	    }
	}
      else
	{
	  real_input_token.value = (OFC_VOID *) clientin;
	  real_input_token.length = clientinlen ;

	  req_flags = GSS_C_INTEG_FLAG ;

	  result = spnego_init (text,
				input_token,
				output_token,
				&out_req_flags) ;

	  if ((result == SASL_OK) || (result == SASL_CONTINUE))
	    {
	      OFC_INT nested_result ;

	      if (text->use_spnego)
		{
		  nested_result = spnego_xreply (text, input_token,
						 output_token,
						 &out_req_flags) ;
		  if (nested_result != SASL_OK)
		    result = nested_result ;
		}
	    }

	  if ((result != SASL_OK) && (result != SASL_CONTINUE))
	    {
	      if (output_token->value)
		of_security_gss_release_buffer(output_token) ;
	    }
	  else
	    {
	      *serveroutlen = (OFC_UINT) output_token->length ;
	      if (output_token->value)
		{
		  if (serverout)
		    {
		      if (text->out_buf) ofc_free (text->out_buf) ;
		      text->out_buf = ofc_malloc (*serveroutlen) ;
		      text->out_buf_len = *serveroutlen ;

		      if (text->out_buf == OFC_NULL)
			{
			  of_security_gss_release_buffer (output_token) ;
			  result = SASL_NOMEM ;
			}
		      else
			{
			  ofc_memcpy (text->out_buf, output_token->value,
				       *serveroutlen) ;
			  *serverout = text->out_buf ;
			  of_security_gss_release_buffer (output_token) ;
			  text->state = SASL_SPNEGO_STATE_NEG_TOKEN_TARG ;
			}
		    }
		}
	    }
	}
      break ;

    case SASL_SPNEGO_STATE_NEG_TOKEN_TARG:
      if (clientinlen == 0)
	input_token = GSS_C_NO_BUFFER;
      else
	{
	  real_input_token.value = (OFC_VOID *) clientin;
	  real_input_token.length = clientinlen ;
	}

      req_flags = GSS_C_INTEG_FLAG ;

      result = spnego_sarg (text,
			    input_token,
			    output_token,
			    &out_req_flags) ;
      
      if ((result == SASL_OK) || (result == SASL_CONTINUE))
	{

	  text->user = ofc_strdup (text->pconn->oparams.user) ;
	  text->authid = ofc_strdup (text->pconn->oparams.authid) ;
	  oparams->user = text->user ;
	  oparams->authid = text->authid ;

	  if (text->use_spnego)
	    {
	      result = spnego_sreply (text, input_token, output_token,
				      &out_req_flags) ;
	    }
	}

      if ((result != SASL_OK) && (result != SASL_CONTINUE))
	{
	  if (output_token->value)
	    of_security_gss_release_buffer(output_token) ;
	}
      else
	{
	  *serveroutlen = (OFC_UINT) output_token->length ;
	  if (output_token->value)
	    {
	      if (serverout)
		{
		  if (text->out_buf) ofc_free (text->out_buf) ;
		  text->out_buf = ofc_malloc (*serveroutlen) ;
		  text->out_buf_len = *serveroutlen ;

		  if (text->out_buf == OFC_NULL)
		    {
		      of_security_gss_release_buffer (output_token) ;
		      result = SASL_NOMEM ;
		    }
		  else
		    {
		      ofc_memcpy (text->out_buf, output_token->value,
				   *serveroutlen) ;
		      *serverout = text->out_buf ;
		      of_security_gss_release_buffer (output_token) ;
		      text->state = SASL_SPNEGO_STATE_NEG_TOKEN_TARG ;
		    }
		}
	    }
	}
      break ;

    default:
	params->utils->log(OFC_NULL, SASL_LOG_ERR,
			   "Invalid GSSAPI server step %d\n", text->state);
	result = SASL_FAIL ;
    }
  
    return result;
}

static void gssapi_server_mech_dispose(void *conn_context,
				       const sasl_utils_t *utils)
{
    server_context_t *text = (server_context_t *) conn_context;
    
    if (!text) return;
    
    if (text->out_buf) utils->free(text->out_buf);

    if (text->user)
      ofc_free (text->user) ;
    if (text->authid)
      ofc_free (text->authid) ;

    if (text->pconn)
      of_security_dispose (&text->pconn) ;

    utils->free(text);
}

static int
gssapi_server_mech_key(void *conn_context,
                       unsigned char session_key[NTLM_SESSKEY_LENGTH])
{
  server_context_t *text = (server_context_t *) conn_context;
  int ret ;

  ret = SASL_FAIL ;
  if (text)
    {
      if (of_security_server_key(text->pconn, session_key) == SASL_OK)
	{
	  ret = OFC_TRUE ;
	}
    }

  return (ret) ;
}

static sasl_server_plug_t gssapi_server_plugins[] = 
{
    {
	"GSSAPI",			/* mech_name */
	0,
	SASL_SEC_NOPLAINTEXT
	| SASL_SEC_NOANONYMOUS,		/* security_flags */
	/*
	SASL_FEAT_WANT_CLIENT_FIRST
	| */ SASL_FEAT_SUPPORTS_HTTP,
	OFC_NULL,				/* glob_context */
	&gssapi_server_mech_new,	/* mech_new */
	&gssapi_server_mech_step,	/* mech_step */
	&gssapi_server_mech_dispose,	/* mech_dispose */
	OFC_NULL,			/* mech_free */
	OFC_NULL,			/* mech_setpass */
	OFC_NULL,			/* mech_user_query */
	OFC_NULL,			/* mech_idle */
	OFC_NULL,			/* mech_avail */
	&gssapi_server_mech_key,	/* mech_session_key */
        OFC_NULL                        /* mechlistmic */
    }
};

int of_security_gssapiv2_server_plug_init(const sasl_utils_t *utils, int maxversion, int *out_version,
				   sasl_server_plug_t **pluglist, int *plugcount)
{
    if (maxversion < SASL_SERVER_PLUG_VERSION) {
	SETERROR(utils, "NTLM version mismatch");
	return SASL_BADVERS;
    }
    
    *out_version = SASL_SERVER_PLUG_VERSION;
    *pluglist = gssapi_server_plugins;
    *plugcount = 1;  

    return SASL_OK;
}

/*****************************  Client Section  *****************************/

typedef struct client_context {
  OFC_INT state;
  const OFC_CHAR *plug ;

    /* per-step mem management */
  OFC_CHAR *out_buf;
  OFC_UINT out_buf_len;

  OFC_UCHAR session_key[NTLM_SESSKEY_LENGTH] ;
  MechTypeList mechTypes;
  sasl_conn_t *pconn ;
  OFC_CHAR *user ;
  OFC_CHAR *authid ;
} client_context_t;

static OFC_INT gssapi_client_mech_new(OFC_VOID *glob_context,
				       sasl_client_params_t *params,
				       OFC_VOID **conn_context)
{
  client_context_t *text;
  OFC_INT result ;
    
  /* holds state are in */
  text = params->utils->malloc(sizeof(client_context_t));
  if (text == OFC_NULL) 
    {
      MEMERROR(params->utils->conn);
      result = SASL_NOMEM ;
    } 
  else 
    {
      text->state = SASL_SPNEGO_STATE_NEG_TOKEN_INIT ;
      text->plug = (const OFC_CHAR *) glob_context;
      text->user = OFC_NULL ;
      text->authid = OFC_NULL ;
      text->out_buf = OFC_NULL ;
      /*
       * Create a context for ntlm
       */
      result = of_security_client_new ("cifs", 
				     params->serverFQDN,
				     params->iplocalport, 
				     params->ipremoteport,
				     OFC_NULL, 0, 
				     (sasl_conn_t **) &text->pconn) ;
      
      *conn_context = text;
      result = SASL_OK ;
    }
    
  return (result) ;
}


/*
 * This normally gets sent as part of the negotiate response
 */
static OFC_INT spnego_initial(client_context_t *text,
			       sasl_interact_t **prompt_need,
			       const gss_buffer_t input_token,
			       gss_buffer_t output_token,
			       OM_uint32 *ret_flags)
{
  NegTokenInit token_init;
  OFC_INT result ;
  OFC_UCHAR *buf = OFC_NULL;
  OFC_SIZET buf_size;
  OFC_SIZET len, taglen;
  OFC_CCHAR *sasl_out ;
  OFC_UINT sasl_outlen ;
  OFC_CCHAR *mech ;
  const oid *desired = OFC_NULL ;
  const char *saslname ;
  /*
   * First is let's see what we got from the server
   */
  result = gssapi_spnego_decapsulate(input_token, &buf,
				     &buf_size, &gss_mech_spnego_oid) ;
  if (result == SASL_OK || result == SASL_NOMECH )
    {
      result = der_match_tag_and_length(buf, buf_size,
					ASN1_C_CONTEXT, CONS, 0, 
					&len, &taglen);
      if (result == SASL_OK)
	{
	  if(len > buf_size - taglen)
	    result = SASL_BUFOVER ;
	  else
	    {
	      result = 
		decode_NegTokenInit(buf + taglen, len, 
				    &token_init, OFC_NULL) ;
	      if (result == SASL_OK)
		{
		  if (token_init.mechTypes.len > 0) 
		    {
		      int i ;
		      /*
		       * Find one we support
		       */
		      desired = OFC_NULL ;
		      for (i = 0 ; i < token_init.mechTypes.len &&
			     desired == OFC_NULL; i++)
			{
#if defined(OFC_KERBEROS)
			  if (ofc_strcmp (text->plug, "GSSAPI") == 0)
			    {
			      if ((token_init.mechTypes.val[i].length ==
				   gss_mech_krb5_gss_oid.length) &&
				  (ofc_memcmp (token_init.mechTypes.val[i].elements,
						gss_mech_krb5_gss_oid.elements,
						gss_mech_krb5_gss_oid.length *
						sizeof (OFC_UINT)) == 0))
				{
				  desired = &gss_mech_krb5_oid ;
				  saslname = "KERBEROS";
				}
			    }
#endif
			  if ((token_init.mechTypes.val[i].length ==
			       gss_mech_ntlmssp_gss_oid.length) &&
			      (ofc_memcmp (token_init.mechTypes.val[i].elements,
					    gss_mech_ntlmssp_gss_oid.elements,
					    gss_mech_ntlmssp_gss_oid.length *
					    sizeof (OFC_UINT)) == 0)) 
			    {
			      desired = &gss_mech_ntlmssp_oid;
			      saslname = "NTLM";
			    }
			}
		    }
		  free_NegTokenInit (&token_init) ;
		}
	    }
	}
    }

  ofc_memset (&token_init, 0, sizeof(token_init)) ;

  if (result == SASL_OK)
    {
      if (desired == OFC_NULL)
	{
	  result = SASL_FAIL ;
	  ofc_log(OFC_LOG_WARN, "Unable to find an authentication method\n");
	}
      else
	result = add_mech(&token_init.mechTypes, desired) ;
    }

  if (result == SASL_OK)
    {
      /*
       * Let's get the ntlmssp stuff (it's in input_token)
       *
       * mech does not need to be freed
       */
      result = of_security_client_start (text->pconn, saslname, prompt_need,
				       OFC_NULL, 0, &mech) ;

      if (result == SASL_CONTINUE)
	{
	  sasl_out = OFC_NULL ;
	  sasl_outlen = 0 ;

	  result = of_security_client_step (text->pconn, 
					  OFC_NULL, 0,
					  prompt_need,
					  &sasl_out, &sasl_outlen) ;

	  if (result == SASL_CONTINUE || result == SASL_OK)
	    {
	      token_init.mechToken = 
		ofc_malloc(sizeof(struct octet_string)) ;
	      if (token_init.mechToken == OFC_NULL)
		{
		  result = SASL_NOMEM ;
		}
	      else
		{
		  token_init.mechToken->data = sasl_out; 
		  token_init.mechToken->length = sasl_outlen ;

		  buf_size = 4096;
		  buf = ofc_malloc(buf_size);

		  do 
		    {
		      OFC_INT nested_result ;
		      nested_result = encode_NegTokenInit(buf + buf_size - 1,
							  buf_size,
							  &token_init, &len);

		      if (nested_result != SASL_OK) 
			result = nested_result ;
		      else
			{
			  OFC_SIZET tmp;

			  nested_result = 
			    der_put_length_and_tag(buf + buf_size - 
						   len - 1,
						   buf_size - len,
						   len,
						   ASN1_C_CONTEXT,
						   CONS,
						   0,
						   &tmp);
			  if (nested_result != SASL_OK)
			    result = nested_result ;
			  else
			    len += tmp;
			}

		      if (result != SASL_OK && result != SASL_CONTINUE) 
			{
			  if (result == SASL_BUFOVER)
			    {
			      OFC_UCHAR *tmp;

			      buf_size *= 2;
			      tmp = ofc_realloc(buf, buf_size);
			      if (tmp == OFC_NULL) 
				{
				  result = SASL_NOMEM ;
				}
			      else
				{
				  buf = tmp;
				  result = SASL_OK ;
				}
			    }
			}
		    }
		  while (result == SASL_BUFOVER) ;

		  /*
		   * Forget about sasl_out.  That is freed separately
		   */
		  token_init.mechToken->data = OFC_NULL ;
		  token_init.mechToken->length = 0 ;

		  if (result == SASL_OK || result == SASL_CONTINUE)
		    {
		      OFC_INT nested_result ;

		      nested_result = 
			gssapi_spnego_encapsulate(buf + buf_size - len, len,
						  output_token, 
						  &gss_mech_spnego_oid) ;
		      if (nested_result != SASL_OK)
			result = nested_result ;
		    }
		  ofc_free (buf) ;
		}
	    }
	}
    }

  free_NegTokenInit (&token_init) ;
  return (result) ;
}

static OFC_INT spnego_arg(client_context_t *text,
			   sasl_interact_t **prompt_need,
			   const gss_buffer_t input_token,
			   gss_buffer_t output_token,
			   OM_uint32 *ret_flags)
{
  NegTokenResp token_arg;
  OFC_INT result ;
  OFC_UCHAR *buf = OFC_NULL ;
  OFC_SIZET buf_size;
  OFC_SIZET len ;

  result = SASL_OK ;
  ofc_memset (&token_arg, 0, sizeof(token_arg)) ;

#if defined(OFC_PARAM_SPNEGO_MECHLISTMIC)
  MechTypeList mechTypes;
  OFC_UCHAR * bufx ;
  OFC_UCHAR * px ;
  OFC_SIZET lenx ;
  OFC_SIZET lx ;
  OFC_UCHAR *mic ;

  ofc_memset (&mechTypes, '\0', sizeof (MechTypeList)) ;
  mechTypes.len = 0 ;
  mechTypes.val = OFC_NULL ;
  add_mech(&mechTypes, &gss_mech_ntlmssp_oid) ;

  bufx = ofc_malloc(1024) ;
  px = bufx + 1024 - 1 ;
  lenx = 1024 ;
  encode_MechTypeList(px, lenx, &mechTypes, &lx);
  px -= lx ;
  lenx -= lx ;
  px++ ;

  free_MechTypeList(&mechTypes);

  mic = ofc_malloc(16) ;
  of_security_mech_list_mic(text->pconn, px, lx, mic) ;
  token_arg.mechListMIC = 
    ofc_malloc(sizeof(struct octet_string));
  token_arg.mechListMIC->data = mic ;
  token_arg.mechListMIC->length = 16 ;

  ofc_free (bufx) ;
#endif

  if (output_token != OFC_NULL && output_token->length != 0U) 
    {
      token_arg.responseToken = 
	ofc_malloc(sizeof(struct octet_string));
      if (token_arg.responseToken == OFC_NULL) 
	{
	  result = SASL_NOMEM ;
	}
      else
	{
	  token_arg.responseToken->length = output_token->length;
	  token_arg.responseToken->data = output_token->value;

	  buf_size = 1024;
	  buf = ofc_malloc(buf_size);

	  do
	    {
	      OFC_INT nested_result ;
	      nested_result = 
		encode_NegTokenResp(buf + buf_size - 1,
				    buf_size,
				    &token_arg, &len);

	      if (nested_result != SASL_OK) 
		result = nested_result ;
	      else
		{
		  OFC_SIZET tmp;

		  nested_result = 
		    der_put_length_and_tag(buf + buf_size - 
					   len - 1,
					   buf_size - len,
					   len,
					   ASN1_C_CONTEXT,
					   CONS,
					   1,
					   &tmp);
		  if (nested_result != SASL_OK)
		    result = nested_result ;
		  else
		    len += tmp;
		}

	      if (result != SASL_OK && result != SASL_CONTINUE) 
		{
		  if (result == SASL_BUFOVER)
		    {
		      OFC_UCHAR *tmp;

		      buf_size *= 2;
		      tmp = ofc_realloc(buf, buf_size);
		      if (tmp == OFC_NULL) 
			{
			  result = SASL_NOMEM ;
			}
		      else
			{
			  buf = tmp;
			  result = SASL_OK ;
			}
		    }
		}
	    }
	  while (result == SASL_BUFOVER) ;
	  if (result == SASL_OK || result == SASL_CONTINUE)
	    {
	      OFC_INT nested_result ;
	      nested_result = 
		gssapi_spnego_encapsulate_len(buf + buf_size - len, 
					      len,
					      output_token) ;
	      if (nested_result != SASL_OK)
		result = nested_result ;
	    }
	  ofc_free (buf) ;
	}
    }
  free_NegTokenResp(&token_arg);
  return (result) ;

}

static OFC_INT spnego_reply(client_context_t *text,
			     sasl_interact_t **prompt_need,
			     const gss_buffer_t input_token,
			     gss_buffer_t output_token,
			     OM_uint32 *time_rec)
{
  OFC_INT result ;
  NegTokenResp resp;
  OFC_UCHAR *buf;
  OFC_SIZET buf_size;
  OFC_UCHAR oidbuf[17];
  OFC_SIZET oidlen;
  gss_buffer_desc sub_token;
  OFC_SIZET len, taglen;
  OFC_CCHAR *sasl_out ;
  OFC_UINT sasl_outlen ;

  result = SASL_OK ;

  output_token->length = 0;
  output_token->value  = OFC_NULL;

  result = gssapi_spnego_decapsulate(input_token, &buf,
				     &buf_size, &gss_mech_spnego_oid) ;
  if (result == SASL_OK || result == SASL_NOMECH)
    {
      result = der_match_tag_and_length(buf, buf_size,
					ASN1_C_CONTEXT, CONS, 1, 
					&len, &taglen);
      if (result == SASL_OK)
	{
	  if(len > buf_size - taglen)
	    result = SASL_BUFOVER ;
	  else
	    {
	      result = decode_NegTokenResp(buf + taglen, len, &resp, NULL);
	      if (result == SASL_OK)
		{
		  if (resp.negState == NULL ||
		      *(resp.negState) == reject ||
		      resp.supportedMech == NULL) 
		    {
		      result = SASL_NOMECH ;
		    }
		  else
		    {
		      result = der_put_oid(oidbuf + sizeof(oidbuf) - 1,
					   sizeof(oidbuf),
					   resp.supportedMech,
					   &oidlen);
		      if (result == SASL_OK)
			{
			  /* is it ntlm */
			  if (!(oidlen == gss_mech_ntlmssp_oid.length &&
				ofc_memcmp (oidbuf + sizeof(oidbuf) - oidlen,
					     gss_mech_ntlmssp_oid.elements,
					     oidlen) == 0) &&
			      !(oidlen == gss_mech_krb5_oid.length &&
				ofc_memcmp (oidbuf + sizeof(oidbuf) - oidlen,
					     gss_mech_krb5_oid.elements,
					     oidlen) == 0))
			    result = SASL_NOMECH ;
			}

		      if (result == SASL_OK)
			{
			  if (resp.responseToken != OFC_NULL) 
			    {
			      sub_token.length = resp.responseToken->length;
			      sub_token.value  = 
				(OFC_VOID *) resp.responseToken->data;
			    } 
			  else 
			    {
			      sub_token.length = 0;
			      sub_token.value  = OFC_NULL;
			    }

			  sasl_out = OFC_NULL ;
			  sasl_outlen = 0 ;

			  /* here's where we call ntlm or kerberos */
			  result = 
			    of_security_client_step (text->pconn, 
						   sub_token.value,
						   (unsigned) sub_token.length,
						   prompt_need,
						   &sasl_out,
						   &sasl_outlen) ;

			  output_token->value = ofc_malloc(sasl_outlen);
			  if (output_token->value == OFC_NULL) 
			    {
			      result = SASL_NOMEM ;
			    }
			  else
			    {
			      output_token->length = sasl_outlen ;
			      ofc_memcpy (output_token->value, sasl_out,
					   sasl_outlen) ;
			    }
			}
		    }
		  free_NegTokenResp(&resp) ;
		}
	    }
	}
    }

  return (result) ;
}




static OFC_INT gssapi_client_mech_step(OFC_VOID *conn_context,
					sasl_client_params_t *params,
					const OFC_CHAR *serverin,
					OFC_UINT serverinlen,
					sasl_interact_t **prompt_need,
					const OFC_CHAR **clientout,
					OFC_UINT *clientoutlen,
					sasl_out_params_t *oparams)
{
  client_context_t *text = (client_context_t *)conn_context;
  gss_buffer_t input_token, output_token;
  gss_buffer_desc real_input_token, real_output_token;
  OFC_INT result = SASL_OK ;
  OM_uint32 req_flags = 0, out_req_flags = 0;

  input_token = &real_input_token;
  output_token = &real_output_token;
  output_token->value = OFC_NULL;
  input_token->value = OFC_NULL; 
  input_token->length = 0;

  result = SASL_OK ;
    
  *clientout = OFC_NULL;
  *clientoutlen = 0;
    
  switch (text->state) 
    {
    case SASL_SPNEGO_STATE_NEG_TOKEN_INIT :
      if (serverinlen == 0)
	input_token = GSS_C_NO_BUFFER;
      else
	{
	  real_input_token.value = (OFC_VOID *)serverin;
	  real_input_token.length = serverinlen;
	}
      /* Setup req_flags properly */
      req_flags = GSS_C_INTEG_FLAG;

      result = spnego_initial(text,
			      prompt_need,
			      input_token,
			      output_token,
			      &out_req_flags) ;

      if (result != SASL_OK && result != SASL_CONTINUE)
	{
	  if (output_token->value)
	    of_security_gss_release_buffer(output_token);
	}
      else
	{
	  if (text->user == OFC_NULL)
	    text->user = ofc_strdup (text->pconn->oparams.user) ;
	  if (text->authid == OFC_NULL)
	    text->authid = ofc_strdup (text->pconn->oparams.authid) ;
	  oparams->user = text->user ;
	  oparams->authid = text->authid ;

	  *clientoutlen = (OFC_UINT) output_token->length ;
	  if (output_token->value)
	    {
	      if (clientout)
		{
		  if (text->out_buf) ofc_free (text->out_buf) ;
		  text->out_buf = ofc_malloc (*clientoutlen) ;
		  text->out_buf_len = *clientoutlen ;

		  if (text->out_buf == OFC_NULL)
		    {
		      of_security_gss_release_buffer (output_token) ;
		      result = SASL_NOMEM ;
		    }
		  else
		    {
		      ofc_memcpy (text->out_buf, output_token->value,
				   *clientoutlen) ;
		      *clientout = text->out_buf ;
		      of_security_gss_release_buffer (output_token) ;
		      text->state = SASL_SPNEGO_STATE_NEG_TOKEN_TARG ;
		    }
		}
	    }
	}
      break ;

    case SASL_SPNEGO_STATE_NEG_TOKEN_TARG: 
      if (serverinlen == 0)
	input_token = GSS_C_NO_BUFFER;
      else
	{
	  real_input_token.value = (OFC_VOID *)serverin;
	  real_input_token.length = serverinlen;
	}
      /* Setup req_flags properly */
      req_flags = GSS_C_INTEG_FLAG;

      result = spnego_reply(text,
			    prompt_need,
			    input_token,
			    output_token,
			    &out_req_flags) ;

      if (result == SASL_OK)
	{
	  result = spnego_arg(text,
			      prompt_need,
			      input_token,
			      output_token,
			      &out_req_flags) ;
	}

      if (result != SASL_OK && result != SASL_CONTINUE)
	{
	  if (output_token->value)
	    of_security_gss_release_buffer(output_token);
	}
      else
	{
	  if (text->user == OFC_NULL)
	    text->user = ofc_strdup (text->pconn->oparams.user) ;
	  if (text->authid == OFC_NULL)
	    text->authid = ofc_strdup (text->pconn->oparams.authid) ;
	  oparams->user = text->user ;
	  oparams->authid = text->authid ;

	  *clientoutlen = (OFC_UINT) output_token->length ;
	  if (output_token->value)
	    {
	      if (clientout)
		{
		  if (text->out_buf) ofc_free (text->out_buf) ;
		  text->out_buf = ofc_malloc (*clientoutlen) ;
		  text->out_buf_len = *clientoutlen ;

		  if (text->out_buf == OFC_NULL)
		    {
		      of_security_gss_release_buffer (output_token) ;
		      result = SASL_NOMEM ;
		    }
		  else
		    {
		      ofc_memcpy (text->out_buf, output_token->value,
				   *clientoutlen) ;
		      *clientout = text->out_buf ;
		      of_security_gss_release_buffer (output_token) ;
		      text->state = SASL_SPNEGO_STATE_NEG_TOKEN_TARG ;
		    }
		}
	    }
	}
      break ;

    default:
	params->utils->log(OFC_NULL, SASL_LOG_ERR,
			   "Invalid GSSAPI client step %d\n", text->state);
	result = SASL_FAIL ;
    }
  return result ;
}

static void gssapi_client_mech_dispose(void *conn_context,
				       const sasl_utils_t *utils)
{
    client_context_t *text = (client_context_t *) conn_context;
    
    if (!text) return;
    
    if (text->user)
      ofc_free (text->user) ;
    if (text->authid)
      ofc_free (text->authid) ;
    text->user = OFC_NULL ;
    text->authid = OFC_NULL ;

    if (text->out_buf) utils->free(text->out_buf);
    
    if (text->pconn)
      of_security_dispose (&text->pconn) ;

    utils->free(text);
}

static int gssapi_client_mech_key(void *conn_context,
				  unsigned char session_key[NTLM_SESSKEY_LENGTH])
{
  client_context_t *text = (client_context_t *) conn_context;
  int ret ;

  ret = SASL_FAIL ;
  if (text)
    {
      if (of_security_client_key(text->pconn, session_key) == SASL_OK)
	{
	  ret = OFC_TRUE ;
	}
    }

  return (ret) ;
}

static int gssapi_client_mech_name(void *conn_context,
				   OFC_TCHAR *name, size_t name_len)
{
  client_context_t *text = (client_context_t *) conn_context;
  int ret ;

  ret = SASL_FAIL ;
  if (text)
    {
      if (of_security_target_name(text->pconn, name, name_len) == SASL_OK)
	{
	  ret = OFC_TRUE ;
	}
    }

  return (ret) ;
}

static const OFC_ULONG gssapi_required_prompts[] = {
    SASL_CB_LIST_END
};  

static sasl_client_plug_t gssapi_client_plugins[] = 
{
    {
	"GSSAPI",			/* mech_name */
	0,			/* max_ssf */
	SASL_SEC_NOPLAINTEXT
	| SASL_SEC_NOACTIVE
	| SASL_SEC_NOANONYMOUS
	| SASL_SEC_MUTUAL_AUTH 
	| SASL_SEC_PASS_CREDENTIALS,    /* security_flags */
	SASL_FEAT_NEEDSERVERFQDN
	| SASL_FEAT_WANT_CLIENT_FIRST
	| SASL_FEAT_ALLOWS_PROXY,	/* features */
	gssapi_required_prompts,	/* required_prompts */
	"GSSAPI",			/* glob context */
	&gssapi_client_mech_new,	/* mech_new */
	&gssapi_client_mech_step,	/* mech_step */
	&gssapi_client_mech_dispose,	/* mech_dispose */
	OFC_NULL,			/* mech_free */
	OFC_NULL,				/* idle */
	&gssapi_client_mech_key,
	&gssapi_client_mech_name,
	OFC_NULL				/* spare */
    },
    {
	"GSSAPI-NTLM",			/* mech_name */
	0,			/* max_ssf */
	SASL_SEC_NOPLAINTEXT
	| SASL_SEC_NOACTIVE
	| SASL_SEC_NOANONYMOUS
	| SASL_SEC_MUTUAL_AUTH 
	| SASL_SEC_PASS_CREDENTIALS,    /* security_flags */
	SASL_FEAT_NEEDSERVERFQDN
	| SASL_FEAT_WANT_CLIENT_FIRST
	| SASL_FEAT_ALLOWS_PROXY,	/* features */
	gssapi_required_prompts,	/* required_prompts */
	"GSSAPI-NTLM",			/* glob context */
	&gssapi_client_mech_new,	/* mech_new */
	&gssapi_client_mech_step,	/* mech_step */
	&gssapi_client_mech_dispose,	/* mech_dispose */
	OFC_NULL,			/* mech_free */
	OFC_NULL,				/* idle */
	&gssapi_client_mech_key,
	&gssapi_client_mech_name,
	OFC_NULL				/* spare */
    }
};

OFC_INT of_security_gssapiv2_client_plug_init(const sasl_utils_t *utils,
			      OFC_INT maxversion,
			      OFC_INT *out_version, 
			      sasl_client_plug_t **pluglist,
			      OFC_INT *plugcount)
{
    if (maxversion < SASL_CLIENT_PLUG_VERSION) {
	SETERROR(utils, "Version mismatch in GSSAPI");
	return SASL_BADVERS;
    }
    
    *out_version = SASL_CLIENT_PLUG_VERSION;
    *pluglist = gssapi_client_plugins;
    *plugcount = 2;

    return SASL_OK;
}

