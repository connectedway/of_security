cmake_minimum_required(VERSION 3.20.0)
project(of_security VERSION 1.0.1 DESCRIPTION "OpenFiles Security and Authentication")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-deprecated-declarations")

include_directories(
        ${of_security_SOURCE_DIR}/include
        ${of_core_SOURCE_DIR}/include
	${of_smb_SOURCE_DIR}/include
	${of_smb_BINARY_DIR}
        ${KRB5_INCLUDE_PATH}
)

if(APPLE)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-deprecated-declarations")
endif()

if(OFC_KERBEROS)
  set(KSRCS
      src/kerberos.c
      src/klist.c
  )
endif()

unset(CSRCS)
if(OF_OPENSSL)
  list(APPEND CSRCS
    src/openssl_smb2.c
    )
  find_package(OpenSSL REQUIRED)
  if (OPENSSL_FOUND)
    include_directories(${OPENSSL_INCLUDE_DIR})
  else()
    if(APPLE)
      include_directories("/opt/homebrew/opt/openssl@3/include")
    endif()
  endif()
endif()

if(OF_MBEDTLS)
  list(APPEND CSRCS
    src/mbedtls_smb2.c
    )
  include_directories(${MBEDTLS_INCLUDE_DIR})
endif()

if (OF_GNUTLS)
  list(APPEND CSRCS
    src/gnutls_smb2.c
    )
  find_package(GnuTLS REQUIRED)
  if (GNUTLS_FOUND)
    include_directories(${GNUTLS_INCLUDE_DIR})
  endif()
endif()

set(SRCS
        src/auxprop.c
	src/canonusr.c
	src/checkpw.c
	src/client.c
	src/common.c
	src/db.c
	src/des_enc.c
	src/ecb_enc.c
	src/gssapi.c
	src/md4_dgst.c
	src/md4_one.c
	src/md5.c
	src/mem_clr.c
	src/ncbc_enc.c
	src/ntlm.c
	src/plugin_common.c
	src/saslutil.c
	src/server.c
	src/set_key.c
	src/seterror.c
	src/sha256.c
        src/security_smb2.c
        )

add_library(of_security OBJECT ${SRCS} ${KSRCS} ${CSRCS})
set_property(TARGET of_security PROPERTY POSITION_INDEPENDENT_CODE ON)

