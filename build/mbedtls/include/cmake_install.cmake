# Install script for directory: D:/projects/net_loom/mbedtls/include

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "C:/Program Files (x86)/ns")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "Debug")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "FALSE")
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/mbedtls" TYPE FILE PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ FILES
    "D:/projects/net_loom/mbedtls/include/mbedtls/aes.h"
    "D:/projects/net_loom/mbedtls/include/mbedtls/aesni.h"
    "D:/projects/net_loom/mbedtls/include/mbedtls/arc4.h"
    "D:/projects/net_loom/mbedtls/include/mbedtls/aria.h"
    "D:/projects/net_loom/mbedtls/include/mbedtls/asn1.h"
    "D:/projects/net_loom/mbedtls/include/mbedtls/asn1write.h"
    "D:/projects/net_loom/mbedtls/include/mbedtls/base64.h"
    "D:/projects/net_loom/mbedtls/include/mbedtls/bignum.h"
    "D:/projects/net_loom/mbedtls/include/mbedtls/blowfish.h"
    "D:/projects/net_loom/mbedtls/include/mbedtls/bn_mul.h"
    "D:/projects/net_loom/mbedtls/include/mbedtls/camellia.h"
    "D:/projects/net_loom/mbedtls/include/mbedtls/ccm.h"
    "D:/projects/net_loom/mbedtls/include/mbedtls/certs.h"
    "D:/projects/net_loom/mbedtls/include/mbedtls/chacha20.h"
    "D:/projects/net_loom/mbedtls/include/mbedtls/chachapoly.h"
    "D:/projects/net_loom/mbedtls/include/mbedtls/check_config.h"
    "D:/projects/net_loom/mbedtls/include/mbedtls/cipher.h"
    "D:/projects/net_loom/mbedtls/include/mbedtls/cipher_internal.h"
    "D:/projects/net_loom/mbedtls/include/mbedtls/cmac.h"
    "D:/projects/net_loom/mbedtls/include/mbedtls/compat-1.3.h"
    "D:/projects/net_loom/mbedtls/include/mbedtls/config.h"
    "D:/projects/net_loom/mbedtls/include/mbedtls/ctr_drbg.h"
    "D:/projects/net_loom/mbedtls/include/mbedtls/debug.h"
    "D:/projects/net_loom/mbedtls/include/mbedtls/des.h"
    "D:/projects/net_loom/mbedtls/include/mbedtls/dhm.h"
    "D:/projects/net_loom/mbedtls/include/mbedtls/ecdh.h"
    "D:/projects/net_loom/mbedtls/include/mbedtls/ecdsa.h"
    "D:/projects/net_loom/mbedtls/include/mbedtls/ecjpake.h"
    "D:/projects/net_loom/mbedtls/include/mbedtls/ecp.h"
    "D:/projects/net_loom/mbedtls/include/mbedtls/ecp_internal.h"
    "D:/projects/net_loom/mbedtls/include/mbedtls/entropy.h"
    "D:/projects/net_loom/mbedtls/include/mbedtls/entropy_poll.h"
    "D:/projects/net_loom/mbedtls/include/mbedtls/error.h"
    "D:/projects/net_loom/mbedtls/include/mbedtls/gcm.h"
    "D:/projects/net_loom/mbedtls/include/mbedtls/havege.h"
    "D:/projects/net_loom/mbedtls/include/mbedtls/hkdf.h"
    "D:/projects/net_loom/mbedtls/include/mbedtls/hmac_drbg.h"
    "D:/projects/net_loom/mbedtls/include/mbedtls/md.h"
    "D:/projects/net_loom/mbedtls/include/mbedtls/md2.h"
    "D:/projects/net_loom/mbedtls/include/mbedtls/md4.h"
    "D:/projects/net_loom/mbedtls/include/mbedtls/md5.h"
    "D:/projects/net_loom/mbedtls/include/mbedtls/md_internal.h"
    "D:/projects/net_loom/mbedtls/include/mbedtls/memory_buffer_alloc.h"
    "D:/projects/net_loom/mbedtls/include/mbedtls/net.h"
    "D:/projects/net_loom/mbedtls/include/mbedtls/net_sockets.h"
    "D:/projects/net_loom/mbedtls/include/mbedtls/nist_kw.h"
    "D:/projects/net_loom/mbedtls/include/mbedtls/oid.h"
    "D:/projects/net_loom/mbedtls/include/mbedtls/padlock.h"
    "D:/projects/net_loom/mbedtls/include/mbedtls/pem.h"
    "D:/projects/net_loom/mbedtls/include/mbedtls/pk.h"
    "D:/projects/net_loom/mbedtls/include/mbedtls/pk_internal.h"
    "D:/projects/net_loom/mbedtls/include/mbedtls/pkcs11.h"
    "D:/projects/net_loom/mbedtls/include/mbedtls/pkcs12.h"
    "D:/projects/net_loom/mbedtls/include/mbedtls/pkcs5.h"
    "D:/projects/net_loom/mbedtls/include/mbedtls/platform.h"
    "D:/projects/net_loom/mbedtls/include/mbedtls/platform_time.h"
    "D:/projects/net_loom/mbedtls/include/mbedtls/platform_util.h"
    "D:/projects/net_loom/mbedtls/include/mbedtls/poly1305.h"
    "D:/projects/net_loom/mbedtls/include/mbedtls/ripemd160.h"
    "D:/projects/net_loom/mbedtls/include/mbedtls/rsa.h"
    "D:/projects/net_loom/mbedtls/include/mbedtls/rsa_internal.h"
    "D:/projects/net_loom/mbedtls/include/mbedtls/sha1.h"
    "D:/projects/net_loom/mbedtls/include/mbedtls/sha256.h"
    "D:/projects/net_loom/mbedtls/include/mbedtls/sha512.h"
    "D:/projects/net_loom/mbedtls/include/mbedtls/ssl.h"
    "D:/projects/net_loom/mbedtls/include/mbedtls/ssl_cache.h"
    "D:/projects/net_loom/mbedtls/include/mbedtls/ssl_ciphersuites.h"
    "D:/projects/net_loom/mbedtls/include/mbedtls/ssl_cookie.h"
    "D:/projects/net_loom/mbedtls/include/mbedtls/ssl_internal.h"
    "D:/projects/net_loom/mbedtls/include/mbedtls/ssl_ticket.h"
    "D:/projects/net_loom/mbedtls/include/mbedtls/threading.h"
    "D:/projects/net_loom/mbedtls/include/mbedtls/timing.h"
    "D:/projects/net_loom/mbedtls/include/mbedtls/version.h"
    "D:/projects/net_loom/mbedtls/include/mbedtls/x509.h"
    "D:/projects/net_loom/mbedtls/include/mbedtls/x509_crl.h"
    "D:/projects/net_loom/mbedtls/include/mbedtls/x509_crt.h"
    "D:/projects/net_loom/mbedtls/include/mbedtls/x509_csr.h"
    "D:/projects/net_loom/mbedtls/include/mbedtls/xtea.h"
    )
endif()

