dnl $Id$
dnl config.m4 for extension lcrypto

PHP_ARG_WITH(lcrypto, for lcrypto support,
[  --with-lcrypto             Include Low-level Crypto support])

if test "$PHP_LCRYPTO" != "no"; then
  test -z "$PHP_OPENSSL" && PHP_OPENSSL=no
  if test "$PHP_OPENSSL" != "no" || test "$PHP_OPENSSL_DIR" != "no"; then
    dnl Try to find pkg-config
    if test -z "$PKG_CONFIG"; then
      AC_PATH_PROG(PKG_CONFIG, pkg-config, no)
    fi
    dnl If pkg-config is found try using it
    if test -x "$PKG_CONFIG" && $PKG_CONFIG --exists openssl; then
      OPENSSL_INCDIR=`$PKG_CONFIG --variable=includedir openssl`
      PHP_ADD_INCLUDE($OPENSSL_INCDIR)
      LCRYPTO_LIBS=`$PKG_CONFIG --libs openssl`
      PHP_EVAL_LIBLINE($LCRYPTO_LIBS, LCRYPTO_SHARED_LIBADD)
    fi

    AC_DEFINE(HAVE_LCRYPTOLIB,1,[Enable objective OpenSSL Low-level Crypto wrapper])
    PHP_SUBST(LCRYPTO_SHARED_LIBADD)
    PHP_NEW_EXTENSION(lcrypto, 
      lcrypto.c \
      lcrypto_rsa.c,
      $ext_shared)
  fi
fi
