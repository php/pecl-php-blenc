dnl $Id$
dnl config.m4 for extension blowfish

dnl Comments in this file start with the string 'dnl'.
dnl Remove where necessary. This file will not work
dnl without editing.

PHP_ARG_ENABLE(blenc, whether to enable blowfish script encryption,
[  --enable-blenc  Enable BLENC script encryption support])

if test "$PHP_BLENC" != "no"; then
  PHP_NEW_EXTENSION(blenc, blenc.c bf_algo.c, $ext_shared)
fi
