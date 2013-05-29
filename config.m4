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

AC_CHECK_FILE(blenc_protect.h, 
[], 
[
	echo 
	echo "--------------------------------------------------------------------"
	echo "Make sure the file blenc_protect.h exists. You must edit & rename the"
	echo "file blenc_protect.h.dist with your key and expiration date."
	echo "--------------------------------------------------------------------"
	echo 
	AC_MSG_FAILURE("File blenc_protect.h not found")
])
