/*
  +----------------------------------------------------------------------+
  | PHP Version 5                                                        |
  +----------------------------------------------------------------------+
  | Copyright (c) 1997-2004 The PHP Group                                |
  +----------------------------------------------------------------------+
  | This source file is subject to version 3.0 of the PHP license,       |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.php.net/license/3_0.txt.                                  |
  | If you did not receive a copy of the PHP license and are unable to   |
  | obtain it through the world-wide-web, please send a note to          |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author: John Coggeshall <john@php.net>                               |
  +----------------------------------------------------------------------+
*/

/* $Id$ */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "ext/standard/md5.h"
#include "php_blenc.h"
#include "bf_algo.h"

ZEND_DECLARE_MODULE_GLOBALS(blenc)

typedef struct _blenc_header {
	b_byte ident[8];
	b_byte version[16];
	b_byte md5[32];
	b_byte reserved[16];
} blenc_header;

/* True global - no need for thread safety here */
HashTable *php_bl_keys;

/* {{{ blenc_functions[] */
function_entry blenc_functions[] = {
	PHP_FE(blenc_encrypt,	NULL)
	{NULL, NULL, NULL}	
};
/* }}} */

/* {{{ blenc_module_entry
 */
zend_module_entry blenc_module_entry = {
#if ZEND_MODULE_API_NO >= 20010901
	STANDARD_MODULE_HEADER,
#endif
	"blenc",
	blenc_functions,
	PHP_MINIT(blenc),
	PHP_MSHUTDOWN(blenc),
	PHP_RINIT(blenc),
	NULL, 
	PHP_MINFO(blenc),
#if ZEND_MODULE_API_NO >= 20010901
	PHP_BLENC_VERSION,
#endif
	STANDARD_MODULE_PROPERTIES
};
/* }}} */

#ifdef COMPILE_DL_BLENC
ZEND_GET_MODULE(blenc)
#endif

/* {{{ PHP_INI */
PHP_INI_BEGIN()
    STD_PHP_INI_ENTRY("blenc.key_file", "/usr/local/etc/blenckeys", PHP_INI_ALL, OnUpdateString, key_file, zend_blenc_globals, blenc_globals)
PHP_INI_END()
/* }}} */

/* {{{ php_blenc_init_globals */
static void php_blenc_init_globals(zend_blenc_globals *blenc_globals)
{
	blenc_globals->key_file = NULL;
	blenc_globals->keys_loaded = FALSE;
	blenc_globals->decoded = NULL;
	blenc_globals->decoded_len = 0;
	blenc_globals->index = 0;

}
/* }}} */

/* {{{ PHP_MINIT_FUNCTION
 */
PHP_MINIT_FUNCTION(blenc)
{
	ZEND_INIT_MODULE_GLOBALS(blenc, php_blenc_init_globals, NULL);
	REGISTER_INI_ENTRIES();
	
	php_bl_keys = pemalloc(sizeof(HashTable), TRUE);
	zend_hash_init(php_bl_keys, 0, NULL, _php_blenc_pefree_wrapper, TRUE);
	
	zend_compile_file_old = zend_compile_file;
	zend_compile_file = blenc_compile;
	
	REGISTER_STRING_CONSTANT("BLENC_EXT_VERSION", PHP_BLENC_VERSION, CONST_CS | CONST_PERSISTENT);
	
	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MSHUTDOWN_FUNCTION
 */
PHP_MSHUTDOWN_FUNCTION(blenc)
{
	UNREGISTER_INI_ENTRIES();

	zend_hash_destroy(php_bl_keys);
    pefree(php_bl_keys, TRUE);
	zend_compile_file = zend_compile_file_old;
	
	return SUCCESS;
}
/* }}} */

/* Remove if there's nothing to do at request start */
/* {{{ PHP_RINIT_FUNCTION
 */
PHP_RINIT_FUNCTION(blenc)
{
	if(!BL_G(keys_loaded)) {
			if(php_blenc_load_keyhash(TSRMLS_C) == FAILURE) {
				zend_error(E_WARNING, "BLENC: Could not load some or all of the Keys");
				return FAILURE;
			}
			BL_G(keys_loaded) = TRUE;
	}
	
	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MINFO_FUNCTION
 */
PHP_MINFO_FUNCTION(blenc)
{
	php_info_print_table_start();
	php_info_print_table_header(2, "blenc support", "enabled");
	php_info_print_table_row(2, "version", PHP_BLENC_VERSION);
	php_info_print_table_end();

	DISPLAY_INI_ENTRIES();
	
}
/* }}} */

PHP_FUNCTION(blenc_encrypt) {
	
	char *data = NULL,  *retval = NULL, *key = NULL, *output_file = NULL;
	int output_len = 0, key_len = 0, data_len = 0, output_file_len = 0;
	php_stream *stream;
	zend_bool dup_key = FALSE;
	
	blenc_header header = {BLENC_IDENT, PHP_BLENC_VERSION};
	
	if(zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss|s", &data, &data_len,
 				&output_file, &output_file_len,
				&key, &key_len) == FAILURE) {
		RETURN_FALSE;
	}
	
	if(key == NULL) {
		key = php_blenc_gen_key(TSRMLS_C);
	} else {
		dup_key = TRUE;
	}

	php_blenc_make_md5((char *)&header.md5, data, data_len TSRMLS_CC);
	
	retval = php_blenc_encode(data, key, data_len, &output_len TSRMLS_CC);

	if((stream = php_stream_open_wrapper(output_file, "wb", ENFORCE_SAFE_MODE | REPORT_ERRORS, NULL))) {
		_php_stream_write(stream, (void *)&header, (int)sizeof(blenc_header) TSRMLS_CC);
		_php_stream_write(stream, retval, output_len TSRMLS_CC);
		php_stream_close(stream);

		RETVAL_STRING(key, dup_key);
	}

	efree(retval);

}

static void php_blenc_make_md5(char *result, void *data, unsigned int data_len TSRMLS_DC)
{
	PHP_MD5_CTX   context;
	unsigned char digest[16];

	PHP_MD5Init(&context);
	PHP_MD5Update(&context, data, data_len);
	PHP_MD5Final(digest, &context);

	make_digest(result, digest);
	
}

static char *php_blenc_file_to_mem(char *filename TSRMLS_DC)
{
	php_stream *stream;
	int len;
	char *data = NULL;
	
	if (!(stream = php_stream_open_wrapper(filename, "rb", ENFORCE_SAFE_MODE, NULL))) {
		return NULL;
	}
	
	if ((len = php_stream_copy_to_mem(stream, &data, PHP_STREAM_COPY_ALL, 0)) == 0) {
		data = estrdup("");
	}
	
	php_stream_close(stream);

	if(data == NULL) {
		return NULL;
	}
	
	return data;
}

static int php_blenc_load_keyhash(TSRMLS_D)
{
	char *strtok_buf = NULL;
	char *key = NULL;
	char *keys = NULL;

	keys = php_blenc_file_to_mem(BL_G(key_file) TSRMLS_CC);

	if(keys) {
		char *t = keys;
	
		while((key = php_strtok_r(t, "\n", &strtok_buf))) {
			char *temp;
			t = NULL;
			
			if(!key) {
				continue;
			}
			
			temp = pestrdup(key, TRUE);
			
			if(zend_hash_next_index_insert(php_bl_keys, &temp, sizeof(char *), NULL) == FAILURE) {
				zend_error(E_WARNING, "Could not add a key to the keyhash!");
			}
			
			temp = NULL;
			
		}
		
		efree(keys);
		
	}
	
	return SUCCESS;
	
}

b_byte *php_blenc_encode(void *script, unsigned char *key, int in_len, int *out_len TSRMLS_DC)
{
	BLOWFISH_CTX *ctx = NULL;
	unsigned long hi = 0, low = 0;
	int i, pad_size = 0;
	b_byte *retval = NULL;
	b_byte *input = NULL;
	
	ctx = emalloc(sizeof(BLOWFISH_CTX));
	
	Blowfish_Init (ctx, (unsigned char *)key, strlen(key));

	
	if((pad_size = in_len % 8)) {
		pad_size = 8 - pad_size;

		retval = emalloc(in_len + pad_size);
		input = estrdup(script);	
		input = erealloc(input, in_len + pad_size);
		
		memset(&input[in_len], '\0', pad_size);
		
	} else {
		retval = emalloc(in_len);
		input = script;
		pad_size = 0;
	}
	
	hi = 0x0L;
	low = 0x0L;
		
	for(i = 0; i < (in_len + pad_size); i+=8) {
		
		hi |= (unsigned int)((char *)input)[i] & 0xFF;
		hi = hi << 8;
		hi |= (unsigned int)((char *)input)[i+1] & 0xFF;
		hi = hi << 8;
		hi |= (unsigned int)((char *)input)[i+2] & 0xFF;
		hi = hi << 8;
		hi |= (unsigned int)((char *)input)[i+3] & 0xFF;
		
		low |= (unsigned int)((char *)input)[i+4] & 0xFF;
		low = low << 8;
		low |= (unsigned int)((char *)input)[i+5] & 0xFF;
		low = low << 8;
		low |= (unsigned int)((char *)input)[i+6] & 0xFF;
		low = low << 8;
		low |= (unsigned int)((char *)input)[i+7] & 0xFF;

		Blowfish_Encrypt(ctx, &hi, &low);
		
		retval[i] = hi >> 24;
		retval[i+1] = hi >> 16;
		retval[i+2] = hi >> 8;
		retval[i+3] = hi;
		retval[i+4] = low >> 24;
		retval[i+5] = low >> 16;
		retval[i+6] = low >> 8;
		retval[i+7] = low;
		
		hi = 0x0L;
		low = 0x0L;
	}
	
	*out_len = in_len+pad_size;
	
	efree(input);
	efree(ctx);
	
	return retval;
}

b_byte *php_blenc_decode(void *input, unsigned char *key, int in_len, int *out_len TSRMLS_DC)
{	
	BLOWFISH_CTX ctx;
	unsigned long hi, low;
	int i;
	b_byte *retval;
	
	Blowfish_Init (&ctx, (unsigned char*)key, strlen(key));
    
	if(in_len % 8) {
		zend_error(E_WARNING, "Attempted to decode non-blenc encrytped file.");
		return estrdup("");
	} else {
		retval = emalloc(in_len);
	}
	
	hi = 0x0L;
	low = 0x0L;
		
	for(i = 0; i < in_len; i+=8) {
		
		hi |= (unsigned int)((char *)input)[i] & 0xFF;
		hi = hi << 8;
		hi |= (unsigned int)((char *)input)[i+1] & 0xFF;
		hi = hi << 8;
		hi |= (unsigned int)((char *)input)[i+2] & 0xFF;
		hi = hi << 8;
		hi |= (unsigned int)((char *)input)[i+3] & 0xFF;
		
		low |= (unsigned int)((char *)input)[i+4] & 0xFF;
		low = low << 8;
		low |= (unsigned int)((char *)input)[i+5] & 0xFF;
		low = low << 8;
		low |= (unsigned int)((char *)input)[i+6] & 0xFF;
		low = low << 8;
		low |= (unsigned int)((char *)input)[i+7] & 0xFF;
		
		Blowfish_Decrypt(&ctx, &hi, &low);
		
		retval[i] = hi >> 24;
		retval[i+1] = hi >> 16;
		retval[i+2] = hi >> 8;
		retval[i+3] = hi;
		retval[i+4] = low >> 24;
		retval[i+5] = low >> 16;
		retval[i+6] = low >> 8;
		retval[i+7] = low;
		
		hi = 0x0L;
		
		low = 0x0L;
	}
	
	*out_len = strlen(retval);
	
	return retval;
}

static unsigned char *php_blenc_gen_key(TSRMLS_D)
{

	int sec = 0 , usec = 0;
	struct timeval tv;
	char *retval = NULL, *tmp = NULL;
	PHP_MD5_CTX   context;
	unsigned char digest[16];
	
	gettimeofday((struct timeval *) &tv, (struct timezone *) NULL);
	sec = (int) tv.tv_sec;
	usec = (int) (tv.tv_usec % 0x100000);
	
	spprintf(&tmp, 0, "%08x%05x", sec, usec);
	
	retval = emalloc(33);
	
	PHP_MD5Init(&context);
	PHP_MD5Update(&context, tmp, strlen(tmp));
	PHP_MD5Final(digest, &context);
	make_digest(retval, digest);
	efree(tmp);
	
	return retval;
}

static size_t blenc_stream_reader(void *handle, char *buf, size_t len TSRMLS_DC)
{
	size_t bytes;
	
	if(BL_G(decoded)) {
		
		bytes = (BL_G(index) + len > BL_G(decoded_len)) ? BL_G(decoded_len) - BL_G(index) : len;
		memcpy(buf, &BL_G(decoded)[BL_G(index)], bytes);
		BL_G(index) += bytes;
		return bytes;

	}
	
	return 0;
}

static void blenc_stream_closer(void *handle TSRMLS_DC)
{
	old_stream_closer(handle TSRMLS_CC);
	efree(BL_G(decoded));
	BL_G(decoded) = NULL;
	BL_G(decoded_len) = 0;
	BL_G(index) = 0;
	
}

zend_op_array *blenc_compile(zend_file_handle *file_handle, int type TSRMLS_DC) {

	int i = 0;
	size_t bytes;
	char *script = NULL;
	unsigned int index = 0;
	unsigned int script_len = 0;
	zend_op_array *retval = NULL;
	
	blenc_header *header;
	
	zend_stream_fixup(file_handle TSRMLS_CC);
	
	old_stream_reader = file_handle->handle.stream.reader;
	old_stream_closer = file_handle->handle.stream.closer;
	
	file_handle->handle.stream.reader = blenc_stream_reader;
	file_handle->handle.stream.closer = blenc_stream_closer;
	
	script = emalloc(BLENC_BUFSIZE);
	
	for(i = 2; (bytes = old_stream_reader(file_handle->handle.stream.handle,
  					      &script[index],
					      BLENC_BUFSIZE TSRMLS_CC)) > 0; i++)
	{		
		script_len += bytes;
		
		if(bytes == BLENC_BUFSIZE) {
			
			script = erealloc(script, BLENC_BUFSIZE * i);
			index += bytes;
		}
		
	}

	script_len += bytes;
		
	header = (blenc_header *)script;
	
	if(!strncmp(script, BLENC_IDENT, strlen(BLENC_IDENT))) {
		char *md5;
		char *encoded = &script[sizeof(blenc_header)];
		char **key = NULL;
		zend_bool validated = FALSE;
		
		for (zend_hash_internal_pointer_reset(php_bl_keys);
			 zend_hash_get_current_data(php_bl_keys, (void **)&key) == SUCCESS;
			 zend_hash_move_forward(php_bl_keys)) {

			BL_G(decoded) = php_blenc_decode(encoded, *key, script_len - sizeof(blenc_header), &BL_G(decoded_len) TSRMLS_CC);
			
			md5 = emalloc(33);
			php_blenc_make_md5(md5, BL_G(decoded), BL_G(decoded_len) TSRMLS_CC);

			if(!strncmp(md5, header->md5, 32)) {
				validated = TRUE;
				efree(md5);
				break;
			}
			
			efree(md5);
			md5 = NULL;
		
			efree(BL_G(decoded));
			BL_G(decoded_len) = 0;
			
		}
			
		if(!validated) {	
		
			zend_error(E_ERROR, "Validation of script '%s' failed, cannot execute.", file_handle->filename);
			efree(script);
			return NULL;
		}
				
	} else {
		
		BL_G(decoded) = script;
		BL_G(decoded_len) = script_len;
		
	}

	index = 0;
	retval = zend_compile_file_old(file_handle, type TSRMLS_CC);
	
	if(BL_G(decoded) != script) {
		efree(script);
	}
	
	return retval;

}

void _php_blenc_pefree_wrapper(void **data)
{	
	pefree(*data, TRUE);
	
}

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
