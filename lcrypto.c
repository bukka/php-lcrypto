/*
  +----------------------------------------------------------------------+
  | PHP Version 5                                                        |
  +----------------------------------------------------------------------+
  | Copyright (c) 1997-2015 Jakub Zelenka                                |
  +----------------------------------------------------------------------+
  | This source file is subject to version 3.01 of the PHP license,      |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.php.net/license/3_01.txt                                  |
  | If you did not receive a copy of the PHP license and are unable to   |
  | obtain it through the world-wide-web, please send a note to          |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author: Jakub Zelenka <bukka@php.net>                                |
  +----------------------------------------------------------------------+
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "zend_exceptions.h"
#include "ext/standard/info.h"
#include "php_lcrypto.h"
#include "php_lcrypto_rsa.h"

#include <openssl/evp.h>

ZEND_DECLARE_MODULE_GLOBALS(lcrypto)

/* {{{ lcrypto_module_entry
 */
zend_module_entry lcrypto_module_entry = {
	STANDARD_MODULE_HEADER,
	"lcrypto",
	NULL,
	PHP_MINIT(lcrypto),
	PHP_MSHUTDOWN(lcrypto),
	NULL,
	NULL,
	PHP_MINFO(lcrypto),
	PHP_LCRYPTO_VERSION,
	PHP_MODULE_GLOBALS(lcrypto),
	PHP_GINIT(lcrypto),
	NULL,
	NULL,
	STANDARD_MODULE_PROPERTIES_EX
};
/* }}} */

#ifdef COMPILE_DL_LCRYPTO
ZEND_GET_MODULE(lcrypto)
#endif

/* {{{ PHP_MINIT_FUNCTION
 */
PHP_MINIT_FUNCTION(lcrypto)
{
	/* Init OpenSSL algorithms */
	OpenSSL_add_all_algorithms();

	PHP_MINIT(plc_rsa)(INIT_FUNC_ARGS_PASSTHRU);

	return SUCCESS;
}
/* }}} */

/* {{{ PHP_GINIT_FUNCTION
*/
PHP_GINIT_FUNCTION(lcrypto)
{
	lcrypto_globals->encoding = PLC_ENC_AUTO;
}
/* }}} */

/* {{{ PHP_MSHUTDOWN_FUNCTION
 */
PHP_MSHUTDOWN_FUNCTION(lcrypto)
{
	EVP_cleanup();

	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MINFO_FUNCTION
 */
PHP_MINFO_FUNCTION(lcrypto)
{
	php_info_print_table_start();
	php_info_print_table_row(2, "Low-level Crypto Support", "enabled");
	php_info_print_table_row(2, "Low-level Crypto Version", PHP_LCRYPTO_VERSION);
	php_info_print_table_row(2, "OpenSSL Library Version", SSLeay_version(SSLEAY_VERSION));
	php_info_print_table_row(2, "OpenSSL Header Version", OPENSSL_VERSION_TEXT);
	php_info_print_table_end();
}
/* }}} */

/* {{{ plc_str_size_to_int */
PLC_API int plc_str_size_to_int(phpc_str_size_t size_len, int *int_len)
{
	PHPC_SIZE_TO_INT_EX(size_len, *int_len, return FAILURE);
	return SUCCESS;
}
/* }}} */

/* {{{ plc_long_to_int */
PLC_API int plc_long_to_int(phpc_long_t plv, int *lv)
{
	PHPC_LONG_TO_INT_EX(plv, *lv, return FAILURE);
	return SUCCESS;
}
/* }}} */

/* {{{ plc_verror */
PLC_API void plc_verror(const plc_error_info *info, zend_class_entry *exc_ce,
		plc_error_action action, int ignore_args TSRMLS_DC, const char *name, va_list args)
{
	const plc_error_info *ei = NULL;
	char *message = NULL;
	long code = 1;

	if (action == PLC_ERROR_ACTION_GLOBAL) {
		action = PLC_G(error_action);
	} else if (action == PLC_ERROR_ACTION_SILENT) {
		return;
	}

	while (info->name != NULL) {
		if (*info->name == *name && !strncmp(info->name, name, strlen(info->name))) {
			ei = info;
			break;
		}
		info++;
		code++;
	}

	if (!ei) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Invalid error message");
		return;
	}
	switch (action) {
		case PLC_ERROR_ACTION_ERROR:
			php_verror(NULL, "", ei->level, PLC_GET_ERROR_MESSAGE(ei->msg, message), args TSRMLS_CC);
			break;
		case PLC_ERROR_ACTION_EXCEPTION:
			if (ignore_args) {
				zend_throw_exception(exc_ce, PLC_GET_ERROR_MESSAGE(ei->msg, message), code TSRMLS_CC);
			} else {
				vspprintf(&message, 0, ei->msg, args);
				zend_throw_exception(exc_ce, message, code TSRMLS_CC);
			}
			break;
		default:
			return;
	}
	if (message) {
		efree(message);
	}
}
/* }}} */

/* {{{ plc_error_ex */
PLC_API void plc_error_ex(const plc_error_info *info, zend_class_entry *exc_ce,
		plc_error_action action, int ignore_args TSRMLS_DC, const char *name, ...)
{
	va_list args;
	va_start(args, name);
	plc_verror(info, exc_ce, action, ignore_args TSRMLS_CC, name, args);
	va_end(args);
}
/* }}} */

/* {{{ plc_error */
PLC_API void plc_error(const plc_error_info *info, zend_class_entry *exc_ce,
		plc_error_action action, int ignore_args TSRMLS_DC, const char *name)
{
	plc_error_ex(info, exc_ce, action, 1 TSRMLS_CC, name);
}
/* }}} */
