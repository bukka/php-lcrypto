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
