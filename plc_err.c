/*
  +----------------------------------------------------------------------+
  | PHP Version 5                                                        |
  +----------------------------------------------------------------------+
  | Copyright (c) 2015-2016 Jakub Zelenka                                |
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
#include "zend_exceptions.h"
#include "php_lcrypto.h"
#include "plc_err.h"

#include <openssl/err.h>

/* methods */
PLC_METHOD(LCryptoException, getOpenSSLErrorString);

static const zend_function_entry plc_err_object_methods[] = {
	PLC_ME(
		LCryptoException, getOpenSSLErrorString,
		NULL,
		ZEND_ACC_PUBLIC
	)
	PHPC_FE_END
};

/* class entry */
PLC_API zend_class_entry *PLC_EXCEPTION_CE(LCrypto);

/* object handler */
PHPC_OBJ_DEFINE_HANDLER_VAR(plc_err);

/* {{{ plc_err free object handler */
PHPC_OBJ_HANDLER_FREE(plc_err)
{
	PHPC_OBJ_HANDLER_FREE_INIT(plc_err);
	PHPC_OBJ_HANDLER_FREE_DESTROY();
}
/* }}} */

/* {{{ plc_err create_ex object helper */
PHPC_OBJ_HANDLER_CREATE_EX(plc_err)
{
	PHPC_OBJ_HANDLER_CREATE_EX_INIT(plc_err);

	if (PHPC_OBJ_HANDLER_CREATE_EX_IS_NEW()) {
		/* when the object is create the last error will be the one
		 * we are looking for */
		PHPC_THIS->openssl_error = ERR_get_error();
		/* we should make sure that no other errors are left */
		ERR_clear_error();
	}

	PHPC_OBJ_HANDLER_CREATE_EX_RETURN(plc_err);
}
/* }}} */

/* {{{ plc_err create object handler */
PHPC_OBJ_HANDLER_CREATE(plc_err)
{
	PHPC_OBJ_HANDLER_CREATE_RETURN(plc_err);
}
/* }}} */

/* {{{ plc_err clone object handler */
PHPC_OBJ_HANDLER_CLONE(plc_err)
{
	PHPC_OBJ_HANDLER_CLONE_INIT(plc_err);

	PHPC_THAT->openssl_error = PHPC_THIS->openssl_error;

	PHPC_OBJ_HANDLER_CLONE_RETURN();
}
/* }}} */

/* {{{ PHP_MINIT_FUNCTION
 */
PHP_MINIT_FUNCTION(plc_err)
{
	zend_class_entry ce;

	/* RSA class */
	INIT_CLASS_ENTRY(ce, PLC_CLASS_NAME(LCryptoException), plc_err_object_methods);
	PHPC_CLASS_SET_HANDLER_CREATE(ce, plc_err);
	PLC_EXCEPTION_CE(LCrypto) = PHPC_CLASS_REGISTER_EX(
			ce, zend_exception_get_default(TSRMLS_C), NULL);
	PHPC_OBJ_INIT_HANDLERS(plc_err);
	PHPC_OBJ_SET_HANDLER_OFFSET(plc_err);
	PHPC_OBJ_SET_HANDLER_FREE(plc_err);
	PHPC_OBJ_SET_HANDLER_CLONE(plc_err);

	return SUCCESS;
}

/* {{{ proto string LCryptoException::getOpenSSLErrorString() */
PLC_METHOD(LCryptoException, getOpenSSLErrorString)
{

}
