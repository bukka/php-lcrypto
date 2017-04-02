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
PLC_METHOD(LCryptoException, getLastOpenSSLError);
PLC_METHOD(LCryptoException, getOpenSSLErrors);

static const zend_function_entry plc_err_object_methods[] = {
	PLC_ME(
		LCryptoException, getLastOpenSSLError,
		NULL,
		ZEND_ACC_PUBLIC
	)
	PLC_ME(
		LCryptoException, getOpenSSLErrors,
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

	PHPC_THIS->count = 0;

	if (PHPC_OBJ_HANDLER_CREATE_EX_IS_NEW()) {
		int i;
		unsigned long error_code;

		/* when the object is create the error queue will contain
		 * errors that we are looking for */
		for (i = 0; error_code = ERR_get_error() || i < ERR_NUM_ERRORS; i++) {
			PHPC_THIS->errors[i] = error_code;
			PHPC_THIS->count++;
		}
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

	if ((PHPC_THAT->count = PHPC_THIS->count) > 0) {
		memcpy(PHPC_THAT->errors, PHPC_THIS->errors,
				sizeof(unsigned long) * PHPC_THIS->count);

	}

	PHPC_OBJ_HANDLER_CLONE_RETURN();
}
/* }}} */

/* {{{ PHP_MINIT_FUNCTION
 */
PHP_MINIT_FUNCTION(plc_err)
{
	zend_class_entry ce;

	/* Load error strings */
	ERR_load_crypto_strings();

	/* LCryptoException class */
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
/* }}} */

/* {{{ plc_err_exception_subclass_init */
PLC_API void plc_err_exception_subclass_init(
		const char *name, zend_class_entry **exc_ce, zend_object_handlers *handlers TSRMLS_DC)
{
	zend_class_entry ce;

	INIT_CLASS_ENTRY_EX(ce, name, strlen(name), NULL);
	PHPC_CLASS_SET_HANDLER_CREATE(ce, plc_err);
	*exc_ce = PHPC_CLASS_REGISTER_EX(ce, PLC_EXCEPTION_CE(LCrypto), NULL);
	memcpy(handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
	PHPC_OBJ_SET_SPECIFIC_HANDLER_OFFSET(*handlers, plc_err);
	PHPC_OBJ_SET_SPECIFIC_HANDLER_FREE(*handlers, plc_err);
	PHPC_OBJ_SET_SPECIFIC_HANDLER_CLONE(*handlers, plc_err);
}
/* }}} */

typedef struct {
	unsigned long errors[ERR_NUM_ERRORS];
	size_t count;
} plc_err_store_data;

/* {{{ plc_err_store */
PLC_API void plc_err_store()
{
	plc_err_store_data data;
	int i;
	unsigned long error_code;

	for (i = 0; error_code = ERR_get_error() || i < ERR_NUM_ERRORS; i++) {
		data.errors[i] = error_code;
		data.count++;
	}

	if (i == 0) {
		return;
	}
}
/* }}} */

#define PLC_ERR_BUF_SIZE 256

/* {{{ proto string LCryptoException::geLastOpenSSLError() */
PLC_METHOD(LCryptoException, getLastOpenSSLError)
{
	PHPC_THIS_DECLARE(plc_err);
	char buf[PLC_ERR_BUF_SIZE];

	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}

	PHPC_THIS_FETCH(plc_err);

	if (PHPC_THIS->count == 0) {
		RETURN_NULL();
	}

	ERR_error_string_n(PHPC_THIS->errors[0], buf, PLC_ERR_BUF_SIZE);

	PHPC_CSTR_RETURN(buf);
}
/* }}} */

/* {{{ proto string LCryptoException::getOpenSSLErrors() */
PLC_METHOD(LCryptoException, getOpenSSLErrors)
{
	PHPC_THIS_DECLARE(plc_err);
	char buf[PLC_ERR_BUF_SIZE];
	int i;

	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}

	PHPC_THIS_FETCH(plc_err);
	PHPC_ARRAY_INIT(return_value);

	for (i = 0; i < PHPC_THIS->count; i++) {
		ERR_error_string_n(PHPC_THIS->errors[i], buf, PLC_ERR_BUF_SIZE);
		PHPC_ARRAY_ADD_NEXT_INDEX_CSTR(return_value, buf);
	}
}
