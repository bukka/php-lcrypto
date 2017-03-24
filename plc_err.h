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

#ifndef PLC_ERR_H
#define PLC_ERR_H

#include "php.h"
#include "phpc/phpc.h"
#include "php_lcrypto.h"
#include <openssl/err.h>

PHPC_OBJ_STRUCT_BEGIN(plc_err)
	unsigned long errors[ERR_NUM_ERRORS];
	size_t count;
PHPC_OBJ_STRUCT_END()

/* INIT function */
PHP_MINIT_FUNCTION(plc_err);

PLC_API void plc_err_exception_subclass_init(
		const char *name, zend_class_entry **exc_ce, zend_object_handlers *handlers);

#endif // PLC_ERR_H

