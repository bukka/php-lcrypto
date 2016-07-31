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

#ifndef PLC_RSA_H
#define PLC_RSA_H

#include "php_lcrypto.h"

/* Exception */
PLC_EXCEPTION_EXPORT(RSA)
/* Error info */
PLC_ERROR_INFO_EXPORT(RSA)

/* INIT function */
PHP_MINIT_FUNCTION(plc_rsa);

/* methods */
PLC_METHOD(RSA, __construct);
PLC_METHOD(RSA, setEncoding);
PLC_METHOD(RSA, getEncoding);
PLC_METHOD(RSA, setKey);
PLC_METHOD(RSA, setFactors);
PLC_METHOD(RSA, setCrtParams);
PLC_METHOD(RSA, getKey);
PLC_METHOD(RSA, getFactors);
PLC_METHOD(RSA, getCrtParams);
PLC_METHOD(RSA, generateKey);
PLC_METHOD(RSA, getSize);
PLC_METHOD(RSA, publicEncrypt);
PLC_METHOD(RSA, privateDecrypt);
PLC_METHOD(RSA, privateEncrypt);
PLC_METHOD(RSA, publicDecrypt);
PLC_METHOD(RSA, sign);
PLC_METHOD(RSA, verify);
PLC_METHOD(RSA, export);

#endif	/* PLC_RSA_H */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
