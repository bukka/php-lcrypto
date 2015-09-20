/*
  +----------------------------------------------------------------------+
  | PHP Version 5                                                        |
  +----------------------------------------------------------------------+
  | Copyright (c) 2015 Jakub Zelenka                                |
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

#ifndef PHP_LCRYPTO_H
#define PHP_LCRYPTO_H

extern zend_module_entry lcrypto_module_entry;
#define phpext_lcrypto_ptr &lcrypto_module_entry

#ifdef PHP_WIN32
#	define PHP_LCRYPTO_API __declspec(dllexport)
#elif defined(__GNUC__) && __GNUC__ >= 4
#	define PHP_LCRYPTO_API __attribute__ ((visibility("default")))
#else
#	define PHP_LCRYPTO_API
#endif

#ifdef ZTS
#include "TSRM.h"
#endif

#include "php.h"

/* Crypto version */
#define PHP_LCRYPTO_VERSION "0.1.0"


/* PHP Compatibility layer */
#include "phpc/phpc.h"

/* Low-level Crypto namespace name */
#define PLC_NS_NAME "LCrypto"

/* Namespace separator */
#define PLC_NS_SEPARATOR "\\"

/* Low-level Crypto class name (including namespace) */
#define PLC_CLASS_NAME(classname) \
	PLC_NS_NAME PLC_NS_SEPARATOR #classname

/* Low-level Crypto method definition */
#define PLC_METHOD(classname, method) \
	PHP_METHOD(LCrypto_##_##classname, method)

/* Low-level Crypto method entry */
#define PLC_ME(classname, name, arg_info, flags) \
	PHP_ME(LCrypto_##_##classname, name, arg_info, flags)

/* Low-level Crypto abstract method entry */
#define PLC_ABSTRACT_ME(classname, name, arg_info) \
	PHP_ABSTRACT_ME(LCrypto_##_##classname, name, arg_info)



/* encoding params */
typedef enum {
	PLC_ENC_AUTO,
	PLC_ENC_HEX,
	PLC_ENC_DEC
} plc_encoding;


/* GLOBALS */
ZEND_BEGIN_MODULE_GLOBALS(lcrypto)
	plc_encoding encoding;
ZEND_END_MODULE_GLOBALS(lcrypto)

#ifdef ZTS
# define PLC_G(v) TSRMG(lcrypto_globals_id, zend_lcrypto_globals *, v)
#else
# define PLC_G(v) (lcrypto_globals.v)
#endif


/* MODULE FUNCTIONS */
PHP_MINIT_FUNCTION(lcrypto);
PHP_GINIT_FUNCTION(lcrypto);
PHP_MSHUTDOWN_FUNCTION(lcrypto);
PHP_MINFO_FUNCTION(lcrypto);


#endif	/* PHP_LCRYPTO_H */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
