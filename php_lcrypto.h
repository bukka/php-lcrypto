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
#	define PLC_API __attribute__ ((visibility("default")))
#else
#	define PLC_API
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


/* ERROR TYPES */

/* Errors info structure */
typedef struct {
	const char *name;
	const char *msg;
	int level;
} plc_error_info;

/* Error processing action */
typedef enum {
	PLC_ERROR_ACTION_GLOBAL = 0,
	PLC_ERROR_ACTION_SILENT,
	PLC_ERROR_ACTION_EXCEPTION,
	PLC_ERROR_ACTION_ERROR
} plc_error_action;

/* Processes error msg and either throw exception,
 * emits error or do nothing (it depends on action) */
PLC_API void plc_verror(
		const plc_error_info *info, zend_class_entry *exc_ce,
		plc_error_action action, zend_bool lib_error, int ignore_args
		TSRMLS_DC, const char *name, va_list args);
/* Main error function with arguments */
PLC_API void plc_error_ex(
		const plc_error_info *info, zend_class_entry *exc_ce,
		plc_error_action action, zend_bool lib_error,
		zend_bool ignore_args TSRMLS_DC, const char *name, ...);
/* Main error function without arguments */
PLC_API void plc_error(
		const plc_error_info *info, zend_class_entry *exc_ce,
		plc_error_action action, zend_bool lib_error,
		zend_bool ignore_args TSRMLS_DC, const char *name);

/* Macros for crypto exceptions info */

#define PLC_EXCEPTION_CE(ename) \
	plc_##ename##Exception_ce

#define PLC_EXCEPTION_EXPORT(ename) \
	extern PLC_API zend_class_entry *PLC_EXCEPTION_CE(ename);

#define PLC_EXCEPTION_DEFINE(ename) \
	PLC_API zend_class_entry *PLC_EXCEPTION_CE(ename);

#define PLC_EXCEPTION_REGISTER_CE(ce, ename, epname_ce) \
	INIT_CLASS_ENTRY(ce, PLC_CLASS_NAME(ename ## Exception), NULL); \
	PLC_EXCEPTION_CE(ename) = PHPC_CLASS_REGISTER_EX(ce, epname_ce, NULL)

#define PLC_EXCEPTION_REGISTER_EX(ce, ename, epname) \
	PLC_EXCEPTION_REGISTER_CE(ce, ename, PLC_EXCEPTION_CE(epname))

#define PLC_EXCEPTION_REGISTER(ce, ename) \
	PLC_EXCEPTION_REGISTER_EX(ce, ename, LCrypto)

/* Macros for error info */

#define PLC_ERROR_INFO_NAME(ename) \
	plc_error_info_##ename

#define PLC_ERROR_INFO_BEGIN(ename) \
	plc_error_info PLC_ERROR_INFO_NAME(ename)[] = {

#define PLC_ERROR_INFO_ENTRY_EX(einame, eimsg, eilevel) \
	{ #einame, eimsg, eilevel },

#define PLC_ERROR_INFO_ENTRY(einame, eimsg) \
	PLC_ERROR_INFO_ENTRY_EX(einame, eimsg, E_WARNING)

#define PLC_ERROR_INFO_END() \
	{ NULL, NULL, 0} };
#define PLC_ERROR_INFO_EXPORT(ename) \
		extern plc_error_info PLC_ERROR_INFO_NAME(ename)[];

#define PLC_ERROR_INFO_REGISTER(ename) do { \
	long code = 1; \
	plc_error_info *einfo = PLC_ERROR_INFO_NAME(ename); \
	while (einfo->name != NULL) { \
		zend_declare_class_constant_long(PLC_EXCEPTION_CE(ename), \
			einfo->name, strlen(einfo->name), code++ TSRMLS_CC); \
		einfo++; \
	} } while(0)

/* Macros for wrapping error arguments passed to plc_error* */

/* extension error with parameters */
#define PLC_ERROR_EXT_ARGS_EX(ename, eexc, eact, einame) \
	PLC_ERROR_INFO_NAME(ename), eexc, eact, 0, 0 TSRMLS_CC, #einame

/* extension error without parameters */
#define PLC_ERROR_EXT_ARGS(ename, einame) \
	PLC_ERROR_ARGS_EX(ename, PLC_EXCEPTION_CE(ename), \
		PLC_ERROR_ACTION_GLOBAL, einame)

/* library error with parameters */
#define PLC_ERROR_LIB_ARGS_EX(ename, eexc, eact, einame) \
	PLC_ERROR_INFO_NAME(ename), eexc, eact, 1, 0 TSRMLS_CC, #einame

/* library error without parameters */
#define PLC_ERROR_LIB_ARGS(ename, einame) \
	PLC_ERROR_ARGS_EX(ename, PLC_EXCEPTION_CE(ename), \
		PLC_ERROR_ACTION_GLOBAL, einame)

/* Base exception class */
PLC_EXCEPTION_EXPORT(LCrypto)


/* ENCODING */

/* encoding params */
typedef enum {
	PLC_ENC_AUTO,
	PLC_ENC_HEX,
	PLC_ENC_DEC
} plc_encoding;


/* GLOBALS */

ZEND_BEGIN_MODULE_GLOBALS(lcrypto)
	plc_error_action error_action;
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


/* COMPATIBILITY */

#define PLC_COPY_ERROR_MESSAGE \
	(PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION == 5 && PHP_RELEASE_VERSION >= 5) \
	|| (PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION >= 6) \
	|| (PHP_MAJOR_VERSION > 5)

#if PLC_COPY_ERROR_MESSAGE
#define PLC_GET_ERROR_MESSAGE(const_msg, tmp_msg) \
	(const_msg)
#else
#define PLC_GET_ERROR_MESSAGE(const_msg, tmp_msg) \
	(tmp_msg = estrdup(const_msg))
#endif

#endif	/* PHP_LCRYPTO_H */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
