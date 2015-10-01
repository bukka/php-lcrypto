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
#include "php_lcrypto_rsa.h"

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/buffer.h>

ZEND_EXTERN_MODULE_GLOBALS(lcrypto)

/* ERRORS */

PLC_EXCEPTION_DEFINE(Cipher)
PLC_ERROR_INFO_BEGIN(Cipher)
PLC_ERROR_INFO_ENTRY(
	INVALID_HEX_ENCODING,
	"The string contains a non-hexadecimal character"
)
PLC_ERROR_INFO_ENTRY(
	INVALID_DEC_ENCODING,
	"The string contains a non-decimal character"
)
PLC_ERROR_INFO_ENTRY(
	INVALID_PADDING,
	"Ivalid padding parameter"
)
PLC_ERROR_INFO_ENTRY(
	KEY_GENERATION_BITS_HIGH,
	"The number of bits for module size is too high"
)
PLC_ERROR_INFO_ENTRY(
	KEY_GENERATION_FAILED,
	"The key generation failed"
)
PLC_ERROR_INFO_ENTRY(
	PUB_ENCRYPT_INPUT_LONG,
	"The public encryption input is too long"
)
PLC_ERROR_INFO_ENTRY(
	PUB_ENCRYPT_FAILED,
	"The public encryption failed"
)
PLC_ERROR_INFO_ENTRY(
	PRIV_DECRYPT_INPUT_LONG,
	"The private decryption input is too long"
)
PLC_ERROR_INFO_ENTRY(
	PRIV_DECRYPT_FAILED,
	"The private decryption failed"
)
PLC_ERROR_INFO_ENTRY(
	PRIV_ENCRYPT_INPUT_LONG,
	"The private encryption input is too long"
)
PLC_ERROR_INFO_ENTRY(
	PRIV_ENCRYPT_FAILED,
	"The private encryption failed"
)
PLC_ERROR_INFO_ENTRY(
	PUB_DECRYPT_INPUT_LONG,
	"The public decryption input is too long"
)
PLC_ERROR_INFO_ENTRY(
	PUB_DECRYPT_FAILED,
	"The public decryption failed"
)
PLC_ERROR_INFO_ENTRY(
	SIGN_FAILED,
	"The signing failed"
)
PLC_ERROR_INFO_END()


typedef enum {
	PLC_RSA_ERROR_INVALID_HEX_ENC = 1,
	PLC_RSA_ERROR_INVALID_DEC_ENC,
	PLC_RSA_ERROR_INVALID_PADDING,
	PLC_RSA_ERROR_KEY_GENERATION_BITS_HIGH,
	PLC_RSA_ERROR_KEY_GENERATION_FAILED,
	PLC_RSA_ERROR_PUB_ENCRYPT_INPUT_LONG,
	PLC_RSA_ERROR_PUB_ENCRYPT_FAILED,
	PLC_RSA_ERROR_PRIV_DECRYPT_INPUT_LONG,
	PLC_RSA_ERROR_PRIV_DECRYPT_FAILED,
	PLC_RSA_ERROR_PRIV_ENCRYPT_INPUT_LONG,
	PLC_RSA_ERROR_PRIV_ENCRYPT_FAILED,
	PLC_RSA_ERROR_PUB_DECRYPT_INPUT_LONG,
	PLC_RSA_ERROR_PUB_DECRYPT_FAILED,
	PLC_RSA_ERROR_SIGN_FAILED
} plc_rsa_error_code;


/* class entries */
static zend_class_entry *plc_rsa_ce;
static zend_class_entry *plc_rsa_exception_ce;


/*
 * Such or greater value would be counted forever. Practically
 * anything higher than 4096 does not make sense already
 */
#define PLC_RSA_MAX_MODULE_SIZE (1 << 15)

PHPC_OBJ_STRUCT_BEGIN(plc_rsa)
	RSA *ctx;
PHPC_OBJ_STRUCT_END()

ZEND_BEGIN_ARG_INFO(arginfo_plc_rsa_set_encoding, 0)
ZEND_ARG_INFO(0, encoding)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_plc_rsa_set_value, 0, 0, 1)
ZEND_ARG_INFO(0, value)
ZEND_ARG_INFO(0, encoding)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_plc_rsa_get_value, 0, 0, 0)
ZEND_ARG_INFO(0, encoding)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_plc_rsa_generate_key, 0)
ZEND_ARG_INFO(0, bits)
ZEND_ARG_INFO(0, exponent)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_plc_rsa_encdec, 0, 0, 1)
ZEND_ARG_INFO(0, from)
ZEND_ARG_INFO(0, padding)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_plc_rsa_sign, 0, 0, 1)
ZEND_ARG_INFO(0, message)
ZEND_ARG_INFO(0, type)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_plc_rsa_verify, 0, 0, 2)
ZEND_ARG_INFO(0, message)
ZEND_ARG_INFO(0, signature)
ZEND_ARG_INFO(0, type)
ZEND_END_ARG_INFO()

static const zend_function_entry plc_rsa_object_methods[] = {
	PLC_ME(RSA, __construct,    NULL,                           ZEND_ACC_CTOR|ZEND_ACC_PUBLIC)
	PLC_ME(RSA, setEncoding,    arginfo_plc_rsa_set_encoding,   ZEND_ACC_PUBLIC)
	PLC_ME(RSA, getEncoding,    NULL,                           ZEND_ACC_PUBLIC)
	PLC_ME(RSA, setN,           arginfo_plc_rsa_set_value,      ZEND_ACC_PUBLIC)
	PLC_ME(RSA, setE,           arginfo_plc_rsa_set_value,      ZEND_ACC_PUBLIC)
	PLC_ME(RSA, setD,           arginfo_plc_rsa_set_value,      ZEND_ACC_PUBLIC)
	PLC_ME(RSA, setP,           arginfo_plc_rsa_set_value,      ZEND_ACC_PUBLIC)
	PLC_ME(RSA, setQ,           arginfo_plc_rsa_set_value,      ZEND_ACC_PUBLIC)
	PLC_ME(RSA, setDMP1,        arginfo_plc_rsa_set_value,      ZEND_ACC_PUBLIC)
	PLC_ME(RSA, setDMQ1,        arginfo_plc_rsa_set_value,      ZEND_ACC_PUBLIC)
	PLC_ME(RSA, setIQMP,        arginfo_plc_rsa_set_value,      ZEND_ACC_PUBLIC)
	PLC_ME(RSA, getN,           arginfo_plc_rsa_get_value,      ZEND_ACC_PUBLIC)
	PLC_ME(RSA, getE,           arginfo_plc_rsa_get_value,      ZEND_ACC_PUBLIC)
	PLC_ME(RSA, getD,           arginfo_plc_rsa_get_value,      ZEND_ACC_PUBLIC)
	PLC_ME(RSA, getP,           arginfo_plc_rsa_get_value,      ZEND_ACC_PUBLIC)
	PLC_ME(RSA, getQ,           arginfo_plc_rsa_get_value,      ZEND_ACC_PUBLIC)
	PLC_ME(RSA, getDMP1,        arginfo_plc_rsa_get_value,      ZEND_ACC_PUBLIC)
	PLC_ME(RSA, getDMQ1,        arginfo_plc_rsa_get_value,      ZEND_ACC_PUBLIC)
	PLC_ME(RSA, getIQMP,        arginfo_plc_rsa_get_value,      ZEND_ACC_PUBLIC)
	PLC_ME(RSA, generateKey,    arginfo_plc_rsa_generate_key,   ZEND_ACC_PUBLIC)
	PLC_ME(RSA, getSize,        NULL,                           ZEND_ACC_PUBLIC)
	PLC_ME(RSA, publicEncrypt,  arginfo_plc_rsa_encdec,         ZEND_ACC_PUBLIC)
	PLC_ME(RSA, privateDecrypt, arginfo_plc_rsa_encdec,         ZEND_ACC_PUBLIC)
	PLC_ME(RSA, privateEncrypt, arginfo_plc_rsa_encdec,         ZEND_ACC_PUBLIC)
	PLC_ME(RSA, publicDecrypt,  arginfo_plc_rsa_encdec,         ZEND_ACC_PUBLIC)
	PLC_ME(RSA, sign,           arginfo_plc_rsa_sign,           ZEND_ACC_PUBLIC)
	PLC_ME(RSA, verify,         arginfo_plc_rsa_verify,         ZEND_ACC_PUBLIC)
	PLC_ME(RSA, export,         NULL,                           ZEND_ACC_PUBLIC)
	PHPC_FE_END
};

/* object handler */
PHPC_OBJ_DEFINE_HANDLER_VAR(plc_rsa);

/* {{{ plc_rsa free object handler */
PHPC_OBJ_HANDLER_FREE(plc_rsa)
{
	PHPC_OBJ_HANDLER_FREE_INIT(plc_rsa);

	RSA_free(PHPC_THIS->ctx);

	PHPC_OBJ_HANDLER_FREE_DESTROY();
}
/* }}} */

/* {{{ plc_rsa create_ex object helper */
PHPC_OBJ_HANDLER_CREATE_EX(plc_rsa)
{
	PHPC_OBJ_HANDLER_CREATE_EX_INIT(plc_rsa);

	/* allocate encode context */
	PHPC_THIS->ctx = RSA_new();

	PHPC_OBJ_HANDLER_CREATE_EX_RETURN(plc_rsa);
}
/* }}} */

/* {{{ plc_rsa create object handler */
PHPC_OBJ_HANDLER_CREATE(plc_rsa)
{
	PHPC_OBJ_HANDLER_CREATE_RETURN(plc_rsa);
}
/* }}} */

/* {{{ plc_rsa clone object handler */
PHPC_OBJ_HANDLER_CLONE(plc_rsa)
{
	PHPC_OBJ_HANDLER_CLONE_INIT(plc_rsa);

	PHPC_THAT->ctx->n = BN_dup(PHPC_THIS->ctx->n);
	PHPC_THAT->ctx->e = BN_dup(PHPC_THIS->ctx->e);
	PHPC_THAT->ctx->d = BN_dup(PHPC_THIS->ctx->d);
	PHPC_THAT->ctx->p = BN_dup(PHPC_THIS->ctx->p);
	PHPC_THAT->ctx->q = BN_dup(PHPC_THIS->ctx->q);

	PHPC_OBJ_HANDLER_CLONE_RETURN();
}
/* }}} */

/* {{{ PHP_MINIT_FUNCTION
 */
PHP_MINIT_FUNCTION(plc_rsa)
{
	zend_class_entry ce;

	/* RSA class */
	INIT_CLASS_ENTRY(ce, PLC_CLASS_NAME(RSA), plc_rsa_object_methods);
	PHPC_CLASS_SET_HANDLER_CREATE(ce, plc_rsa);
	plc_rsa_ce = PHPC_CLASS_REGISTER(ce);
	PHPC_OBJ_INIT_HANDLERS(plc_rsa);
	PHPC_OBJ_SET_HANDLER_OFFSET(plc_rsa);
	PHPC_OBJ_SET_HANDLER_FREE(plc_rsa);
	PHPC_OBJ_SET_HANDLER_CLONE(plc_rsa);

	/* Register RSA constant */
	/* encoding constants */
	zend_declare_class_constant_long(plc_rsa_ce,
			"ENCODING_AUTO", sizeof("ENCODING_AUTO") - 1,
			PLC_ENC_AUTO TSRMLS_CC);
	zend_declare_class_constant_long(plc_rsa_ce,
			"ENCODING_HEX", sizeof("ENCODING_HEX") - 1,
			PLC_ENC_HEX TSRMLS_CC);
	zend_declare_class_constant_long(plc_rsa_ce,
			"ENCODING_DEC", sizeof("ENCODING_DEC") - 1,
			PLC_ENC_DEC TSRMLS_CC);
	/* max module size */
	zend_declare_class_constant_long(plc_rsa_ce,
			"MAX_MODULE_SIZE", sizeof("MAX_MODULE_SIZE") - 1,
			PLC_RSA_MAX_MODULE_SIZE TSRMLS_CC);
	/* padding constants */
	zend_declare_class_constant_long(plc_rsa_ce,
			"PADDING_NONE", sizeof("PADDING_NONE") - 1,
			RSA_NO_PADDING TSRMLS_CC);
	zend_declare_class_constant_long(plc_rsa_ce,
			"PADDING_PKCS1", sizeof("PADDING_PKCS1") - 1,
			RSA_PKCS1_PADDING TSRMLS_CC);
	zend_declare_class_constant_long(plc_rsa_ce,
			"PADDING_OAEP", sizeof("PADDING_OAEP") - 1,
			RSA_PKCS1_OAEP_PADDING TSRMLS_CC);
	zend_declare_class_constant_long(plc_rsa_ce,
			"PADDING_SSLV23", sizeof("PADDING_SSLV23") - 1,
			RSA_SSLV23_PADDING TSRMLS_CC);
	zend_declare_class_constant_long(plc_rsa_ce,
			"PADDING_X931", sizeof("PADDING_X931") - 1,
			RSA_X931_PADDING TSRMLS_CC);
	/* NID of the most used algorithms for sign and verify */
	zend_declare_class_constant_long(plc_rsa_ce,
			"NID_RIPEMD160", sizeof("NID_RIPEMD160") - 1,
			NID_ripemd160 TSRMLS_CC);
	zend_declare_class_constant_long(plc_rsa_ce,
			"NID_MD5", sizeof("NID_MD5") - 1,
			NID_md5 TSRMLS_CC);
	zend_declare_class_constant_long(plc_rsa_ce,
			"NID_MD5_SHA1", sizeof("NID_MD5_SHA1") - 1,
			NID_md5_sha1 TSRMLS_CC);
	zend_declare_class_constant_long(plc_rsa_ce,
			"NID_SHA1", sizeof("NID_SHA1") - 1,
			NID_sha1 TSRMLS_CC);
	zend_declare_class_constant_long(plc_rsa_ce,
			"NID_SHA224", sizeof("NID_SHA224") - 1,
			NID_sha224 TSRMLS_CC);
	zend_declare_class_constant_long(plc_rsa_ce,
			"NID_SHA256", sizeof("NID_SHA256") - 1,
			NID_sha256 TSRMLS_CC);
	zend_declare_class_constant_long(plc_rsa_ce,
			"NID_SHA384", sizeof("NID_SHA384") - 1,
			NID_sha384 TSRMLS_CC);
	zend_declare_class_constant_long(plc_rsa_ce,
			"NID_SHA512", sizeof("NID_SHA512") - 1,
			NID_sha512 TSRMLS_CC);

	/* RSAException class */
	INIT_CLASS_ENTRY(ce, PLC_CLASS_NAME(RSAException), NULL);
	plc_rsa_exception_ce = PHPC_CLASS_REGISTER_EX(ce,
			zend_exception_get_default(TSRMLS_C), NULL);

	/* Register RSAException error constant */
	/* encoding errors */
	zend_declare_class_constant_long(plc_rsa_exception_ce,
			"INVALID_HEX_ENCODING", sizeof("INVALID_HEX_ENCODING") - 1,
			PLC_RSA_ERROR_INVALID_HEX_ENC TSRMLS_CC);
	zend_declare_class_constant_long(plc_rsa_exception_ce,
			"INVALID_DEC_ENCODING", sizeof("INVALID_DEC_ENCODING") - 1,
			PLC_RSA_ERROR_INVALID_DEC_ENC TSRMLS_CC);
	/* padding error */
	zend_declare_class_constant_long(plc_rsa_exception_ce,
			"INVALID_PADDING", sizeof("INVALID_PADDING") - 1,
			PLC_RSA_ERROR_INVALID_PADDING TSRMLS_CC);
	/* generation key errors */
	zend_declare_class_constant_long(plc_rsa_exception_ce,
			"KEY_GENERATION_BITS_HIGH", sizeof("KEY_GENERATION_BITS_HIGH") - 1,
			PLC_RSA_ERROR_KEY_GENERATION_BITS_HIGH TSRMLS_CC);
	zend_declare_class_constant_long(plc_rsa_exception_ce,
			"KEY_GENERATION_FAILED", sizeof("KEY_GENERATION_FAILED") - 1,
			PLC_RSA_ERROR_KEY_GENERATION_FAILED TSRMLS_CC);
	/* public encryption */
	zend_declare_class_constant_long(plc_rsa_exception_ce,
			"PUB_ENCRYPT_INPUT_LONG", sizeof("PUB_ENCRYPT_INPUT_LONG") - 1,
			PLC_RSA_ERROR_PUB_ENCRYPT_INPUT_LONG TSRMLS_CC);
	zend_declare_class_constant_long(plc_rsa_exception_ce,
			"PUB_ENCRYPT_FAILED", sizeof("PUB_ENCRYPT_FAILED") - 1,
			PLC_RSA_ERROR_PUB_ENCRYPT_FAILED TSRMLS_CC);
	/* private decryption */
	zend_declare_class_constant_long(plc_rsa_exception_ce,
			"PRIV_DECRYPT_INPUT_LONG", sizeof("PRIV_DECRYPT_INPUT_LONG") - 1,
			PLC_RSA_ERROR_PRIV_DECRYPT_INPUT_LONG TSRMLS_CC);
	zend_declare_class_constant_long(plc_rsa_exception_ce,
			"PRIV_DECRYPT_FAILED", sizeof("PRIV_DECRYPT_FAILED") - 1,
			PLC_RSA_ERROR_PRIV_DECRYPT_FAILED TSRMLS_CC);
	/* private encryption */
	zend_declare_class_constant_long(plc_rsa_exception_ce,
			"PRIV_ENCRYPT_INPUT_LONG", sizeof("PRIV_ENCRYPT_INPUT_LONG") - 1,
			PLC_RSA_ERROR_PRIV_ENCRYPT_INPUT_LONG TSRMLS_CC);
	zend_declare_class_constant_long(plc_rsa_exception_ce,
			"PRIV_ENCRYPT_FAILED", sizeof("PRIV_ENCRYPT_FAILED") - 1,
			PLC_RSA_ERROR_PRIV_ENCRYPT_FAILED TSRMLS_CC);
	/* public decryption */
	zend_declare_class_constant_long(plc_rsa_exception_ce,
			"PUB_DECRYPT_INPUT_LONG", sizeof("PUB_DECRYPT_INPUT_LONG") - 1,
			PLC_RSA_ERROR_PUB_DECRYPT_INPUT_LONG TSRMLS_CC);
	zend_declare_class_constant_long(plc_rsa_exception_ce,
			"PUB_DECRYPT_FAILED", sizeof("PUB_DECRYPT_FAILED") - 1,
			PLC_RSA_ERROR_PUB_DECRYPT_FAILED TSRMLS_CC);
	/* signing */
	zend_declare_class_constant_long(plc_rsa_exception_ce,
			"SIGN_FAILED", sizeof("SIGN_FAILED") - 1,
			PLC_RSA_ERROR_SIGN_FAILED TSRMLS_CC);


	return SUCCESS;
}
/* }}} */

/* {{{ */
static int plc_rsa_check_padding(phpc_long_t padding, zend_bool sigver TSRMLS_DC)
{
	zend_bool ok;

	switch (padding) {
		case RSA_PKCS1_PADDING:
		case RSA_NO_PADDING:
			ok = 1;
			break;
		case RSA_PKCS1_OAEP_PADDING:
		case RSA_SSLV23_PADDING:
			ok = !sigver;
			break;
		case RSA_X931_PADDING:
			ok = sigver;
			break;
		default:
			ok = 0;
	}

	if (ok) {
		return SUCCESS;
	}

	zend_throw_exception(plc_rsa_exception_ce,
			"Ivalid padding parameter",
			PLC_RSA_ERROR_INVALID_PADDING TSRMLS_CC);
	return FAILURE;
}
/* }}} */

/* {{{ */
static int plc_rsa_check_encoding(const char **p_sval, phpc_str_size_t *p_sval_len,
		plc_encoding *p_encoding TSRMLS_DC)
{
	phpc_str_size_t pos;
	char c;
	const char *sval;
	plc_encoding encoding;

	if (*p_encoding == PLC_ENC_AUTO) {
		if (*p_sval_len > 2 && !strncmp("0x", *p_sval, 2)) {
			*p_sval += 2;
			*p_sval_len -= 2;
			*p_encoding = PLC_ENC_HEX;
		} else {
			*p_encoding = PLC_ENC_DEC;
		}
	}

	sval = *p_sval;
	encoding = *p_encoding;

	for (pos = 0; pos < *p_sval_len; pos++) {
		c = sval[pos];
		if ((c >= '0') && (c <= '9')) {
			continue;
		}
		if (encoding == PLC_ENC_DEC) {
			zend_throw_exception(plc_rsa_exception_ce,
					"The string contains a non-decimal character",
					PLC_RSA_ERROR_INVALID_DEC_ENC TSRMLS_CC);
			return FAILURE;
		}

		if (!((c >= 'a') && (c <= 'f')) && !((c >= 'A') && (c <= 'F'))) {
			zend_throw_exception(plc_rsa_exception_ce,
					"The string contains a non-hexadecimal character",
					PLC_RSA_ERROR_INVALID_HEX_ENC TSRMLS_CC);
			return FAILURE;
		}
	}

	return SUCCESS;
}
/* }}} */

/* {{{ */
static plc_encoding plc_rsa_long_to_encoding(phpc_long_t encoding_value)
{
	switch (encoding_value) {
		case PLC_ENC_DEC:
			return PLC_ENC_DEC;
		case PLC_ENC_HEX:
			return PLC_ENC_HEX;
		default:
			return PLC_ENC_AUTO;
	}
}
/* }}} */

/* {{{ */
static int plc_rsa_set_value(BIGNUM **bnval, const char *sval, phpc_str_size_t sval_len,
		plc_encoding encoding TSRMLS_DC)
{
	int rc;

	if (plc_rsa_check_encoding(&sval, &sval_len, &encoding TSRMLS_CC) == FAILURE) {
		return FAILURE;
	}

	switch (encoding) {
		case PLC_ENC_DEC:
			rc = BN_dec2bn(bnval, sval);
			break;

		default:
			rc = BN_hex2bn(bnval, sval);
	}

	return rc != 0 ? SUCCESS : FAILURE;
}
/* }}} */

/* {{{ */
static char *plc_rsa_get_value(BIGNUM *bnval, plc_encoding encoding TSRMLS_DC)
{
	char *value;

	switch (encoding) {
		case PLC_ENC_HEX:
			value = BN_bn2hex(bnval);
			break;

		default:
			value = BN_bn2dec(bnval);
	}

	return value;
}
/* }}} */

/* {{{ */
static void plc_rsa_set_value_method(INTERNAL_FUNCTION_PARAMETERS, BIGNUM **bnval)
{
	char *sval;
	phpc_str_size_t sval_len;
	phpc_long_t encoding_value = PLC_G(encoding);

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|l",
			&sval, &sval_len, &encoding_value) == FAILURE) {
		return;
	}

	plc_rsa_set_value(bnval, sval, sval_len,
			plc_rsa_long_to_encoding(encoding_value) TSRMLS_CC);

	RETURN_NULL();
}
/* }}} */

/* {{{ */
static void plc_rsa_get_value_method(INTERNAL_FUNCTION_PARAMETERS, BIGNUM **bnval)
{
	PHPC_STR_DECLARE(out);
	char *value;
	phpc_long_t encoding_value = PLC_G(encoding);

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|l",
			&encoding_value) == FAILURE) {
		return;
	}

	if (!*bnval) {
		RETURN_EMPTY_STRING();
	}

	value = plc_rsa_get_value(*bnval, plc_rsa_long_to_encoding(encoding_value) TSRMLS_CC);
	PHPC_STR_INIT(out, value, strlen(value));
	OPENSSL_free(value);

	PHPC_STR_RETURN(out);
}
/* }}} */

/* {{{ proto void RSA::__Construct() */
PLC_METHOD(RSA, __construct)
{
}
/* }}} */

/* {{{ proto void RSA::setEncoding() */
PLC_METHOD(RSA, setEncoding)
{
	phpc_long_t encoding_value;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l",
			&encoding_value) == FAILURE) {
		return;
	}

	PLC_G(encoding) = plc_rsa_long_to_encoding(encoding_value);
}
/* }}} */

/* {{{ proto int RSA::getEncoding() */
PLC_METHOD(RSA, getEncoding)
{
	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}

	RETURN_LONG((phpc_long_t) PLC_G(encoding));
}
/* }}} */

#define PLC_RSA_METHOD_VALUE_SETTER(name) \
	PHPC_THIS_DECLARE_AND_FETCH(plc_rsa); \
	plc_rsa_set_value_method(INTERNAL_FUNCTION_PARAM_PASSTHRU, &PHPC_THIS->ctx->name);

/* {{{ proto void RSA::setN($value, $format = RSA_ENC_HEX) */
PLC_METHOD(RSA, setN)
{
	PLC_RSA_METHOD_VALUE_SETTER(n);
}
/* }}} */

/* {{{ proto void RSA::setE($value, $format = RSA_ENC_HEX) */
PLC_METHOD(RSA, setE)
{
	PLC_RSA_METHOD_VALUE_SETTER(e);
}
/* }}} */

/* {{{ proto void RSA::setD($value, $format = RSA_ENC_HEX) */
PLC_METHOD(RSA, setD)
{
	PLC_RSA_METHOD_VALUE_SETTER(d);
}
/* }}} */

/* {{{ proto void RSA::setP($value, $format = RSA_ENC_HEX) */
PLC_METHOD(RSA, setP)
{
	PLC_RSA_METHOD_VALUE_SETTER(p);
}
/* }}} */

/* {{{ proto void RSA::setQ($value, $format = RSA_ENC_HEX) */
PLC_METHOD(RSA, setQ)
{
	PLC_RSA_METHOD_VALUE_SETTER(q);
}
/* }}} */

/* {{{ proto string RSA::setDMP1($value, $format = RSA_ENC_HEX) */
PLC_METHOD(RSA, setDMP1)
{
	PLC_RSA_METHOD_VALUE_SETTER(dmp1);
}
/* }}} */

/* {{{ proto string RSA::setDMQ1($value, $format = RSA_ENC_HEX) */
PLC_METHOD(RSA, setDMQ1)
{
	PLC_RSA_METHOD_VALUE_SETTER(dmq1);
}
/* }}} */

/* {{{ proto string RSA::setIQMP($value, $format = RSA_ENC_HEX) */
PLC_METHOD(RSA, setIQMP)
{
	PLC_RSA_METHOD_VALUE_SETTER(iqmp);
}
/* }}} */

#define PLC_RSA_METHOD_VALUE_GETTER(name) \
	PHPC_THIS_DECLARE_AND_FETCH(plc_rsa); \
	plc_rsa_get_value_method(INTERNAL_FUNCTION_PARAM_PASSTHRU, &PHPC_THIS->ctx->name);

/* {{{ proto string RSA::getN($format = RSA_ENC_HEX) */
PLC_METHOD(RSA, getN)
{
	PLC_RSA_METHOD_VALUE_GETTER(n);
}
/* }}} */

/* {{{ proto string RSA::getE($format = RSA_ENC_HEX) */
PLC_METHOD(RSA, getE)
{
	PLC_RSA_METHOD_VALUE_GETTER(e);
}
/* }}} */

/* {{{ proto string RSA::getD($format = RSA_ENC_HEX) */
PLC_METHOD(RSA, getD)
{
	PLC_RSA_METHOD_VALUE_GETTER(d);
}
/* }}} */

/* {{{ proto string RSA::getP($format = RSA_ENC_HEX) */
PLC_METHOD(RSA, getP)
{
	PLC_RSA_METHOD_VALUE_GETTER(p);
}
/* }}} */

/* {{{ proto string RSA::getQ($format = RSA_ENC_HEX) */
PLC_METHOD(RSA, getQ)
{
	PLC_RSA_METHOD_VALUE_GETTER(q);
}
/* }}} */

/* {{{ proto string RSA::getDMP1($format = RSA_ENC_HEX) */
PLC_METHOD(RSA, getDMP1)
{
	PLC_RSA_METHOD_VALUE_GETTER(dmp1);
}
/* }}} */

/* {{{ proto string RSA::getDMQ1($format = RSA_ENC_HEX) */
PLC_METHOD(RSA, getDMQ1)
{
	PLC_RSA_METHOD_VALUE_GETTER(dmq1);
}
/* }}} */

/* {{{ proto string RSA::getIQMP($format = RSA_ENC_HEX) */
PLC_METHOD(RSA, getIQMP)
{
	PLC_RSA_METHOD_VALUE_GETTER(iqmp);
}
/* }}} */

/* {{{ proto void RSA::generateKey($bits, $exponent) */
PLC_METHOD(RSA, generateKey)
{
	PHPC_THIS_DECLARE(plc_rsa);
	BIGNUM *bn_exp = NULL;
	phpc_str_size_t exponent_len;
	char *exponent;
	phpc_long_t bits;
	phpc_long_t encoding_value = PLC_ENC_AUTO;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ls",
			&bits, &exponent, &exponent_len, &encoding_value) == FAILURE) {
		return;
	}

	RETVAL_NULL();

	PHPC_THIS_FETCH(plc_rsa);

	if (bits > PLC_RSA_MAX_MODULE_SIZE) {
		zend_throw_exception(plc_rsa_exception_ce,
				"The number of bits for module size is too high",
				PLC_RSA_ERROR_KEY_GENERATION_BITS_HIGH TSRMLS_CC);
		return;
	}

	plc_rsa_set_value(&bn_exp, exponent, exponent_len,
			plc_rsa_long_to_encoding(encoding_value) TSRMLS_CC);


	if (!RSA_generate_key_ex(PHPC_THIS->ctx, bits, bn_exp, NULL)) {
		zend_throw_exception(plc_rsa_exception_ce,
				"The key generation failed",
				PLC_RSA_ERROR_KEY_GENERATION_FAILED TSRMLS_CC);
	}

	BN_free(bn_exp);
}

/* {{{ proto int RSA::getSize() */
PLC_METHOD(RSA, getSize)
{
	PHPC_THIS_DECLARE(plc_rsa);

	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}

	PHPC_THIS_FETCH(plc_rsa);

	RETURN_LONG((phpc_long_t) RSA_size(PHPC_THIS->ctx));
}
/* }}} */

/* {{{ */
static int plc_rsa_get_max_input_len(int rsa_size, int padding)
{
	switch (padding) {
		case RSA_PKCS1_PADDING:
		case RSA_SSLV23_PADDING:
			return rsa_size - 12;

		case RSA_PKCS1_OAEP_PADDING:
			return rsa_size - 42;

		default:
			return rsa_size;
	}
}
/* }}} */

/* {{{ proto string RSA::publicEncrypt($from, $padding = RSA::PADDING_OEAP) */
PLC_METHOD(RSA, publicEncrypt)
{
	PHPC_THIS_DECLARE(plc_rsa);
	PHPC_STR_DECLARE(out);
	char *from;
	phpc_str_size_t flen;
	int rsa_size, enc_len;
	phpc_long_t padding = RSA_PKCS1_OAEP_PADDING;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|l",
			&from, &flen, &padding) == FAILURE) {
		return;
	}

	if (plc_rsa_check_padding(padding, 0 TSRMLS_CC) == FAILURE) {
		RETURN_NULL();
	}

	PHPC_THIS_FETCH(plc_rsa);

	rsa_size = RSA_size(PHPC_THIS->ctx);
	if (flen > plc_rsa_get_max_input_len(rsa_size, padding)) {
		zend_throw_exception(plc_rsa_exception_ce,
				"The public encryption input is too long",
				PLC_RSA_ERROR_PUB_ENCRYPT_INPUT_LONG TSRMLS_CC);
		RETURN_NULL();
	}

	PHPC_STR_ALLOC(out, rsa_size);

	enc_len = RSA_public_encrypt(flen,
			(unsigned char *) from, (unsigned char *) PHPC_STR_VAL(out),
			PHPC_THIS->ctx, padding);

	if (enc_len < 0) {
		zend_throw_exception(plc_rsa_exception_ce,
				"The public encryption failed",
				PLC_RSA_ERROR_PUB_ENCRYPT_FAILED TSRMLS_CC);
		PHPC_STR_RELEASE(out);
		RETURN_NULL();
	}

	if (enc_len < rsa_size) {
		PHPC_STR_REALLOC(out, enc_len);
	}
	PHPC_STR_VAL(out)[enc_len] = '\0';

	PHPC_STR_RETURN(out);

}
/* }}} */

/* {{{ proto string RSA::privateDecrypt($from, $padding = RSA::PADDING_OEAP) */
PLC_METHOD(RSA, privateDecrypt)
{
	PHPC_THIS_DECLARE(plc_rsa);
	PHPC_STR_DECLARE(out);
	char *from;
	phpc_str_size_t flen;
	int rsa_size, dec_len;
	phpc_long_t padding = RSA_PKCS1_OAEP_PADDING;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|l",
			&from, &flen, &padding) == FAILURE) {
		return;
	}

	if (plc_rsa_check_padding(padding, 0 TSRMLS_CC) == FAILURE) {
		RETURN_NULL();
	}

	PHPC_THIS_FETCH(plc_rsa);

	rsa_size = RSA_size(PHPC_THIS->ctx);
	if (flen > rsa_size) {
		zend_throw_exception(plc_rsa_exception_ce,
				"The private decryption input is too long",
				PLC_RSA_ERROR_PRIV_DECRYPT_INPUT_LONG TSRMLS_CC);
		RETURN_NULL();
	}

	PHPC_STR_ALLOC(out, rsa_size);

	dec_len = RSA_private_decrypt(flen,
			(unsigned char *) from, (unsigned char *) PHPC_STR_VAL(out),
			PHPC_THIS->ctx, padding);

	if (dec_len < 0) {
		zend_throw_exception(plc_rsa_exception_ce,
				"The private decryption failed",
				PLC_RSA_ERROR_PRIV_DECRYPT_FAILED TSRMLS_CC);
		PHPC_STR_RELEASE(out);
		RETURN_NULL();
	}

	if (dec_len < rsa_size) {
		PHPC_STR_REALLOC(out, dec_len);
	}
	PHPC_STR_VAL(out)[dec_len] = '\0';

	PHPC_STR_RETURN(out);
}
/* }}} */

/* {{{ proto string RSA::privateEncrypt($from, $padding = RSA::PADDING_PKCS1) */
PLC_METHOD(RSA, privateEncrypt)
{
	PHPC_THIS_DECLARE(plc_rsa);
	PHPC_STR_DECLARE(out);
	char *from;
	phpc_str_size_t flen;
	int rsa_size, dec_len;
	phpc_long_t padding = RSA_PKCS1_PADDING;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|l",
			&from, &flen, &padding) == FAILURE) {
		return;
	}

	if (plc_rsa_check_padding(padding, 1 TSRMLS_CC) == FAILURE) {
		RETURN_NULL();
	}

	PHPC_THIS_FETCH(plc_rsa);

	rsa_size = RSA_size(PHPC_THIS->ctx);
	if (flen > rsa_size) {
		zend_throw_exception(plc_rsa_exception_ce,
				"The private encryption input is too long",
				PLC_RSA_ERROR_PRIV_ENCRYPT_INPUT_LONG TSRMLS_CC);
		RETURN_NULL();
	}

	PHPC_STR_ALLOC(out, rsa_size);

	dec_len = RSA_private_encrypt(flen,
			(unsigned char *) from, (unsigned char *) PHPC_STR_VAL(out),
			PHPC_THIS->ctx, padding);

	if (dec_len < 0) {
		zend_throw_exception(plc_rsa_exception_ce,
				"The private encryption failed",
				PLC_RSA_ERROR_PRIV_ENCRYPT_FAILED TSRMLS_CC);
		PHPC_STR_RELEASE(out);
		RETURN_NULL();
	}

	if (dec_len < rsa_size) {
		PHPC_STR_REALLOC(out, dec_len);
	}
	PHPC_STR_VAL(out)[dec_len] = '\0';

	PHPC_STR_RETURN(out);

}
/* }}} */

/* {{{ proto string RSA::publicDecrypt($from, $padding = RSA::PADDING_PKCS1) */
PLC_METHOD(RSA, publicDecrypt)
{
	PHPC_THIS_DECLARE(plc_rsa);
	PHPC_STR_DECLARE(out);
	char *from;
	phpc_str_size_t flen;
	int rsa_size, dec_len;
	phpc_long_t padding = RSA_PKCS1_PADDING;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|l",
			&from, &flen, &padding) == FAILURE) {
		return;
	}

	if (plc_rsa_check_padding(padding, 1 TSRMLS_CC) == FAILURE) {
		RETURN_NULL();
	}

	PHPC_THIS_FETCH(plc_rsa);

	rsa_size = RSA_size(PHPC_THIS->ctx);
	if (flen > rsa_size) {
		zend_throw_exception(plc_rsa_exception_ce,
				"The public decryption input is too long",
				PLC_RSA_ERROR_PUB_DECRYPT_INPUT_LONG TSRMLS_CC);
		RETURN_NULL();
	}

	PHPC_STR_ALLOC(out, rsa_size);

	dec_len = RSA_public_decrypt(flen,
			(unsigned char *) from, (unsigned char *) PHPC_STR_VAL(out),
			PHPC_THIS->ctx, padding);

	if (dec_len < 0) {
		zend_throw_exception(plc_rsa_exception_ce,
				"The public decryption failed",
				PLC_RSA_ERROR_PUB_DECRYPT_FAILED TSRMLS_CC);
		PHPC_STR_RELEASE(out);
		RETURN_NULL();
	}

	if (dec_len < rsa_size) {
		PHPC_STR_REALLOC(out, dec_len);
	}
	PHPC_STR_VAL(out)[dec_len] = '\0';

	PHPC_STR_RETURN(out);
}
/* }}} */

/* {{{ proto string RSA::sign($message, $type = RSA::NID_SHA1) */
PLC_METHOD(RSA, sign)
{
	PHPC_THIS_DECLARE(plc_rsa);
	PHPC_STR_DECLARE(sig);
	char *msg;
	phpc_str_size_t msg_len;
	phpc_long_t type = NID_sha1;
	unsigned int sig_len;
	int rsa_size;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|l",
			&msg, &msg_len, &type) == FAILURE) {
		return;
	}

	PHPC_THIS_FETCH(plc_rsa);

	rsa_size = RSA_size(PHPC_THIS->ctx);
	PHPC_STR_ALLOC(sig, rsa_size);

	if (!RSA_sign(type, (unsigned char *) msg, msg_len,
			(unsigned char *) PHPC_STR_VAL(sig), &sig_len, PHPC_THIS->ctx)) {
		zend_throw_exception(plc_rsa_exception_ce,
				"The signing failed",
				PLC_RSA_ERROR_SIGN_FAILED TSRMLS_CC);
		PHPC_STR_RELEASE(sig);
		RETURN_NULL();
	}

	if (sig_len < rsa_size) {
		PHPC_STR_REALLOC(sig, sig_len);
	}
	PHPC_STR_VAL(sig)[sig_len] = '\0';

	PHPC_STR_RETURN(sig);
}
/* }}} */

/* {{{ proto string RSA::verify($message, $signature, $type = RSA::NID_SHA1) */
PLC_METHOD(RSA, verify)
{
	PHPC_THIS_DECLARE(plc_rsa);
	char *msg, *sig;
	phpc_str_size_t msg_len;
	phpc_str_size_t sig_len;
	phpc_long_t type = NID_sha1;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss|l",
			&msg, &msg_len, &sig, &sig_len, &type) == FAILURE) {
		return;
	}

	PHPC_THIS_FETCH(plc_rsa);

	RETURN_BOOL(RSA_verify(type, (unsigned char *) msg, msg_len,
			(unsigned char *) sig, sig_len, PHPC_THIS->ctx));
}
/* }}} */

/* {{{ proto string RSA::export() */
PLC_METHOD(RSA, export)
{
	BIO *bio_mem;
	BUF_MEM *bio_buf;
	PHPC_THIS_DECLARE(plc_rsa);

	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}

	PHPC_THIS_FETCH(plc_rsa);
	bio_mem = BIO_new(BIO_s_mem());
	RSA_print(bio_mem, PHPC_THIS->ctx, 0);
	BIO_get_mem_ptr(bio_mem, &bio_buf);

	PHPC_CSTRL_RETVAL(bio_buf->data, bio_buf->length);

	BIO_free(bio_mem);
}
/* }}} */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
