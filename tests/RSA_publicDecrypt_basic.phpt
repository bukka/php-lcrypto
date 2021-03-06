--TEST--
RSA::publicDecrypt basic usage.
--SKIPIF--
<?php
if (!extension_loaded('lcrypto'))
	die("Skip: Low-level Crypto extension not loaded");
?>
--FILE--
<?php
require_once dirname(__FILE__) . "/rsa_keys.inc";

list($rsa1, $ctext1_ex) = rsa_test_key1();
list($rsa2, $ctext2_ex) = rsa_test_key2();
list($rsa3, $ctext3_ex) = rsa_test_key3();

// test exceptions
try {
	$rsa1->publicDecrypt(str_repeat('x', 1024));
} catch (LCrypto\RSAException $e) {
	echo $e->getCode() === LCrypto\RSAException::PUB_DECRYPT_INPUT_LONG ? "INPUT LONG\n" : "BAD CODE\n";
}

$ptext_ex = pack("H*" , "54859b342c49ea2a");

// test padding exception
try {
	$rsa1->publicDecrypt($ctext1_ex, LCrypto\RSA::PADDING_OAEP);
} catch (LCrypto\RSAException $e) {
	echo $e->getCode() === LCrypto\RSAException::INVALID_PADDING ? "INVALID PADDING\n" : "BAD CODE\n";
}

// key 1 test
function rsa_test_public_crypt($i, $rsa, $ptext_ex, $ctext_ex) {
	$ctext1_pkcs1_1_5 = $rsa->privateEncrypt($ptext_ex, LCrypto\RSA::PADDING_PKCS1);

	if (strlen($ctext1_pkcs1_1_5) !== strlen($ctext_ex)) {
		echo "KEY $i: PKCS#1 v1.5 encryption failed\n";
	}

	$ptext1_pkcs1_1_5 = $rsa->publicDecrypt($ctext1_pkcs1_1_5, LCrypto\RSA::PADDING_PKCS1);
	if ($ptext1_pkcs1_1_5 === $ptext_ex) {
		echo "KEY $i: PKCS#1 v1.5 decryption ok\n";
	} else {
		echo "KEY $i: PKCS#1 v1.5 decryption failed\n";
	}
}

rsa_test_public_crypt(1, $rsa1, $ptext_ex, $ctext1_ex);
rsa_test_public_crypt(2, $rsa2, $ptext_ex, $ctext2_ex);
rsa_test_public_crypt(3, $rsa3, $ptext_ex, $ctext3_ex);

?>
--EXPECT--
INPUT LONG
INVALID PADDING
KEY 1: PKCS#1 v1.5 decryption ok
KEY 2: PKCS#1 v1.5 decryption ok
KEY 3: PKCS#1 v1.5 decryption ok
