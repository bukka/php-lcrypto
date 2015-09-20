--TEST--
RSA::getEncoding basic usage.
--SKIPIF--
<?php
if (!extension_loaded('lcrypto'))
	die("Skip: Low-level Crypto extension not loaded");
?>die("Skip: RSA extension not loaded");
?>
--FILE--
<?php
$rsa = new LCrypto\RSA();
var_dump($rsa->getEncoding() === LCrypto\RSA::ENCODING_AUTO);
?>
--EXPECT--
bool(true)
