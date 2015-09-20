--TEST--
RSA::setEncoding basic usage.
--SKIPIF--
<?php
if (!extension_loaded('lcrypto'))
	die("Skip: Low-level Crypto extension not loaded");
?>
--FILE--
<?php
$rsa = new LCrypto\RSA();
$rsa->setEncoding(LCrypto\RSA::ENCODING_DEC);
var_dump($rsa->getEncoding() === LCrypto\RSA::ENCODING_DEC);
?>
--EXPECT--
bool(true)
