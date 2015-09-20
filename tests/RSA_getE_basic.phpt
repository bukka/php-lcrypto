--TEST--
RSA::setE basic usage.
--SKIPIF--
<?php
if (!extension_loaded('lcrypto'))
	die("Skip: Low-level Crypto extension not loaded");
?>
--FILE--
<?php
$rsa = new LCrypto\RSA();
$rsa->setE("0x10001");
var_dump($rsa->getE(LCrypto\RSA::ENCODING_HEX));
var_dump($rsa->getE(LCrypto\RSA::ENCODING_DEC));
?>
--EXPECT--
string(6) "010001"
string(5) "65537"
