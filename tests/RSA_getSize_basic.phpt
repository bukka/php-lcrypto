--TEST--
RSA::getSize basic usage.
--SKIPIF--
<?php
if (!extension_loaded('lcrypto'))
	die("Skip: Low-level Crypto extension not loaded");
?>
--FILE--
<?php
$rsa = new LCrypto\RSA();
$rsa->generateKey(1024, 65537);

var_dump($rsa->getSize());

?>
--EXPECTF--
int(128)
