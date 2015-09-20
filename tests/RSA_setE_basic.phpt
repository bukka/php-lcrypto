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
try {
	$rsa->setE("1000i", LCrypto\RSA::ENCODING_HEX);
} catch (LCrypto\RSAException $e) {
	echo $e->getCode() === LCrypto\RSAException::INVALID_HEX_ENCODING ? "INVALID HEX\n" : "BAD CODE\n";
}

try {
	$rsa->setE("1000d");
} catch (LCrypto\RSAException $e) {
	echo $e->getCode() === LCrypto\RSAException::INVALID_DEC_ENCODING ? "INVALID DEC\n" : "BAD CODE\n";
}

$rsa->setE("10001");
$rsa->setE(65537);
echo "SUCCESS\n";
?>
--EXPECT--
INVALID HEX
INVALID DEC
SUCCESS
