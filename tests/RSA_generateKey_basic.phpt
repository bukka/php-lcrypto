--TEST--
RSA::generateKey basic usage.
--SKIPIF--
<?php
if (!extension_loaded('lcrypto'))
	die("Skip: Low-level Crypto extension not loaded");
?>
--FILE--
<?php
$rsa = new LCrypto\RSA();
try {
	$rsa->generateKey(LCrypto\RSA::MAX_MODULE_SIZE + 1, 65537);
} catch (LCrypto\RSAException $e) {
	echo $e->getCode() === LCrypto\RSAException::KEY_GENERATION_BITS_HIGH ? "BITS HIGH\n" : "BAD CODE\n";
}

$rsa->generateKey(1024, 65537);

$rsa->setEncoding(LCrypto\RSA::ENCODING_HEX);
var_dump($rsa->getKey());
var_dump($rsa->getFactors());

?>
--EXPECTF--
BITS HIGH
array(3) {
  ["n"]=>
  string(%d) "%s"
  ["e"]=>
  string(6) "010001"
  ["d"]=>
  string(%d) "%s"
}
array(2) {
  ["p"]=>
  string(%d) "%s"
  ["q"]=>
  string(%d) "%s"
}
