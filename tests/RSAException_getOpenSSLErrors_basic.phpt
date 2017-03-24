--TEST--
LCrypto\RSAException::getOpenSSLErrors basic usage.
--SKIPIF--
<?php
if (!extension_loaded('lcrypto'))
	die("Skip: Low-level Crypto extension not loaded");
?>
--FILE--
<?php

$params = array(
	'n' => "0x" .
		"00A3079A90DF0DFD72AC090CCC2A78B8" .
		"7413133E40759C98FAF8204F358A0B26" .
		"3C6770E783A93B6971B73779D2717BE8" .
		"34770F",

	'e' => "0x3",

	'd' => "0x" .
		"6CAFBC6094B3FE4C72B0B332C6FB25A2" .
		"B76229804E6865FCA45A74DF0F8FB841" .
		"3B52C0D0E53D9B590FF19BE79F49DD21" .
		"E5EB",

	'p' => "0x" .
		"00CF2035028B9D869840B41666B42E92" .
		"EA0DA3B43204B5CFCE91",

	'q' => "0x" .
		"00C97FB1F027F453F6341233EAAAD1D9" .
		"353F6C42D08866B1D05F",
);

$rsa = new LCrypto\RSA();
$rsa->setKey($params['n'], $params['e'], $params['d']);
$rsa->setFactors($params['p'], $params['q']);

// test exceptions
try {
	$rsa->publicDecrypt(str_repeat('x', 32));
} catch (LCrypto\RSAException $e) {
	print_r($e->getOpenSSLErrors());
}

?>
--EXPECT--
