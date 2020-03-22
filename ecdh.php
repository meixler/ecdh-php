<?php
/*
# Elliptic Curve Diffie Hellman (ECDH) Implementation in PHP
A port of [Andrea Corbellini's](https://andrea.corbellini.name/) python [ECDHE and ECDSA implementations](https://github.com/andreacorbellini/ecc/tree/master/scripts) from python to PHP.  Includes functions for ECDH key generation, ECDHE key exchange, and ECDSA signing and verification.

# Requirements
The script has been tested with PHP 7.2.  [GMP](https://www.php.net/manual/en/book.gmp.php) for PHP is required (for working with large integers).  See [https://www.php.net/manual/en/book.gmp.php](https://www.php.net/manual/en/book.gmp.php) for more information, including installation instructions.  This [page on Stackoverflow](https://stackoverflow.com/questions/40010197/how-to-install-gmp-for-php7-on-ubuntu/40010211#40010211) is also helpful.

# Usage
Simply copy ecdh.php to your web server, and point your browser to the URL for ecdh.php.  It should produce output similar to that shown in output.html.

# License
This project is licensed under the [MIT open source license](https://opensource.org/licenses/MIT).

# GitHub
https://github.com/meixler/ecdh-php
*/

$curve=new stdClass();
$curve->name='P-256';
$curve->p=gmp_init('0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff');
$curve->a=gmp_init(-3);
$curve->b=gmp_init('0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b');
$curve->g=array(gmp_init('0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296'), gmp_init('0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5'));
$curve->n=gmp_init('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551');
$curve->h=gmp_init(1);

function is_on_curve($point) {
	global $curve;

	if(is_null($point)) { return True; }
	list($x, $y)=$point;
	if(gmp_cmp(gmp_mod(gmp_sub(gmp_sub(gmp_sub(gmp_pow($y, 2), gmp_pow($x, 3)), gmp_mul($curve->a, $x)), $curve->b) ,$curve->p), 0)==0) { return True; } else {return False; }
}

function point_neg($point) {
	global $curve;
	assert(is_on_curve($point));

	if(is_null($point)) { return null; }
	list($x, $y)=$point;
	$result=array($x, gmp_mod(gmp_neg($y), $curve->p));

	assert(is_on_curve($result));
	return $result;
}

function point_add($point1, $point2) {
	global $curve;
	assert(is_on_curve($point1));
	assert(is_on_curve($point1));

	if(is_null($point1)) { return $point2; }
	if(is_null($point2)) { return $point1; }

	list($x1, $y1)=$point1;
	list($x2, $y2)=$point2;		

	if(gmp_cmp($x1, $x2)==0 && gmp_cmp($y1, $y2)!=0) { return null; }

	if(gmp_cmp($x1, $x2)==0) { 
		$m=gmp_mul(gmp_add(gmp_mul(3, gmp_pow($x1, 2)), $curve->a), gmp_invert(gmp_mul(2, $y1), $curve->p));
	} else {
		$m=gmp_mul(gmp_sub($y1, $y2), gmp_invert(gmp_sub($x1, $x2), $curve->p));
	}

	$x3=gmp_sub(gmp_sub(gmp_pow($m, 2), $x1), $x2);
	$y3=gmp_add($y1, gmp_mul($m, gmp_sub($x3, $x1)));
	$result=array(gmp_mod($x3, $curve->p), gmp_mod(gmp_neg($y3), $curve->p));

	assert(is_on_curve($result));
	return $result;
}

function scalar_mult($k, $point) {
	global $curve;
	assert(is_on_curve($point));

	if(gmp_cmp($k, 0)<0) { return scalar_mult(gmp_neg($k), point_neg($point)); }

	$result=null;
	$addend=$point;

	while(gmp_cmp($k, 0)>0) {
		if(gmp_cmp(gmp_mod($k, 2), 1)==0) { $result=point_add($result, $addend); }
		$addend=point_add($addend, $addend);

		$k=gmp_div_q($k, 2);
	}

	assert(is_on_curve($result));
	return $result;
}

function sign_message($private_key, $messagehashhex) {
	global $curve;
	$z=gmp_init('0x' . $messagehashhex);
	$r=gmp_init(0);
	$s=gmp_init(0);
	
	while(gmp_cmp($r, 0)==0 || gmp_cmp($s, 0)==0) {
		$k=gmp_random_range(1, $curve->n);	
		list($x, $y)=scalar_mult($k, $curve->g);
		$r=gmp_mod($x, $curve->n);
		$s=gmp_mod(gmp_mul(gmp_add($z, gmp_mul($r, $private_key)), gmp_invert($k, $curve->n)), $curve->n);
	}	
	return array($r, $s);
}

function verify_signature($public_key, $messagehashhex, $signature) {
	global $curve;
	$z=gmp_init('0x' . $messagehashhex);
	list($r, $s)=$signature;
	$w=gmp_invert($s, $curve->n);	
	$u1=gmp_mod(gmp_mul($z, $w), $curve->n);
	$u2=gmp_mod(gmp_mul($r, $w), $curve->n);
    	list($x, $y)=point_add(scalar_mult($u1, $curve->g), scalar_mult($u2, $public_key));		
	if(gmp_cmp(gmp_mod($r, $curve->n), gmp_mod($x, $curve->n))==0) { return True; } else { return False; }
}

?>
<!DOCTYPE html>
<html lang="en">
	<head>
		<meta charset="utf-8">
		<title>Elliptic Curve Diffie Hellman (ECDH) Implementation in PHP</title>
	</head>
	<style>
		body {
	  		font-family: 'Helvetica', 'Arial', 'sans-serif'; 
			color: black;
			font-size: 11pt;		
		}
	</style>
	<body>
		<h1>Elliptic Curve Diffie Hellman (ECDH) Implementation in PHP</h1>
		<p>
		A port of <a href='https://andrea.corbellini.name/'>Andrea Corbellini's</a> python <a href='https://github.com/andreacorbellini/ecc/tree/master/scripts'>ECDHE and ECDSA implementations</a> from python to PHP.  
		Includes functions for ECDH key generation, ECDHE key exchange, and ECDSA signing and verification.<BR>
		</p>
		
		<p>
		<u>License</u><BR>
		This project is licensed under the <a href='https://opensource.org/licenses/MIT'>MIT open source license</a>.
		</p>
		
		<p>
		<u>GitHub</u><BR>
		<a href='https://github.com/meixler/ecdh-php'>https://github.com/meixler/ecdh-php</a>
		</p>

		<hr>
		<h2>ECDHE</h2>
		<?php
			print('Curve: ' . $curve->name . "<BR>\n");

			//Alice generates her own keypair.
			$alice_private_key=gmp_init('0x' . bin2hex(random_bytes(32)));
			$alice_public_key=scalar_mult($alice_private_key, $curve->g);
			list($alice_public_key_x, $alice_public_key_y)=$alice_public_key;
			print("Alice's private key: " . bin2hex(gmp_export($alice_private_key)) . "<BR>\n");
			print("Alice's public key: " . bin2hex(gmp_export($alice_public_key_x)) . ', ' . bin2hex(gmp_export($alice_public_key_y)) . "<BR>\n");
			print("<BR>\n");

			//Bob generates his own keypair.
			$bob_private_key=gmp_init('0x' . bin2hex(random_bytes(32)));
			$bob_public_key=scalar_mult($bob_private_key, $curve->g);
			list($bob_public_key_x, $bob_public_key_y)=$bob_public_key;
			print("Bob's private key: " . bin2hex(gmp_export($bob_private_key)) . "<BR>\n");
			print("Bob's public key: " . bin2hex(gmp_export($bob_public_key_x)) . ', ' . bin2hex(gmp_export($bob_public_key_y)) . "<BR>\n");
			print("<BR>\n");

			//Alice and Bob exchange their public keys and calculate the shared secret.
			$alice_shared_secret=scalar_mult($alice_private_key, $bob_public_key);
			$bob_shared_secret=scalar_mult($bob_private_key, $alice_public_key);
			list($alice_shared_secret_x, $alice_shared_secret_y)=$alice_shared_secret;
			list($bob_shared_secret_x, $bob_shared_secret_y)=$bob_shared_secret;
			print("Alice's shared secret: " . bin2hex(gmp_export($alice_shared_secret_x)) . ', ' . bin2hex(gmp_export($alice_shared_secret_y)) . "<BR>\n");
			print("Bob's shared secret: " . bin2hex(gmp_export($bob_shared_secret_x)) . ', ' . bin2hex(gmp_export($bob_shared_secret_y)) . "<BR>\n");
		?>
		<hr>
		<h2>ECDSA</h2>
		<?php
			print('Curve: ' . $curve->name . "<BR>\n");
			$private_key=gmp_init('0x' . bin2hex(random_bytes(32)));
			$public_key=scalar_mult($private_key, $curve->g);
			list($public_key_x, $public_key_y)=$public_key;
			print("Private key: " . bin2hex(gmp_export($private_key)) . "<BR>\n");
			print("Public key: " . bin2hex(gmp_export($public_key_x)) . ', ' . bin2hex(gmp_export($public_key_y)) . "<BR>\n");
			
			$msg=utf8_decode('Hello!');
			$signature = sign_message($private_key, hash('sha256', $msg));
			list($signature_r, $signature_s)=$signature;
			print("<BR>\n");
			print('Message: ' . $msg . "<BR>\n");
			print('Signature: ' . bin2hex(gmp_export($signature_r)) . ', ' . bin2hex(gmp_export($signature_s)) . "<BR>\n");
			print('Verification: ' . (int)verify_signature($public_key, hash('sha256', $msg), $signature) . "<BR>\n");

			$msg=utf8_decode('Hi there!');
			print("<BR>\n");
			print('Message: ' . $msg . "<BR>\n");
			print('Verification: ' . (int)verify_signature($public_key, hash('sha256', $msg), $signature) . "<BR>\n");

			$private_key=gmp_init('0x' . bin2hex(random_bytes(32)));
			$public_key=scalar_mult($private_key, $curve->g);
			list($public_key_x, $public_key_y)=$public_key;

			$msg=utf8_decode('Hello!');
			print("<BR>\n");
			print('Message: ' . $msg . "<BR>\n");
			print("Public key: " . bin2hex(gmp_export($public_key_x)) . ', ' . bin2hex(gmp_export($public_key_y)) . "<BR>\n");
			print('Verification: ' . (int)verify_signature($public_key, hash('sha256', $msg), $signature) . "<BR>\n");
		?>
	</body>
</html>	

