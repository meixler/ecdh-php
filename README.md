# Elliptic Curve Diffie Hellman (ECDH) Implementation in PHP
A port of [Andrea Corbellini's](https://andrea.corbellini.name/) python [ECDHE and ECDSA implementations](https://github.com/andreacorbellini/ecc/tree/master/scripts) from python to PHP.  Includes functions for ECDH key generation, ECDHE key exchange, and ECDSA signing and verification.

# Requirements
The script has been tested with PHP 7.2.  [GMP](https://www.php.net/manual/en/book.gmp.php) for PHP is required (for working with large integers).  See [https://www.php.net/manual/en/book.gmp.php](https://www.php.net/manual/en/book.gmp.php) for more information, including installation instructions.  This [page on Stackoverflow](https://stackoverflow.com/questions/40010197/how-to-install-gmp-for-php7-on-ubuntu/40010211#40010211) is also helpful.

# Usage
Simply copy ecdh.php to your web server, and point your browser to the URL for ecdh.php.  It should produce output similar to that shown in output.html.

# License
This project is licensed under the [MIT open source license](https://opensource.org/licenses/MIT).

