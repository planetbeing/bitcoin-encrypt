bitcoin-encrypt
===============
Elliptic Curve Integrated Encryption Scheme implementation tailored for
bitcoin. It should allow anyone to send messages that only the owner of a
specific bitcoin address can read. The public key of the bitcoin address must
be known. Either it must have appeared on the blockchain (through a spend, for
example), or it can be derived from any signed message from the owner of the
address.

This code is provided for entertainment and educational purposes only.


Algorithm
---------
ECIES as described at
[Wikipedia](http://en.wikipedia.org/wiki/Integrated_Encryption_Scheme) using a
variation of ANSI-X9.63-KDF that uses SHA-256 instead of SHA-1 and HMAC-SHA-256
as the MAC. The symmetric encryption used is AES-256-CTR with a randomly
generated 64-bit prefix.


Usage
-----
Don't.


License
-------
MIT License.
