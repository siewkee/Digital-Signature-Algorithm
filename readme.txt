# Digital Signature Algorithm

This program accepts a file as an input, and it should produce sig.txt, which is a signature on the input file. 

This program is also able to verify the input file and the signature in sig.txt and this should return True. Otherwise, return False.

Algorithm:

= Key Generation Public Key
	> p = 512 - 1024 bit prime
	> q = 160 bit prime factor of p - 1
	> g = h^(p-1)/q mod p
	> y = g^x mod p

= Key Generation Private key
	> x < q (160 bit)

= Message Signing
	> random k, < q
	> r (signature) = (g^k mod p) mod q
	> H(m) = SHA1 message
	> s (signature) = (k^-1(H(m) + xr)) mod q

= Signature Verification
	> w = s^-1
	> u1 = (H(m) * w) mod q
	> u2 = (rw) mod q
	> v = ((g^u1 * y^u2) mod p) mod q
	> if v = r = true, else false








