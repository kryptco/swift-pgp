# swift-pgp
A PGP [RFC 4880](https://tools.ietf.org/html/rfc4880) library written purely in Swift<sup>1</sup>, that currently only formats (serializes and deserializes) PGP signatures, public keys, and UserIDs. This library is public-key-cryptography-implementation-agnostic. That is, you can use swift-pgp with any public-key crypto implementation you want, provided it is either an RSA or  Ed25519 cryptosystem. swift-pgp only helps to format signatures and signed public key identities according
the PGP RFC 4880 spec.

> 1: Except for SHA hash functions from CommonCrypto.

# License
We are currently working on a new license for Kryptonite. For now, the code
is released under All Rights Reserved.
