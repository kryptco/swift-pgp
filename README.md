# swift-pgp
A pure<sup>1</sup> Swift library for parsing and creating PGP [RFC 4880](https://tools.ietf.org/html/rfc4880)  public keys, user ids, and signatures. This library is designed to be public-key-cryptography-implementation-agnostic. That is, you can use swift-pgp with any public-key crypto implementation you choose, provided it is either an RSA or Ed25519 cryptosystem.

> **1**. Except for SHA hash functions from CommonCrypto.

# Created For Kryptonite 
<a href="https://krypt.co"><img src="https://krypt.co/static/dist/img/kryptonite-logo-green-on-white.svg" width="200"/> </a> 
This library was created for __Kryptonite__. For more information, check out [krypt.co](https://krypt.co).

# Supported Features
Currently, swift-pgp only signatures for certifications and binary documents, but it's abstracted to support the full RFC 4880 spec, see the next section for whats in the pipeline.

- Public Keys: parse and create PGP public keys
    [ x ] RSA
    [ x ] Ed25519 (via ext. [eddsa draft](https://tools.ietf.org/html/draft-koch-eddsa-for-openpgp-00))
    
- Signatures: parse and create PGP Signatures
    [ x ] Certify Public Key <> User ID binding (aka Certification Signatures)
    [ x ] Binary Documents 

 - ASCII Armor: parse and create ASCII armored PGP messages

# Coming Soon
The next phase of swift-pgp is to support formatting PGP encrypted messages. This will add support for parsing and creating structures like:

 [ ] Symmetric-Key Encrypted Session Keys
 [ ] Symmetrically Encrypted Data
 
# How to use swift-pgp
Create signatures with swift-pgp by utilizing the `Signable` interface. The `Signable` interface is what makes the swift-pgp library public-key-cryptography-implementation-agnostic.

```swift
    /**
        Represents a structure that can be signed
    */
    public protocol Signable {
        var signature:Signature { get set }
        func signableData() throws -> Data
    }
```

The `Signable` interface is extended to provide two useful functions
 - `func dataToHash() throws -> Data`
 - `mutating func set(hash:Data, signedHash:Data) throws`
 
This lets you initialize a signable, extract the data that needs to be hashed via `dataToHash()`, hash it, sign it, and then set the hash and signature via `set(hash:Data, signedHash:Data)`. The `dataToHash()` function can also be used to extract the data that needs to be hashed to verify signatures.

Currently, there are only two types of Signables: `SignedPublicKeyIdentity` and `SignedBinaryDocument`.

# Examples
Below are a few examples for creating certification and binary document signatures.

## `SignedPublicKeyIdentity`
A Public Key <> User ID binding certification.

```swift
// initialize a public key
let publicKeyData = RSAPublicKey(modulus: ..., exponent: ...)
let publicKey = try PublicKey(create: .rsaSignOnly, publicKeyData: publicKeyData, date: Date())

// initialize a user id
let userID = UserID(name: "Alex Grinman", email: "hello@krypt.co")

// initialize the signed public key
var signedPublicKey = try SignedPublicKeyIdentity(publicKey: publicKey, userID: userID, hashAlgorithm: .sha512)

// extract the data to hash and sign, sign it, and set it on the signedPublicKey
let dataToHash = try signedPublicKey.dataToHash()
let hash = H(dataToHash) // where H is your chosen (i.e. sha512) hash implementation
let signatureData = X(dataToHash) // where X is your chosen RSA sign implementation

try signedPublicKey.set(hash: hash, signedHash: signatureData)

// get the ASCII armored message
let asciiMessage = try signedPublicKey.armoredMessage(blockType: .publicKey, comment: "created with swift-pgp")
```


> **Multiple UserIDs** often certifications need to say that several User IDs are binded to a public key. swift-pgp provides a helper struct for this called `SignedPublicKeyIdentities` that is initialized with an list of `SignedPublicKeyIdentity`s.

## `SignedBinaryDocument`
A signature for a binary document.

```swift
// the bytes of the document being signed, i.e. 0xDEADBEEF
let binaryData = Data(bytes: [0xDE, 0xAD, 0xBE, 0xEF])

var signedBinary = SignedBinaryDocument(binary: binaryData, publicKeyAlgorithm: .rsaSignOnly, hashAlgorithm: .sha512)

// extract the data to hash and sign, sign it, and set it on the signedPublicKey
let dataToHash = try signedBinary.dataToHash()
let hash = H(dataToHash) // where H is your chosen (i.e. sha512) hash implementation
let signatureData = X(dataToHash) // where X is your chosen RSA sign implementation

// compile the signed public key packets
try signedBinary.set(hash: hash, signedHash: signatureData)

// return ascii armored signature
let asciiMessage = try signedBinary.set(blockType: .signature, comment: "created with swift-pgp")
```

# License
We are currently deciding on a license for swift-pgp.
For now, the code is released under All Rights Reserved.
