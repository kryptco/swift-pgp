//
//  PublicKeyToSign.swift
//  PGPFormat
//
//  Created by Alex Grinman on 5/19/17.
//  Copyright © 2017 KryptCo, Inc. All rights reserved.
//

import Foundation

public struct PublicKeyIdentityToSign {
    
    public var publicKey:PublicKey
    public var userID:UserID
    public var created:Date
    
    public func dataToHash(hashAlgorithm:Signature.HashAlgorithm) throws -> Data {
        let bareSignature = Signature(bare: Signature.Kind.positiveUserID, publicKeyAlgorithm: publicKey.algorithm, hashAlgorithm: hashAlgorithm, created: created)
        
        var dataToHash = Data()
        dataToHash.append(contentsOf: [0x99])
        
        // pubkey length + data
        let publicKeyPacketData = try publicKey.toData()
        let pubKeyLengthBytes = UInt32(publicKeyPacketData.count).twoByteBigEndianBytes()
        dataToHash.append(contentsOf: pubKeyLengthBytes)
        dataToHash.append(publicKeyPacketData)
        
        // userid byte, length + data
        let userIdPacketData = try userID.toData()
        let userIdLengthBytes = UInt32(userIdPacketData.count).fourByteBigEndianBytes()
        dataToHash.append(contentsOf: [0xB4])
        dataToHash.append(contentsOf: userIdLengthBytes)
        dataToHash.append(userIdPacketData)
        
        // add signature data
        let signatureData = try bareSignature.signedData()
        dataToHash.append(signatureData)
        
        // trailer
        dataToHash.append(contentsOf: [UInt8(bareSignature.supportedVersion)])
        dataToHash.append(contentsOf: [0xFF])
        dataToHash.append(contentsOf: UInt32(signatureData.count).fourByteBigEndianBytes())

        return dataToHash
    }
    
    public func signedPublicKey(hash:Data, hashAlgorithm:Signature.HashAlgorithm, signatureData:Data) throws -> SignedPublicKeyIdentity {
        var bareSignature = Signature(bare: Signature.Kind.positiveUserID, publicKeyAlgorithm: publicKey.algorithm, hashAlgorithm: hashAlgorithm, created: created)
        
        bareSignature.unhashedSubpacketables = try [SignatureIssuer(keyID: publicKey.keyID())]
        
        guard hash.count >= 2 else {
            throw PublicKeyIdentitySiginingError.invalidHashLength(hash.count)
        }
        
        bareSignature.leftTwoHashBytes = [UInt8](hash.bytes[0...1])
        bareSignature.signature = signatureData
        
        return SignedPublicKeyIdentity(publicKey: publicKey, userID: userID, signature: bareSignature)
    }
}

public enum PublicKeyIdentitySiginingError:Error {
    case invalidHashLength(Int)
}
public struct SignedPublicKeyIdentity {
    public var publicKey:PublicKey
    public var userID:UserID
    public var signature:Signature
}
