//
//  PublicKeyToSign.swift
//  PGPFormat
//
//  Created by Alex Grinman on 5/19/17.
//  Copyright © 2017 KryptCo, Inc. All rights reserved.
//

import Foundation

public struct SignedPublicKeyIdentity:Signable {
    
    public var publicKey:PublicKey
    public var userID:UserID
    public var signature:Signature
    
    public init(publicKey:PublicKey, userID:UserID, hashAlgorithm:Signature.HashAlgorithm, hashedSubpacketables:[SignatureSubpacketable] = []) throws {
        self.publicKey  = publicKey
        self.userID     = userID
        
        self.signature = Signature(bare: Signature.Kind.positiveUserID, publicKeyAlgorithm: publicKey.algorithm, hashAlgorithm: hashAlgorithm, hashedSubpacketables: hashedSubpacketables)
        
        self.signature.unhashedSubpacketables = try [SignatureIssuer(keyID: publicKey.keyID())]

    }
    
    public func signableData() throws -> Data {
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
        
        return dataToHash
    }
    
    public func toPackets() throws -> [Packet] {
        return try [publicKey.toPacket(), userID.toPacket(), signature.toPacket()]
    }
}
