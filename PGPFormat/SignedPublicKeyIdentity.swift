//
//  PublicKeyToSign.swift
//  PGPFormat
//
//  Created by Alex Grinman on 5/19/17.
//  Copyright © 2017 KryptCo, Inc. All rights reserved.
//

import Foundation

/**
    A signed public key identity
    A list of packets: public key, user id, signatures
 */
public struct SignedPublicKeyIdentity:Signable, Messagable {
    
    public let publicKey:PublicKey
    public let userID:UserID
    public var signature:Signature
    
    public init(publicKey:PublicKey, userID:UserID, hashAlgorithm:Signature.HashAlgorithm, hashedSubpacketables:[SignatureSubpacketable] = []) throws {
        self.publicKey  = publicKey
        self.userID     = userID
        
        self.signature = Signature(bare: Signature.Kind.positiveUserID, publicKeyAlgorithm: publicKey.algorithm, hashAlgorithm: hashAlgorithm, hashedSubpacketables: hashedSubpacketables)
        
        self.signature.unhashedSubpacketables = try [SignatureIssuer(keyID: publicKey.keyID())]

    }
    
    public func signableData() -> Data {
        var dataToHash = Data()
        dataToHash.append(contentsOf: [0x99])
        
        // pubkey length + data
        let publicKeyPacketData = publicKey.toData()
        let pubKeyLengthBytes = UInt32(publicKeyPacketData.count).twoByteBigEndianBytes()
        dataToHash.append(contentsOf: pubKeyLengthBytes)
        dataToHash.append(publicKeyPacketData)
        
        // userid byte, length + data
        let userIdPacketData = userID.toData()
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

/**
    A list of signed public key identites
 */
public struct SignedPublicKeyIdentities:Messagable {
    let signedPublicKeys:[SignedPublicKeyIdentity]
    
    public init(_ signedIdentities:[SignedPublicKeyIdentity]) {
        self.signedPublicKeys = signedIdentities
    }
    
    public func toPackets() throws -> [Packet] {
        var packets = [Packet]()
        
        if let first = signedPublicKeys.first {
            try packets.append(first.publicKey.toPacket())
        }
        
        try signedPublicKeys.forEach {
            try packets.append(contentsOf: [$0.userID.toPacket(), $0.signature.toPacket()])
        }
        
        return packets
    }
}
