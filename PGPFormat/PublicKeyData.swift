//
//  PublicKeyData.swift
//  PGPFormat
//
//  Created by Alex Grinman on 6/3/17.
//  Copyright © 2017 KryptCo, Inc. All rights reserved.
//

import Foundation

/**
    Represents a public key data structure
 */
public protocol PublicKeyData {
    func toData() -> Data
}

/**
    The RSA public key data structure
 */
public struct RSAPublicKey:PublicKeyData{
    public let modulus:Data
    public let exponent:Data
    
    public init(modulus:Data, exponent:Data) {
        self.modulus = modulus
        self.exponent = exponent
    }
    
    public func toData() -> Data {
        var data = Data()
        
        // modulus:  MPI two-octet scalar length then modulus
        data.append(contentsOf: UInt32(modulus.numBits).twoByteBigEndianBytes())
        data.append(modulus)
        
        // exponent:  MPI two-octet scalar length then exponent
        data.append(contentsOf: UInt32(exponent.numBits).twoByteBigEndianBytes())
        data.append(exponent)
        
        return data
    }
}

/**
    The Ed25519 public key data structure
    https://tools.ietf.org/html/draft-koch-eddsa-for-openpgp-00
 */
public struct Ed25519PublicKey:PublicKeyData {
    public var rawData:Data
    
    /**
        Ed25519 constants: 
            - prefix byte
            - curve OID
     */
    public struct Constants {
        public static let prefixByte:UInt8 = 0x40
        public static let curveOID:[UInt8] = [0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01]
    }
    
    public init(rawData:Data) {
        self.rawData = rawData
    }
    
    public func toData() -> Data {
        var data = Data()
        data.append(contentsOf: [UInt8(Constants.curveOID.count)] + Constants.curveOID)
        
        let prefixedRawData = Data(bytes: [Constants.prefixByte] + rawData.bytes)
        
        data.append(contentsOf: UInt32(prefixedRawData.numBits).twoByteBigEndianBytes())
        data.append(prefixedRawData)
        
        return data
    }
}
