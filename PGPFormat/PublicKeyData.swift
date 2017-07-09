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
    init(mpintData:Data) throws
    func toData() -> Data
}

/**
    The RSA public key data structure
 */
public struct RSAPublicKey:PublicKeyData{
    public let modulus:MPInt
    public let exponent:MPInt
    
    public init(modulus:Data, exponent:Data) {
        self.modulus = MPInt(integerData: modulus)
        self.exponent = MPInt(integerData: exponent)
    }
    
    public init(mpintData: Data) throws {
        let bytes = mpintData.bytes
        
        var start = 0
        
        self.modulus = try MPInt(mpintData: Data(bytes: bytes[start ..< bytes.count]))
        start += modulus.byteLength
        
        guard bytes.count >= start else {
            throw DataError.tooShort(bytes.count)
        }
        
        self.exponent = try MPInt(mpintData: Data(bytes: bytes[start ..< bytes.count]))
    }
    
    public func toData() -> Data {
        var data = Data()
        
        // modulus:  MPI two-octet scalar length then modulus
        data.append(contentsOf: modulus.lengthBytes)
        data.append(modulus.data)
        
        // exponent:  MPI two-octet scalar length then exponent
        data.append(contentsOf: exponent.lengthBytes)
        data.append(exponent.data)
        
        return data
    }
}

/**
    The Ed25519 public key data structure
    https://tools.ietf.org/html/draft-koch-eddsa-for-openpgp-00
 */

public struct Ed25519PublicKey:PublicKeyData {
    
    var rawData:Data
    
    enum ParsingError:Error {
        case missingECCPrefixByte
        case badECCCurveOIDLength(UInt8)
        case unsupportedECCCurveOID(Data)
    }
    
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
    
    public init(mpintData:Data) throws {
        
        let bytes = mpintData.bytes
        
        guard bytes.count >= 1 + Constants.curveOID.count else {
            throw DataError.tooShort(bytes.count)
        }

        var start = 0
        guard Int(bytes[start]) == Constants.curveOID.count else {
            throw ParsingError.badECCCurveOIDLength(bytes[start])
        }
        
        start += 1
        
        let curveOID = [UInt8](bytes[start ..< start + Constants.curveOID.count])
        guard curveOID == Constants.curveOID else {
            throw ParsingError.unsupportedECCCurveOID(Data(bytes: curveOID))
        }
        
        start += Constants.curveOID.count
        
        guard bytes.count > start else {
            throw DataError.tooShort(bytes.count)
        }
        
        let mpintBytes = try MPInt(mpintData: Data(bytes: bytes[start ..< bytes.count])).data.bytes
        
        guard mpintBytes.first == Constants.prefixByte else {
            throw ParsingError.missingECCPrefixByte
        }
        
        guard mpintBytes.count > 1 else {
            throw DataError.tooShort(mpintBytes.count)
        }
        
        self.rawData = Data(bytes: mpintBytes[1 ..< mpintBytes.count])
    }
    
    
    public func toData() -> Data {
        var data = Data()
        data.append(contentsOf: [UInt8(Constants.curveOID.count)] + Constants.curveOID)
        
        let mpint = MPInt(integerData: Data(bytes: [Constants.prefixByte] + rawData.bytes))
        
        data.append(contentsOf: mpint.lengthBytes)
        data.append(mpint.data)
        
        return data
    }
}
