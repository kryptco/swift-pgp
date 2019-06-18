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
        
        self.modulus = try MPInt(mpintData: Data(bytes[start ..< bytes.count]))
        start += modulus.byteLength
        
        guard bytes.count >= start else {
            throw DataError.tooShort(bytes.count)
        }
        
        self.exponent = try MPInt(mpintData: Data(bytes[start ..< bytes.count]))
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
    The ECC public key data structure
        - supports Ed25519: https://tools.ietf.org/html/draft-koch-eddsa-for-openpgp-00
        - supports ECDSA (nistP256):  https://tools.ietf.org/html/rfc6637
 */

public struct ECPublicKey:PublicKeyData {
    
    let curve:Curve
    let rawData:Data
    
    enum ParsingError:Error {
        case invalidOrMissingECCPrefixByte
        case badECCCurveOIDLength(UInt8)
        case unsupportedECCCurveOID([UInt8])
    }
    
    public enum Curve {
        case ed25519
        case nistP256
        
        static var supported:[Curve] {
            return [.ed25519, .nistP256]
        }
        
        var prefixByte:UInt8 {
            switch self {
            case .ed25519:
                return 0x40
            case .nistP256:
                return 0x04
            }
        }
        
        var oid:[UInt8] {
            switch self {
            case .ed25519:
                return [0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01]
            case .nistP256:
                return [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]
            }
        }
        
        init?(oid:[UInt8]) {
            for curve in Curve.supported {
                if curve.oid == oid {
                    self = curve
                    return
                }
            }
            
            return nil
        }
    }

    public init(curve:Curve, rawData:Data) {
        self.curve = curve
        self.rawData = rawData
    }
    
    public init(curve:Curve, prefixedRawData:Data) throws {
        guard prefixedRawData.count >= 1 else {
            throw DataError.tooShort(prefixedRawData.count)
        }
        
        guard curve.prefixByte == prefixedRawData[0] else {
            throw ParsingError.invalidOrMissingECCPrefixByte
        }
        
        self.curve = curve
        self.rawData = Data(prefixedRawData.suffix(from: 1))
    }
    
    public init(mpintData:Data) throws {
        
        let bytes = mpintData.bytes
        
        guard bytes.count >= 1 else {
            throw DataError.tooShort(bytes.count)
        }
        
        var start = 0
        let oidLength = Int(bytes[start])
        
        guard bytes.count >= 1 + oidLength else {
            throw DataError.tooShort(bytes.count)
        }
        
        start += 1
        
        let oid = [UInt8](bytes[start ..< start + oidLength])
        
        guard let curve = Curve(oid: oid) else {
            throw ParsingError.unsupportedECCCurveOID(oid)
        }

        self.curve = curve
    
        start += oidLength
        
        guard bytes.count > start else {
            throw DataError.tooShort(bytes.count)
        }
        
        let mpintBytes = try MPInt(mpintData: Data(bytes[start ..< bytes.count])).data.bytes
        
        guard mpintBytes.first == curve.prefixByte else {
            throw ParsingError.invalidOrMissingECCPrefixByte
        }
        
        guard mpintBytes.count > 1 else {
            throw DataError.tooShort(mpintBytes.count)
        }
        
        self.rawData = Data(mpintBytes[1 ..< mpintBytes.count])
    }
    
    
    public func toData() -> Data {
        var data = Data()
        data.append(contentsOf: [UInt8(curve.oid.count)] + curve.oid)
        
        let mpint = MPInt(integerData: Data([curve.prefixByte] + rawData.bytes))
        
        data.append(contentsOf: mpint.lengthBytes)
        data.append(mpint.data)
        
        return data
    }
}

