//
//  PublicKey.swift
//  PGPFormat
//
//  Created by Alex Grinman on 5/15/17.
//  Copyright © 2017 KryptCo, Inc. All rights reserved.
//


import Foundation

public struct UnsupportedPublicKeyAlgorithm:Error {
    var type:UInt8
}

public enum PublicKeyAlgorithm:UInt8 {
    case rsaEncryptOrSign = 1
    case rsaEncryptOnly = 2
    case rsaSignOnly = 3
    
    init(type:UInt8) throws {
        guard let algo = PublicKeyAlgorithm(rawValue: type) else {
            throw UnsupportedPublicKeyAlgorithm(type: type)
        }
        
        self = algo
    }
}

public struct PublicKey:Packetable {
    private let supportedVersion = 4
    
    public let tag:PacketTag
    
    public var created:Date
    public var algorithm:PublicKeyAlgorithm
    
    public var modulus:Data
    public var exponent:Data
    
    public enum ParsingError:Error {
        case tooShort(Int)
        case unsupportedVersion(UInt8)
        case invalidFinerprintLength(Int)
    }
    
    public init(create algorithm:PublicKeyAlgorithm, modulus:Data, exponent:Data, date:Date = Date()) {
        self.tag = .publicKey
        self.algorithm = algorithm
        self.modulus = modulus
        self.exponent = exponent
        self.created = date
    }
    
    public init(packet:Packet) throws {
        
        // get packet tag, ensure it's a public key type
        switch packet.header.tag {
        case .publicKey, .publicSubkey:
            self.tag = packet.header.tag
        default:
            throw PacketableError.invalidPacketTag(packet.header.tag)
        }
        
        // parse the body
        let data = packet.body
        
        guard data.count > 5 else {
            throw FormatError.tooShort(data.count)
        }
        
        let bytes = data.bytes
        
        // version (0)
        guard Int(bytes[0]) == supportedVersion else {
            throw ParsingError.unsupportedVersion(bytes[0])
        }
        
        // created (1 ..< 5)
        let creationSeconds = Double(UInt32(bigEndianBytes: [UInt8](bytes[1 ..< 5])))
        created = Date(timeIntervalSince1970: creationSeconds)
        
        // algo (5)
        algorithm = try PublicKeyAlgorithm(type: bytes[5])
        
        switch algorithm {
        case .rsaSignOnly, .rsaEncryptOnly, .rsaEncryptOrSign:
            // modulus n (MPI: 2 + len(n))
            var  start = 6
            guard data.count >= start + 2 else {
                throw FormatError.tooShort(data.count)
            }
            
            let modulusLength = Int(UInt32(bigEndianBytes: [UInt8](bytes[start ..< start + 2])) + 7)/8
            
            start += 2
            guard data.count >= start + modulusLength else {
                throw FormatError.tooShort(data.count)
            }
            
            modulus = Data(bytes: bytes[start ..< start + modulusLength])
            
            
            // public exponent e (MPI: 2 + len(e))
            start += modulusLength
            guard data.count >= start + 2 else {
                throw FormatError.tooShort(data.count)
            }
            
            let exponentLength = Int(UInt32(bigEndianBytes: [UInt8](bytes[start ..< (start+2)])) + 7)/8
            
            start += 2
            guard data.count >= start + exponentLength else {
                throw FormatError.tooShort(data.count)
            }
            
            exponent = Data(bytes: bytes[start ..< start + exponentLength])
        }

    }
    
    public func toData() throws -> Data {
        
        var data = Data()
        
        // add supported version
        data.append(contentsOf: [UInt8(supportedVersion)])
        
        // add created time
        data.append(contentsOf: UInt32(created.timeIntervalSince1970).fourByteBigEndianBytes())
        
        // add algorithm
        data.append(contentsOf: [algorithm.rawValue])
        
        switch algorithm {
        case .rsaSignOnly, .rsaEncryptOnly, .rsaEncryptOrSign:
            
            // modulus:  MPI two-octet scalar length then modulus
            data.append(contentsOf: UInt32(modulus.numBits).twoByteBigEndianBytes())
            data.append(modulus)
            
            // exponent:  MPI two-octet scalar length then exponent
            data.append(contentsOf: UInt32(exponent.numBits).twoByteBigEndianBytes())
            data.append(exponent)
        }
        
        return data
    }

    public func fingerprint() throws -> Data {
        var dataToHash = Data()
        dataToHash.append(contentsOf: [0x99])
        
        // pubkey length + data
        let publicKeyPacketData = try self.toData()
        let pubKeyLengthBytes = UInt32(publicKeyPacketData.count).twoByteBigEndianBytes()
        dataToHash.append(contentsOf: pubKeyLengthBytes)
        dataToHash.append(publicKeyPacketData)
        
        return dataToHash.SHA1
    }

    public func keyID() throws -> Data {
        let fingerprint = try self.fingerprint()
        
        guard fingerprint.count == 20 else {
            throw ParsingError.invalidFinerprintLength(fingerprint.count)
        }
        
        return Data(bytes: [UInt8](fingerprint[12 ..< 20]))
    }
}


