//
//  PGPFormatTests.swift
//  PGPFormatTests
//
//  Created by Alex Grinman on 5/17/17.
//  Copyright © 2017 KryptCo, Inc. All rights reserved.
//

import XCTest
@testable import PGPFormat

class PGPFormatTests: XCTestCase {
    
    var pubkey1:String!
    var pubkey2:String!
    var pubkeyEd25519:String!
    var pubkeyEd25519_2:String!

    var binarySignature:String!
    var binaryDocument:String!

    override func setUp() {
        super.setUp()
        
        let bundle = Bundle(for: type(of: self))
        pubkey1 = try! String(contentsOfFile: bundle.path(forResource: "pubkey1", ofType: "txt")!)
        pubkey2 = try! String(contentsOfFile: bundle.path(forResource: "pubkey2", ofType: "txt")!)
        pubkeyEd25519 = try! String(contentsOfFile: bundle.path(forResource: "pubkey3", ofType: "txt")!)
        pubkeyEd25519_2 = try! String(contentsOfFile: bundle.path(forResource: "pubkey4", ofType: "txt")!)

        binarySignature = try! String(contentsOfFile: bundle.path(forResource: "signature", ofType: "txt")!)
        binaryDocument = try! String(contentsOfFile: bundle.path(forResource: "signed_raw", ofType: "txt")!)

    }
    
    override func tearDown() {
        super.tearDown()
    }
    
    //MARK: Ascii Armor
    func testAsciiArmor() {
        do {
            let pubMsg = try AsciiArmorMessage(string: pubkey1)

            if pubMsg.comment != "Some test hello" {
                XCTFail("invalid comment: \(pubMsg.comment)")
            }
            
            if pubMsg.crcChecksum.toBase64() != "m4zw" {
                XCTFail("invalid checksum: \(pubMsg.crcChecksum.toBase64())")
            }
            
            if pubMsg.blockType != ArmorMessageBlock.publicKey {
                XCTFail("invalid block type: \(pubMsg.blockType)")
            }
            
            let pubMsgAgain = try AsciiArmorMessage(string: pubMsg.toString())

        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }
    
    func testChecksum() {
        let data = try! "yDgBO22WxBHv7O8X7O/jygAEzol56iUKiXmV+XmpCtmpqQUKiQrFqclFqUDBovzSvBSFjNSiVHsuAA==".fromBase64()
        
        let check = data.crc24Checksum.toBase64()
        
        guard check == "njUN" else {
            XCTFail("mismatching checksum. got: \(check)")
            return
        }
    }
    
    //MARK: Packets
    
    func testPublicKeySerializeDeserializePacket() {
        do  {
            let pubMsg = try AsciiArmorMessage(string: pubkey1)
            let packets = try [Packet](data: pubMsg.packetData)
            
            for packet in [packets[0], packets[4]] {
                let packetOriginal = packet
                let pubKeyOriginal = try PublicKey(packet: packetOriginal)
                
                let packetSerialized = try pubKeyOriginal.toPacket()
                let pubKeyDeserialized = try PublicKey(packet: packetSerialized)
                
                guard packetSerialized.body == packetOriginal.body else {
                    print("original: \(packetOriginal.body.bytes)")
                    print("serialized: \(packetSerialized.body.bytes)")
                    XCTFail("packets differ after serialization deserialization")
                    return
                    
                }

            }
            
        } catch {
            XCTFail("Unexpected error: \(error)")

        }
    }
    
    func testPublicKeyTwoSerializeDeserializePacket() {
        do  {
            let pubMsg = try AsciiArmorMessage(string: pubkey2)
            let packets = try [Packet](data: pubMsg.packetData)
            
            for packet in [packets[0]] {                                
                let packetOriginal = packet
                let pubKeyOriginal = try PublicKey(packet: packetOriginal)
                
                let packetSerialized = try pubKeyOriginal.toPacket()
                let pubKeyDeserialized = try PublicKey(packet: packetSerialized)
                
                guard packetSerialized.body == packetOriginal.body else {
                    print("original: \(packetOriginal.body.bytes)")
                    print("serialized: \(packetSerialized.body.bytes)")
                    XCTFail("packets differ after serialization deserialization")
                    return
                    
                }
                
            }
            
        } catch {
            XCTFail("Unexpected error: \(error)")
            
        }
    }
    
    func testPublicKeyEd25519SerializeDeserializePacket() {
        do  {
            let pubMsg = try AsciiArmorMessage(string: pubkeyEd25519)
            let packets = try [Packet](data: pubMsg.packetData)
            
            let packetOriginal = packets[0]
            let pubKeyOriginal = try PublicKey(packet: packetOriginal)
            
            let packetSerialized = try pubKeyOriginal.toPacket()
            let pubKeyDeserialized = try PublicKey(packet: packetSerialized)
            
            guard packetSerialized.body == packetOriginal.body else {
                print("original: \(packetOriginal.body.bytes)")
                print("serialized: \(packetSerialized.body.bytes)")
                XCTFail("packets differ after serialization deserialization")
                return
                
            }
            
            let userID = try UserID(packet: packets[1])
            
            let signature = try Signature(packet: packets[2])
            print(signature.hashedSubpacketables)
            let fingerprint = try (signature.hashedSubpacketables[0] as? SignatureIssuerFingerprint)?.fingerprint
            print(fingerprint?.bytes)
        } catch {
            XCTFail("Unexpected error: \(error)")
            
        }
    }


    
    func testFingerprintAndKeyId() {
        do  {
            let pubMsg = try AsciiArmorMessage(string: pubkey1)
            let packets = try [Packet](data: pubMsg.packetData)
            
            for packet in [packets[0]] {
                let packetOriginal = packet
                let pubKeyOriginal = try PublicKey(packet: packetOriginal)
                
                let fp = try pubKeyOriginal.fingerprint().hex
                let keyID = try pubKeyOriginal.keyID().hex
                
                guard fp.uppercased() == "F7A83D5CE65C42817A4AB7647A1037F5EF07891E" else {
                    XCTFail("Fingerprint does not match, got: \(fp)")
                    return
                }
                
                guard keyID.uppercased() == "7A1037F5EF07891E" else {
                    XCTFail("KeyID does not match, got: \(keyID)")
                    return
                }

            }
            
        } catch {
            XCTFail("Unexpected error: \(error)")
            
        }
    }

    
    // UserID
    func testUserIDPacket() {
        do  {
            let pubMsg = try AsciiArmorMessage(string: pubkey1)
            let packets = try [Packet](data: pubMsg.packetData)
            
            let packetOriginal = packets[1]
            let userIDOriginal = try UserID(packet: packetOriginal)
            
            let packetSerialized = try userIDOriginal.toPacket()
            let userIDDeserialized = try UserID(packet: packetSerialized)
            
            guard packetSerialized.body == packetOriginal.body else {
                print("original: \(packetOriginal.body.bytes)")
                print("serialized: \(packetSerialized.body.bytes)")
                XCTFail("packets differ after serialization deserialization")
                return
                
            }
            
        } catch {
            XCTFail("Unexpected error: \(error)")
            
        }
    }
    
    // Signature
    func testSignatureSerializeDeserializePacket() {
        do  {
            let pubMsg = try AsciiArmorMessage(string: pubkey1)
            let packets = try [Packet](data: pubMsg.packetData)
            
            for packet in [packets[2], packets[3], packets[5]] {
                let packetOriginal = packet
                let sigOriginal = try Signature(packet: packetOriginal)
                
                let packetSerialized = try sigOriginal.toPacket()
                let sigDeserialized = try Signature(packet: packetSerialized)
                
                guard packetSerialized.body == packetOriginal.body else {
                    print("original: \(packetOriginal.body.bytes)")
                    print("serialized: \(packetSerialized.body.bytes)")
                    XCTFail("packets differ after serialization deserialization")
                    return
                    
                }
            }
            
        } catch {
            XCTFail("Unexpected error: \(error)")
            
        }
    }
    
    func testSignatureSerializeDeserializeEd25519Packet() {
        do  {
            let pubMsg = try AsciiArmorMessage(string: pubkeyEd25519)
            let packets = try [Packet](data: pubMsg.packetData)
            
            let packetOriginal = packets[2]
            let sigOriginal = try Signature(packet: packetOriginal)
            
            let packetSerialized = try sigOriginal.toPacket()
            let sigDeserialized = try Signature(packet: packetSerialized)
            
            guard packetSerialized.body == packetOriginal.body else {
                print("original: \(packetOriginal.body.bytes)")
                print("serialized: \(packetSerialized.body.bytes)")
                XCTFail("packets differ after serialization deserialization")
                return
                
            }
            
        } catch {
            XCTFail("Unexpected error: \(error)")
            
        }
    }

    
    // Test RSA left two bytes match
    func testRSAPublicKeySignatureHashLeftTwoBytes() {
        do  {
            let pubMsg = try AsciiArmorMessage(string: pubkey1)
            let packets = try [Packet](data: pubMsg.packetData)
            
            let publicKey = try PublicKey(packet: packets[0])
            let userID = try UserID(packet: packets[1])
            let signature = try Signature(packet: packets[3])
            
            var signedPubKey = try SignedPublicKeyIdentity(publicKey: publicKey, userID: userID, hashAlgorithm: signature.hashAlgorithm, hashedSubpacketables: signature.hashedSubpacketables)
            
            let dataToHash = try signedPubKey.dataToHash()
            
            var hash:Data

            switch signature.hashAlgorithm {
            case .sha1:
                hash = dataToHash.SHA1
            case .sha224:
                hash = dataToHash.SHA224
            case .sha256:
                hash = dataToHash.SHA256
            case .sha384:
                hash = dataToHash.SHA384
            case .sha512:
                hash = dataToHash.SHA512
            }
            
            try signedPubKey.set(hash: hash, signedHash: signature.signature)

            guard signedPubKey.signature.leftTwoHashBytes == signature.leftTwoHashBytes else {
                XCTFail("Left two hash bytes don't match: \nGot: \(signedPubKey.signature.leftTwoHashBytes)\nExpected: \(signature.leftTwoHashBytes)")
                return
            }
            
            let outMsg = try AsciiArmorMessage(message: signedPubKey.toMessage(), blockType: ArmorMessageBlock.publicKey).toString()
            let inPackets = try [Packet](data: AsciiArmorMessage(string: outMsg).packetData)
            
            print(outMsg)
            
            
        } catch {
            XCTFail("Unexpected error: \(error)")            
        }
    }

    
    // Test signature hash
    func testEd25519SignatureHashMatchesLeft16Bits() {
        do  {
            let pubMsg = try AsciiArmorMessage(string: pubkeyEd25519)
            let packets = try [Packet](data: pubMsg.packetData)
            
            let publicKey = try PublicKey(packet: packets[0])
            let userID = try UserID(packet: packets[1])
            let signature = try Signature(packet: packets[2])
            
            var signedPubKey = try SignedPublicKeyIdentity(publicKey: publicKey, userID: userID, hashAlgorithm: signature.hashAlgorithm, hashedSubpacketables: signature.hashedSubpacketables)
            
            let dataToHash = try signedPubKey.dataToHash()
            
            var hash:Data
            
            switch signature.hashAlgorithm {
            case .sha1:
                hash = dataToHash.SHA1
            case .sha224:
                hash = dataToHash.SHA224
            case .sha256:
                hash = dataToHash.SHA256
            case .sha384:
                hash = dataToHash.SHA384
            case .sha512:
                hash = dataToHash.SHA512
            }
            
            try signedPubKey.set(hash: hash, signedHash: signature.signature)
            
            guard signedPubKey.signature.leftTwoHashBytes == signature.leftTwoHashBytes else {
                XCTFail("Left two hash bytes don't match: \nGot: \(signedPubKey.signature.leftTwoHashBytes)\nExpected: \(signature.leftTwoHashBytes)")
                return
            }
            
            
        } catch {
            XCTFail("Unexpected error: \(error)")
            
        }
    }
    
    // Test binary document signature
    func testBinaryDocumentSignature() {
        do {
            let msg = try AsciiArmorMessage(string: binarySignature)
            let packets = try [Packet](data: msg.packetData)
            let signature = try Signature(packet: packets[0])
            
            print("Kind: \(signature.kind)")
            print("Hashed Sbpkt Type: \(signature.hashedSubpacketables[0].type)")
            
            var binaryData = binaryDocument.data(using: String.Encoding.utf8)!
            
            var signedBinary = SignedBinaryDocument(binary: binaryData, publicKeyAlgorithm: signature.publicKeyAlgorithm, hashAlgorithm: signature.hashAlgorithm, hashedSubpacketables: signature.hashedSubpacketables)
            
            let dataToHash = try signedBinary.dataToHash()

            var hash:Data
            switch signature.hashAlgorithm {
            case .sha1:
                hash = dataToHash.SHA1
            case .sha224:
                hash = dataToHash.SHA224
            case .sha256:
                hash = dataToHash.SHA256
            case .sha384:
                hash = dataToHash.SHA384
            case .sha512:
                hash = dataToHash.SHA512
            }
            
            try signedBinary.set(hash: hash, signedHash: signature.signature)
            
            guard signedBinary.signature.leftTwoHashBytes == signature.leftTwoHashBytes else {
                XCTFail("Left two hash bytes don't match: \nGot: \(signedBinary.signature.leftTwoHashBytes)\nExpected: \(signature.leftTwoHashBytes)")
                return
            }


        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }

    func testOldPacketLengthSerialization() {
        do {
            do {
                let length = try PacketLength(body: 100)
                guard case .old(let l) = length.length,
                    l == .oneOctet,
                    length.formatBytes == [UInt8]([0x64]) else {
                        XCTFail("incorrect length")
                        return
                }
            }
            do {
                let length = try PacketLength(body: 1723)
                guard case .old(let l) = length.length,
                    l == .twoOctet,
                    length.formatBytes == [UInt8]([0x06, 0xBB]) else {
                        XCTFail("incorrect length")
                        return
                }
            }
            do {
                let length = try PacketLength(body: 100000)
                guard case .old(let l) = length.length,
                    l == .fourOctet,
                    length.formatBytes == [UInt8]([0x00, 0x01, 0x86, 0xA0]) else {
                        XCTFail("incorrect length")
                        return
                }
            }
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }

    func testOldPacketLengthDeserialization() {
        do {
            do {
                let length = try PacketLength(oldFormat: [0x64], type: PacketLength.OldFormatType.oneOctet.rawValue)
                guard length.body == 100 else {
                        XCTFail("incorrect length")
                    return
                }
            }
            do {
                let length = try PacketLength(oldFormat: [0x06, 0xBB], type: PacketLength.OldFormatType.twoOctet.rawValue)
                guard length.body == 1723 else {
                        XCTFail("incorrect length")
                    return
                }
            }
            do {
                let length = try PacketLength(oldFormat: [0x00, 0x01, 0x86, 0xA0], type: PacketLength.OldFormatType.fourOctet.rawValue)
                guard length.body == 100000 else {
                        XCTFail("incorrect length")
                    return
                }
            }
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }

    func testNewPacketLengthDeserialization() {
        do {
            do {
                let length = try PacketLength(newFormat: [0x64])
                guard length.body == 100 else {
                    XCTFail("incorrect length")
                    return
                }
            }
            do {
                let length = try PacketLength(newFormat: [0xC5, 0xFB])
                guard length.body == 1723 else {
                    XCTFail("incorrect length")
                    return
                }
            }
            do {
                let length = try PacketLength(newFormat: [0xFF, 0x00, 0x01, 0x86, 0xA0])
                guard length.body == 100000 else {
                    XCTFail("incorrect length")
                    return
                }
            }
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }
    
}
