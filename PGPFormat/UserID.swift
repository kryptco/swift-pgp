//
//  UserID.swift
//  PGPFormat
//
//  Created by Alex Grinman on 5/15/17.
//  Copyright © 2017 KryptCo, Inc. All rights reserved.
//


import Foundation


public struct UserID {
    
    public var name:String?
    public var email:String?
    
    public var content:String
    
    public init(data:Data) throws {
        guard let all = String(data: data, encoding: .utf8)
        else {
            throw FormatError.encoding
        }
        
        self.content = all
        setNameAndEmail()
    }
    
    mutating private func setNameAndEmail() {
        let components = content.components(separatedBy: "<")
        guard components.count >= 2 else {
            return
        }
        
        self.name = components[0].trimmingCharacters(in: CharacterSet.whitespaces)
        self.email = components[1].replacingOccurrences(of: ">", with: "").trimmingCharacters(in: CharacterSet.whitespaces)
    }
}

