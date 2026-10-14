//  KeePassium Password Manager
//  Copyright © 2018-2025 KeePassium Labs <info@keepassium.com>
//
//  This program is free software: you can redistribute it and/or modify it
//  under the terms of the GNU General Public License version 3 as published
//  by the Free Software Foundation: https://www.gnu.org/licenses/).
//  For commercial licensing, please contact the author.

import Foundation

public enum FTPFileURL {
    public static let schemePrefix = "ftp"
    public static let schemes = ["ftp", "ftps"]
    public static let prefixedSchemes = [
        "ftp\(urlSchemePrefixSeparator)ftp",
        "ftp\(urlSchemePrefixSeparator)ftps"
    ]

    public static func build(nakedURL: URL) -> URL {
        return nakedURL.withSchemePrefix(schemePrefix)
    }

    public static func getNakedURL(from prefixedURL: URL) -> URL {
        return prefixedURL.withoutSchemePrefix()
    }

    public static func getDescription(for prefixedURL: URL) -> String? {
        let urlString = getNakedURL(from: prefixedURL).absoluteString
        return "\(LString.connectionTypeFTP) → \(urlString)"
    }
}

internal extension URL {
    var isFTPFileURL: Bool {
        guard let scheme = self.scheme else {
            return false
        }
        return FTPFileURL.prefixedSchemes.contains(scheme)
    }
}
