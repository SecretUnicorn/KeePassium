//  KeePassium Password Manager
//  Copyright © 2018-2025 KeePassium Labs <info@keepassium.com>
//
//  This program is free software: you can redistribute it and/or modify it
//  under the terms of the GNU General Public License version 3 as published
//  by the Free Software Foundation: https://www.gnu.org/licenses/).
//  For commercial licensing, please contact the author.

import Foundation

/// Keeps database versions that were saved while the original file was unreachable,
/// so that they can be merged into the original once it becomes reachable again.
///
/// There is at most one pending file per original database. It is stored in the shared
/// app group container (so AutoFill sees it too), and doubles as the fallback copy
/// whenever the original cannot be opened.
public final class OfflineChangesStore {
    public static let shared = OfflineChangesStore()

    private static let directoryName = "OfflineChanges"

    internal lazy var baseDirURL: URL? = {
        guard let containerURL = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: AppGroup.id
        ) else {
            Diag.error("Failed to access app group container")
            return nil
        }
        return containerURL.appendingPathComponent(Self.directoryName, isDirectory: true)
    }()

    private init() {}

    /// Whether changes to the given database can be kept offline.
    public func isEligible(_ originalRef: URLReference?) -> Bool {
        guard let originalRef else { return false }
        switch originalRef.location {
        case .external, .remote:
            return originalRef.url != nil
        default:
            return false
        }
    }

    public func hasPendingChanges(for originalRef: URLReference?) -> Bool {
        guard isEligible(originalRef),
              let fileURL = getFileURL(for: originalRef!)
        else {
            return false
        }
        return FileManager.default.fileExists(atPath: fileURL.path)
    }

    /// Location of the pending file for the given database (whether or not it exists).
    public func getFileURL(for originalRef: URLReference) -> URL? {
        guard let baseDirURL,
              let originalURL = originalRef.url
        else {
            return nil
        }
        let key = ByteArray(utf8String: originalURL.absoluteString).sha256.asHexString
        return baseDirURL
            .appendingPathComponent(key, isDirectory: true)
            .appendingPathComponent(originalRef.visibleFileName, isDirectory: false)
    }

    public func getReference(for originalRef: URLReference) -> URLReference? {
        guard hasPendingChanges(for: originalRef),
              let fileURL = getFileURL(for: originalRef)
        else {
            return nil
        }
        do {
            return try URLReference(from: fileURL, location: .internalBackup)
        } catch {
            Diag.error("Failed to create reference to offline changes [message: \(error.localizedDescription)]")
            return nil
        }
    }

    public func loadPendingChanges(for originalRef: URLReference) throws -> ByteArray? {
        guard hasPendingChanges(for: originalRef),
              let fileURL = getFileURL(for: originalRef)
        else {
            return nil
        }
        return try ByteArray(data: Data(contentsOf: fileURL))
    }

    @discardableResult
    public func save(_ data: ByteArray, for originalRef: URLReference) throws -> URL {
        guard isEligible(originalRef),
              let fileURL = getFileURL(for: originalRef)
        else {
            throw FileAccessError.internalError
        }
        try FileManager.default.createDirectory(
            at: fileURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        try data.asData.write(to: fileURL, options: [.atomic, .completeFileProtection])
        Diag.info("Saved database changes offline")
        return fileURL
    }

    public func clearPendingChanges(for originalRef: URLReference) {
        guard let fileURL = getFileURL(for: originalRef) else { return }
        let dirURL = fileURL.deletingLastPathComponent()
        guard FileManager.default.fileExists(atPath: dirURL.path) else { return }
        do {
            try FileManager.default.removeItem(at: dirURL)
            Diag.info("Offline changes cleared")
        } catch {
            Diag.error("Failed to clear offline changes [message: \(error.localizedDescription)]")
        }
    }
}
