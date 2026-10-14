//  KeePassium Password Manager
//  Copyright © 2018-2025 KeePassium Labs <info@keepassium.com>
//
//  This program is free software: you can redistribute it and/or modify it
//  under the terms of the GNU General Public License version 3 as published
//  by the Free Software Foundation: https://www.gnu.org/licenses/).
//  For commercial licensing, please contact the author.

import Foundation

public final class FTPDataSource: DataSource {
    func getAccessCoordinator() -> FileAccessCoordinator {
        return PassthroughFileAccessCoordinator()
    }

    public func readFileInfo(
        at url: URL,
        fileProvider: FileProvider?,
        canUseCache: Bool,
        timeout: Timeout,
        queue: OperationQueue,
        completionQueue: OperationQueue,
        completion: @escaping FileOperationCompletion<FileInfo>
    ) {
        assert(fileProvider == .keepassiumFTP)
        guard let credential = checkAccess(url: url, completionQueue: completionQueue, completion: completion)
        else { return }
        FTPManager.shared.getFileInfo(
            url: FTPFileURL.getNakedURL(from: url),
            credential: credential,
            timeout: timeout,
            completionQueue: completionQueue,
            completion: completion
        )
    }

    public func read(
        _ url: URL,
        fileProvider: FileProvider?,
        timeout: Timeout,
        queue: OperationQueue,
        completionQueue: OperationQueue,
        completion: @escaping FileOperationCompletion<ByteArray>
    ) {
        assert(fileProvider == .keepassiumFTP)
        guard let credential = checkAccess(url: url, completionQueue: completionQueue, completion: completion)
        else { return }
        FTPManager.shared.downloadFile(
            url: FTPFileURL.getNakedURL(from: url),
            credential: credential,
            timeout: timeout,
            completionQueue: completionQueue,
            completion: completion
        )
    }

    public func write(
        _ data: ByteArray,
        to url: URL,
        fileProvider: FileProvider?,
        timeout: Timeout,
        queue: OperationQueue,
        completionQueue: OperationQueue,
        completion: @escaping FileOperationCompletion<Void>
    ) {
        assert(fileProvider == .keepassiumFTP)
        guard let credential = checkAccess(url: url, completionQueue: completionQueue, completion: completion)
        else { return }
        FTPManager.shared.uploadFile(
            data: data,
            url: FTPFileURL.getNakedURL(from: url),
            credential: credential,
            timeout: timeout,
            completionQueue: completionQueue,
            completion: completion
        )
    }

    private func checkAccess<T>(
        url: URL,
        completionQueue: OperationQueue,
        completion: @escaping FileOperationCompletion<T>
    ) -> NetworkCredential? {
        guard Settings.current.isNetworkAccessAllowed else {
            Diag.error("Network access denied")
            completionQueue.addOperation {
                completion(.failure(.networkAccessDenied))
            }
            return nil
        }
        guard let credential = CredentialManager.shared.get(for: url) else {
            Diag.warning("Found no FTP credentials, skipping")
            completionQueue.addOperation {
                completion(.failure(.noInfoAvailable))
            }
            return nil
        }
        return credential
    }
}
