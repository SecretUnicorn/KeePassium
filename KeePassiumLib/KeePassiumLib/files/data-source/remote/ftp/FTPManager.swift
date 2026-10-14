//  KeePassium Password Manager
//  Copyright © 2018-2025 KeePassium Labs <info@keepassium.com>
//
//  This program is free software: you can redistribute it and/or modify it
//  under the terms of the GNU General Public License version 3 as published
//  by the Free Software Foundation: https://www.gnu.org/licenses/).
//  For commercial licensing, please contact the author.

import Foundation

public final class FTPManager {
    public static let shared = FTPManager()

    private init() {}

    public func getFileInfo(
        url: URL,
        credential: NetworkCredential,
        timeout: Timeout,
        completionQueue: OperationQueue? = nil,
        completion: @escaping (Result<FileInfo, FileAccessError>) -> Void
    ) {
        perform(
            url: url,
            credential: credential,
            timeout: timeout,
            completionQueue: completionQueue ?? .main,
            completion: completion,
            operation: { session, path in
                try await session.getFileInfo(path: path)
            }
        )
    }

    public func downloadFile(
        url: URL,
        credential: NetworkCredential,
        timeout: Timeout,
        completionQueue: OperationQueue? = nil,
        completion: @escaping (Result<ByteArray, FileAccessError>) -> Void
    ) {
        perform(
            url: url,
            credential: credential,
            timeout: timeout,
            completionQueue: completionQueue ?? .main,
            completion: completion,
            operation: { session, path in
                let data = try await session.retrieve(path: path)
                return ByteArray(data: data)
            }
        )
    }

    public func uploadFile(
        data: ByteArray,
        url: URL,
        credential: NetworkCredential,
        timeout: Timeout,
        completionQueue: OperationQueue? = nil,
        completion: @escaping (Result<Void, FileAccessError>) -> Void
    ) {
        let dataToUpload = data.asData
        perform(
            url: url,
            credential: credential,
            timeout: timeout,
            completionQueue: completionQueue ?? .main,
            completion: completion,
            operation: { session, path in
                try await session.store(dataToUpload, path: path)
            }
        )
    }

    public func checkFolderExists(
        url: URL,
        credential: NetworkCredential,
        timeout: Timeout,
        completionQueue: OperationQueue? = nil,
        completion: @escaping (Result<Void, FileAccessError>) -> Void
    ) {
        perform(
            url: url,
            credential: credential,
            timeout: timeout,
            completionQueue: completionQueue ?? .main,
            completion: completion,
            operation: { session, path in
                try await session.checkFolderExists(path: path)
            }
        )
    }

    private func perform<T>(
        url: URL,
        credential: NetworkCredential,
        timeout: Timeout,
        completionQueue: OperationQueue,
        completion: @escaping (Result<T, FileAccessError>) -> Void,
        operation: @escaping (FTPSession, String) async throws -> T
    ) {
        guard let endpoint = FTPEndpoint(nakedURL: url) else {
            Diag.error("Invalid FTP URL")
            completionQueue.addOperation {
                completion(.failure(.serverSideError(message: FTPError.invalidURL.localizedDescription)))
            }
            return
        }

        Task.detached {
            let session = FTPSession(
                endpoint: endpoint,
                allowUntrustedCertificate: credential.allowUntrustedCertificate,
                timeout: timeout
            )
            let result: Result<T, FileAccessError>
            do {
                try await session.login(username: credential.username, password: credential.password)
                let value = try await operation(session, endpoint.path)
                result = .success(value)
            } catch {
                result = .failure(Self.makeFileAccessError(from: error, session: session))
            }
            session.close()
            completionQueue.addOperation {
                completion(result)
            }
        }
    }

    private static func makeFileAccessError(from error: Error, session: FTPSession) -> FileAccessError {
        Diag.error("FTP operation failed [message: \(error.localizedDescription)]")
        if session.isTimedOut {
            return .timeout(fileProvider: .keepassiumFTP)
        }
        guard let ftpError = error as? FTPError else {
            return .networkError(message: error.localizedDescription)
        }
        switch ftpError {
        case .timedOut:
            return .timeout(fileProvider: .keepassiumFTP)
        case .connectionFailed(let message):
            return .networkError(message: message)
        default:
            return .serverSideError(message: ftpError.localizedDescription)
        }
    }
}
