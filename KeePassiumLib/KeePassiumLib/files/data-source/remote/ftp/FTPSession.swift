//  KeePassium Password Manager
//  Copyright © 2018-2025 KeePassium Labs <info@keepassium.com>
//
//  This program is free software: you can redistribute it and/or modify it
//  under the terms of the GNU General Public License version 3 as published
//  by the Free Software Foundation: https://www.gnu.org/licenses/).
//  For commercial licensing, please contact the author.

import Foundation
import Network

internal enum FTPError: LocalizedError {
    case invalidURL
    case invalidArgument
    case connectionFailed(message: String)
    case authenticationFailed(message: String)
    case fileNotFound(path: String)
    case unexpectedReply(code: Int, message: String)
    case invalidReply
    case timedOut

    var errorDescription: String? {
        switch self {
        case .invalidURL:
            return "Invalid FTP URL"
        case .invalidArgument:
            return "Invalid characters in FTP path or credentials"
        case .connectionFailed(let message):
            return message
        case .authenticationFailed(let message):
            return "\(LString.errorAuthenticationFailed) (\(message))"
        case .fileNotFound(let path):
            return "File not found: \(path)"
        case .unexpectedReply(let code, let message):
            return "FTP \(code): \(message)"
        case .invalidReply:
            return "Unexpected response from FTP server"
        case .timedOut:
            return "FTP operation timed out"
        }
    }
}

internal struct FTPEndpoint {
    let host: String
    let port: UInt16
    let usesTLS: Bool
    let path: String

    var fileName: String {
        return path.split(separator: "/").last.map(String.init) ?? path
    }

    /// Parses `ftp://host[:port]/path` (plain) or `ftps://host[:port]/path` (implicit TLS).
    /// Like curl, the path is relative to the login directory; use `//` for an absolute path.
    init?(nakedURL url: URL) {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let scheme = components.scheme?.lowercased(),
              FTPFileURL.schemes.contains(scheme),
              let host = components.host,
              host.isNotEmpty
        else {
            return nil
        }
        self.host = host
        self.usesTLS = (scheme == "ftps")
        if let port = components.port {
            guard let validPort = UInt16(exactly: port), validPort > 0 else { return nil }
            self.port = validPort
        } else {
            self.port = usesTLS ? 990 : 21
        }

        var path = components.percentEncodedPath.removingPercentEncoding ?? components.path
        if path.hasPrefix("/") {
            path.removeFirst()
        }
        self.path = path
    }
}

private struct FTPReply {
    let code: Int
    let message: String

    var isPreliminary: Bool { (100...199).contains(code) }
    var isCompletion: Bool { (200...299).contains(code) }
}

/// A minimal FTP client session: one control connection plus passive-mode data connections.
/// Supports plain FTP and implicit FTPS (TLS from the first byte, usually port 990).
internal final class FTPSession {
    private let endpoint: FTPEndpoint
    private let allowUntrustedCertificate: Bool
    private let timeout: Timeout
    private let queue = DispatchQueue(label: "com.keepassium.ftp.session")

    private var controlConnection: NWConnection?
    private var controlBuffer = Data()

    private var activeConnections = [NWConnection]()
    private var connectionErrors = [ObjectIdentifier: NWError]()
    private var finishedConnections = Set<ObjectIdentifier>()
    private var timeoutWorkItem: DispatchWorkItem?
    private var _isTimedOut = false

    var isTimedOut: Bool {
        queue.sync { _isTimedOut }
    }

    init(endpoint: FTPEndpoint, allowUntrustedCertificate: Bool, timeout: Timeout) {
        self.endpoint = endpoint
        self.allowUntrustedCertificate = allowUntrustedCertificate
        self.timeout = timeout
    }

    deinit {
        timeoutWorkItem?.cancel()
    }


    func login(username: String, password: String) async throws {
        guard isSafeArgument(username), isSafeArgument(password) else {
            throw FTPError.invalidArgument
        }
        startTimeoutTimer()

        let connection = makeConnection(port: endpoint.port)
        controlConnection = connection

        let greeting = try await readReply()
        guard greeting.code == 220 else {
            throw FTPError.unexpectedReply(code: greeting.code, message: greeting.message)
        }

        let user = username.isEmpty ? "anonymous" : username
        let pass = username.isEmpty ? "anonymous@" : password
        var reply = try await sendCommand("USER \(user)")
        if reply.code == 331 {
            reply = try await sendCommand("PASS \(pass)", isSensitive: true)
        }
        guard reply.code == 230 || reply.code == 202 else {
            throw FTPError.authenticationFailed(message: "\(reply.code): \(reply.message)")
        }

        if endpoint.usesTLS {
            _ = try await sendCommand("PBSZ 0")
            let protReply = try await sendCommand("PROT P")
            guard protReply.isCompletion else {
                throw FTPError.unexpectedReply(code: protReply.code, message: protReply.message)
            }
        }
        _ = try? await sendCommand("OPTS UTF8 ON")
        let typeReply = try await sendCommand("TYPE I")
        guard typeReply.isCompletion else {
            throw FTPError.unexpectedReply(code: typeReply.code, message: typeReply.message)
        }
    }

    func getFileInfo(path: String) async throws -> FileInfo {
        guard isSafeArgument(path), path.isNotEmpty else { throw FTPError.invalidArgument }

        var fileSize: Int64 = -1
        let sizeReply = try await sendCommand("SIZE \(path)")
        switch sizeReply.code {
        case 213:
            fileSize = Int64(sizeReply.message.trimmingCharacters(in: .whitespaces)) ?? -1
        case 550:
            throw FTPError.fileNotFound(path: path)
        default:
            Diag.debug("FTP server does not support SIZE [code: \(sizeReply.code)]")
        }

        var modificationDate: Date?
        let mdtmReply = try await sendCommand("MDTM \(path)")
        if mdtmReply.code == 213 {
            modificationDate = Self.parseMDTM(mdtmReply.message)
        } else {
            Diag.debug("FTP server did not return MDTM [code: \(mdtmReply.code)]")
        }

        return FileInfo(
            fileName: endpoint.fileName,
            fileSize: fileSize,
            creationDate: nil,
            modificationDate: modificationDate,
            attributes: [:],
            isInTrash: false,
            hash: nil
        )
    }

    func checkFolderExists(path: String) async throws {
        guard isSafeArgument(path) else { throw FTPError.invalidArgument }
        guard path.isNotEmpty else { return }
        let reply = try await sendCommand("CWD \(path)")
        guard reply.isCompletion else {
            throw FTPError.fileNotFound(path: path)
        }
    }

    func retrieve(path: String) async throws -> Data {
        guard isSafeArgument(path), path.isNotEmpty else { throw FTPError.invalidArgument }

        let dataConnection = try await openDataConnection()
        defer { dataConnection.cancel() }

        let reply = try await sendCommand("RETR \(path)")
        guard reply.isPreliminary else {
            throw makeError(from: reply, path: path)
        }

        var fileData = Data()
        while let chunk = try await receive(on: dataConnection) {
            fileData.append(chunk)
        }

        let finalReply = try await readReply()
        guard finalReply.isCompletion else {
            throw makeError(from: finalReply, path: path)
        }
        return fileData
    }

    func store(_ data: Data, path: String) async throws {
        guard isSafeArgument(path), path.isNotEmpty else { throw FTPError.invalidArgument }

        let dataConnection = try await openDataConnection()
        defer { dataConnection.cancel() }

        let reply = try await sendCommand("STOR \(path)")
        guard reply.isPreliminary else {
            throw makeError(from: reply, path: path)
        }

        try await send(data, on: dataConnection, isFinal: true)

        let finalReply = try await readReply()
        guard finalReply.isCompletion else {
            throw makeError(from: finalReply, path: path)
        }
    }

    func close() {
        if let controlConnection {
            controlConnection.send(
                content: Data("QUIT\r\n".utf8),
                completion: .contentProcessed { _ in }
            )
        }
        queue.async { [self] in
            timeoutWorkItem?.cancel()
            activeConnections.forEach { $0.cancel() }
            activeConnections.removeAll()
        }
    }
}

extension FTPSession {
    private func isSafeArgument(_ value: String) -> Bool {
        return !value.unicodeScalars.contains { $0 == "\r" || $0 == "\n" || $0 == "\0" }
    }

    private func makeError(from reply: FTPReply, path: String) -> FTPError {
        if reply.code == 550 {
            return .fileNotFound(path: path)
        }
        return .unexpectedReply(code: reply.code, message: reply.message)
    }

    private func startTimeoutTimer() {
        let workItem = DispatchWorkItem { [weak self] in
            guard let self else { return }
            Diag.error("FTP operation timed out, cancelling")
            _isTimedOut = true
            activeConnections.forEach { $0.cancel() }
        }
        timeoutWorkItem = workItem
        queue.asyncAfter(deadline: timeout.deadline, execute: workItem)
    }

    private func makeParameters() -> NWParameters {
        let tcpOptions = NWProtocolTCP.Options()
        tcpOptions.connectionTimeout = max(1, Int(timeout.remainingTimeInterval.rounded(.up)))
        guard endpoint.usesTLS else {
            return NWParameters(tls: nil, tcp: tcpOptions)
        }

        let tlsOptions = NWProtocolTLS.Options()
        let allowUntrusted = allowUntrustedCertificate
        sec_protocol_options_set_verify_block(
            tlsOptions.securityProtocolOptions,
            { _, secTrust, complete in
                if allowUntrusted {
                    complete(true)
                    return
                }
                let trust = sec_trust_copy_ref(secTrust).takeRetainedValue()
                var cfError: CFError?
                let isTrusted = SecTrustEvaluateWithError(trust, &cfError)
                if let cfError {
                    Diag.warning("FTP server certificate is not valid [details: \((cfError as Error).localizedDescription)]")
                }
                complete(isTrusted)
            },
            queue
        )
        return NWParameters(tls: tlsOptions, tcp: tcpOptions)
    }

    /// Creates and starts a connection. Does not wait for readiness: reads/writes are queued
    /// until the connection is ready. (This matters for TLS data connections, since many servers
    /// only start the TLS handshake after receiving the transfer command.)
    private func makeConnection(port: UInt16) -> NWConnection {
        let connection = NWConnection(
            host: NWEndpoint.Host(endpoint.host),
            port: NWEndpoint.Port(rawValue: port)!,
            using: makeParameters()
        )
        let connectionID = ObjectIdentifier(connection)
        connection.stateUpdateHandler = { [weak self, weak connection] state in
            guard let self, let connection else { return }
            switch state {
            case .waiting(let error), .failed(let error):
                Diag.error("FTP connection failed [message: \(error.localizedDescription)]")
                connectionErrors[connectionID] = error
                connection.cancel()
            default:
                break
            }
        }
        queue.sync {
            activeConnections.append(connection)
            if _isTimedOut {
                connection.cancel()
            }
        }
        connection.start(queue: queue)
        return connection
    }

    /// Must be called on `queue` (that is, from NWConnection callbacks).
    private func connectionError(for connection: NWConnection, fallback: Error) -> FTPError {
        dispatchPrecondition(condition: .onQueue(queue))
        if _isTimedOut {
            return .timedOut
        }
        let error = connectionErrors[ObjectIdentifier(connection)] ?? fallback
        return .connectionFailed(message: error.localizedDescription)
    }

    /// Returns the next chunk of data, or `nil` once the peer has finished sending.
    private func receive(on connection: NWConnection) async throws -> Data? {
        let connectionID = ObjectIdentifier(connection)
        if queue.sync(execute: { finishedConnections.contains(connectionID) }) {
            return nil
        }
        while true {
            let chunk: Data? = try await withCheckedThrowingContinuation { continuation in
                connection.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) {
                    [weak self] data, _, isComplete, error in
                    if isComplete {
                        self?.finishedConnections.insert(connectionID)
                    }
                    if let data, !data.isEmpty {
                        continuation.resume(returning: data)
                    } else if isComplete {
                        continuation.resume(returning: nil)
                    } else if let error {
                        let ftpError = self?.connectionError(for: connection, fallback: error)
                        continuation.resume(throwing: ftpError ?? FTPError.connectionFailed(message: ""))
                    } else {
                        continuation.resume(returning: Data())
                    }
                }
            }
            guard let chunk else { return nil }
            if !chunk.isEmpty {
                return chunk
            }
        }
    }

    private func send(_ data: Data, on connection: NWConnection, isFinal: Bool = false) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            connection.send(
                content: data,
                contentContext: isFinal ? .finalMessage : .defaultMessage,
                isComplete: isFinal,
                completion: .contentProcessed { [weak self] error in
                    if let error {
                        let ftpError = self?.connectionError(for: connection, fallback: error)
                        continuation.resume(throwing: ftpError ?? FTPError.connectionFailed(message: ""))
                    } else {
                        continuation.resume()
                    }
                }
            )
        }
    }

    private func readLine() async throws -> String {
        guard let controlConnection else {
            throw FTPError.connectionFailed(message: "Not connected")
        }
        while true {
            if let newlineIndex = controlBuffer.firstIndex(of: 0x0A) {
                let lineData = controlBuffer[controlBuffer.startIndex..<newlineIndex]
                controlBuffer.removeSubrange(controlBuffer.startIndex...newlineIndex)
                var line = String(decoding: lineData, as: UTF8.self)
                if line.hasSuffix("\r") {
                    line.removeLast()
                }
                return line
            }
            guard let chunk = try await receive(on: controlConnection) else {
                let connectionID = ObjectIdentifier(controlConnection)
                let message = queue.sync { connectionErrors[connectionID]?.localizedDescription }
                throw FTPError.connectionFailed(message: message ?? "Connection closed by FTP server")
            }
            controlBuffer.append(chunk)
        }
    }

    private func readReply() async throws -> FTPReply {
        let firstLine = try await readLine()
        guard firstLine.count >= 3,
              let code = Int(firstLine.prefix(3))
        else {
            throw FTPError.invalidReply
        }
        let separator = firstLine.dropFirst(3).first
        var message = String(firstLine.dropFirst(4))
        if separator == "-" {
            let terminator = "\(code) "
            while true {
                let line = try await readLine()
                if line.hasPrefix(terminator) || line == String(code) {
                    message += "\n" + line.dropFirst(4)
                    break
                }
                message += "\n" + line
            }
        }
        return FTPReply(code: code, message: message)
    }

    private func sendCommand(_ command: String, isSensitive: Bool = false) async throws -> FTPReply {
        guard let controlConnection else {
            throw FTPError.connectionFailed(message: "Not connected")
        }
        let commandName = command.split(separator: " ", maxSplits: 1).first ?? ""
        Diag.debug("FTP > \(isSensitive ? commandName + " ***" : command)")
        try await send(Data((command + "\r\n").utf8), on: controlConnection)
        let reply = try await readReply()
        Diag.debug("FTP < \(reply.code)")
        return reply
    }

    private func openDataConnection() async throws -> NWConnection {
        var dataPort: UInt16?
        let epsvReply = try await sendCommand("EPSV")
        if epsvReply.code == 229 {
            dataPort = Self.parseEPSV(epsvReply.message)
        }
        if dataPort == nil {
            let pasvReply = try await sendCommand("PASV")
            guard pasvReply.code == 227 else {
                throw FTPError.unexpectedReply(code: pasvReply.code, message: pasvReply.message)
            }
            dataPort = Self.parsePASV(pasvReply.message)
        }
        guard let dataPort else {
            throw FTPError.invalidReply
        }
        return makeConnection(port: dataPort)
    }

    /// Parses "Entering Extended Passive Mode (|||6446|)"
    internal static func parseEPSV(_ message: String) -> UInt16? {
        guard let open = message.firstIndex(of: "("),
              let close = message[open...].firstIndex(of: ")")
        else {
            return nil
        }
        let inner = message[message.index(after: open)..<close]
        guard let delimiter = inner.first else { return nil }
        let parts = inner.split(separator: delimiter, omittingEmptySubsequences: true)
        guard let portString = parts.last else { return nil }
        return UInt16(portString)
    }

    /// Parses "Entering Passive Mode (h1,h2,h3,h4,p1,p2)".
    /// The address is ignored in favor of the control connection's host (NAT-friendly).
    internal static func parsePASV(_ message: String) -> UInt16? {
        let digits = message
            .split(whereSeparator: { !$0.isNumber && $0 != "," })
            .first(where: { $0.filter({ $0 == "," }).count == 5 })
        guard let numbers = digits?.split(separator: ",").compactMap({ UInt16($0) }),
              numbers.count == 6,
              numbers[4] <= 255, numbers[5] <= 255
        else {
            return nil
        }
        return numbers[4] * 256 + numbers[5]
    }

    /// Parses MDTM timestamps such as "20250131235959" or "20250131235959.123" (UTC).
    internal static func parseMDTM(_ message: String) -> Date? {
        let timestamp = message
            .trimmingCharacters(in: .whitespaces)
            .split(separator: ".")
            .first
            .map(String.init) ?? ""
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(identifier: "UTC")
        formatter.dateFormat = "yyyyMMddHHmmss"
        return formatter.date(from: timestamp)
    }
}
