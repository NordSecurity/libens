import Foundation

private let newline = Data("\n".utf8)

struct Handshake: Decodable {
    let port: UInt16
    let publicKey: String
    let rootCertificate: String
    let username: String?
    let password: String?
}

enum StubError: Error {
    case announcedNothing
    case didNotExit
    case exited(Int32)
}

final class StubServer {
    private static let stubEnvVar = "ENS_STUB"
    private static let exitTimeout = 10.0
    private static let pollInterval: UInt32 = 10_000

    private let process = Process()
    private let input: FileHandle

    let handshake: Handshake

    var publicKey: Data { Data(base64Encoded: handshake.publicKey)! }

    var rootCertificate: Data { Data(base64Encoded: handshake.rootCertificate)! }

    init(schema: String) throws {
        let output = Pipe()
        let stdin = Pipe()
        input = stdin.fileHandleForWriting

        process.executableURL = URL(fileURLWithPath: StubServer.stubPath())
        process.arguments = [schema]
        process.standardInput = stdin
        process.standardOutput = output

        try process.run()

        do {
            guard let announcement = StubServer.readLine(output.fileHandleForReading) else {
                throw StubError.announcedNothing
            }

            let decoder = JSONDecoder()
            decoder.keyDecodingStrategy = .convertFromSnakeCase
            handshake = try decoder.decode(Handshake.self, from: announcement)
        } catch {
            process.terminate()
            throw error
        }
    }

    func notify(code: Int32, additionalInfo: String?) {
        send(["command": "notification", "code": code, "additional_info": additionalInfo])
    }

    func shutdown() throws {
        try? input.close()

        let deadline = Date(timeIntervalSinceNow: StubServer.exitTimeout)
        while process.isRunning && Date() < deadline {
            usleep(StubServer.pollInterval)
        }

        guard !process.isRunning else {
            process.terminate()
            throw StubError.didNotExit
        }

        guard process.terminationStatus == 0 else {
            throw StubError.exited(process.terminationStatus)
        }
    }

    private func send(_ command: [String: Any?]) {
        let line = try! JSONSerialization.data(withJSONObject: command.compactMapValues { $0 })
        input.write(line + newline)
    }

    private static func readLine(_ handle: FileHandle) -> Data? {
        var line = Data()
        while case let byte = handle.readData(ofLength: 1), !byte.isEmpty {
            guard byte != newline else { return line }
            line.append(byte)
        }

        return line.isEmpty ? nil : line
    }

    private static func stubPath() -> String {
        if let configured = ProcessInfo.processInfo.environment[stubEnvVar], !configured.isEmpty {
            return configured
        }

        let target = ProcessInfo.processInfo.environment["CARGO_TARGET_DIR"] ?? "../../target"
        return "\(target)/debug/ens-stub"
    }
}
