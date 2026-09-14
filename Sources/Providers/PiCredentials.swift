import Foundation
import Darwin

/// Read-only borrowing of Pi's OAuth store. Pi alone owns token renewal.
enum PiCredentials {
    struct Credential: Sendable {
        let accessToken: String
        let expiresAt: Date
        let accountID: String?

        var isExpired: Bool { expiresAt <= Date() }
    }

    static func authURL(
        environment: [String: String] = ProcessInfo.processInfo.environment,
        home: String = NSHomeDirectory()
    ) -> URL {
        for key in ["PI_CODING_AGENT_DIR", "PI_AGENT_DIR"] {
            if let directory = environment[key], !directory.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                return directoryURL(directory, home: home).appendingPathComponent("auth.json")
            }
        }
        let root = URL(fileURLWithPath: home, isDirectory: true).appendingPathComponent(".pi")
        let current = root.appendingPathComponent("agent/auth.json")
        let legacy = root.appendingPathComponent("auth.json")
        if !FileManager.default.fileExists(atPath: current.path),
           FileManager.default.fileExists(atPath: legacy.path) { return legacy }
        return current
    }

    static func load(from url: URL, provider: String) throws -> Credential {
        // O_NONBLOCK plus fstat also refuses named pipes/devices: a malformed
        // store must not turn a small local read into an unbounded wait.
        guard url.isFileURL else { throw UsageProviderError.needsAuth }
        let fd = open(url.path, O_RDONLY | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else { throw UsageProviderError.needsAuth }
        let file = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        defer { try? file.close() }
        var info = stat()
        let limit = 256 * 1024
        guard fstat(fd, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG,
              info.st_size <= limit else { throw UsageProviderError.needsAuth }
        var data = Data()
        do {
            while data.count <= limit {
                guard let chunk = try file.read(upToCount: limit + 1 - data.count), !chunk.isEmpty else { break }
                data.append(chunk)
            }
        } catch { throw UsageProviderError.needsAuth }
        guard data.count <= limit,
              let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let entry = root[provider] as? [String: Any],
              let entryData = try? JSONSerialization.data(withJSONObject: entry),
              let oauth = try? JSONDecoder().decode(OAuth.self, from: entryData),
              oauth.type == "oauth",
              !oauth.access.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              !oauth.refresh.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              oauth.expires.isFinite, oauth.expires > 0
        else { throw UsageProviderError.needsAuth }
        return Credential(accessToken: oauth.access,
                          expiresAt: Date(timeIntervalSince1970: oauth.expires / 1000),
                          accountID: oauth.accountId?.trimmingCharacters(in: .whitespacesAndNewlines).nilIfEmpty)
    }

    private struct OAuth: Decodable {
        let type: String
        let access: String
        let refresh: String
        let expires: Double
        let accountId: String?
    }

    fileprivate static func directoryURL(_ path: String, home: String) -> URL {
        let expanded = path == "~" ? home : path.hasPrefix("~/") ? home + String(path.dropFirst()) : path
        return URL(fileURLWithPath: expanded, relativeTo: URL(fileURLWithPath: home, isDirectory: true))
            .absoluteURL.standardizedFileURL
    }
}

private extension String {
    var nilIfEmpty: String? { isEmpty ? nil : self }
}

/// Never requests credential output, logs it, or refreshes against an OAuth
/// endpoint itself. After this succeeds the caller must reread the same store.
enum PiAuthCheck {
    static func run(
        provider: String, authURL: URL,
        timeout: TimeInterval = 20,
        environment: [String: String] = ProcessInfo.processInfo.environment,
        home: String = NSHomeDirectory(),
        executable: URL? = nil
    ) async throws {
        // Process launch, polling, and file descriptor reads stay off Swift's
        // cooperative executor. The test seams never need a real Pi install.
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            DispatchQueue.global(qos: .utility).async {
                do {
                    try runBlocking(provider: provider, authURL: authURL, timeout: timeout,
                                    environment: environment, home: home, executable: executable)
                    continuation.resume()
                } catch { continuation.resume(throwing: error) }
            }
        }
    }

    static func searchDirectories(environment: [String: String], home: String) -> [String] {
        var paths = (environment["PATH"] ?? "").split(separator: ":").map(String.init)
            .filter { $0.hasPrefix("/") }
        paths += [".volta/bin", ".local/bin", ".npm-global/bin", ".npm/bin", "npm-global/bin"]
            .map { home + "/" + $0 }
        for key in ["VOLTA_HOME", "NPM_CONFIG_PREFIX", "npm_config_prefix"] {
            if let path = environment[key], !path.isEmpty {
                paths.append(PiCredentials.directoryURL(path, home: home).appendingPathComponent("bin").path)
            }
        }
        let nvm = PiCredentials.directoryURL(environment["NVM_DIR"] ?? "~/.nvm", home: home)
            .appendingPathComponent("versions/node")
        let versions = (try? FileManager.default.contentsOfDirectory(atPath: nvm.path)) ?? []
        paths += versions.sorted { $0.compare($1, options: .numeric) == .orderedDescending }
            .map { nvm.appendingPathComponent($0).appendingPathComponent("bin").path }
        paths += ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin"]
        var seen = Set<String>()
        return paths.filter { seen.insert($0).inserted }
    }

    static func findExecutable(in directories: [String]) -> URL? {
        directories.lazy.map { URL(fileURLWithPath: $0).appendingPathComponent("pi") }
            .first { FileManager.default.isExecutableFile(atPath: $0.path) }
    }

    private static func runBlocking(
        provider: String, authURL: URL, timeout: TimeInterval,
        environment: [String: String], home: String, executable: URL?
    ) throws {
        guard timeout.isFinite, timeout > 0, authURL.isFileURL,
              authURL.lastPathComponent == "auth.json", !provider.isEmpty
        else { throw UsageProviderError.credentialExpired }
        let directories = searchDirectories(environment: environment, home: home)
        guard let cli = executable ?? findExecutable(in: directories) else {
            throw UsageProviderError.credentialExpired
        }
        var env = environment
        env["PATH"] = ([cli.deletingLastPathComponent().path] + directories).joined(separator: ":")
        env["HOME"] = home
        env["PWD"] = home
        env["PI_CODING_AGENT_DIR"] = authURL.deletingLastPathComponent().path
        env.removeValue(forKey: "PI_AGENT_DIR")
        // Do not inherit Node preload hooks or project-oriented npm context.
        for key in ["NODE_OPTIONS", "NODE_PATH", "INIT_CWD"] { env.removeValue(forKey: key) }
        let process = Process()
        process.executableURL = cli
        process.arguments = ["auth", "check", "--provider", provider, "--json"]
        process.environment = env
        process.currentDirectoryURL = URL(fileURLWithPath: home, isDirectory: true)
        process.standardInput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        let pipe = Pipe()
        process.standardOutput = pipe
        defer {
            try? pipe.fileHandleForReading.close()
            try? pipe.fileHandleForWriting.close()
        }
        let fd = pipe.fileHandleForReading.fileDescriptor
        guard fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK) != -1 else {
            throw UsageProviderError.credentialExpired
        }
        let started = ProcessInfo.processInfo.systemUptime
        do { try process.run() } catch { throw UsageProviderError.credentialExpired }
        try? pipe.fileHandleForWriting.close()
        var output = Data()
        let limit = 64 * 1024
        var buffer = [UInt8](repeating: 0, count: 4096)
        var reachedEOF = false
        while true {
            // Read at most one buffer per tick, checking the deadline even if a
            // child continuously floods stdout or leaves it open in a descendant.
            let count = Darwin.read(fd, &buffer, min(buffer.count, limit + 1 - output.count))
            if count > 0 { output.append(contentsOf: buffer.prefix(count)) }
            else if count == 0 { reachedEOF = true }
            else if errno != EAGAIN && errno != EINTR {
                stop(process)
                throw UsageProviderError.credentialExpired
            }
            if output.count > limit || ProcessInfo.processInfo.systemUptime - started >= timeout {
                stop(process)
                throw UsageProviderError.credentialExpired
            }
            if !process.isRunning && reachedEOF { break }
            if count <= 0 { Thread.sleep(forTimeInterval: 0.01) }
        }
        guard let result = try? JSONDecoder().decode(CheckResult.self, from: output) else {
            throw UsageProviderError.credentialExpired
        }
        if result.status == "not_ready" { throw UsageProviderError.needsAuth }
        guard process.terminationReason == .exit, process.terminationStatus == 0,
              result.status == "ready" else { throw UsageProviderError.credentialExpired }
    }

    private struct CheckResult: Decodable { let status: String }

    private static func stop(_ process: Process) {
        guard process.isRunning else { return }
        process.terminate()
        let grace = ProcessInfo.processInfo.systemUptime + 0.2
        while process.isRunning && ProcessInfo.processInfo.systemUptime < grace {
            Thread.sleep(forTimeInterval: 0.01)
        }
        if process.isRunning { kill(process.processIdentifier, SIGKILL) }
        // Foundation reaps the child. Do not waitUntilExit: even cleanup has a
        // bound, including when a descendant has inherited the output pipe.
        let reapDeadline = ProcessInfo.processInfo.systemUptime + 1
        while process.isRunning && ProcessInfo.processInfo.systemUptime < reapDeadline {
            Thread.sleep(forTimeInterval: 0.01)
        }
    }
}
