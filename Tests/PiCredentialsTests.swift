import XCTest
@testable import Codenotch

final class PiCredentialsTests: XCTestCase {
    private func home() throws -> URL {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("PiCredentialsTests-\(UUID())")
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: url) }
        return url
    }

    @discardableResult
    private func write(_ text: String, to url: URL) throws -> URL {
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Data(text.utf8).write(to: url)
        return url
    }

    private func oauth(expires: String = "4102444800000", extra: String = "") -> String {
        "{\"type\":\"oauth\",\"access\":\"fake-access\",\"refresh\":\"fake-refresh\",\"expires\":\(expires)\(extra)}"
    }

    private func assertNeedsAuth(_ action: () throws -> Void, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try action(), file: file, line: line) { error in
            guard case UsageProviderError.needsAuth = error else {
                return XCTFail("Expected needsAuth", file: file, line: line)
            }
        }
    }

    func testDefaultAndLegacyResolution() throws {
        let root = try home()
        let current = root.appendingPathComponent(".pi/agent/auth.json")
        let legacy = root.appendingPathComponent(".pi/auth.json")
        XCTAssertEqual(PiCredentials.authURL(environment: [:], home: root.path), current)
        try write("{}", to: legacy)
        XCTAssertEqual(PiCredentials.authURL(environment: [:], home: root.path), legacy)
        try write("invalid", to: current)
        XCTAssertEqual(PiCredentials.authURL(environment: [:], home: root.path), current,
                       "A present but invalid current store must never select another identity")
    }

    func testEnvironmentPrecedenceAndNoFallbackForOverrides() throws {
        let root = try home()
        try write("{}", to: root.appendingPathComponent(".pi/auth.json"))
        let old = root.appendingPathComponent("old")
        let preferred = root.appendingPathComponent("preferred")
        XCTAssertEqual(PiCredentials.authURL(environment: ["PI_AGENT_DIR": old.path], home: root.path),
                       old.appendingPathComponent("auth.json"))
        XCTAssertEqual(PiCredentials.authURL(environment: ["PI_AGENT_DIR": old.path,
                                                          "PI_CODING_AGENT_DIR": preferred.path], home: root.path),
                       preferred.appendingPathComponent("auth.json"))
        XCTAssertEqual(PiCredentials.authURL(environment: ["PI_AGENT_DIR": old.path,
                                                          "PI_CODING_AGENT_DIR": ""], home: root.path),
                       old.appendingPathComponent("auth.json"))
        XCTAssertEqual(PiCredentials.authURL(environment: ["PI_CODING_AGENT_DIR": "~/custom"], home: root.path),
                       root.appendingPathComponent("custom/auth.json"))
    }

    func testOAuthAndExpiryUseMilliseconds() throws {
        let url = try write("{\"anthropic\":\(oauth(extra: ",\"accountId\":\"account-123\""))}",
                            to: try home().appendingPathComponent("auth.json"))
        let value = try PiCredentials.load(from: url, provider: "anthropic")
        XCTAssertEqual(value.accessToken, "fake-access")
        XCTAssertEqual(value.accountID, "account-123")
        XCTAssertEqual(value.expiresAt.timeIntervalSince1970, 4_102_444_800)
        XCTAssertFalse(value.isExpired)
        try write("{\"anthropic\":\(oauth(expires: "1"))}", to: url)
        let expired = try PiCredentials.load(from: url, provider: "anthropic")
        XCTAssertTrue(expired.isExpired, "Expired OAuth is returned so the owner can refresh it")
        XCTAssertNil(expired.accountID)
    }

    func testProviderIsolationAndNoCredentialWrites() throws {
        let original = "{\"anthropic\":\(oauth()),\"openai-codex\":null,\"other\":17}"
        let url = try write(original, to: try home().appendingPathComponent("auth.json"))
        XCTAssertEqual(try PiCredentials.load(from: url, provider: "anthropic").accessToken, "fake-access")
        assertNeedsAuth { _ = try PiCredentials.load(from: url, provider: "openai-codex") }
        assertNeedsAuth { _ = try PiCredentials.load(from: url, provider: "absent") }
        XCTAssertEqual(try String(contentsOf: url, encoding: .utf8), original)
    }

    func testRejectsAPIKeysTombstonesAndMalformedEntries() throws {
        let url = try home().appendingPathComponent("auth.json")
        let invalid = [
            "null", "{}", "[]", "\"token\"",
            "{\"type\":\"api_key\",\"key\":\"fake-key\"}",
            oauth().replacingOccurrences(of: "oauth", with: "OAuth"),
            oauth().replacingOccurrences(of: "fake-access", with: ""),
            oauth().replacingOccurrences(of: "fake-refresh", with: "  "),
            "{\"type\":\"oauth\",\"access\":\"fake\",\"expires\":4102444800000}",
            oauth(extra: ",\"accountId\":123")
        ]
        for entry in invalid {
            try write("{\"anthropic\":\(entry)}", to: url)
            assertNeedsAuth { _ = try PiCredentials.load(from: url, provider: "anthropic") }
        }
        for document in ["not json", "[]", "null", "{\"anthropic\":"] {
            try write(document, to: url)
            assertNeedsAuth { _ = try PiCredentials.load(from: url, provider: "anthropic") }
        }
    }

    func testRejectsNonNumericNonFiniteAndNonPositiveExpiry() throws {
        let url = try home().appendingPathComponent("auth.json")
        for expiry in ["0", "-1", "true", "null", "\"4102444800000\"", "1e999", "NaN"] {
            try write("{\"anthropic\":\(oauth(expires: expiry))}", to: url)
            assertNeedsAuth { _ = try PiCredentials.load(from: url, provider: "anthropic") }
        }
    }

    func testReadBoundAndMissingOrNonRegularStore() throws {
        let root = try home()
        let url = root.appendingPathComponent("auth.json")
        assertNeedsAuth { _ = try PiCredentials.load(from: url, provider: "anthropic") }
        let valid = "{\"anthropic\":\(oauth())}"
        try write(valid + String(repeating: " ", count: 256 * 1024 - valid.utf8.count), to: url)
        XCTAssertNoThrow(try PiCredentials.load(from: url, provider: "anthropic"))
        try write(valid + String(repeating: " ", count: 256 * 1024), to: url)
        assertNeedsAuth { _ = try PiCredentials.load(from: url, provider: "anthropic") }
        assertNeedsAuth { _ = try PiCredentials.load(from: root, provider: "anthropic") }
        try FileManager.default.removeItem(at: url)
        XCTAssertEqual(mkfifo(url.path, 0o600), 0)
        assertNeedsAuth { _ = try PiCredentials.load(from: url, provider: "anthropic") }
    }

    @discardableResult
    private func script(_ body: String, root: URL, path: String = "bin/pi") throws -> URL {
        let url = try write("#!/bin/sh\n" + body + "\n", to: root.appendingPathComponent(path))
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: url.path)
        return url
    }

    func testCLIPathPrecedenceAndGUINodeLocations() throws {
        let root = try home()
        let volta = try script("exit 0", root: root, path: ".volta/bin/pi")
        let nvm = try script("exit 0", root: root, path: ".nvm/versions/node/v22.12.0/bin/pi")
        try script("exit 0", root: root, path: ".nvm/versions/node/v9.0.0/bin/pi")
        let explicit = try script("exit 0", root: root, path: "chosen/pi")
        let dirs = PiAuthCheck.searchDirectories(environment: ["PATH": ":.:relative:\(explicit.deletingLastPathComponent().path)"], home: root.path)
        XCTAssertEqual(PiAuthCheck.findExecutable(in: dirs), explicit)
        XCTAssertFalse(dirs.contains("."))
        XCTAssertFalse(dirs.contains("relative"))
        XCTAssertTrue(dirs.contains(root.appendingPathComponent(".local/bin").path))
        XCTAssertTrue(dirs.contains(root.appendingPathComponent(".npm-global/bin").path))
        XCTAssertTrue(dirs.contains("/opt/homebrew/bin"))
        XCTAssertEqual(PiAuthCheck.findExecutable(in: PiAuthCheck.searchDirectories(environment: [:], home: root.path)), volta)
        try FileManager.default.removeItem(at: volta)
        XCTAssertEqual(PiAuthCheck.findExecutable(in: PiAuthCheck.searchDirectories(environment: [:], home: root.path)), nvm)
    }

    func testReadyUsesExactStoreNeutralCWDNoCredentialsAndClosedStdin() async throws {
        let root = try home()
        let auth = try write("fixture unchanged", to: root.appendingPathComponent("selected store/auth.json"))
        let cli = try script("""
        [ "$#" -eq 5 ] || exit 10
        [ "$1" = auth ] && [ "$2" = check ] && [ "$3" = --provider ] || exit 11
        [ "$4" = 'anthropic; do-not-run' ] && [ "$5" = --json ] || exit 12
        [ "$PI_CODING_AGENT_DIR" = "$HOME/selected store" ] || exit 13
        [ "$(pwd -P)" = "$(cd "$HOME" && pwd -P)" ] || exit 14
        [ -z "$PI_AGENT_DIR$NODE_OPTIONS$NODE_PATH$INIT_CWD" ] || exit 15
        read input && exit 16
        printf 'secret diagnostic that must not be captured' >&2
        printf '{"status":"ready"}'
        """, root: root, path: ".volta/bin/pi")
        // Discovery, not an executable override, proves GUI PATH recovery.
        try await PiAuthCheck.run(provider: "anthropic; do-not-run", authURL: auth,
                                  environment: ["PATH": "/usr/bin:/bin", "PI_AGENT_DIR": "/wrong",
                                                "PI_CODING_AGENT_DIR": "/also-wrong", "PI_SESSION_ID": "harmless",
                                                "NODE_OPTIONS": "--require project", "NODE_PATH": "/project",
                                                "INIT_CWD": "/project"], home: root.path)
        XCTAssertTrue(FileManager.default.isExecutableFile(atPath: cli.path))
        XCTAssertEqual(try String(contentsOf: auth, encoding: .utf8), "fixture unchanged")
    }

    func testNodeShebangCanFindNodeBesideNVMExecutable() async throws {
        let root = try home()
        // A fake node: no real runtime, Pi, credentials or network involved.
        try script("printf '{\"status\":\"ready\"}'", root: root, path: ".nvm/versions/node/v22.0.0/bin/node")
        let cli = try write("#!/usr/bin/env node\n", to: root.appendingPathComponent(".nvm/versions/node/v22.0.0/bin/pi"))
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: cli.path)
        try await PiAuthCheck.run(provider: "anthropic", authURL: root.appendingPathComponent("auth.json"),
                                  environment: ["PATH": "/usr/bin:/bin"], home: root.path)
    }

    private func assertCheckError(body: String, needsAuth: Bool = false, timeout: TimeInterval = 2,
                                  file: StaticString = #filePath, line: UInt = #line) async throws {
        let root = try home()
        let cli = try script(body, root: root)
        do {
            try await PiAuthCheck.run(provider: "anthropic", authURL: root.appendingPathComponent("auth.json"),
                                      timeout: timeout, environment: [:], home: root.path, executable: cli)
            XCTFail("Expected auth check failure", file: file, line: line)
        } catch {
            switch error {
            case UsageProviderError.needsAuth where needsAuth: break
            case UsageProviderError.credentialExpired where !needsAuth: break
            default: XCTFail("Incorrect auth check error", file: file, line: line)
            }
        }
    }

    func testNotReadyMeansNeedsAuthEvenWithNonzeroExit() async throws {
        try await assertCheckError(body: "printf '{\"status\":\"not_ready\"}'; exit 1", needsAuth: true)
    }

    func testNonzeroMalformedAndUnknownResultsPreserveExpiredState() async throws {
        for body in ["printf '{\"status\":\"ready\"}'; exit 2", "exit 1", "printf 'not json'",
                     "printf '{\"status\":\"error\"}'", "printf '{}'", "printf '{\"status\":true}'"] {
            try await assertCheckError(body: body)
        }
    }

    func testOutputIsBounded() async throws {
        try await assertCheckError(body: "while :; do printf 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'; done")
    }

    func testMissingExecutableMeansCredentialExpired() async throws {
        let root = try home()
        do {
            try await PiAuthCheck.run(provider: "anthropic", authURL: root.appendingPathComponent("auth.json"),
                                      environment: [:], home: root.path, executable: root.appendingPathComponent("absent"))
            XCTFail("Expected launch failure")
        } catch {
            guard case UsageProviderError.credentialExpired = error else { return XCTFail("Wrong error") }
        }
    }

    func testTimeoutKillsEvenAChildIgnoringTermination() async throws {
        let root = try home()
        let cli = try script("trap '' TERM\nprintf '%s' \"$$\" > \"$HOME/pid\"\nwhile :; do :; done", root: root)
        let started = Date()
        do {
            try await PiAuthCheck.run(provider: "anthropic", authURL: root.appendingPathComponent("auth.json"),
                                      timeout: 1, environment: [:], home: root.path, executable: cli)
            XCTFail("Expected timeout")
        } catch {
            guard case UsageProviderError.credentialExpired = error else { return XCTFail("Wrong error") }
        }
        XCTAssertLessThan(Date().timeIntervalSince(started), 3)
        let pid = try XCTUnwrap(Int32(String(contentsOf: root.appendingPathComponent("pid"), encoding: .utf8)))
        XCTAssertEqual(kill(pid, 0), -1)
        XCTAssertEqual(errno, ESRCH)
    }
}
