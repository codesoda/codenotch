import XCTest
@testable import Codenotch

final class PiUsageProviderTests: XCTestCase {
    private var directory: URL!
    private var authURL: URL { directory.appendingPathComponent("auth.json") }
    private var defaults: UserDefaults!
    private var suite: String!

    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        suite = "PiUsageProviderTests.\(UUID().uuidString)"
        defaults = UserDefaults(suiteName: suite)!
        PiEndpoint.reset()
    }

    override func tearDownWithError() throws {
        try FileManager.default.removeItem(at: directory)
        defaults.removePersistentDomain(forName: suite)
    }

    private func store(provider: String = "anthropic", token: String = "old", expires: Double = 9_000_000_000_000) throws {
        try Self.store(url: authURL, provider: provider, token: token, expires: expires)
    }

    private static func store(url: URL, provider: String, token: String, expires: Double) throws {
        let data = try JSONSerialization.data(withJSONObject: [provider: [
            "type": "oauth", "access": token, "refresh": "fake-refresh", "expires": expires,
            "accountId": "pi-account"
        ]])
        try data.write(to: url)
    }

    private func provider(_ service: PiUsageProvider.Service = .claude,
                          check: @escaping @Sendable (String, URL) async throws -> Void = { _, _ in }) -> PiUsageProvider {
        PiUsageProvider(service: service, authURL: authURL, session: PiEndpoint.session(),
                        archive: UsageArchive(defaults: defaults), checkAuth: check)
    }

    func testExpiredCredentialIsRefreshedByPiAndReread() async throws {
        try store(expires: 1)
        let p = provider { key, url in
            XCTAssertEqual(key, "anthropic")
            try Self.store(url: url, provider: key, token: "rotated", expires: 9_000_000_000_000)
        }
        let snapshot = try await p.fetchSnapshot()
        XCTAssertEqual(snapshot.id, "pi-anthropic")
        XCTAssertEqual(snapshot.windows.first?.usedFraction, 0.25)
        XCTAssertEqual(PiEndpoint.requests.first?.value(forHTTPHeaderField: "Authorization"), "Bearer rotated")
        XCTAssertEqual(PiEndpoint.requests.first?.value(forHTTPHeaderField: "anthropic-beta"), "oauth-2025-04-20")
    }

    func testFreshTokensAreAlsoCheckedAndReread() async throws {
        try store()
        let p = provider { key, url in
            try Self.store(url: url, provider: key, token: "new-account", expires: 9_000_000_000_000)
        }
        _ = try await p.fetchSnapshot()
        XCTAssertEqual(PiEndpoint.requests.first?.value(forHTTPHeaderField: "Authorization"), "Bearer new-account")
        XCTAssertEqual(p.account()?.source, "Pi")
    }

    func testCodexUsesPiAccountAndExistingWindowParser() async throws {
        try store(provider: "openai-codex")
        PiEndpoint.reset(body: """
        {"plan_type":"pro","rate_limit":{"primary_window":{"used_percent":30,"limit_window_seconds":18000},
        "secondary_window":{"used_percent":40,"limit_window_seconds":604800}}}
        """)
        let snapshot = try await provider(.codex).fetchSnapshot()
        XCTAssertEqual(snapshot.id, "pi-openai-codex")
        XCTAssertEqual(snapshot.windows.map(\.usedFraction), [0.3, 0.4])
        XCTAssertEqual(PiEndpoint.requests.first?.url?.host, "chatgpt.com")
        XCTAssertEqual(PiEndpoint.requests.first?.value(forHTTPHeaderField: "ChatGPT-Account-Id"), "pi-account")
    }

    func testMissingEntryNeverChecksOrUsesAnotherLogin() async throws {
        try store(provider: "openai-codex")
        let p = provider { _, _ in XCTFail("must not run Pi for missing entry") }
        do { _ = try await p.fetchSnapshot(); XCTFail("expected failure") }
        catch UsageProviderError.needsAuth { }
        XCTAssertTrue(PiEndpoint.requests.isEmpty)
    }

    func testSignOutDuringCheckDoesNotUseOldToken() async throws {
        try store()
        let p = provider { _, url in try Data("{}".utf8).write(to: url) }
        do { _ = try await p.fetchSnapshot(); XCTFail("expected failure") }
        catch UsageProviderError.needsAuth { }
        XCTAssertTrue(PiEndpoint.requests.isEmpty)
    }

    func testReadyButStillExpiredIsNotSent() async throws {
        try store(expires: 1)
        do { _ = try await provider().fetchSnapshot(); XCTFail("expected failure") }
        catch UsageProviderError.credentialExpired { }
        XCTAssertTrue(PiEndpoint.requests.isEmpty)
    }

    func testCheckFailureHasCooldownAndNoNetwork() async throws {
        try store()
        let p = provider { _, _ in throw UsageProviderError.needsAuth }
        do { _ = try await p.fetchSnapshot(); XCTFail("expected failure") }
        catch UsageProviderError.needsAuth { }
        do { _ = try await p.fetchSnapshot(); XCTFail("expected cooldown") }
        catch UsageProviderError.credentialExpired { }
        XCTAssertTrue(PiEndpoint.requests.isEmpty)
    }

    func testRateLimitPersistsAndSkipsAuthAndNetwork() async throws {
        try store()
        PiEndpoint.reset(status: 429)
        do { _ = try await provider().fetchSnapshot(); XCTFail("expected rate limit") }
        catch UsageProviderError.rateLimited { }
        let recreated = provider { _, _ in XCTFail("must respect persisted backoff") }
        do { _ = try await recreated.fetchSnapshot(); XCTFail("expected rate limit") }
        catch UsageProviderError.rateLimited { }
        XCTAssertEqual(PiEndpoint.requests.count, 1)
    }

    func testUnauthorizedDoesNotFallBackToNativeAccount() async throws {
        try store()
        PiEndpoint.reset(status: 401)
        do { _ = try await provider().fetchSnapshot(); XCTFail("expected needsAuth") }
        catch UsageProviderError.needsAuth { }
        XCTAssertEqual(PiEndpoint.requests.count, 1)
    }
}

private final class PiEndpoint: URLProtocol {
    private static let lock = NSLock()
    private static var recorded: [URLRequest] = []
    private static var status = 200
    private static var body = ""
    static var requests: [URLRequest] { lock.lock(); defer { lock.unlock() }; return recorded }

    static func reset(status: Int = 200, body: String = "{\"five_hour\":{\"utilization\":25,\"resets_at\":\"2099-01-01T00:00:00Z\"}}") {
        lock.lock(); defer { lock.unlock() }
        recorded = []; self.status = status; self.body = body
    }
    static func session() -> URLSession {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [PiEndpoint.self]
        return URLSession(configuration: config)
    }
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        Self.lock.lock()
        Self.recorded.append(request)
        let status = Self.status, body = Self.body
        Self.lock.unlock()
        let response = HTTPURLResponse(url: request.url!, statusCode: status, httpVersion: nil, headerFields: nil)!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: Data(body.utf8))
        client?.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() {}
}
