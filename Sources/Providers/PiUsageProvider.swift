import Foundation

/// Separate carriers: never substitute a Claude Code/Codex login for Pi's account.
/// These are account-wide provider limits, not usage attributable only to Pi.
actor PiUsageProvider: UsageProvider {
    enum Service: String, CaseIterable, Sendable {
        case claude = "anthropic"
        case codex = "openai-codex"

        var name: String { self == .claude ? "Pi · Claude" : "Pi · Codex" }
        var endpoint: URL {
            URL(string: self == .claude
                ? "https://api.anthropic.com/api/oauth/usage"
                : "https://chatgpt.com/backend-api/wham/usage")!
        }
        var manageURL: URL {
            URL(string: self == .claude
                ? "https://claude.ai/settings/usage"
                : "https://chatgpt.com/#settings/Account")!
        }
    }

    nonisolated let id: String
    nonisolated let displayName: String
    nonisolated let glyph: ProviderGlyph
    nonisolated let service: Service
    nonisolated private let authURL: URL
    private let session: URLSession
    private let archive: UsageArchive
    private let checkAuth: @Sendable (String, URL) async throws -> Void
    private var checking: Task<Void, Error>?
    private var lastCheckFailure: Date?
    private var retryNoEarlierThan: Date?
    private var consecutiveRateLimits = 0

    init(service: Service, authURL: URL = PiCredentials.authURL(),
         session: URLSession = .shared, archive: UsageArchive = UsageArchive(),
         checkAuth: @escaping @Sendable (String, URL) async throws -> Void = {
             try await PiAuthCheck.run(provider: $0, authURL: $1)
         }) {
        self.service = service
        self.id = "pi-\(service.rawValue)"
        self.displayName = service.name
        self.glyph = service == .claude ? .claude : .openai
        self.authURL = authURL
        self.session = session
        self.archive = archive
        self.checkAuth = checkAuth
        self.retryNoEarlierThan = archive.loadBackoffUntil(providerID: "pi-\(service.rawValue)")
    }

    nonisolated var signInRoute: SignInRoute {
        .guidance(L10n.t("Sign in using /login in Pi. Codenotch reads Pi's auth.json and runs pi auth check to keep tokens fresh."))
    }

    nonisolated func account() -> ProviderAccount? {
        guard let credential = try? PiCredentials.load(from: authURL, provider: service.rawValue) else { return nil }
        let claims = CodexCredentials.claims(inJWT: credential.accessToken)
        let auth = claims?["https://api.openai.com/auth"] as? [String: Any]
        let profile = claims?["https://api.openai.com/profile"] as? [String: Any]
        return ProviderAccount(
            label: profile?["email"] as? String ?? claims?["email"] as? String ?? credential.accountID,
            plan: auth?["chatgpt_plan_type"] as? String,
            source: "Pi", manageURL: service.manageURL
        )
    }

    private func ensureFresh() async throws {
        if let checking { return try await checking.value }
        // Failed checks must not spawn a CLI storm. Successful checks are cheap
        // and run once per normal usage poll; only Pi decides whether to rotate.
        if let lastCheckFailure, Date().timeIntervalSince(lastCheckFailure) < 30 {
            throw UsageProviderError.credentialExpired
        }
        let provider = service.rawValue
        let url = authURL
        let check = checkAuth
        let task = Task { try await check(provider, url) }
        checking = task
        defer { checking = nil }
        do {
            try await task.value
            lastCheckFailure = nil
        } catch {
            lastCheckFailure = Date()
            throw error
        }
    }

    func fetchSnapshot() async throws -> ProviderSnapshot {
        if let until = retryNoEarlierThan, until > Date() {
            throw UsageProviderError.rateLimited(retryAfter: until.timeIntervalSinceNow)
        }
        // Do not invoke Pi for absent/API-key entries: these subscription
        // endpoints cannot meter them. Never copy a credential to another store.
        _ = try PiCredentials.load(from: authURL, provider: service.rawValue)
        try await ensureFresh()
        try Task.checkCancellation()
        // Pi may have rotated credentials or the user may have signed out while
        // the check ran. Always reread, even when the old token was unexpired.
        let credential = try PiCredentials.load(from: authURL, provider: service.rawValue)
        guard !credential.isExpired else { throw UsageProviderError.credentialExpired }

        var request = URLRequest(url: service.endpoint,
                                 cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 15)
        request.setValue("Bearer \(credential.accessToken)", forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        if service == .claude {
            request.setValue("oauth-2025-04-20", forHTTPHeaderField: "anthropic-beta")
        } else {
            let claims = CodexCredentials.claims(inJWT: credential.accessToken)
            let auth = claims?["https://api.openai.com/auth"] as? [String: Any]
            guard let accountID = credential.accountID ?? auth?["chatgpt_account_id"] as? String,
                  !accountID.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                throw UsageProviderError.needsAuth
            }
            request.setValue(accountID, forHTTPHeaderField: "ChatGPT-Account-Id")
        }
        let (data, response) = try await session.data(for: request)
        let status = (response as? HTTPURLResponse)?.statusCode ?? 0
        if status == 401 || status == 403 { throw UsageProviderError.needsAuth }
        if status == 429 {
            let delay = ClaudeOAuthProvider.backoff(forAttempt: consecutiveRateLimits,
                retryAfter: ClaudeOAuthProvider.retryAfter(from: response))
            consecutiveRateLimits += 1
            retryNoEarlierThan = Date().addingTimeInterval(delay)
            archive.saveBackoffUntil(retryNoEarlierThan, providerID: id)
            throw UsageProviderError.rateLimited(retryAfter: delay)
        }
        guard (200..<300).contains(status) else { throw UsageProviderError.badResponse(status: status) }
        let windows: [LimitWindow]
        if service == .claude {
            windows = try UsageResponse.decoder.decode(UsageResponse.self, from: data).limitWindows()
            guard !windows.isEmpty else { throw UsageProviderError.badResponse(status: status) }
        } else {
            windows = try CodexUsage.windows(from: data,
                includeExtras: Preferences.storedShowCodexExtraLimits())
        }
        consecutiveRateLimits = 0
        retryNoEarlierThan = nil
        archive.saveBackoffUntil(nil, providerID: id)
        return ProviderSnapshot(id: id, displayName: displayName, glyph: glyph,
            fidelity: .official, status: .ok, windows: windows,
            headlineID: service == .claude ? "session" : "primary",
            weeklyID: service == .claude ? "weekly_all" : "secondary",
            plan: service == .codex ? CodexUsage.plan(from: data) : nil)
    }
}
