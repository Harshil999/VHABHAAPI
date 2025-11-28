using ABHA_HIMS.Application.External;
using ABHA_HIMS.Application.Interfaces;
using ABHA_HIMS.Domain;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;
using System.Threading.Tasks;
using static ABHA_HIMS.Domain.AbhaDtos;
namespace ABHA_HIMS.Infrastructure.Abha;

public class AbhaGatewayService : IAbhaGatewayService
{
    private readonly IHttpClientFactory _httpFactory;
    private readonly AbhaOptions _opt;
    private readonly IAbhaAuditRepository _audit;
    private readonly IMemoryCache _cache;
    private readonly IConfiguration _config;
    private readonly IAbhaHttpClient _abhaHttpClient;
    // per-client locks to avoid thundering herd
    private static readonly ConcurrentDictionary<string, SemaphoreSlim> _locks = new();

    public AbhaGatewayService(
        IHttpClientFactory httpFactory,
        IOptions<AbhaOptions> opt,
        IAbhaAuditRepository audit,
        IMemoryCache cache,
        IConfiguration config,
        IAbhaHttpClient abhaHttpClient)
    {
        _httpFactory = httpFactory;
        _opt = opt.Value;
        _audit = audit;
        _cache = cache;
        _config = config;
        _abhaHttpClient = abhaHttpClient;
    }

    // wrapper we store in cache — keeps issued timestamp for lifetime checks
    private class SessionCacheItem
    {
        public SessionResponse Session { get; init; } = default!;
        public DateTime IssuedAtUtc { get; init; }
    }

    // --------------------
    // Parameterless: use configured clientId/clientSecret from AbhaOptions
    // --------------------
    public async Task<SessionResponse> GetSessionTokenAsync()
    {
        var clientId = _opt.ClientId ?? throw new InvalidOperationException("Abha ClientId not configured");
        var clientSecret = _opt.ClientSecret ?? throw new InvalidOperationException("Abha ClientSecret not configured");

        return await GetSessionTokenForClientAsync(clientId, clientSecret);
    }

    public Task<SessionResponse> GetSessionTokenAsync(string clientId, string clientSecret)
        => GetSessionTokenForClientAsync(clientId, clientSecret);

    // central method: check cache first, refresh if needed
    private async Task<SessionResponse> GetSessionTokenForClientAsync(string clientId, string clientSecret)
    {
        var cacheKey = $"abha_session_{clientId}";

        // 1) try fast path - cache
        if (_cache.TryGetValue<SessionResponse>(cacheKey, out var cachedSession))
        {
            // quick check: ensure token string not null
            if (!string.IsNullOrWhiteSpace(cachedSession?.AccessToken))
                return cachedSession;
        }

        // 2) Acquire per-client lock so only one fetch happens
        var sem = _locks.GetOrAdd(cacheKey, _ => new SemaphoreSlim(1, 1));
        await sem.WaitAsync();
        try
        {
            // Double-check after acquiring lock
            if (_cache.TryGetValue<SessionResponse>(cacheKey, out cachedSession))
            {
                if (!string.IsNullOrWhiteSpace(cachedSession?.AccessToken))
                    return cachedSession;
            }

            // 3) fetch fresh from ABHA (delegating to HttpClient wrapper)
            var fresh = await _abhaHttpClient.GetSessionAsync(clientId, clientSecret);

            if (fresh == null || string.IsNullOrWhiteSpace(fresh.AccessToken))
                throw new InvalidOperationException("ABHA session fetch returned empty token");

            // compute TTL: expiresIn minus buffer (default 30s)
            var bufferSeconds = 30;
            var ttlSec = Math.Max(60, (fresh.ExpiresIn > bufferSeconds ? fresh.ExpiresIn - bufferSeconds : fresh.ExpiresIn));
            _cache.Set(cacheKey, fresh, TimeSpan.FromSeconds(ttlSec));

            return fresh;
        }
        finally
        {
            sem.Release();
            // optional: cleanup the SemaphoreSlim for keys no longer needed (not strictly necessary)
            // if you want, remove it when no longer used, but race conditions can occur; safe to keep.
        }
    }

    // returns true if not near expiry (we consider valid if remaining > 60s)
    //private bool IsSessionValid(SessionCacheItem item)
    //{
    //    if (item?.Session == null) return false;

    //    var issued = item.IssuedAtUtc;
    //    var expiresIn = item.Session.ExpiresIn; // seconds as returned by ABHA

    //    var expiresAt = issued.AddSeconds(expiresIn);
    //    var remaining = expiresAt - DateTime.UtcNow;

    //    // consider token invalid if <= 60 seconds remaining
    //    return remaining.TotalSeconds > 60;
    //}

    // --------------------
    // Existing internal logic: make HTTP call and parse response
    // --------------------
    //private async Task<SessionResponse> GetSessionTokenInternalAsync(string clientId, string clientSecret)
    //{
    //    return await _abhaHttpClient.GetSessionAsync(clientId, clientSecret);
    //}

    // --------------------
    // Public key
    // --------------------
    //public async Task<string> GetPublicKeyAsync(string accessToken)
    public async Task<PublicCertResponse> GetPublicKeyAsync()
    {
        // If no access token passed, get session (some endpoints may allow unauth)
        var session = await GetSessionTokenAsync();
        var accessToken = session.AccessToken;

        //return await _abhaHttpClient.GetPublicKeyAsync(accessToken);

        var cert = await _abhaHttpClient.GetPublicKeyAsync(accessToken);
        // optionally cache cert in _cache for 24h (already in earlier impl)
        _cache.Set("abha_publiccert", cert, TimeSpan.FromHours(24));
        return cert;
    }

    // Example SendOtp (uses cached token internally)
    public async Task<SendOtpResponse?> SendOtpAsync(SendOtpRequest req)
    {
        var session = await GetSessionTokenAsync();
        var accessToken = session.AccessToken;
        return await _abhaHttpClient.SendOtpAsync(req, accessToken);
    }

    // CreateByAadhaar
    public async Task<CreateAbhaResponse?> CreateAbhaByAadhaarAsync(object reqBody)
    {
        var session = await GetSessionTokenAsync();
        var accessToken = session.AccessToken;
        return await _abhaHttpClient.CreateAbhaByAadhaarAsync(reqBody, accessToken);
    }

    public async Task<SendOtpResponse_MobileUpdate?> CreateMobileUpdateOtpAsync(SendMobileOtpRequest req)
    {
        var session = await GetSessionTokenAsync();
        var accessToken = session?.AccessToken ?? string.Empty;
        return await _abhaHttpClient.CreateMobileUpdateOtpAsync(req, accessToken);
    }

    public async Task<MobileVerifyResponse?> VerifyMobileUpdateOtpAsync(object reqBody)
    {
        var session = await GetSessionTokenAsync();
        var accessToken = session?.AccessToken ?? string.Empty;
        return await _abhaHttpClient.CreateMobileUpdateVerifyOtpAsync(reqBody, accessToken);
    }

    public async Task<EmailVerificationResponse?> SendEmailVerificationLinkAsync(EmailVerificationRequest req, string? authToken, string? xToken)
    {
        var session = await GetSessionTokenAsync();
        var accessToken = session?.AccessToken ?? string.Empty;
        return await _abhaHttpClient.SendEmailVerificationLinkAsync(req, accessToken, xToken);
    }

    public async Task<AbhaSuggestionResponse?> GetAbhaSuggestionsAsync(string txnId)
    {
        var session = await GetSessionTokenAsync();
        var accessToken = session?.AccessToken ?? string.Empty;
        return await _abhaHttpClient.GetAbhaSuggestionsAsync(txnId, accessToken);
    }

    public async Task<AbhaAddressResponse?> PostAbhaAddressAsync(AbhaAddressRequest request)
    {
        var session = await GetSessionTokenAsync(); // your existing session method
        var accessToken = session?.AccessToken ?? string.Empty;
        return await _abhaHttpClient.PostAbhaAddressAsync(request, accessToken);
    }

    public async Task<AbhaProfileResponse?> GetProfileDetailsAsync(string txnId, string xToken)
    {
        var session = await GetSessionTokenAsync();
        var accessToken = session?.AccessToken ?? string.Empty;
        return await _abhaHttpClient.GetProfileDetailsAsync(txnId, accessToken, xToken);
    }

    public async Task<AbhaCardFile?> GetAbhaCardAsync(string xToken)
    {
        var session = await GetSessionTokenAsync();
        var accessToken = session?.AccessToken ?? string.Empty;

        return await _abhaHttpClient.GetAbhaCardAsync(xToken, accessToken);
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    public async Task<SendOtpResponse_Login?> CreateAadhaarLoginOtpAsync(SendAadhaarLoginOtpRequest request)
    {
        var session = await GetSessionTokenAsync();
        var accessToken = session?.AccessToken ?? string.Empty;

        return await _abhaHttpClient.CreateAadhaarLoginOtpAsync(request, accessToken);
    }

    public async Task<LoginVerifyOtpResponse?> VerifyAadhaarLoginOtpAsync(LoginVerifyOtpRequest req)
    {
        var session = await GetSessionTokenAsync();
        var accessToken = session?.AccessToken ?? string.Empty;

        return await _abhaHttpClient.VerifyAadhaarLoginOtpAsync(req, accessToken);
    }

    public async Task<SendOtpResponse_Login?> CreateAbhaNumberAadhaarOtpAsync(SendAadhaarLoginOtpRequest request)
    {
        var session = await GetSessionTokenAsync();
        var accessToken = session?.AccessToken ?? string.Empty;

        return await _abhaHttpClient.CreateAbhaNumberAadhaarOtpAsync(request, accessToken);
    }

    public async Task<LoginVerifyOtpResponse?> VerifyAbhaNumberAadhaarOtpAsync(LoginVerifyOtpRequest request)
    {
        var session = await GetSessionTokenAsync();
        var accessToken = session?.AccessToken ?? string.Empty;

        return await _abhaHttpClient.VerifyAbhaNumberAadhaarOtpAsync(request, accessToken);
    }

    public async Task<SendOtpResponse_Login?> CreateAbhaNumberAbhaOtpAsync(SendAadhaarLoginOtpRequest request)
    {
        var session = await GetSessionTokenAsync();
        var accessToken = session?.AccessToken ?? string.Empty;

        return await _abhaHttpClient.CreateAbhaNumberAbhaOtpAsync(request, accessToken);
    }

    public async Task<LoginVerifyOtpResponse?> VerifyAbhaNumberAbhaOtpAsync(LoginVerifyOtpRequest request)
    {
        var session = await GetSessionTokenAsync();
        var accessToken = session?.AccessToken ?? string.Empty;

        return await _abhaHttpClient.VerifyAbhaNumberAbhaOtpAsync(request, accessToken);
    }

    public async Task<SendOtpResponse_Login?> CreateMobileLoginOtpAsync(SendAadhaarLoginOtpRequest request)
    {
        var session = await GetSessionTokenAsync();
        var accessToken = session?.AccessToken ?? string.Empty;

        return await _abhaHttpClient.CreateMobileLoginOtpAsync(request, accessToken);
    }

    public async Task<LoginVerifyOtpResponse?> VerifyMobileLoginOtpAsync(LoginVerifyOtpRequest request)
    {
        var session = await GetSessionTokenAsync();
        var accessToken = session?.AccessToken ?? string.Empty;

        return await _abhaHttpClient.VerifyMobileLoginOtpAsync(request, accessToken);
    }

    public async Task<VerifyUserResponseDto?> VerifyUserAsync(VerifyUserRequestDto request)
    {
        var session = await GetSessionTokenAsync();
        var accessToken = session?.AccessToken ?? string.Empty;

        return await _abhaHttpClient.VerifyUserAsync(request, accessToken);
    }

}
