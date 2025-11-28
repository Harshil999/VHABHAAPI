using ABHA_HIMS.Application.External;
using ABHA_HIMS.Application.Interfaces;
using ABHA_HIMS.Domain;
using Microsoft.Extensions.Options;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using static ABHA_HIMS.Domain.AbhaDtos;
using static System.Net.WebRequestMethods;

namespace ABHA_HIMS.Infrastructure.Abha
{
    public class AbhaHttpClient : IAbhaHttpClient
    {
        private readonly HttpClient _http;
        private readonly AbhaOptions _opt;
        private readonly IAbhaAuditRepository _audit;

        public AbhaHttpClient(HttpClient http, IOptions<AbhaOptions> opt, IAbhaAuditRepository audit)
        {
            _http = http ?? throw new ArgumentNullException(nameof(http));
            _opt = opt?.Value ?? throw new ArgumentNullException(nameof(opt));
            _audit = audit ?? throw new ArgumentNullException(nameof(audit));
        }

        // Application.External expects clientId & clientSecret provided by caller
        public async Task<SessionResponse> GetSessionAsync(string clientId, string clientSecret)
        {
            if (string.IsNullOrWhiteSpace(clientId)) throw new ArgumentNullException(nameof(clientId));
            if (string.IsNullOrWhiteSpace(clientSecret)) throw new ArgumentNullException(nameof(clientSecret));

            var url = !string.IsNullOrWhiteSpace(_opt.SessionUrl)
                ? _opt.SessionUrl
                : ((_http.BaseAddress != null)
                    ? new Uri(_http.BaseAddress, "/gateway/v3/sessions").ToString()
                    : "/gateway/v3/sessions");

            var body = new SessionRequest(clientId, clientSecret, _opt.GrantType ?? "client_credentials");

            using var req = new HttpRequestMessage(HttpMethod.Post, url)
            {
                Content = JsonContent.Create(body)
            };

            // Required headers
            req.Headers.Add("REQUEST-ID", Guid.NewGuid().ToString());
            req.Headers.Add("TIMESTAMP", DateTime.UtcNow.ToString("o"));

            var xcm = _opt.GetType().GetProperty("XCMID") != null
                ? (typeof(AbhaOptions).GetProperty("XCMID") != null ? (_opt.GetType().GetProperty("XCMID")?.GetValue(_opt) as string) : null)
                : null;

            // fallback: use sbx if not specified (sandbox)
            // (If you added XCMID property to AbhaOptions, it will be used; otherwise default to "sbx")
            if (string.IsNullOrWhiteSpace(xcm))
                xcm = "sbx";

            req.Headers.Add("X-CM-ID", xcm);
            req.Headers.Accept.Clear();
            req.Headers.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));

            HttpResponseMessage resp;
            string raw;
            try
            {
                resp = await _http.SendAsync(req);
                raw = await resp.Content.ReadAsStringAsync();
            }
            catch (Exception ex)
            {
                // log minimal info
                await _audit.LogRequestAsync(url, JsonSerializer.Serialize(body), ex.Message, req.Headers.Contains("REQUEST-ID") ? req.Headers.GetValues("REQUEST-ID").FirstOrDefault() ?? "" : "");
                throw new HttpRequestException("Network error while calling ABHA session endpoint: " + ex.Message, ex);
            }

            await _audit.LogRequestAsync(url, JsonSerializer.Serialize(body), raw, req.Headers.Contains("REQUEST-ID") ? req.Headers.GetValues("REQUEST-ID").FirstOrDefault() ?? "" : "");

            if (!resp.IsSuccessStatusCode)
            {
                // include truncated body for diagnostics
                var tr = raw ?? "";
                if (tr.Length > 2000) tr = tr.Substring(0, 2000) + "...(truncated)";
                throw new HttpRequestException($"ABHA session request failed. StatusCode={(int)resp.StatusCode} ({resp.ReasonPhrase}). Response body: {tr}");
            }

            try
            {
                var session = JsonSerializer.Deserialize<SessionResponse>(raw, new JsonSerializerOptions { PropertyNameCaseInsensitive = true })
                              ?? throw new Exception("Empty session response");
                return session;
            }
            catch (JsonException je)
            {
                throw new InvalidOperationException("Failed to parse ABHA session response JSON: " + je.Message + ". Raw: " + (raw?.Length > 2000 ? raw.Substring(0, 2000) + "...(truncated)" : raw));
            }
        }

        public async Task<PublicCertResponse> GetPublicKeyAsync(string accessToken)
        {
            var url = !string.IsNullOrWhiteSpace(_opt.PublicCertUrl)
               ? _opt.PublicCertUrl
               : ((_http.BaseAddress != null)
                   ? new Uri(_http.BaseAddress, "/v3/profile/public/certificate").ToString()
                   : "/abha/api/v3/profile/public/certificate");

            using var req = new HttpRequestMessage(HttpMethod.Get, url);
            req.Headers.Add("REQUEST-ID", Guid.NewGuid().ToString());
            req.Headers.Add("TIMESTAMP", DateTime.UtcNow.ToString("o"));
            if (!string.IsNullOrWhiteSpace(accessToken))
                req.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);

            req.Headers.Accept.Clear();
            req.Headers.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));

            var resp = await _http.SendAsync(req);
            var raw = await resp.Content.ReadAsStringAsync();

            await _audit.LogRequestAsync(url, "GET", raw, req.Headers.Contains("REQUEST-ID") ? req.Headers.GetValues("REQUEST-ID").FirstOrDefault() ?? "" : "");

            if (!resp.IsSuccessStatusCode)
            {
                var tr = raw ?? "";
                if (tr.Length > 2000) tr = tr.Substring(0, 2000) + "...(truncated)";
                throw new HttpRequestException($"ABHA public cert request failed. StatusCode={(int)resp.StatusCode} ({resp.ReasonPhrase}). Response body: {tr}");
            }

            try
            {
                var parsed = JsonSerializer.Deserialize<PublicCertResponse>(raw, new JsonSerializerOptions { PropertyNameCaseInsensitive = true })
                             ?? throw new InvalidOperationException("Empty public certificate response");
                return parsed;
            }
            catch (JsonException je)
            {
                throw new InvalidOperationException("Failed to parse ABHA public certificate JSON: " + je.Message + ". Raw: " + (raw?.Length > 2000 ? raw.Substring(0, 2000) + "...(truncated)" : raw));
            }
        }

        public async Task<SendOtpResponse?> SendOtpAsync(SendOtpRequest reqBody, string accessToken)
        {
            if (reqBody.Scope == null || reqBody.Scope.Length == 0)
                reqBody.Scope = new[] { "abha-enrol" };

            // build base url (prefer options)
            var baseUrl = (_opt?.BaseUrl?.TrimEnd('/')) ?? (_http.BaseAddress?.ToString().TrimEnd('/')) ?? "";
            var reqUri = baseUrl + "/v3/enrollment/request/otp";

            var jsonOptions = new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                PropertyNameCaseInsensitive = true,
                DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
            };

            using var req = new HttpRequestMessage(HttpMethod.Post, reqUri)
            {
                Content = JsonContent.Create(reqBody, options: jsonOptions)
            };

            var requestId = Guid.NewGuid().ToString();
            req.Headers.Add("REQUEST-ID", requestId);
            req.Headers.Add("TIMESTAMP", DateTime.UtcNow.ToString("o"));

            // X-CM-ID from AbhaOptions (we added it)
            //if (!string.IsNullOrWhiteSpace(_opt?.XCMID))
            //    req.Headers.Add("X-CM-ID", _opt.XCMID);

            if (!string.IsNullOrWhiteSpace(accessToken))
                req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

            req.Headers.Accept.Clear();
            req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));


            //var resp = await _http.SendAsync(req);
            //var raw = await resp.Content.ReadAsStringAsync();

            HttpResponseMessage resp;
            try
            {
                resp = await _http.SendAsync(req);
            }
            catch (Exception ex)
            {
                // Audit best-effort and then wrap+throw so upstream gets details
                try { await _audit.LogRequestAsync(reqUri, JsonSerializer.Serialize(reqBody, jsonOptions), ex.ToString(), requestId); } catch { }

                var httpEx = new HttpRequestException($"Network/HTTP error while calling ABHA {reqUri}", ex);
                try { httpEx.Data["RequestId"] = requestId; } catch { }
                try { httpEx.Data["RequestUri"] = reqUri; } catch { }
                throw httpEx;
            }

            string raw = string.Empty;
            // read raw body
            try
            {
                raw = await resp.Content.ReadAsStringAsync();
            }
            catch (Exception ex)
            {
                // If reading body fails, audit and throw
                try { await _audit.LogRequestAsync(reqUri, JsonSerializer.Serialize(reqBody, jsonOptions), ex.ToString(), requestId); } catch { }

                var readEx = new InvalidOperationException("Failed to read response body from ABHA", ex);
                try { readEx.Data["RequestId"] = requestId; } catch { }
                try { readEx.Data["RequestUri"] = reqUri; } catch { }
                throw readEx;
            }

            try
            {
                // audit log (don't crash on logger failure)
                await _audit.LogRequestAsync(reqUri, JsonSerializer.Serialize(reqBody, jsonOptions), raw, requestId);
            }
            catch { /* swallow logging errors */ }

            //if (!resp.IsSuccessStatusCode)

            if (!resp.IsSuccessStatusCode)
            {
                var msg = $"ABHA returned non-success {(int)resp.StatusCode} {resp.ReasonPhrase}";
                var httpEx = new HttpRequestException(msg);
                try { httpEx.Data["StatusCode"] = (int)resp.StatusCode; } catch { }
                try { httpEx.Data["RawBody"] = raw ?? ""; } catch { }
                try { httpEx.Data["RequestId"] = requestId; } catch { }
                try { httpEx.Data["RequestUri"] = reqUri; } catch { }
                throw httpEx;
            }

            //var result = JsonSerializer.Deserialize<AbhaDtos.SendOtpResponse>(raw, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            //return result;
            try
            {
                var result = JsonSerializer.Deserialize<AbhaDtos.SendOtpResponse>(raw, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                return result;
            }
            catch (Exception ex)
            {
                // attach raw body for debugging and throw
                var pex = new InvalidOperationException("Failed to deserialize ABHA SendOtp response.", ex);
                try { pex.Data["RawBody"] = raw ?? ""; } catch { }
                try { pex.Data["RequestId"] = requestId; } catch { }
                try { pex.Data["RequestUri"] = reqUri; } catch { }
                throw pex;
            }
        }

        public async Task<CreateAbhaResponse?> CreateAbhaByAadhaarAsync(object reqBody, string accessToken)
        {
            var baseUrl = _opt.BaseUrl?.TrimEnd('/') ?? (_http.BaseAddress?.ToString().TrimEnd('/') ?? "");
            var url = baseUrl + "/v3/enrollment/enrol/byAadhaar";

            var jsonOptions = new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                PropertyNameCaseInsensitive = true,
                DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
            };

            var payload = JsonSerializer.Serialize(reqBody, jsonOptions);
            using var req = new HttpRequestMessage(HttpMethod.Post, url)
            {
                Content = new StringContent(payload, Encoding.UTF8, "application/json")
            };

            var requestId = Guid.NewGuid().ToString();
            req.Headers.Add("REQUEST-ID", requestId);
            req.Headers.Add("TIMESTAMP", DateTime.UtcNow.ToString("o"));

            if (!string.IsNullOrWhiteSpace(accessToken))
                req.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);

            req.Headers.Accept.Clear();
            req.Headers.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));

            //HttpResponseMessage resp;
            //string raw = string.Empty;

            //try
            //{
            //    resp = await _http.SendAsync(req);
            //    raw = await resp.Content.ReadAsStringAsync();
            //}
            //catch (Exception ex)
            //{
            //    await _audit.LogRequestAsync(url, payload, ex.ToString(), requestId);
            //    //_logger?.LogError(ex, "HTTP call to CreateAbhaByAadhaarAsync failed");
            //}

            HttpResponseMessage resp;
            string raw = string.Empty;
            try
            {
                resp = await _http.SendAsync(req);
            }
            catch (Exception ex)
            {
                // audit failure and rethrow wrapped exception with diagnostics
                try { await _audit.LogRequestAsync(url, payload, ex.ToString(), requestId); } catch { }

                var httpEx = new HttpRequestException($"Network/HTTP error while calling ABHA {url}", ex);
                try { httpEx.Data["RequestId"] = requestId; } catch { }
                try { httpEx.Data["RequestUri"] = url; } catch { }
                throw httpEx;
            }

            // read raw body (with safe catch)
            try
            {
                raw = await resp.Content.ReadAsStringAsync();
            }
            catch (Exception ex)
            {
                try { await _audit.LogRequestAsync(url, payload, ex.ToString(), requestId); } catch { }

                var readEx = new InvalidOperationException("Failed to read response body from ABHA", ex);
                try { readEx.Data["RequestId"] = requestId; } catch { }
                try { readEx.Data["RequestUri"] = url; } catch { }
                throw readEx;
            }

            // Audit logging of request/response
            try
            {
                await _audit.LogRequestAsync(url, payload, raw, requestId);
            }
            catch (Exception ex)
            {
                //_logger?.LogWarning(ex, "Audit logging failed for CreateAbhaByAadhaarAsync");
            }

            //if (!resp.IsSuccessStatusCode)
            //{
            //    //_logger?.LogWarning("ABHA returned non-success {StatusCode} for {Url}. Response: {Raw}", resp.StatusCode, url, raw);
            //    return null;
            //}

            if (!resp.IsSuccessStatusCode)
            {
                var msg = $"ABHA returned non-success {(int)resp.StatusCode} {resp.ReasonPhrase}";
                var httpEx = new HttpRequestException(msg);
                try { httpEx.Data["StatusCode"] = (int)resp.StatusCode; } catch { }
                try { httpEx.Data["RawBody"] = raw ?? ""; } catch { }
                try { httpEx.Data["RequestId"] = requestId; } catch { }
                try { httpEx.Data["RequestUri"] = url; } catch { }
                throw httpEx;
            }

            try
            {
                var result = JsonSerializer.Deserialize<CreateAbhaResponse>(raw, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                return result;
            }
            catch (Exception ex)
            {
                //_logger?.LogError(ex, "Failed to deserialize CreateAbhaResponse from ABHA.");
                //return null;
                var pex = new InvalidOperationException("Failed to deserialize CreateAbhaResponse from ABHA.", ex);
                try { pex.Data["RawBody"] = raw ?? ""; } catch { }
                try { pex.Data["RequestId"] = requestId; } catch { }
                try { pex.Data["RequestUri"] = url; } catch { }
                throw pex;
            }
        }

        public async Task<SendOtpResponse_MobileUpdate?> CreateMobileUpdateOtpAsync(SendMobileOtpRequest reqBody, string accessToken)
        {
            var baseUrl = _opt.BaseUrl?.TrimEnd('/') ?? (_http.BaseAddress?.ToString().TrimEnd('/') ?? "");
            // default path - change in options if your gateway has different endpoint
            //var path = _opt.BaseUrl ?? "/v3/enrollment/request/otp";
            var url = baseUrl + "/v3/enrollment/request/otp";

            var jsonOptions = new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                PropertyNameCaseInsensitive = true,
                DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
            };

            var payload = JsonSerializer.Serialize(reqBody, jsonOptions);

            using var req = new HttpRequestMessage(HttpMethod.Post, url)
            {
                Content = new StringContent(payload, Encoding.UTF8, "application/json")
            };

            var requestId = Guid.NewGuid().ToString();
            req.Headers.Add("REQUEST-ID", requestId);
            req.Headers.Add("TIMESTAMP", DateTime.UtcNow.ToString("o"));

            if (!string.IsNullOrWhiteSpace(accessToken))
                req.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);

            // ensure Accept
            req.Headers.Accept.Clear();
            req.Headers.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));

            //HttpResponseMessage resp;
            //string raw = string.Empty;
            //try
            //{
            //    resp = await _http.SendAsync(req);
            //    raw = await resp.Content.ReadAsStringAsync();
            //}
            //catch (Exception ex)
            //{
            //    await _audit.LogRequestAsync(url, payload, ex.ToString(), requestId);
            //    //_logger?.LogError(ex, "HTTP call to CreateMobileUpdateOtpAsync failed");
            //    return null;
            //}

            HttpResponseMessage resp;
            string raw = string.Empty;
            try
            {
                resp = await _http.SendAsync(req);
            }
            catch (Exception ex)
            {
                // audit failure and rethrow wrapped exception with diagnostics
                try { await _audit.LogRequestAsync(url, payload, ex.ToString(), requestId); } catch { }

                var netEx = new HttpRequestException($"Network/HTTP error while calling ABHA {url}", ex);
                try { netEx.Data["RequestId"] = requestId; } catch { }
                try { netEx.Data["RequestUri"] = url; } catch { }
                throw netEx;
            }

            // read raw body
            try
            {
                raw = await resp.Content.ReadAsStringAsync();
            }
            catch (Exception ex)
            {
                try { await _audit.LogRequestAsync(url, payload, ex.ToString(), requestId); } catch { }

                var readEx = new InvalidOperationException("Failed to read response body from ABHA", ex);
                try { readEx.Data["RequestId"] = requestId; } catch { }
                try { readEx.Data["RequestUri"] = url; } catch { }
                throw readEx;
            }

            // audit
            try
            {
                await _audit.LogRequestAsync(url, payload, raw, requestId);
            }
            catch (Exception aex)
            {
                //_logger?.LogWarning(aex, "Audit logging failed for CreateMobileUpdateOtpAsync");
            }

            if (!resp.IsSuccessStatusCode)
            {
                //try
                // {
                //     var maybe = JsonSerializer.Deserialize<SendOtpResponse_MobileUpdate>(raw, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                //     if (maybe != null) return maybe;
                // }
                // catch { /* ignore */ }

                // return null;

                if (!resp.IsSuccessStatusCode)
                {
                    // try to deserialize if ABHA returns structured error body — but still throw so controller can map status
                    try
                    {
                        var maybe = JsonSerializer.Deserialize<SendOtpResponse_MobileUpdate>(raw, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                        if (maybe != null)
                        {
                            var httpExWithBody = new HttpRequestException($"ABHA returned non-success {(int)resp.StatusCode} {resp.ReasonPhrase}");
                            try { httpExWithBody.Data["StatusCode"] = (int)resp.StatusCode; } catch { }
                            try { httpExWithBody.Data["RawBody"] = raw ?? ""; } catch { }
                            try { httpExWithBody.Data["RequestId"] = requestId; } catch { }
                            try { httpExWithBody.Data["RequestUri"] = url; } catch { }
                            // we still throw to let controller decide response code, but include the parsed body if needed via RawBody
                            throw httpExWithBody;
                        }
                    }
                    catch { /* ignore parse errors, will throw below */ }

                    var httpEx = new HttpRequestException($"ABHA returned non-success {(int)resp.StatusCode} {resp.ReasonPhrase}");
                    try { httpEx.Data["StatusCode"] = (int)resp.StatusCode; } catch { }
                    try { httpEx.Data["RawBody"] = raw ?? ""; } catch { }
                    try { httpEx.Data["RequestId"] = requestId; } catch { }
                    try { httpEx.Data["RequestUri"] = url; } catch { }
                    throw httpEx;
                }
            }

            try
            {
                var result = JsonSerializer.Deserialize<SendOtpResponse_MobileUpdate>(raw, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                return result;
            }
            catch (Exception ex)
            {
                //_logger?.LogError(ex, "Failed to deserialize SendOtpResponse from ABHA.");
                //return null;
                var pex = new InvalidOperationException("Failed to deserialize ABHA CreateMobileUpdateOtp response.", ex);
                try { pex.Data["RawBody"] = raw ?? ""; } catch { }
                try { pex.Data["RequestId"] = requestId; } catch { }
                try { pex.Data["RequestUri"] = url; } catch { }
                throw pex;
            }
        }

        public async Task<MobileVerifyResponse?> CreateMobileUpdateVerifyOtpAsync(object reqBody, string accessToken)
        {
            var baseUrl = _opt.BaseUrl?.TrimEnd('/') ?? (_http.BaseAddress?.ToString().TrimEnd('/') ?? "");
            var url = baseUrl + "/v3/enrollment/auth/byAbdm";

            var jsonOptions = new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                PropertyNameCaseInsensitive = true,
                DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
            };

            var payload = JsonSerializer.Serialize(reqBody, jsonOptions);

            using var req = new HttpRequestMessage(HttpMethod.Post, url)
            {
                Content = new StringContent(payload, Encoding.UTF8, "application/json")
            };

            var requestId = Guid.NewGuid().ToString();
            req.Headers.Add("REQUEST-ID", requestId);
            // TIMESTAMP header (server-supplied ISO UTC)
            req.Headers.Add("TIMESTAMP", DateTime.UtcNow.ToString("o"));

            if (!string.IsNullOrWhiteSpace(accessToken))
                req.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);

            req.Headers.Accept.Clear();
            req.Headers.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));

            //HttpResponseMessage resp;
            //string raw = string.Empty;
            //try
            //{
            //    resp = await _http.SendAsync(req);
            //    raw = await resp.Content.ReadAsStringAsync();
            //}
            //catch (Exception ex)
            //{
            //    await _audit.LogRequestAsync(url, payload, ex.ToString(), requestId);
            //    //_logger?.LogError(ex, "HTTP call to CreateMobileUpdateVerifyOtpAsync failed");
            //    return null;
            //}

            HttpResponseMessage resp;
            string raw = string.Empty;
            try
            {
                resp = await _http.SendAsync(req);
            }
            catch (Exception ex)
            {
                // audit failure and rethrow wrapped exception with diagnostics
                try { await _audit.LogRequestAsync(url, payload, ex.ToString(), requestId); } catch { }

                var netEx = new HttpRequestException($"Network/HTTP error while calling ABHA {url}", ex);
                try { netEx.Data["RequestId"] = requestId; } catch { }
                try { netEx.Data["RequestUri"] = url; } catch { }
                throw netEx;
            }

            // read raw body safely
            try
            {
                raw = await resp.Content.ReadAsStringAsync();
            }
            catch (Exception ex)
            {
                try { await _audit.LogRequestAsync(url, payload, ex.ToString(), requestId); } catch { }

                var readEx = new InvalidOperationException("Failed to read response body from ABHA (verifyOtp)", ex);
                try { readEx.Data["RequestId"] = requestId; } catch { }
                try { readEx.Data["RequestUri"] = url; } catch { }
                throw readEx;
            }

            try
            {
                await _audit.LogRequestAsync(url, payload, raw, requestId);
            }
            catch (Exception aex)
            {
                //_logger?.LogWarning(aex, "Audit logging failed for CreateMobileUpdateVerifyOtpAsync");
            }

            if (!resp.IsSuccessStatusCode)
            {
                //try
                //{
                //    var maybe = JsonSerializer.Deserialize<MobileVerifyResponse>(raw, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                //    if (maybe != null) return maybe;
                //}
                //catch { /* ignore */ }

                //return null;

                try
                {
                    var maybe = JsonSerializer.Deserialize<MobileVerifyResponse>(raw, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                    if (maybe != null)
                    {
                        var httpExWithBody = new HttpRequestException($"ABHA returned non-success {(int)resp.StatusCode} {resp.ReasonPhrase}");
                        try { httpExWithBody.Data["StatusCode"] = (int)resp.StatusCode; } catch { }
                        try { httpExWithBody.Data["RawBody"] = raw ?? ""; } catch { }
                        try { httpExWithBody.Data["RequestId"] = requestId; } catch { }
                        try { httpExWithBody.Data["RequestUri"] = url; } catch { }
                        throw httpExWithBody;
                    }
                }
                catch { /* ignore parse errors, will throw below */ }

                var httpEx = new HttpRequestException($"ABHA returned non-success {(int)resp.StatusCode} {resp.ReasonPhrase}");
                try { httpEx.Data["StatusCode"] = (int)resp.StatusCode; } catch { }
                try { httpEx.Data["RawBody"] = raw ?? ""; } catch { }
                try { httpEx.Data["RequestId"] = requestId; } catch { }
                try { httpEx.Data["RequestUri"] = url; } catch { }
                throw httpEx;
            }

            try
            {
                var result = JsonSerializer.Deserialize<MobileVerifyResponse>(raw, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                return result;
            }
            catch (Exception ex)
            {
                //_logger?.LogError(ex, "Failed to deserialize CreateAbhaResponse from ABHA (verifyOtp). Raw: {Raw}", raw);
                //return null;
                var pex = new InvalidOperationException("Failed to deserialize ABHA CreateMobileUpdateVerifyOtp response.", ex);
                try { pex.Data["RawBody"] = raw ?? ""; } catch { }
                try { pex.Data["RequestId"] = requestId; } catch { }
                try { pex.Data["RequestUri"] = url; } catch { }
                throw pex;
            }
        }

        public async Task<EmailVerificationResponse?> SendEmailVerificationLinkAsync(EmailVerificationRequest reqBody, string? authToken, string? xToken)
        {
            var baseUrl = _opt.BaseUrl?.TrimEnd('/') ?? "https://abhasbx.abdm.gov.in";
            var url = baseUrl + "/v3/profile/account/request/emailVerificationLink";

            var jsonOptions = new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                PropertyNameCaseInsensitive = true
            };

            var payload = JsonSerializer.Serialize(reqBody, jsonOptions);

            using var req = new HttpRequestMessage(HttpMethod.Post, url)
            {
                Content = new StringContent(payload, Encoding.UTF8, "application/json")
            };

            var requestId = Guid.NewGuid().ToString();
            req.Headers.Add("REQUEST-ID", requestId);
            req.Headers.Add("TIMESTAMP", DateTime.UtcNow.ToString("o"));

            // Authorization headers
            if (!string.IsNullOrWhiteSpace(authToken))
                req.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", authToken);

            if (!string.IsNullOrWhiteSpace(xToken))
                req.Headers.Add("X-token", $"Bearer {xToken}");

            req.Headers.Accept.Clear();
            req.Headers.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));

            //HttpResponseMessage resp;
            //string raw;
            //try
            //{
            //    resp = await _http.SendAsync(req);
            //    raw = await resp.Content.ReadAsStringAsync();
            //}
            //catch (Exception ex)
            //{
            //    await _audit.LogRequestAsync(url, payload, ex.ToString(), requestId);
            //    //_logger?.LogError(ex, "HTTP call failed for SendEmailVerificationLinkAsync");
            //    return null;
            //}

            HttpResponseMessage resp;
            string raw;
            try
            {
                resp = await _http.SendAsync(req);
            }
            catch (Exception ex)
            {
                // audit failure and rethrow wrapped exception with diagnostics
                try { await _audit.LogRequestAsync(url, payload, ex.ToString(), requestId); } catch { }

                var netEx = new HttpRequestException($"Network/HTTP error while calling ABHA {url}", ex);
                try { netEx.Data["RequestId"] = requestId; } catch { }
                try { netEx.Data["RequestUri"] = url; } catch { }
                throw netEx;
            }

            // read raw body safely
            try
            {
                raw = await resp.Content.ReadAsStringAsync();
            }
            catch (Exception ex)
            {
                try { await _audit.LogRequestAsync(url, payload, ex.ToString(), requestId); } catch { }

                var readEx = new InvalidOperationException("Failed to read response body from ABHA (emailVerificationLink)", ex);
                try { readEx.Data["RequestId"] = requestId; } catch { }
                try { readEx.Data["RequestUri"] = url; } catch { }
                throw readEx;
            }

            await _audit.LogRequestAsync(url, payload, raw, requestId);

            if (!resp.IsSuccessStatusCode)
            {
                //try
                //{
                //    var maybe = JsonSerializer.Deserialize<EmailVerificationResponse>(raw, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                //    if (maybe != null) return maybe;
                //}
                //catch { }

                //return new EmailVerificationResponse { Message = $"Error: {resp.StatusCode}", TxnId = null };

                try
                {
                    var maybe = JsonSerializer.Deserialize<EmailVerificationResponse>(raw, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                    if (maybe != null)
                    {
                        var httpExWithBody = new HttpRequestException($"ABHA returned non-success {(int)resp.StatusCode} {resp.ReasonPhrase}");
                        try { httpExWithBody.Data["StatusCode"] = (int)resp.StatusCode; } catch { }
                        try { httpExWithBody.Data["RawBody"] = raw ?? ""; } catch { }
                        try { httpExWithBody.Data["RequestId"] = requestId; } catch { }
                        try { httpExWithBody.Data["RequestUri"] = url; } catch { }
                        throw httpExWithBody;
                    }
                }
                catch { /* ignore parse errors, will throw below */ }

                var httpEx = new HttpRequestException($"ABHA returned non-success {(int)resp.StatusCode} {resp.ReasonPhrase}");
                try { httpEx.Data["StatusCode"] = (int)resp.StatusCode; } catch { }
                try { httpEx.Data["RawBody"] = raw ?? ""; } catch { }
                try { httpEx.Data["RequestId"] = requestId; } catch { }
                try { httpEx.Data["RequestUri"] = url; } catch { }
                throw httpEx;
            }

            try
            {
                return JsonSerializer.Deserialize<EmailVerificationResponse>(raw, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            }
            catch (Exception ex)
            {
                //_logger?.LogError(ex, "Failed to deserialize EmailVerificationResponse from ABHA. Raw: {Raw}", raw);
                //return null;
                var pex = new InvalidOperationException("Failed to deserialize EmailVerificationResponse from ABHA.", ex);
                try { pex.Data["RawBody"] = raw ?? ""; } catch { }
                try { pex.Data["RequestId"] = requestId; } catch { }
                try { pex.Data["RequestUri"] = url; } catch { }
                throw pex;
            }
        }

        public async Task<AbhaSuggestionResponse?> GetAbhaSuggestionsAsync(string txnId, string authToken)
        {
            var baseUrl = _opt.BaseUrl?.TrimEnd('/') ?? "https://abhasbx.abdm.gov.in";
            var url = baseUrl + "/v3/enrollment/enrol/suggestion";

            using var req = new HttpRequestMessage(HttpMethod.Get, url);

            var requestId = Guid.NewGuid().ToString();
            req.Headers.Add("REQUEST-ID", requestId);
            req.Headers.Add("TIMESTAMP", DateTime.UtcNow.ToString("o"));
            req.Headers.Add("Transaction_Id", txnId);

            if (!string.IsNullOrWhiteSpace(authToken))
                req.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", authToken);

            req.Headers.Accept.Clear();
            req.Headers.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));

            //HttpResponseMessage resp;
            //string raw = "";

            //try
            //{
            //    resp = await _http.SendAsync(req);
            //    raw = await resp.Content.ReadAsStringAsync();
            //}
            //catch (Exception ex)
            //{
            //    await _audit.LogRequestAsync(url, $"txnId: {txnId}", ex.ToString(), requestId);
            //    //_logger?.LogError(ex, "HTTP call failed in GetAbhaSuggestionsAsync");
            //    return null;
            //}

            HttpResponseMessage resp;
            string raw = "";
            try
            {
                resp = await _http.SendAsync(req);
            }
            catch (Exception ex)
            {
                try { await _audit.LogRequestAsync(url, $"txnId={txnId}", ex.ToString(), requestId); } catch { }

                var netEx = new HttpRequestException($"Network/HTTP failure calling ABHA {url}", ex);
                try { netEx.Data["RequestId"] = requestId; } catch { }
                try { netEx.Data["RequestUri"] = url; } catch { }
                throw netEx;
            }

            try
            {
                raw = await resp.Content.ReadAsStringAsync();
            }
            catch (Exception ex)
            {
                try { await _audit.LogRequestAsync(url, $"txnId={txnId}", ex.ToString(), requestId); } catch { }

                var readEx = new InvalidOperationException("Failed to read ABHA suggestion response body.", ex);
                try { readEx.Data["RequestId"] = requestId; } catch { }
                try { readEx.Data["RequestUri"] = url; } catch { }
                throw readEx;
            }

            try
            {
                await _audit.LogRequestAsync(url, $"txnId={txnId}", raw, requestId);
            }
            catch { }
            //await _audit.LogRequestAsync(url, $"txnId: {txnId}", raw, requestId);

            if (!resp.IsSuccessStatusCode)
            {
                //try
                //{
                //    var maybe = JsonSerializer.Deserialize<AbhaSuggestionResponse>(raw, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                //    if (maybe != null) return maybe;
                //}
                //catch { }

                //return null;

                try
                {
                    var parsed = JsonSerializer.Deserialize<AbhaSuggestionResponse>(
                        raw,
                        new JsonSerializerOptions { PropertyNameCaseInsensitive = true }
                    );

                    if (parsed != null)
                    {
                        var httpEx = new HttpRequestException(
                            $"ABHA suggestion returned {(int)resp.StatusCode} {resp.ReasonPhrase}"
                        );

                        try { httpEx.Data["StatusCode"] = (int)resp.StatusCode; } catch { }
                        try { httpEx.Data["RawBody"] = raw; } catch { }
                        try { httpEx.Data["RequestId"] = requestId; } catch { }
                        try { httpEx.Data["RequestUri"] = url; } catch { }

                        throw httpEx;
                    }
                }
                catch
                {
                    // ignore parsing error, throw below
                }

                var genericEx = new HttpRequestException(
                    $"ABHA suggestion request failed with {(int)resp.StatusCode} {resp.ReasonPhrase}"
                );
                try { genericEx.Data["StatusCode"] = (int)resp.StatusCode; } catch { }
                try { genericEx.Data["RawBody"] = raw; } catch { }
                try { genericEx.Data["RequestId"] = requestId; } catch { }
                try { genericEx.Data["RequestUri"] = url; } catch { }
                throw genericEx;
            }

            try
            {
                return JsonSerializer.Deserialize<AbhaSuggestionResponse>(raw, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            }
            catch (Exception ex)
            {
                var pex = new InvalidOperationException("Failed to deserialize AbhaSuggestionResponse.", ex);
                try { pex.Data["RawBody"] = raw; } catch { }
                try { pex.Data["RequestId"] = requestId; } catch { }
                try { pex.Data["RequestUri"] = url; } catch { }
                throw pex;
            }
        }

        public async Task<AbhaAddressResponse?> PostAbhaAddressAsync(AbhaAddressRequest request, string accessToken)
        {
            var baseUrl = _opt.BaseUrl?.TrimEnd('/') ?? "https://abhasbx.abdm.gov.in";
            var url = baseUrl + "/v3/enrollment/enrol/abha-address";

            using var req = new HttpRequestMessage(HttpMethod.Post, url);

            var requestId = Guid.NewGuid().ToString();

            req.Headers.Add("REQUEST-ID", requestId);
            req.Headers.Add("TIMESTAMP", DateTime.UtcNow.ToString("o"));

            if (!string.IsNullOrWhiteSpace(accessToken))
                req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

            req.Headers.Accept.Clear();
            req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            var bodyJson = JsonSerializer.Serialize(request);
            req.Content = new StringContent(bodyJson, Encoding.UTF8, "application/json");

            HttpResponseMessage resp;
            string raw = "";

            try
            {
                resp = await _http.SendAsync(req);
            }
            catch (Exception ex)
            {
                try { await _audit.LogRequestAsync(url, $"txnId={request?.TxnId}", ex.ToString(), requestId); } catch { }
                throw;
            }

            try { raw = await resp.Content.ReadAsStringAsync(); }
            catch (Exception ex)
            {
                try { await _audit.LogRequestAsync(url, $"txnId={request?.TxnId}", ex.ToString(), requestId); } catch { }
                throw;
            }

            try { await _audit.LogRequestAsync(url, $"txnId={request?.TxnId}", raw, requestId); } catch { }

            if (!resp.IsSuccessStatusCode)
            {
                try
                {
                    var maybe = JsonSerializer.Deserialize<AbhaAddressResponse>(
                        raw,
                        new JsonSerializerOptions { PropertyNameCaseInsensitive = true }
                    );
                    if (maybe != null) return maybe;
                }
                catch { }

                throw new HttpRequestException($"ABHA enrol abha-address failed: {(int)resp.StatusCode} {resp.ReasonPhrase}");
            }

            return JsonSerializer.Deserialize<AbhaAddressResponse>(
                raw,
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true }
            );
        }

        public async Task<AbhaCardFile?> GetAbhaCardAsync(string xToken, string accessToken)
        {
            var baseUrl = _opt.BaseUrl?.TrimEnd('/') ?? "https://abhasbx.abdm.gov.in";
            var url = baseUrl + "/v3/profile/account/abha-card";

            using var req = new HttpRequestMessage(HttpMethod.Get, url);

            var requestId = Guid.NewGuid().ToString();

            // headers
            req.Headers.Add("REQUEST-ID", requestId);
            req.Headers.Add("TIMESTAMP", DateTime.UtcNow.ToString("o"));

            // Authorization: Bearer accessToken
            if (!string.IsNullOrWhiteSpace(accessToken))
                req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

            // X-Token: Bearer {{X-token}}
            if (!string.IsNullOrWhiteSpace(xToken))
                req.Headers.Add("X-Token", $"Bearer {xToken}");

            // Expect image/PDF
            req.Headers.Accept.Clear();
            req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("image/png"));
            req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("image/jpeg"));
            req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/pdf"));
            req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("*/*"));

            HttpResponseMessage resp;
            byte[] bytes = Array.Empty<byte>();
            string? rawTextForError = null;

            // ---- SEND ----
            try
            {
                resp = await _http.SendAsync(req);
            }
            catch (Exception ex)
            {
                try { await _audit.LogRequestAsync(url, "GET ABHA card", ex.ToString(), requestId); } catch { }

                var netEx = new HttpRequestException($"Network/HTTP failure calling ABHA {url}", ex);
                try { netEx.Data["RequestId"] = requestId; } catch { }
                try { netEx.Data["RequestUri"] = url; } catch { }
                throw netEx;
            }

            // ---- READ CONTENT (binary) ----
            try
            {
                bytes = await resp.Content.ReadAsByteArrayAsync();

                // agar ABHA error JSON/text bhej de, debug ke liye ek try:
                try
                {
                    rawTextForError = await resp.Content.ReadAsStringAsync();
                }
                catch
                {
                    // ignore, agar pure binary hai to yeh fail ho sakta hai
                }
            }
            catch (Exception ex)
            {
                try { await _audit.LogRequestAsync(url, "Read ABHA card bytes failed", ex.ToString(), requestId); } catch { }

                var readEx = new InvalidOperationException("Failed to read ABHA card response body.", ex);
                try { readEx.Data["RequestId"] = requestId; } catch { }
                try { readEx.Data["RequestUri"] = url; } catch { }
                throw readEx;
            }

            var contentType = resp.Content.Headers.ContentType?.MediaType;

            // ---- AUDIT ----
            try
            {
                var info = $"status={(int)resp.StatusCode}, contentType={contentType}, length={bytes.Length}";
                if (!string.IsNullOrWhiteSpace(rawTextForError) && rawTextForError.Length < 2000)
                {
                    await _audit.LogRequestAsync(url, info, rawTextForError, requestId);
                }
                else
                {
                    await _audit.LogRequestAsync(url, info, $"[binary {bytes.Length} bytes]", requestId);
                }
            }
            catch { }

            // ---- STATUS CHECK ----
            if (!resp.IsSuccessStatusCode)
            {
                var httpEx = new HttpRequestException(
                    $"ABHA card request failed with {(int)resp.StatusCode} {resp.ReasonPhrase}"
                );
                try { httpEx.Data["StatusCode"] = (int)resp.StatusCode; } catch { }
                try { httpEx.Data["ContentType"] = contentType ?? ""; } catch { }
                try { httpEx.Data["RequestId"] = requestId; } catch { }
                try { httpEx.Data["RequestUri"] = url; } catch { }
                try { httpEx.Data["RawBody"] = rawTextForError ?? ""; } catch { }

                throw httpEx;
            }

            // ---- SUCCESS ----
            return new AbhaCardFile
            {
                Content = bytes,
                ContentType = contentType,
                FileName = "abha-card.png" // ya "abha-card.pdf" agar contentType PDF ho
            };
        }

        public async Task<AbhaProfileResponse?> GetProfileDetailsAsync(string txnId, string authToken, string xToken)
        {
            var baseUrl = _opt.BaseUrl?.TrimEnd('/') ?? "https://abhasbx.abdm.gov.in";
            var url = baseUrl + "/v3/profile/account";

            using var req = new HttpRequestMessage(HttpMethod.Get, url);

            var requestId = Guid.NewGuid().ToString();
            req.Headers.Add("REQUEST-ID", requestId);
            req.Headers.Add("TIMESTAMP", DateTime.UtcNow.ToString("o"));
            req.Headers.Add("Transaction_Id", txnId);
            if (!string.IsNullOrWhiteSpace(xToken))
                req.Headers.Add("X-Token", $"Bearer {xToken}");


            if (!string.IsNullOrWhiteSpace(authToken))
                req.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", authToken);

            req.Headers.Accept.Clear();
            req.Headers.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));

            HttpResponseMessage resp;
            string raw = "";
            try
            {
                resp = await _http.SendAsync(req);
            }
            catch (Exception ex)
            {
                try { await _audit.LogRequestAsync(url, $"txnId={txnId}", ex.ToString(), requestId); } catch { }

                var netEx = new HttpRequestException($"Network/HTTP failure calling ABHA {url}", ex);
                try { netEx.Data["RequestId"] = requestId; } catch { }
                try { netEx.Data["RequestUri"] = url; } catch { }
                throw netEx;
            }

            try
            {
                raw = await resp.Content.ReadAsStringAsync();
            }
            catch (Exception ex)
            {
                try { await _audit.LogRequestAsync(url, $"txnId={txnId}", ex.ToString(), requestId); } catch { }

                var readEx = new InvalidOperationException("Failed to read ABHA profile response body.", ex);
                try { readEx.Data["RequestId"] = requestId; } catch { }
                try { readEx.Data["RequestUri"] = url; } catch { }
                throw readEx;
            }

            try
            {
                await _audit.LogRequestAsync(url, $"txnId={txnId}", raw, requestId);
            }
            catch { }

            if (!resp.IsSuccessStatusCode)
            {
                try
                {
                    var parsed = JsonSerializer.Deserialize<AbhaProfileResponse>(
                        raw,
                        new JsonSerializerOptions { PropertyNameCaseInsensitive = true }
                    );

                    if (parsed != null)
                    {
                        var httpEx = new HttpRequestException(
                            $"ABHA profile returned {(int)resp.StatusCode} {resp.ReasonPhrase}"
                        );

                        try { httpEx.Data["StatusCode"] = (int)resp.StatusCode; } catch { }
                        try { httpEx.Data["RawBody"] = raw; } catch { }
                        try { httpEx.Data["RequestId"] = requestId; } catch { }
                        try { httpEx.Data["RequestUri"] = url; } catch { }

                        throw httpEx;
                    }
                }
                catch
                {
                    // ignore parse error, throw generic below
                }

                var genericEx = new HttpRequestException(
                    $"ABHA profile request failed with {(int)resp.StatusCode} {resp.ReasonPhrase}"
                );
                try { genericEx.Data["StatusCode"] = (int)resp.StatusCode; } catch { }
                try { genericEx.Data["RawBody"] = raw; } catch { }
                try { genericEx.Data["RequestId"] = requestId; } catch { }
                try { genericEx.Data["RequestUri"] = url; } catch { }
                throw genericEx;
            }

            try
            {
                return JsonSerializer.Deserialize<AbhaProfileResponse>(raw, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            }
            catch (Exception ex)
            {
                var pex = new InvalidOperationException("Failed to deserialize AbhaProfileResponse.", ex);
                try { pex.Data["RawBody"] = raw; } catch { }
                try { pex.Data["RequestId"] = requestId; } catch { }
                try { pex.Data["RequestUri"] = url; } catch { }
                throw pex;
            }
        }

        /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

        public async Task<SendOtpResponse_Login?> CreateAadhaarLoginOtpAsync(SendAadhaarLoginOtpRequest request, string accessToken)
        {
            var baseUrl = _opt.BaseUrl?.TrimEnd('/') ?? "https://abhasbx.abdm.gov.in";
            var url = baseUrl + "/v3/profile/login/request/otp";

            using var req = new HttpRequestMessage(HttpMethod.Post, url);

            var requestId = Guid.NewGuid().ToString();

            // headers
            req.Headers.Add("REQUEST-ID", requestId);
            req.Headers.Add("TIMESTAMP", DateTime.UtcNow.ToString("o"));

            if (!string.IsNullOrWhiteSpace(accessToken))
                req.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);

            req.Headers.Accept.Clear();
            req.Headers.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));

            var bodyJson = JsonSerializer.Serialize(request);
            req.Content = new StringContent(bodyJson, Encoding.UTF8, "application/json");

            HttpResponseMessage resp;
            string raw = "";

            try
            {
                resp = await _http.SendAsync(req);
            }
            catch (Exception ex)
            {
                try { await _audit.LogRequestAsync(url, "Send Aadhaar login OTP", ex.ToString(), requestId); } catch { }
                var netEx = new HttpRequestException($"Network/HTTP failure calling ABHA {url}", ex);
                try { netEx.Data["RequestId"] = requestId; } catch { }
                try { netEx.Data["RequestUri"] = url; } catch { }
                throw netEx;
            }

            try
            {
                raw = await resp.Content.ReadAsStringAsync();
            }
            catch (Exception ex)
            {
                try { await _audit.LogRequestAsync(url, "Read Aadhaar login OTP response failed", ex.ToString(), requestId); } catch { }
                var readEx = new InvalidOperationException("Failed to read Aadhaar login OTP response body.", ex);
                try { readEx.Data["RequestId"] = requestId; } catch { }
                try { readEx.Data["RequestUri"] = url; } catch { }
                throw readEx;
            }

            try
            {
                await _audit.LogRequestAsync(url, bodyJson, raw, requestId);
            }
            catch { }

            if (!resp.IsSuccessStatusCode)
            {
                var httpEx = new HttpRequestException(
                    $"Aadhaar login send-otp failed with {(int)resp.StatusCode} {resp.ReasonPhrase}"
                );
                try { httpEx.Data["StatusCode"] = (int)resp.StatusCode; } catch { }
                try { httpEx.Data["RawBody"] = raw; } catch { }
                try { httpEx.Data["RequestId"] = requestId; } catch { }
                try { httpEx.Data["RequestUri"] = url; } catch { }
                throw httpEx;
            }

            try
            {
                return JsonSerializer.Deserialize<SendOtpResponse_Login>(
                    raw,
                    new JsonSerializerOptions { PropertyNameCaseInsensitive = true }
                );
            }
            catch (Exception ex)
            {
                var pex = new InvalidOperationException("Failed to deserialize SendOtpResponse_Login (Aadhaar login).", ex);
                try { pex.Data["RawBody"] = raw; } catch { }
                try { pex.Data["RequestId"] = requestId; } catch { }
                try { pex.Data["RequestUri"] = url; } catch { }
                throw pex;
            }
        }

        public async Task<LoginVerifyOtpResponse?> VerifyAadhaarLoginOtpAsync(LoginVerifyOtpRequest request, string accessToken)
        {
            var baseUrl = _opt.BaseUrl?.TrimEnd('/') ?? "https://abhasbx.abdm.gov.in";
            var url = baseUrl + "/v3/profile/login/verify";

            using var req = new HttpRequestMessage(HttpMethod.Post, url);

            var requestId = Guid.NewGuid().ToString();

            req.Headers.Add("REQUEST-ID", requestId);
            req.Headers.Add("TIMESTAMP", DateTime.UtcNow.ToString("o"));

            if (!string.IsNullOrWhiteSpace(accessToken))
                req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

            req.Headers.Accept.Clear();
            req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            var bodyJson = JsonSerializer.Serialize(request);
            req.Content = new StringContent(bodyJson, Encoding.UTF8, "application/json");

            HttpResponseMessage resp;
            string raw = "";

            try
            {
                resp = await _http.SendAsync(req);
            }
            catch (Exception ex)
            {
                try { await _audit.LogRequestAsync(url, "Aadhaar login verify", ex.ToString(), requestId); } catch { }
                throw new HttpRequestException($"Network/HTTP failure calling ABHA {url}", ex);
            }

            try
            {
                raw = await resp.Content.ReadAsStringAsync();
            }
            catch (Exception ex)
            {
                try { await _audit.LogRequestAsync(url, "Read Aadhaar login verify body failed", ex.ToString(), requestId); } catch { }
                throw new InvalidOperationException("Failed to read verify OTP response body.", ex);
            }

            try { await _audit.LogRequestAsync(url, bodyJson, raw, requestId); } catch { }

            if (!resp.IsSuccessStatusCode)
                throw new HttpRequestException($"Aadhaar login verify failed: {(int)resp.StatusCode} {resp.ReasonPhrase}. Body={raw}");

            return JsonSerializer.Deserialize<LoginVerifyOtpResponse>(
                raw,
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true }
            );
        }

        public async Task<SendOtpResponse_Login?> CreateAbhaNumberAadhaarOtpAsync(SendAadhaarLoginOtpRequest request, string accessToken)
        {
            var baseUrl = _opt.BaseUrl?.TrimEnd('/') ?? "https://abhasbx.abdm.gov.in";
            var url = baseUrl + "/v3/profile/login/request/otp";

            using var req = new HttpRequestMessage(HttpMethod.Post, url);

            var requestId = Guid.NewGuid().ToString();

            // headers
            req.Headers.Add("REQUEST-ID", requestId);
            req.Headers.Add("TIMESTAMP", DateTime.UtcNow.ToString("o"));

            if (!string.IsNullOrWhiteSpace(accessToken))
                req.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);

            req.Headers.Accept.Clear();
            req.Headers.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));

            var bodyJson = JsonSerializer.Serialize(request);
            req.Content = new StringContent(bodyJson, Encoding.UTF8, "application/json");

            HttpResponseMessage resp;
            string raw = "";

            try
            {
                resp = await _http.SendAsync(req);
            }
            catch (Exception ex)
            {
                try { await _audit.LogRequestAsync(url, "Send ABHA-number Aadhaar OTP", ex.ToString(), requestId); } catch { }
                var netEx = new HttpRequestException($"Network/HTTP failure calling ABHA {url}", ex);
                try { netEx.Data["RequestId"] = requestId; } catch { }
                try { netEx.Data["RequestUri"] = url; } catch { }
                throw netEx;
            }

            try
            {
                raw = await resp.Content.ReadAsStringAsync();
            }
            catch (Exception ex)
            {
                try { await _audit.LogRequestAsync(url, "Read ABHA-number Aadhaar OTP response failed", ex.ToString(), requestId); } catch { }
                var readEx = new InvalidOperationException("Failed to read ABHA-number Aadhaar OTP response body.", ex);
                try { readEx.Data["RequestId"] = requestId; } catch { }
                try { readEx.Data["RequestUri"] = url; } catch { }
                throw readEx;
            }

            try
            {
                await _audit.LogRequestAsync(url, bodyJson, raw, requestId);
            }
            catch { }

            if (!resp.IsSuccessStatusCode)
            {
                var httpEx = new HttpRequestException(
                    $"ABHA-number Aadhaar send-otp failed with {(int)resp.StatusCode} {resp.ReasonPhrase}"
                );
                try { httpEx.Data["StatusCode"] = (int)resp.StatusCode; } catch { }
                try { httpEx.Data["RawBody"] = raw; } catch { }
                try { httpEx.Data["RequestId"] = requestId; } catch { }
                try { httpEx.Data["RequestUri"] = url; } catch { }
                throw httpEx;
            }

            try
            {
                return JsonSerializer.Deserialize<SendOtpResponse_Login>(
                    raw,
                    new JsonSerializerOptions { PropertyNameCaseInsensitive = true }
                );
            }
            catch (Exception ex)
            {
                var pex = new InvalidOperationException("Failed to deserialize SendOtpResponse_Login (ABHA-number Aadhaar).", ex);
                try { pex.Data["RawBody"] = raw; } catch { }
                try { pex.Data["RequestId"] = requestId; } catch { }
                try { pex.Data["RequestUri"] = url; } catch { }
                throw pex;
            }
        }

        public async Task<LoginVerifyOtpResponse?> VerifyAbhaNumberAadhaarOtpAsync(LoginVerifyOtpRequest request, string accessToken)
        {
            var baseUrl = _opt.BaseUrl?.TrimEnd('/') ?? "https://abhasbx.abdm.gov.in";
            var url = baseUrl + "/v3/profile/login/verify";

            using var req = new HttpRequestMessage(HttpMethod.Post, url);

            var requestId = Guid.NewGuid().ToString();

            req.Headers.Add("REQUEST-ID", requestId);
            req.Headers.Add("TIMESTAMP", DateTime.UtcNow.ToString("o"));

            if (!string.IsNullOrWhiteSpace(accessToken))
                req.Headers.Authorization =
                    new AuthenticationHeaderValue("Bearer", accessToken);

            req.Headers.Accept.Clear();
            req.Headers.Accept.Add(
                new MediaTypeWithQualityHeaderValue("application/json"));

            var bodyJson = JsonSerializer.Serialize(request);
            req.Content = new StringContent(bodyJson, Encoding.UTF8, "application/json");

            HttpResponseMessage resp;
            string raw = "";

            try
            {
                resp = await _http.SendAsync(req);
            }
            catch (Exception ex)
            {
                try { await _audit.LogRequestAsync(url, "Verify ABHA-number Aadhaar OTP", ex.ToString(), requestId); } catch { }
                throw new HttpRequestException($"Network/HTTP failure calling ABHA {url}", ex);
            }

            try
            {
                raw = await resp.Content.ReadAsStringAsync();
            }
            catch (Exception ex)
            {
                try { await _audit.LogRequestAsync(url, "Read ABHA-number Aadhaar OTP response failed", ex.ToString(), requestId); } catch { }
                throw new InvalidOperationException("Failed to read ABHA-number Aadhaar verify response.", ex);
            }

            try { await _audit.LogRequestAsync(url, bodyJson, raw, requestId); } catch { }

            if (!resp.IsSuccessStatusCode)
            {
                var httpEx = new HttpRequestException(
                    $"ABHA-number Aadhaar verify-otp failed with {(int)resp.StatusCode} {resp.ReasonPhrase}"
                );
                try { httpEx.Data["RawBody"] = raw; } catch { }
                throw httpEx;
            }

            return JsonSerializer.Deserialize<LoginVerifyOtpResponse>(
                raw,
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true }
            );
        }

        public async Task<SendOtpResponse_Login?> CreateAbhaNumberAbhaOtpAsync(SendAadhaarLoginOtpRequest request, string accessToken)
        {
            var baseUrl = _opt.BaseUrl?.TrimEnd('/') ?? "https://abhasbx.abdm.gov.in";
            var url = baseUrl + "/v3/profile/login/request/otp";

            using var req = new HttpRequestMessage(HttpMethod.Post, url);

            var requestId = Guid.NewGuid().ToString();

            // Headers
            req.Headers.Add("REQUEST-ID", requestId);
            req.Headers.Add("TIMESTAMP", DateTime.UtcNow.ToString("o"));

            if (!string.IsNullOrWhiteSpace(accessToken))
                req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

            req.Headers.Accept.Clear();
            req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            // Body
            var bodyJson = JsonSerializer.Serialize(request);
            req.Content = new StringContent(bodyJson, Encoding.UTF8, "application/json");

            HttpResponseMessage resp;
            string raw = "";

            try
            {
                resp = await _http.SendAsync(req);
            }
            catch (Exception ex)
            {
                await _audit.LogRequestAsync(url, "Send ABHA OTP", ex.ToString(), requestId);
                throw new HttpRequestException($"Network/HTTP failure calling ABHA {url}", ex);
            }

            try
            {
                raw = await resp.Content.ReadAsStringAsync();
            }
            catch (Exception ex)
            {
                await _audit.LogRequestAsync(url, "Read ABHA OTP response failed", ex.ToString(), requestId);
                throw new InvalidOperationException("Failed to read ABHA OTP response body.", ex);
            }

            await _audit.LogRequestAsync(url, bodyJson, raw, requestId);

            if (!resp.IsSuccessStatusCode)
                throw new HttpRequestException($"ABHA-number ABHA OTP send failed: {(int)resp.StatusCode} {resp.ReasonPhrase} Body={raw}");

            return JsonSerializer.Deserialize<SendOtpResponse_Login>(raw,
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        }

        public async Task<LoginVerifyOtpResponse?> VerifyAbhaNumberAbhaOtpAsync(LoginVerifyOtpRequest request, string accessToken)
        {
            var baseUrl = _opt.BaseUrl?.TrimEnd('/') ?? "https://abhasbx.abdm.gov.in";
            var url = baseUrl + "/v3/profile/login/verify";

            using var req = new HttpRequestMessage(HttpMethod.Post, url);

            var requestId = Guid.NewGuid().ToString();

            req.Headers.Add("REQUEST-ID", requestId);
            req.Headers.Add("TIMESTAMP", DateTime.UtcNow.ToString("o"));

            if (!string.IsNullOrWhiteSpace(accessToken))
                req.Headers.Authorization =
                    new AuthenticationHeaderValue("Bearer", accessToken);

            req.Headers.Accept.Clear();
            req.Headers.Accept.Add(
                new MediaTypeWithQualityHeaderValue("application/json"));

            var bodyJson = JsonSerializer.Serialize(request);
            req.Content = new StringContent(bodyJson, Encoding.UTF8, "application/json");

            HttpResponseMessage resp;
            string raw = "";

            try
            {
                resp = await _http.SendAsync(req);
            }
            catch (Exception ex)
            {
                await _audit.LogRequestAsync(url, "Verify ABHA OTP", ex.ToString(), requestId);
                throw new HttpRequestException($"Network/HTTP failure calling ABHA {url}", ex);
            }

            try
            {
                raw = await resp.Content.ReadAsStringAsync();
            }
            catch (Exception ex)
            {
                await _audit.LogRequestAsync(url, "Read ABHA verify-otp response failed", ex.ToString(), requestId);
                throw new InvalidOperationException("Failed to read ABHA verify-otp response body.", ex);
            }

            await _audit.LogRequestAsync(url, bodyJson, raw, requestId);

            if (!resp.IsSuccessStatusCode)
                throw new HttpRequestException(
                    $"ABHA-number ABHA verify-otp failed: {(int)resp.StatusCode} {resp.ReasonPhrase}. Body={raw}"
                );

            return JsonSerializer.Deserialize<LoginVerifyOtpResponse>(
                raw,
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true }
            );
        }

        public async Task<SendOtpResponse_Login?> CreateMobileLoginOtpAsync(SendAadhaarLoginOtpRequest request, string accessToken)
        {
            var baseUrl = _opt.BaseUrl?.TrimEnd('/') ?? "https://abhasbx.abdm.gov.in";
            var url = baseUrl + "/v3/profile/login/request/otp";

            using var req = new HttpRequestMessage(HttpMethod.Post, url);

            var requestId = Guid.NewGuid().ToString();

            // headers
            req.Headers.Add("REQUEST-ID", requestId);
            req.Headers.Add("TIMESTAMP", DateTime.UtcNow.ToString("o"));

            if (!string.IsNullOrWhiteSpace(accessToken))
                req.Headers.Authorization =
                    new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);

            req.Headers.Accept.Clear();
            req.Headers.Accept.Add(
                new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));

            var bodyJson = JsonSerializer.Serialize(request);
            req.Content = new StringContent(bodyJson, Encoding.UTF8, "application/json");

            HttpResponseMessage resp;
            string raw = "";

            try
            {
                resp = await _http.SendAsync(req);
            }
            catch (Exception ex)
            {
                try
                {
                    await _audit.LogRequestAsync(
                        url,
                        "Send mobile login OTP",
                        ex.ToString(),
                        requestId
                    );
                }
                catch { }

                var netEx = new HttpRequestException($"Network/HTTP failure calling ABHA {url}", ex);
                try { netEx.Data["RequestId"] = requestId; } catch { }
                try { netEx.Data["RequestUri"] = url; } catch { }
                throw netEx;
            }

            try
            {
                raw = await resp.Content.ReadAsStringAsync();
            }
            catch (Exception ex)
            {
                try
                {
                    await _audit.LogRequestAsync(
                        url,
                        "Read mobile login OTP response failed",
                        ex.ToString(),
                        requestId
                    );
                }
                catch { }

                var readEx = new InvalidOperationException("Failed to read mobile login OTP response body.", ex);
                try { readEx.Data["RequestId"] = requestId; } catch { }
                try { readEx.Data["RequestUri"] = url; } catch { }
                throw readEx;
            }

            try
            {
                await _audit.LogRequestAsync(url, bodyJson, raw, requestId);
            }
            catch { }

            if (!resp.IsSuccessStatusCode)
            {
                var httpEx = new HttpRequestException(
                    $"Mobile login send-otp failed with {(int)resp.StatusCode} {resp.ReasonPhrase}"
                );
                try { httpEx.Data["StatusCode"] = (int)resp.StatusCode; } catch { }
                try { httpEx.Data["RawBody"] = raw; } catch { }
                try { httpEx.Data["RequestId"] = requestId; } catch { }
                try { httpEx.Data["RequestUri"] = url; } catch { }
                throw httpEx;
            }

            try
            {
                return JsonSerializer.Deserialize<SendOtpResponse_Login>(
                    raw,
                    new JsonSerializerOptions { PropertyNameCaseInsensitive = true }
                );
            }
            catch (Exception ex)
            {
                var pex = new InvalidOperationException("Failed to deserialize SendOtpResponse_Login (mobile login).", ex);
                try { pex.Data["RawBody"] = raw; } catch { }
                try { pex.Data["RequestId"] = requestId; } catch { }
                try { pex.Data["RequestUri"] = url; } catch { }
                throw pex;
            }
        }

        public async Task<LoginVerifyOtpResponse?> VerifyMobileLoginOtpAsync(LoginVerifyOtpRequest request, string accessToken)
        {
            var baseUrl = _opt.BaseUrl?.TrimEnd('/') ?? "https://abhasbx.abdm.gov.in";
            var url = baseUrl + "/v3/profile/login/verify";

            using var req = new HttpRequestMessage(HttpMethod.Post, url);

            var requestId = Guid.NewGuid().ToString();

            req.Headers.Add("REQUEST-ID", requestId);
            req.Headers.Add("TIMESTAMP", DateTime.UtcNow.ToString("o"));

            if (!string.IsNullOrWhiteSpace(accessToken))
                req.Headers.Authorization =
                    new AuthenticationHeaderValue("Bearer", accessToken);

            req.Headers.Accept.Clear();
            req.Headers.Accept.Add(
                new MediaTypeWithQualityHeaderValue("application/json"));

            var bodyJson = JsonSerializer.Serialize(request);
            req.Content = new StringContent(bodyJson, Encoding.UTF8, "application/json");

            HttpResponseMessage resp;
            string raw = "";

            try
            {
                resp = await _http.SendAsync(req);
            }
            catch (Exception ex)
            {
                await _audit.LogRequestAsync(url, "Verify mobile login OTP", ex.ToString(), requestId);
                throw new HttpRequestException($"Network/HTTP failure calling ABHA {url}", ex);
            }

            try
            {
                raw = await resp.Content.ReadAsStringAsync();
            }
            catch (Exception ex)
            {
                await _audit.LogRequestAsync(url, "Read OTP verify response failed", ex.ToString(), requestId);
                throw new InvalidOperationException("Failed to read verify OTP response body.", ex);
            }

            await _audit.LogRequestAsync(url, bodyJson, raw, requestId);

            if (!resp.IsSuccessStatusCode)
                throw new HttpRequestException(
                    $"Mobile verify-otp failed with {(int)resp.StatusCode} {resp.ReasonPhrase}. Body={raw}"
                );

            return JsonSerializer.Deserialize<LoginVerifyOtpResponse>(
                raw,
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true }
            );
        }

        public async Task<VerifyUserResponseDto?> VerifyUserAsync(VerifyUserRequestDto request, string accessToken)
        {
            var baseUrl = _opt.BaseUrl?.TrimEnd('/') ?? "https://abhasbx.abdm.gov.in";
            var url = baseUrl + "/v3/profile/login/verify/user";

            using var req = new HttpRequestMessage(HttpMethod.Post, url);

            var requestId = Guid.NewGuid().ToString();

            req.Headers.Add("REQUEST-ID", requestId);
            req.Headers.Add("TIMESTAMP", DateTime.UtcNow.ToString("o"));

            if (!string.IsNullOrWhiteSpace(request.tToken))
                req.Headers.TryAddWithoutValidation("T-token", $"Bearer {request.tToken}");
            //req.Headers.Add("T-token", request.tToken);   // 👈 IMPORTANT

            if (!string.IsNullOrWhiteSpace(accessToken))
                req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

            req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            var bodyJson = JsonSerializer.Serialize(request);
            req.Content = new StringContent(bodyJson, Encoding.UTF8, "application/json");

            HttpResponseMessage resp;
            string raw = "";

            try
            {
                resp = await _http.SendAsync(req);
            }
            catch (Exception ex)
            {
                await _audit.LogRequestAsync(url, "VerifyUser", ex.ToString(), requestId);
                throw;
            }

            raw = await resp.Content.ReadAsStringAsync();
            await _audit.LogRequestAsync(url, bodyJson, raw, requestId);

            if (!resp.IsSuccessStatusCode)
                throw new HttpRequestException($"verify-user failed {(int)resp.StatusCode}. Body={raw}")
                {
                    Data = { ["StatusCode"] = (int)resp.StatusCode, ["RawBody"] = raw }
                };

            return JsonSerializer.Deserialize<VerifyUserResponseDto>(
                raw, new JsonSerializerOptions { PropertyNameCaseInsensitive = true }
            );
        }

    }
}
