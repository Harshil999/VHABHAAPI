using ABHA_HIMS.Application.Dtos;
using ABHA_HIMS.Application.External;
using ABHA_HIMS.Application.Interfaces;
using ABHA_HIMS.Domain;
using ABHA_HIMS.Domain.Utils;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using System;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using static ABHA_HIMS.Domain.AbhaDtos;


namespace ABHA_HIMS.Application.Services
{
    public class AbhaService : IAbhaService
    {
        private readonly IAbhaGatewayService _gateway;
        private readonly IAbhaAuditRepository _audit;
        private readonly AbhaOptions _opt;
        private readonly IMemoryCache _cache; // used to store txn -> metadata

        public async Task<SessionResponse> GetSessionAsync()
        => await _gateway.GetSessionTokenAsync();

        public async Task<SessionResponse> GetSessionAsync(string clientId, string clientSecret)
            => await _gateway.GetSessionTokenAsync(clientId, clientSecret);

        public async Task<PublicCertResponse> GetPublicKeyAsync()
            => await _gateway.GetPublicKeyAsync();

        public AbhaService(IAbhaGatewayService gateway, IAbhaAuditRepository audit, IOptions<AbhaOptions> opt, IMemoryCache cache)
        {
            _gateway = gateway ?? throw new ArgumentNullException(nameof(gateway));
            _audit = audit ?? throw new ArgumentNullException(nameof(audit));
            _opt = opt?.Value ?? throw new ArgumentNullException(nameof(opt));
            _cache = cache ?? throw new ArgumentNullException(nameof(cache));
        }

        /// <summary>
        /// High-level: encrypts aadhaar using public cert, builds SendOtpRequest and calls gateway.
        /// Returns ABHA SendOtpResponse (contains txnId which we cache for later verify).
        /// </summary>
        public async Task<SendOtpResponse?> SendOtpAsync(string aadhaarPlain)
        {
            if (string.IsNullOrWhiteSpace(aadhaarPlain)) throw new ArgumentNullException(nameof(aadhaarPlain));

            // 1) get public cert
            var cert = await _gateway.GetPublicKeyAsync();
            if (cert == null) throw new InvalidOperationException("Unable to obtain public certificate");

            // cert.PublicKey or cert.PublicKeyPem name depends on your DTO; adapt accordingly.
            // Assume PublicCertResponse has properties: PublicKey / PublicKeyPem and EncryptionAlgorithm
            var publicKeyPem = cert.PublicKey ?? cert.PublicKey ?? throw new InvalidOperationException("Public key missing in certificate response");
            var algo = cert.EncryptionAlgorithm; // may be null

            // 2) encrypt aadhaar
            var encLoginId = AbhaEncryptionHelper.EncryptWithPublicKey(publicKeyPem, aadhaarPlain, algo);

            // 3) build SendOtpRequest (camel-case names will be used by HttpClient)
            var sendReq = new SendOtpRequest
            {
                TxnId = "", // let ABHA create
                Scope = new[] { "abha-enrol" },
                LoginHint = "aadhaar",
                LoginId = encLoginId,
                OtpSystem = "aadhaar"
            };

            // 4) call gateway
            var resp = await _gateway.SendOtpAsync(sendReq);

            // 5) cache txn metadata for verify flow (10 minutes)
            try
            {
                if (resp != null && !string.IsNullOrWhiteSpace(resp.TxnId))
                {
                    var meta = new { AadhaarHash = ComputeSha256Hash(aadhaarPlain), Created = DateTime.UtcNow };
                    _cache.Set($"txn_{resp.TxnId}", meta, TimeSpan.FromMinutes(10));
                }
            }
            catch { /* swallow caching errors */ }

            // 6) audit (optional)
            try
            {
                await _audit.LogRequestAsync("/abha/api/v3/enrollment/request/otp", JsonSerializer.Serialize(sendReq), JsonSerializer.Serialize(resp), resp?.TxnId ?? "");
            }
            catch { /* don't fail on audit */ }

            return resp;
        }

        public async Task<CreateAbhaResponse?> CreateAbhaAsync(object reqBody)
        {
            if (reqBody == null) throw new ArgumentNullException(nameof(reqBody));

            // serialize incoming body to JSON so we can inspect/modify
            var jsonOptions = new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                PropertyNameCaseInsensitive = true,
                DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
            };

            string incomingJson = JsonSerializer.Serialize(reqBody, jsonOptions);
            var requestId = Guid.NewGuid().ToString();
            JsonNode? root;
            try
            {
                root = JsonNode.Parse(incomingJson);
                if (root == null) throw new InvalidOperationException("Invalid JSON payload");
            }
            catch (Exception ex)
            {
                //_logger?.LogError(ex, "Failed to parse reqBody JSON in CreateAbhaAsync");
                throw;
            }

            try
            {
                // Navigate to otp value: authData -> otp -> otpValue
                var otpNode = root["authData"]?["otp"]?["otpValue"];
                if (otpNode != null)
                {
                    var otpValue = otpNode.GetValue<string>() ?? string.Empty;

                    // Heuristic: If otpValue looks like already-encrypted (long base64 or contains '=' or looks non-numeric),
                    // skip encryption. If it's short numeric (typical 4-6 digit OTP) then encrypt.
                    bool looksPlainOtp = !string.IsNullOrWhiteSpace(otpValue) &&
                                          otpValue.Length <= 10 && // typical OTP length <= 6-8, safe margin
                                          otpValue.All(ch => char.IsDigit(ch));

                    if (looksPlainOtp)
                    {
                        // 1) get public cert/key from gateway
                        var cert = await _gateway.GetPublicKeyAsync();
                        if (cert == null) throw new InvalidOperationException("Unable to obtain public certificate for OTP encryption");

                        // adapt property name according to your cert DTO
                        var publicKeyPem = cert.PublicKey ?? cert.PublicKey ?? throw new InvalidOperationException("Public key missing in certificate response");
                        var algo = cert.EncryptionAlgorithm; // optional

                        // 2) encrypt otp using helper
                        var encryptedOtp = AbhaEncryptionHelper.EncryptWithPublicKey(publicKeyPem, otpValue, algo);

                        // 3) replace otpValue in JSON tree with encrypted value
                        root["authData"]!["otp"]!["otpValue"] = encryptedOtp;
                        //_logger?.LogDebug("OTP was plain; encrypted inside CreateAbhaAsync before forwarding.");
                    }
                    else
                    {
                        //_logger?.LogDebug("OTP appears already encrypted or non-numeric; forwarding as-is.");
                    }
                }
                else
                {
                    //_logger?.LogWarning("CreateAbhaAsync: otpValue not found in request body (authData.otp.otpValue). Forwarding original payload.");
                }
            }
            catch (Exception ex)
            {
                // Non-fatal: log and continue with original payload (or rethrow if you prefer)
                //_logger?.LogError(ex, "Error while attempting to encrypt OTP in CreateAbhaAsync - forwarding original payload");
            }

            // Final payload to send
            var finalJson = root.ToJsonString(jsonOptions);
            var finalReqElement = JsonDocument.Parse(finalJson).RootElement;

            // Call gateway and audit
            CreateAbhaResponse? resp = null;
            try
            {
                // reuse token flow inside gateway
                resp = await _gateway.CreateAbhaByAadhaarAsync(finalReqElement);

                // Audit: store request/response (stringify)
                try
                {
                    await _audit.LogRequestAsync("/abha/api/v3/enrollment/enrol/byAadhaar", finalJson, JsonSerializer.Serialize(resp, jsonOptions), "");
                }
                catch (Exception ex)
                {
                    //_logger?.LogWarning(aex, "Audit logging failed for CreateAbhaAsync");
                }

                return resp;
            }
            catch (Exception ex)
            {
                try
                {
                    if (!ex.Data.Contains("RequestId"))
                        ex.Data["RequestId"] = requestId;
                    if (!ex.Data.Contains("Payload"))
                        ex.Data["Payload"] = finalJson;
                }
                catch { /* ignore */ }

                // rethrow (preserve stack)
                throw;
            }
        }

        public async Task<SendOtpResponse_MobileUpdate?> SendMobileUpdateOtpAsync(string mobilePlain, string? txnId = null)
        {
            var requestId = Guid.NewGuid().ToString();
            if (string.IsNullOrWhiteSpace(mobilePlain)) throw new ArgumentNullException(nameof(mobilePlain));

            // 1) get public key/cert
            var cert = await _gateway.GetPublicKeyAsync();
            if (cert == null)
            {
                //_logger?.LogError("Public key fetch failed for SendMobileUpdateOtpAsync");
                throw new InvalidOperationException("Unable to obtain public certificate");
            }

            var publicKeyPem = cert.PublicKey ?? cert.PublicKey ?? throw new InvalidOperationException("Public key missing in certificate response");
            var algo = cert.EncryptionAlgorithm;

            // 2) encrypt mobile
            var encryptedMobile = AbhaEncryptionHelper.EncryptWithPublicKey(publicKeyPem, mobilePlain, algo);

            // 3) build ABHA request object
            var sendReq = new SendMobileOtpRequest
            {
                TxnId = txnId ?? "",
                Scope = new[] { "abha-enrol", "mobile-verify" },
                LoginHint = "mobile",
                LoginId = encryptedMobile,
                OtpSystem = "abdm"
            };

            // 4) call gateway
            SendOtpResponse_MobileUpdate? resp = null;
            try
            {
                resp = await _gateway.CreateMobileUpdateOtpAsync(sendReq);
            }
            catch (Exception ex)
            {
                try
                {
                    if (ex.Data != null && !ex.Data.Contains("RequestId"))
                        ex.Data["RequestId"] = requestId;
                    if (ex.Data != null && !ex.Data.Contains("Payload"))
                        ex.Data["Payload"] = JsonSerializer.Serialize(sendReq, new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase });
                }
                catch { /* swallow */ }

                try
                {
                    // best-effort audit of failed attempt
                    await _audit.LogRequestAsync("/abha/mobile/update/sendOtp", JsonSerializer.Serialize(sendReq), ex.ToString(), requestId);
                }
                catch { /* swallow audit errors */ }

                // rethrow preserving stack (use throw; in callers — here we rethrow same exception)
                throw;
            }

            // 5) audit request/response
            try
            {
                await _audit.LogRequestAsync("/abha/mobile/update/sendOtp", JsonSerializer.Serialize(sendReq), JsonSerializer.Serialize(resp), "");
            }
            catch (Exception aex)
            {
                //_logger?.LogWarning(aex, "Audit logging failed for SendMobileUpdateOtpAsync");
            }

            return resp;
        }

        public async Task<MobileVerifyResponse?> VerifyMobileUpdateOtpAsync(string txnId, string otpPlainOrEncrypted)
        {
            if (string.IsNullOrWhiteSpace(txnId)) throw new ArgumentNullException(nameof(txnId));
            if (string.IsNullOrWhiteSpace(otpPlainOrEncrypted)) throw new ArgumentNullException(nameof(otpPlainOrEncrypted));

            // 1) prepare JSON object structure per ABHA
            // We'll try to detect if otp is plain numeric; if so, encrypt it using public key.
            string otpToSend = otpPlainOrEncrypted;

            bool looksPlainOtp = otpPlainOrEncrypted.Length <= 10 && otpPlainOrEncrypted.All(char.IsDigit);

            if (looksPlainOtp)
            {
                var cert = await _gateway.GetPublicKeyAsync();
                if (cert == null)
                {
                    //_logger?.LogError("Public key fetch failed for VerifyMobileUpdateOtpAsync");
                    throw new InvalidOperationException("Unable to obtain public certificate for OTP encryption");
                }

                var publicKeyPem = cert.PublicKey ?? cert.PublicKey ?? throw new InvalidOperationException("Public key missing in certificate response");
                var algo = cert.EncryptionAlgorithm;
                otpToSend = AbhaEncryptionHelper.EncryptWithPublicKey(publicKeyPem, otpPlainOrEncrypted, algo);
            }
            else
            {
                //_logger?.LogDebug("OTP appears encrypted; forwarding as-is.");
            }

            // build final request object matching the schema you posted
            var reqBody = new
            {
                scope = new[] { "abha-enrol", "mobile-verify" },
                authData = new
                {
                    authMethods = new[] { "otp" },
                    otp = new
                    {
                        timeStamp = DateTime.UtcNow.ToString("o"), // server-provided timestamp (can be overridden if required)
                        txnId = txnId,
                        otpValue = otpToSend
                    }
                }
            };

            // 2) call gateway
            MobileVerifyResponse? resp = null;
            var requestId = Guid.NewGuid().ToString();
            string reqJson = JsonSerializer.Serialize(reqBody, new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase });

            try
            {
                resp = await _gateway.VerifyMobileUpdateOtpAsync(reqBody);
            }
            catch (Exception ex)
            {
                try
                {
                    if (ex.Data != null && !ex.Data.Contains("RequestId")) ex.Data["RequestId"] = requestId;
                    if (ex.Data != null && !ex.Data.Contains("Payload")) ex.Data["Payload"] = reqJson;
                    if (ex.Data != null && !ex.Data.Contains("GatewayMethod")) ex.Data["GatewayMethod"] = "VerifyMobileUpdateOtpAsync";
                }
                catch { /* ignore */ }

                // best-effort audit of failure
                try { await _audit.LogRequestAsync("/abha/mobile/update/verifyOtp", reqJson, ex.ToString(), requestId); } catch { }

                // rethrow preserving original stack
                throw;
            }

            // 3) audit
            try
            {
                await _audit.LogRequestAsync("/abha/mobile/update/verifyOtp", reqJson, JsonSerializer.Serialize(resp), "");
            }
            catch (Exception aex)
            {
                //_logger?.LogWarning(aex, "Audit logging failed for VerifyMobileUpdateOtpAsync");
            }

            return resp;
        }

        public async Task<EmailVerificationResponse?> SendEmailVerificationLinkAsync(string emailPlain, string? authToken, string? xToken)
        {
            if (string.IsNullOrWhiteSpace(emailPlain)) throw new ArgumentNullException(nameof(emailPlain));

            // 1) Get public key
            var cert = await _gateway.GetPublicKeyAsync();
            if (cert == null) throw new InvalidOperationException("Unable to obtain public certificate");

            var publicKeyPem = cert.PublicKey ?? cert.PublicKey ?? throw new InvalidOperationException("Public key missing");
            var algo = cert.EncryptionAlgorithm;

            // 2) Encrypt email
            var encryptedEmail = AbhaEncryptionHelper.EncryptWithPublicKey(publicKeyPem, emailPlain, algo);

            // 3) Prepare request object
            var req = new EmailVerificationRequest
            {
                LoginId = encryptedEmail
            };

            var requestId = Guid.NewGuid().ToString();
            var urlPath = "/abha/api/v3/profile/account/request/emailVerificationLink";
            EmailVerificationResponse? resp = null;
            try
            {
                resp = await _gateway.SendEmailVerificationLinkAsync(req, authToken, xToken);

                await _audit.LogRequestAsync("/abha/api/v3/profile/account/request/emailVerificationLink",
                    JsonSerializer.Serialize(req), JsonSerializer.Serialize(resp), "");
            }
            catch (Exception ex)
            {
                //_logger?.LogError(ex, "Gateway call failed in SendEmailVerificationLinkAsync");
                //try { await _audit.LogRequestAsync("/abha/api/v3/profile/account/request/emailVerificationLink", JsonSerializer.Serialize(req), ex.ToString(), ""); } catch { }
                try
                {
                    await _audit.LogRequestAsync(urlPath, JsonSerializer.Serialize(req), ex.ToString(), requestId);
                }
                catch { /* swallow audit errors */ }

                // rethrow to let controller handle mapping to proper HTTP status & response
                throw;
            }

            return resp;
        }

        public async Task<AbhaSuggestionResponse?> GetAbhaSuggestionsAsync(string txnId)
        {
            if (string.IsNullOrWhiteSpace(txnId)) throw new ArgumentNullException(nameof(txnId));

            AbhaSuggestionResponse? resp = null;

            try
            {
                resp = await _gateway.GetAbhaSuggestionsAsync(txnId);

                await _audit.LogRequestAsync("/abha/api/v3/enrollment/enrol/suggestion",
                    $"txnId: {txnId}", JsonSerializer.Serialize(resp), "");
            }
            catch (Exception ex)
            {
                //_logger?.LogError(ex, "Error calling GetAbhaSuggestionsAsync");
                try { await _audit.LogRequestAsync("/abha/api/v3/enrollment/enrol/suggestion", $"txnId: {txnId}", ex.ToString(), ""); } catch { }
                throw;
            }

            return resp;
        }

        public async Task<AbhaAddressResponse?> PostAbhaAddressAsync(AbhaAddressRequest request)
        {
            if (string.IsNullOrWhiteSpace(request.TxnId)) throw new ArgumentNullException(nameof(request.TxnId));
            if (request == null) throw new ArgumentNullException(nameof(request));

            AbhaAddressResponse? resp = null;
            try
            {
                // ensure request txnId is set (server wants it)
                resp = await _gateway.PostAbhaAddressAsync(request);

                await _audit.LogRequestAsync("/abha/api/v3/enrollment/enrol/abha-address",
                    $"txnId: {request.TxnId}", JsonSerializer.Serialize(request), JsonSerializer.Serialize(resp));
            }
            catch (Exception ex)
            {
                try { await _audit.LogRequestAsync("/abha/api/v3/enrollment/enrol/abha-address", $"txnId: {request.TxnId}", ex.ToString(), ""); } catch { }
                throw;
            }

            return resp;
        }

        public async Task<AbhaProfileResponse?> GetProfileDetailsAsync(string txnId, string xToken)
        {
            if (string.IsNullOrWhiteSpace(txnId)) throw new ArgumentNullException(nameof(txnId));

            AbhaProfileResponse? resp = null;

            try
            {
                // call gateway (or lower-level service) which will actually call ABHA endpoint
                resp = await _gateway.GetProfileDetailsAsync(txnId, xToken);

                await _audit.LogRequestAsync("/abha/api/v3/profile/account",
                    $"txnId: {txnId}", JsonSerializer.Serialize(resp), "");
            }
            catch (Exception ex)
            {
                try { await _audit.LogRequestAsync("/abha/api/v3/profile/account", $"txnId: {txnId}", ex.ToString(), ""); } catch { }
                throw;
            }

            return resp;
        }

        public async Task<AbhaCardFile?> GetAbhaCardAsync(string xToken)
        {
            if (string.IsNullOrWhiteSpace(xToken))
                throw new ArgumentNullException(nameof(xToken));

            AbhaCardFile? resp = null;

            try
            {
                resp = await _gateway.GetAbhaCardAsync(xToken);

                // Audit: just metadata, content length only
                var info = $"ABHA card fetched, contentLength={(resp?.Content?.Length ?? 0)}";
                await _audit.LogRequestAsync(
                    "/abha/api/v3/profile/account/abha-card",
                    info,
                    "", // no body
                    ""
                );
            }
            catch (Exception ex)
            {
                try
                {
                    await _audit.LogRequestAsync(
                        "/abha/api/v3/profile/account/abha-card",
                        $"xToken: [hidden]",
                        ex.ToString(),
                        ""
                    );
                }
                catch { }

                throw;
            }

            return resp;
        }

        ///////////////////////////////////////////////////////////////////////////////////////////////////////

        public async Task<SendOtpResponse_Login?> SendAadhaarLoginOtpAsync(string aadhaarPlain)
        {
            var requestId = Guid.NewGuid().ToString();
            if (string.IsNullOrWhiteSpace(aadhaarPlain))
                throw new ArgumentNullException(nameof(aadhaarPlain));

            // 1) get public key/cert
            var cert = await _gateway.GetPublicKeyAsync();
            if (cert == null)
                throw new InvalidOperationException("Unable to obtain public certificate");

            var publicKeyPem = cert.PublicKey ?? throw new InvalidOperationException("Public key missing in certificate response");
            var algo = cert.EncryptionAlgorithm;

            // 2) encrypt Aadhaar
            var encryptedAadhaar = AbhaEncryptionHelper.EncryptWithPublicKey(publicKeyPem, aadhaarPlain, algo);

            // 3) build ABHA request object (LOGIN via AADHAAR)
            var sendReq = new SendAadhaarLoginOtpRequest
            {
                Scope = new[] { "abha-login", "aadhaar-verify" },
                LoginHint = "aadhaar",
                LoginId = encryptedAadhaar,
                OtpSystem = "aadhaar"
            };

            SendOtpResponse_Login? resp = null;

            try
            {
                // 4) call gateway
                resp = await _gateway.CreateAadhaarLoginOtpAsync(sendReq);
            }
            catch (Exception ex)
            {
                try
                {
                    if (ex.Data != null && !ex.Data.Contains("RequestId"))
                        ex.Data["RequestId"] = requestId;
                    if (ex.Data != null && !ex.Data.Contains("Payload"))
                        ex.Data["Payload"] = JsonSerializer.Serialize(sendReq,
                            new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase });
                }
                catch { }

                try
                {
                    await _audit.LogRequestAsync(
                        "/abha/login/aadhaar/sendOtp",
                        JsonSerializer.Serialize(sendReq),
                        ex.ToString(),
                        requestId
                    );
                }
                catch { }

                throw;
            }

            // 5) audit success
            try
            {
                await _audit.LogRequestAsync(
                    "/abha/login/aadhaar/sendOtp",
                    JsonSerializer.Serialize(sendReq),
                    JsonSerializer.Serialize(resp),
                    ""
                );
            }
            catch { }

            return resp;
        }

        public async Task<LoginVerifyOtpResponse?> VerifyAadhaarLoginOtpAsync(string txnId, string otpPlain)
        {
            var requestId = Guid.NewGuid().ToString();

            if (string.IsNullOrWhiteSpace(txnId))
                throw new ArgumentNullException(nameof(txnId));
            if (string.IsNullOrWhiteSpace(otpPlain))
                throw new ArgumentNullException(nameof(otpPlain));

            // 1) get public key/cert (same as send-OTP)
            var cert = await _gateway.GetPublicKeyAsync();
            if (cert == null)
                throw new InvalidOperationException("Unable to obtain public certificate");

            var publicKeyPem = cert.PublicKey ?? throw new InvalidOperationException("Public key missing in certificate response");
            var algo = cert.EncryptionAlgorithm;

            // 2) encrypt OTP using ABHA public key
            var encryptedOtp = AbhaEncryptionHelper.EncryptWithPublicKey(publicKeyPem, otpPlain, algo);

            // 3) build ABHA verify request
            var verifyReq = new LoginVerifyOtpRequest
            {
                Scope = new[] { "abha-login", "aadhaar-verify" },
                AuthData = new LoginVerifyAuthData
                {
                    AuthMethods = new[] { "otp" },
                    Otp = new LoginVerifyOtpBlock
                    {
                        TxnId = txnId,
                        OtpValue = encryptedOtp
                    }
                }
            };

            LoginVerifyOtpResponse? resp = null;

            try
            {
                // 4) call gateway
                resp = await _gateway.VerifyAadhaarLoginOtpAsync(verifyReq);
            }
            catch (Exception ex)
            {
                try
                {
                    if (ex.Data != null && !ex.Data.Contains("RequestId"))
                        ex.Data["RequestId"] = requestId;
                    if (ex.Data != null && !ex.Data.Contains("Payload"))
                        ex.Data["Payload"] = JsonSerializer.Serialize(verifyReq,
                            new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase });
                }
                catch { }

                try
                {
                    await _audit.LogRequestAsync(
                        "/abha/login/aadhaar/verifyOtp",
                        JsonSerializer.Serialize(verifyReq),
                        ex.ToString(),
                        requestId
                    );
                }
                catch { }

                throw;
            }

            // 5) audit success
            try
            {
                await _audit.LogRequestAsync(
                    "/abha/login/aadhaar/verifyOtp",
                    JsonSerializer.Serialize(verifyReq),
                    JsonSerializer.Serialize(resp),
                    ""
                );
            }
            catch { }

            return resp;
        }

        public async Task<SendOtpResponse_Login?> SendAbhaNumberAadhaarOtpAsync(string abhaNumberPlain)
        {
            var requestId = Guid.NewGuid().ToString();
            if (string.IsNullOrWhiteSpace(abhaNumberPlain))
                throw new ArgumentNullException(nameof(abhaNumberPlain));

            // 1) get public key/cert
            var cert = await _gateway.GetPublicKeyAsync();
            if (cert == null)
                throw new InvalidOperationException("Unable to obtain public certificate");

            var publicKeyPem = cert.PublicKey ?? throw new InvalidOperationException("Public key missing in certificate response");
            var algo = cert.EncryptionAlgorithm;

            // 2) encrypt ABHA number
            var encryptedAbha = AbhaEncryptionHelper.EncryptWithPublicKey(publicKeyPem, abhaNumberPlain, algo);

            // 3) build ABHA request object (LOGIN via ABHA NUMBER using Aadhaar OTP)
            var sendReq = new SendAadhaarLoginOtpRequest   // same structure, sirf values alag
            {
                Scope = new[] { "abha-login", "aadhaar-verify" },
                LoginHint = "abha-number",
                LoginId = encryptedAbha,
                OtpSystem = "aadhaar"
            };

            SendOtpResponse_Login? resp = null;

            try
            {
                // 4) call gateway
                resp = await _gateway.CreateAbhaNumberAadhaarOtpAsync(sendReq);
            }
            catch (Exception ex)
            {
                try
                {
                    if (ex.Data != null && !ex.Data.Contains("RequestId"))
                        ex.Data["RequestId"] = requestId;
                    if (ex.Data != null && !ex.Data.Contains("Payload"))
                        ex.Data["Payload"] = JsonSerializer.Serialize(sendReq,
                            new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase });
                }
                catch { }

                try
                {
                    await _audit.LogRequestAsync(
                        "/abha/login/abha-number/aadhaar-otp/sendOtp",
                        JsonSerializer.Serialize(sendReq),
                        ex.ToString(),
                        requestId
                    );
                }
                catch { }

                throw;
            }

            // 5) audit success
            try
            {
                await _audit.LogRequestAsync(
                    "/abha/login/abha-number/aadhaar-otp/sendOtp",
                    JsonSerializer.Serialize(sendReq),
                    JsonSerializer.Serialize(resp),
                    ""
                );
            }
            catch { }

            return resp;
        }

        public async Task<LoginVerifyOtpResponse?> VerifyAbhaNumberAadhaarOtpAsync(string txnId, string otpPlain)
        {
            var requestId = Guid.NewGuid().ToString();

            if (string.IsNullOrWhiteSpace(txnId))
                throw new ArgumentNullException(nameof(txnId));
            if (string.IsNullOrWhiteSpace(otpPlain))
                throw new ArgumentNullException(nameof(otpPlain));

            // 1) get public key
            var cert = await _gateway.GetPublicKeyAsync();
            if (cert == null)
                throw new InvalidOperationException("Unable to obtain public certificate");

            var publicKeyPem = cert.PublicKey ?? throw new InvalidOperationException("Public key missing");
            var algo = cert.EncryptionAlgorithm;

            // 2) encrypt OTP
            var encryptedOtp = AbhaEncryptionHelper.EncryptWithPublicKey(publicKeyPem, otpPlain, algo);

            // 3) create ABHA request
            var verifyReq = new LoginVerifyOtpRequest
            {
                Scope = new[] { "abha-login", "aadhaar-verify" },
                AuthData = new LoginVerifyAuthData
                {
                    AuthMethods = new[] { "otp" },
                    Otp = new LoginVerifyOtpBlock
                    {
                        TxnId = txnId,
                        OtpValue = encryptedOtp
                    }
                }
            };

            LoginVerifyOtpResponse? resp = null;

            try
            {
                resp = await _gateway.VerifyAbhaNumberAadhaarOtpAsync(verifyReq);
            }
            catch (Exception ex)
            {
                try
                {
                    if (ex.Data != null)
                    {
                        if (!ex.Data.Contains("RequestId")) ex.Data["RequestId"] = requestId;
                        if (!ex.Data.Contains("Payload"))
                            ex.Data["Payload"] = JsonSerializer.Serialize(verifyReq);
                    }
                }
                catch { }

                try
                {
                    await _audit.LogRequestAsync(
                        "/abha/login/abha-number/aadhaar-otp/verify",
                        JsonSerializer.Serialize(verifyReq),
                        ex.ToString(),
                        requestId
                    );
                }
                catch { }

                throw;
            }

            // success audit
            try
            {
                await _audit.LogRequestAsync(
                    "/abha/login/abha-number/aadhaar-otp/verify",
                    JsonSerializer.Serialize(verifyReq),
                    JsonSerializer.Serialize(resp),
                    ""
                );
            }
            catch { }

            return resp;
        }

        public async Task<SendOtpResponse_Login?> SendAbhaNumberAbhaOtpAsync(string abhaNumberPlain)
        {
            var requestId = Guid.NewGuid().ToString();

            if (string.IsNullOrWhiteSpace(abhaNumberPlain))
                throw new ArgumentNullException(nameof(abhaNumberPlain));

            // 1) Get ABDM public key
            var cert = await _gateway.GetPublicKeyAsync();
            if (cert == null)
                throw new InvalidOperationException("Unable to obtain public certificate");

            var publicKeyPem = cert.PublicKey ?? throw new InvalidOperationException("Public key missing");
            var algo = cert.EncryptionAlgorithm;

            // 2) Encrypt ABHA number
            var encryptedAbha = AbhaEncryptionHelper.EncryptWithPublicKey(publicKeyPem, abhaNumberPlain, algo);

            // 3) Build ABHA Request
            var sendReq = new SendAadhaarLoginOtpRequest
            {
                Scope = new[] { "abha-login", "mobile-verify" },
                LoginHint = "abha-number",
                LoginId = encryptedAbha,
                OtpSystem = "abdm"
            };

            SendOtpResponse_Login? resp = null;

            try
            {
                // 4) Call Gateway
                resp = await _gateway.CreateAbhaNumberAbhaOtpAsync(sendReq);
            }
            catch (Exception ex)
            {
                try
                {
                    if (!ex.Data.Contains("RequestId"))
                        ex.Data["RequestId"] = requestId;

                    if (!ex.Data.Contains("Payload"))
                        ex.Data["Payload"] = JsonSerializer.Serialize(sendReq);
                }
                catch { }

                try
                {
                    await _audit.LogRequestAsync("/abha/login/abha-number/abha-otp/sendOtp",
                        JsonSerializer.Serialize(sendReq),
                        ex.ToString(),
                        requestId);
                }
                catch { }

                throw;
            }

            // 5) Audit success
            try
            {
                await _audit.LogRequestAsync("/abha/login/abha-number/abha-otp/sendOtp",
                    JsonSerializer.Serialize(sendReq),
                    JsonSerializer.Serialize(resp),
                    "");
            }
            catch { }

            return resp;
        }

        public async Task<LoginVerifyOtpResponse?> VerifyAbhaNumberAbhaOtpAsync(string txnId, string otpPlain)
        {
            var requestId = Guid.NewGuid().ToString();

            if (string.IsNullOrWhiteSpace(txnId))
                throw new ArgumentNullException(nameof(txnId));
            if (string.IsNullOrWhiteSpace(otpPlain))
                throw new ArgumentNullException(nameof(otpPlain));

            // 1) get ABDM public key
            var cert = await _gateway.GetPublicKeyAsync();
            if (cert == null)
                throw new InvalidOperationException("Unable to obtain public certificate");

            var publicKeyPem = cert.PublicKey ?? throw new InvalidOperationException("Public key missing");
            var algo = cert.EncryptionAlgorithm;

            // 2) encrypt OTP
            var encryptedOtp = AbhaEncryptionHelper.EncryptWithPublicKey(publicKeyPem, otpPlain, algo);

            // 3) FINAL REQUEST BODY
            var verifyReq = new LoginVerifyOtpRequest
            {
                Scope = new[] { "abha-login", "mobile-verify" },
                AuthData = new LoginVerifyAuthData
                {
                    AuthMethods = new[] { "otp" },
                    Otp = new LoginVerifyOtpBlock
                    {
                        TxnId = txnId,
                        OtpValue = encryptedOtp
                    }
                }
            };

            LoginVerifyOtpResponse? resp = null;

            try
            {
                resp = await _gateway.VerifyAbhaNumberAbhaOtpAsync(verifyReq);
            }
            catch (Exception ex)
            {
                try
                {
                    if (!ex.Data.Contains("RequestId"))
                        ex.Data["RequestId"] = requestId;

                    if (!ex.Data.Contains("Payload"))
                        ex.Data["Payload"] = JsonSerializer.Serialize(verifyReq);
                }
                catch { }

                try
                {
                    await _audit.LogRequestAsync(
                        "/abha/login/abha-number/abha-otp/verify",
                        JsonSerializer.Serialize(verifyReq),
                        ex.ToString(),
                        requestId
                    );
                }
                catch { }

                throw;
            }

            // Success audit
            try
            {
                await _audit.LogRequestAsync(
                    "/abha/login/abha-number/abha-otp/verify",
                    JsonSerializer.Serialize(verifyReq),
                    JsonSerializer.Serialize(resp),
                    ""
                );
            }
            catch { }

            return resp;
        }

        public async Task<SendOtpResponse_Login?> SendMobileLoginOtpAsync(string mobilePlain)
        {
            var requestId = Guid.NewGuid().ToString();
            if (string.IsNullOrWhiteSpace(mobilePlain))
                throw new ArgumentNullException(nameof(mobilePlain));

            // 1) get public key/cert
            var cert = await _gateway.GetPublicKeyAsync();
            if (cert == null)
                throw new InvalidOperationException("Unable to obtain public certificate");

            var publicKeyPem = cert.PublicKey ?? throw new InvalidOperationException("Public key missing in certificate response");
            var algo = cert.EncryptionAlgorithm;

            // 2) encrypt mobile number
            var encryptedMobile = AbhaEncryptionHelper.EncryptWithPublicKey(publicKeyPem, mobilePlain, algo);

            // 3) build ABHA request object (LOGIN via MOBILE)
            var sendReq = new SendAadhaarLoginOtpRequest
            {
                Scope = new[] { "abha-login", "mobile-verify" },
                LoginHint = "mobile",
                LoginId = encryptedMobile,
                OtpSystem = "abdm"
            };

            SendOtpResponse_Login? resp = null;

            try
            {
                // 4) call gateway
                resp = await _gateway.CreateMobileLoginOtpAsync(sendReq);
            }
            catch (Exception ex)
            {
                try
                {
                    if (ex.Data != null && !ex.Data.Contains("RequestId"))
                        ex.Data["RequestId"] = requestId;
                    if (ex.Data != null && !ex.Data.Contains("Payload"))
                        ex.Data["Payload"] = JsonSerializer.Serialize(sendReq,
                            new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase });
                }
                catch { }

                try
                {
                    await _audit.LogRequestAsync(
                        "/abha/login/mobile/sendOtp",
                        JsonSerializer.Serialize(sendReq),
                        ex.ToString(),
                        requestId
                    );
                }
                catch { }

                throw;
            }

            // 5) audit success
            try
            {
                await _audit.LogRequestAsync(
                    "/abha/login/mobile/sendOtp",
                    JsonSerializer.Serialize(sendReq),
                    JsonSerializer.Serialize(resp),
                    ""
                );
            }
            catch { }

            return resp;
        }

        public async Task<LoginVerifyOtpResponse?> VerifyMobileLoginOtpAsync(string txnId, string otpPlain)
        {
            var requestId = Guid.NewGuid().ToString();

            if (string.IsNullOrWhiteSpace(txnId))
                throw new ArgumentNullException(nameof(txnId));
            if (string.IsNullOrWhiteSpace(otpPlain))
                throw new ArgumentNullException(nameof(otpPlain));

            // 1) get public key
            var cert = await _gateway.GetPublicKeyAsync();
            if (cert == null)
                throw new InvalidOperationException("Unable to obtain public certificate");

            var publicKeyPem = cert.PublicKey ?? throw new InvalidOperationException("Public key missing");
            var algo = cert.EncryptionAlgorithm;

            // 2) encrypt OTP
            var encryptedOtp = AbhaEncryptionHelper.EncryptWithPublicKey(publicKeyPem, otpPlain, algo);

            // 3) FINAL request body
            var verifyReq = new LoginVerifyOtpRequest
            {
                Scope = new[] { "abha-login", "mobile-verify" },
                AuthData = new LoginVerifyAuthData
                {
                    AuthMethods = new[] { "otp" },
                    Otp = new LoginVerifyOtpBlock
                    {
                        TxnId = txnId,
                        OtpValue = encryptedOtp
                    }
                }
            };

            LoginVerifyOtpResponse? resp = null;

            try
            {
                resp = await _gateway.VerifyMobileLoginOtpAsync(verifyReq);
            }
            catch (Exception ex)
            {
                try
                {
                    if (!ex.Data.Contains("RequestId"))
                        ex.Data["RequestId"] = requestId;

                    if (!ex.Data.Contains("Payload"))
                        ex.Data["Payload"] = JsonSerializer.Serialize(verifyReq);
                }
                catch { }

                try
                {
                    await _audit.LogRequestAsync(
                        "/abha/login/mobile/verifyOtp",
                        JsonSerializer.Serialize(verifyReq),
                        ex.ToString(),
                        requestId
                    );
                }
                catch { }

                throw;
            }

            // success audit
            try
            {
                await _audit.LogRequestAsync(
                    "/abha/login/mobile/verifyOtp",
                    JsonSerializer.Serialize(verifyReq),
                    JsonSerializer.Serialize(resp),
                    ""
                );
            }
            catch { }

            return resp;
        }

        public async Task<VerifyUserResponseDto?> VerifyUserAsync(string abhaNumber, string txnId, string tToken)
        {
            var requestId = Guid.NewGuid().ToString();

            var req = new VerifyUserRequestDto
            {
                ABHANumber = abhaNumber,
                txnId = txnId,
                tToken = tToken
            };

            VerifyUserResponseDto? resp = null;

            try
            {
                resp = await _gateway.VerifyUserAsync(req);
            }
            catch (Exception ex)
            {
                ex.Data["RequestId"] = requestId;
                ex.Data["Payload"] = JsonSerializer.Serialize(req);

                await _audit.LogRequestAsync(
                    "/abha/login/verify-user",
                    JsonSerializer.Serialize(req),
                    ex.ToString(),
                    requestId
                );

                throw;
            }

            await _audit.LogRequestAsync(
                "/abha/login/verify-user",
                JsonSerializer.Serialize(req),
                JsonSerializer.Serialize(resp),
                ""
            );

            return resp;
        }


        private static string ComputeSha256Hash(string raw)
        {
            using var sha = System.Security.Cryptography.SHA256.Create();
            var bytes = System.Text.Encoding.UTF8.GetBytes(raw);
            var hash = sha.ComputeHash(bytes);
            return Convert.ToHexString(hash).ToLowerInvariant();
        }
    }
}
