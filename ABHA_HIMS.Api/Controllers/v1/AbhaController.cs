using ABHA_HIMS.Application.Dtos;
using ABHA_HIMS.Application.Interfaces;
using ABHA_HIMS.Application.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Net;
using System.Security.Authentication;
using System.Text.Json;
using static ABHA_HIMS.Domain.AbhaDtos;

namespace ABHA_HIMS.Api.Controllers.v1;

[ApiController]
[Route("api/v1/abha")]
public class AbhaController : ControllerBase
{
    private readonly IAbhaService _abhaService;               // high-level app service (preferred)
    private readonly ILogger<AbhaController> _logger;

    public AbhaController(IAbhaService abhaService, ILogger<AbhaController> logger)
    {
        _abhaService = abhaService;
        //_abhaGateway = abhaGateway;
        _logger = logger;
    }

    private IActionResult HandleExceptionForClient(Exception ex, string context = null)
    {
        Exception root = ex;
        while (root.InnerException != null) root = root.InnerException;

        int statusCode = 502;
        string detail = ex.Message;
        string inner = root?.ToString() ?? "";

        // ---- Extract RequestId safely ----
        string reqId = "";
        if (ex.Data != null)
        {
            try
            {
                if (ex.Data.Contains("RequestId"))
                    reqId = ex.Data["RequestId"]?.ToString() ?? "";
            }
            catch { /* ignore */ }
        }

        // ---- StatusCode from HttpRequestException (if present) ----
        if (ex is HttpRequestException httpEx)
        {
            if (httpEx.Data.Contains("StatusCode") &&
                int.TryParse(httpEx.Data["StatusCode"]?.ToString(), out var sc))
                statusCode = sc;
        }
        else if (ex is TaskCanceledException)
        {
            statusCode = 504;
        }

        var payload = new
        {
            error = context ?? "ABHA request failed",
            detail,
            inner,
            requestId = reqId
        };

        _logger?.LogError(ex, "Error: {Context} RequestId={ReqId}", context, reqId);

        return StatusCode(statusCode, payload);
    }

    // -----------------------
    // 1) Config-based session (no request body) - debug / healthcheck use
    // -----------------------
    [HttpPost("session")]
    public async Task<IActionResult> Session()
    {
        try
        {
            var resConfig = await _abhaService.GetSessionAsync();
            return Ok(resConfig);
        }
        catch (Exception ex)
        {
            return HandleExceptionForClient(ex, "ABHA session error");
            //_logger.LogError(ex, "Error while getting ABHA session (config).");
            //var detail = GetExceptionDetails(ex);
            //return StatusCode(502, new { error = "ABHA session error", detail });
        }
    }

    // -----------------------
    // 2) Explicit credentials session (body)
    // -----------------------
    [HttpPost("session/credentials")]
    public async Task<IActionResult> SessionWithCredentials([FromBody] SessionRequest req)
    {
        if (req == null || string.IsNullOrWhiteSpace(req.ClientId) || string.IsNullOrWhiteSpace(req.ClientSecret))
            return BadRequest(new { error = "clientId and clientSecret are required in body." });

        try
        {
            var res = await _abhaService.GetSessionAsync(req.ClientId, req.ClientSecret);
            return Ok(res);
        }
        catch (Exception ex)
        {
            return HandleExceptionForClient(ex, "ABHA session-with-credentials failed");
            //_logger.LogError(ex, "Error while getting ABHA session with credentials.");
            //var detail = GetExceptionDetails(ex);
            //return StatusCode(502, new { error = "ABHA session error", detail });
        }
    }

    // -----------------------
    // 3) Public key (returns ABHA public cert DTO)
    // -----------------------
    [HttpGet("public-key")]
    public async Task<IActionResult> GetPublicKey()
    {
        try
        {
            var key = await _abhaService.GetPublicKeyAsync();
            return Ok(key);
        }
        catch (Exception ex)
        {
            return HandleExceptionForClient(ex, "ABHA public key error");
            //_logger.LogError(ex, "Error while fetching ABHA public key.");
            //return StatusCode(502, new { error = "ABHA public key error", detail = ex.Message });
        }
    }

    [HttpPost("send-otp")]
    public async Task<IActionResult> SendOtp([FromBody] SendOtpFromClientDto dto)
    {
        if (dto == null || string.IsNullOrWhiteSpace(dto.Aadhaar))
        {
            var badResp = new ApiResponse<SendOtpResponse>
            {
                StatusCode = 400,
                IsSuccess = "false",
                Message = "aadhaar is required in request body",
                Data = default
            };
            return Ok(badResp);
        }

        try
        {
            var gatewayResp = await _abhaService.SendOtpAsync(dto.Aadhaar);
            if (gatewayResp == null)
            {
                var apiRespNull = new ApiResponse<SendOtpResponse>
                {
                    StatusCode = 502,
                    IsSuccess = "false",
                    Message = "ABHA gateway error",
                    Data = default
                };
                return Ok(apiRespNull);
            }
            var apiResp = new ApiResponse<SendOtpResponse>
            {
                StatusCode = 200,
                IsSuccess = "true",
                Message = gatewayResp.Message,   // {"txnId","message"} me se "message"
                Data = gatewayResp
            };

            //return Ok(apiResp);
            return Ok(apiResp);
        }
        catch (Exception ex)
        {
            //return HandleExceptionForClient(ex, "ABHA send-otp failed");
            // yaha pe ABHA ke error response ko decode karenge (400/401 etc.)
            int statusCode = 500;
            string message = "ABHA send-otp failed";
            string? rawBody = null;

            if (ex is HttpRequestException httpEx && httpEx.Data != null)
            {
                // HttpClient me StatusCode / RawBody set kiya hua hona chahiye
                if (httpEx.Data.Contains("StatusCode") && httpEx.Data["StatusCode"] is int sc)
                    statusCode = sc;

                if (httpEx.Data.Contains("RawBody") && httpEx.Data["RawBody"] is string rb)
                    rawBody = rb;

                if (!string.IsNullOrWhiteSpace(rawBody))
                {
                    try
                    {
                        using var doc = JsonDocument.Parse(rawBody);
                        var root = doc.RootElement;

                        if (statusCode == 401)
                        {
                            // 401 ke liye: message + description merge
                            string? msg = null;
                            string? desc = null;

                            if (root.TryGetProperty("message", out var mEl) && mEl.ValueKind == JsonValueKind.String)
                                msg = mEl.GetString();

                            if (root.TryGetProperty("description", out var dEl) && dEl.ValueKind == JsonValueKind.String)
                                desc = dEl.GetString();

                            if (!string.IsNullOrWhiteSpace(msg) || !string.IsNullOrWhiteSpace(desc))
                            {
                                if (!string.IsNullOrWhiteSpace(msg) && !string.IsNullOrWhiteSpace(desc))
                                    message = $"{msg} - {desc}";
                                else
                                    message = msg ?? desc ?? message;
                            }
                        }
                        else if (statusCode == 400)
                        {
                            // 400 ke liye: pehla key (scope / loginId) ki value
                            string? firstValue = null;

                            foreach (var prop in root.EnumerateObject())
                            {
                                if (prop.NameEquals("timestamp")) continue;

                                if (prop.Value.ValueKind == JsonValueKind.String)
                                {
                                    firstValue = prop.Value.GetString();
                                    if (!string.IsNullOrWhiteSpace(firstValue))
                                        break;
                                }
                            }

                            if (!string.IsNullOrWhiteSpace(firstValue))
                                message = firstValue;
                        }
                    }
                    catch
                    {
                        // JSON parse fail ho jaye to default message hi rahe
                    }
                }
            }

            var errorResp = new ApiResponse<SendOtpResponse>
            {
                StatusCode = statusCode,
                IsSuccess = "false",
                Message = message,
                Data = default
            };

            // Frontend ke liye ham hamesha 200 return kar rahe hain, 
            // aur andar StatusCode me ABHA ka code jaa raha hai
            return Ok(errorResp);
        }
    }

    // -----------------------
    // 5) Create ABHA by Aadhaar (accepts full ABHA request body)
    // If you already have an access token and want to call gateway directly, pass Authorization header,
    // but AbhaService/Gateway will handle token acquisition automatically.
    // -----------------------
    [HttpPost("create-by-aadhaar")]
    public async Task<IActionResult> CreateByAadhaar([FromBody] CreateByAadhaarInput input, [FromHeader(Name = "Authorization")] string? auth = null)
    {
        //if (input == null) return BadRequest(new { error = "Invalid request body" });

        if (input == null)
        {
            var badResp = new ApiResponse<CreateAbhaResponse>
            {
                StatusCode = 400,
                IsSuccess = "false",
                Message = "Invalid request body",
                Data = default
            };
            return Ok(badResp);
        }

        //if (string.IsNullOrWhiteSpace(input.TxnId) || string.IsNullOrWhiteSpace(input.OtpValue) || string.IsNullOrWhiteSpace(input.Mobile))
        //    return BadRequest(new { error = "txnId, otpValue and mobile are required" });

        if (string.IsNullOrWhiteSpace(input.TxnId) || string.IsNullOrWhiteSpace(input.OtpValue) || string.IsNullOrWhiteSpace(input.Mobile))
        {
            var badResp = new ApiResponse<CreateAbhaResponse>
            {
                StatusCode = 400,
                IsSuccess = "false",
                Message = "txnId, otpValue and mobile are required",
                Data = default
            };
            return Ok(badResp);
        }

        //// Build the request body required by ABHA gateway where everything else is static
        //var reqBody = new
        //{
        //    authData = new
        //    {
        //        authMethods = new[] { "otp" },
        //        otp = new
        //        {
        //            txnId = input.TxnId,
        //            otpValue = input.OtpValue,
        //            mobile = input.Mobile
        //        }
        //    },
        //    consent = new
        //    {
        //        code = "abha-enrollment",
        //        version = "1.4"
        //    }
        //};

        //var resp = await _abhaService.CreateAbhaAsync(reqBody);

        try
        {
            // 2) Build ABHA request body (static consent)
            var reqBody = new
            {
                authData = new
                {
                    authMethods = new[] { "otp" },
                    otp = new
                    {
                        txnId = input.TxnId,
                        otpValue = input.OtpValue,
                        mobile = input.Mobile
                    }
                },
                consent = new
                {
                    code = "abha-enrollment",
                    version = "1.4"
                }
            };

            var gatewayResp = await _abhaService.CreateAbhaAsync(reqBody);

            if (gatewayResp == null)
            {
                var nullResp = new ApiResponse<CreateAbhaResponse>
                {
                    StatusCode = 502,
                    IsSuccess = "false",
                    Message = "ABHA gateway error",
                    Data = default
                };
                return Ok(nullResp);
            }

            // 3) Success – set cookie + ApiResponse 200
            var xToken = gatewayResp.Tokens?.Token;
            if (!string.IsNullOrWhiteSpace(xToken))
            {
                var cookieOptions = new CookieOptions
                {
                    HttpOnly = true,
                    Secure = true,
                    SameSite = SameSiteMode.Strict,
                    Expires = DateTimeOffset.UtcNow.AddMinutes(gatewayResp.Tokens?.ExpiresIn ?? 30)
                };
                Response.Cookies.Append("X-ABHA-Token", xToken, cookieOptions);
            }

            var apiResp = new ApiResponse<CreateAbhaResponse>
            {
                StatusCode = 200,
                IsSuccess = "true",
                Message = gatewayResp.Message,   // positive response ka "message"
                Data = gatewayResp
            };

            return Ok(apiResp);
        }
        catch (Exception ex)
        {
            // 4) Error mapping: 400 / 401 / 422 / 500 etc.
            int statusCode = 500;
            string message = "ABHA create-by-aadhaar failed";
            string? rawBody = null;

            if (ex is HttpRequestException httpEx && httpEx.Data != null)
            {
                // HttpClient me set hona chahiye: Data["StatusCode"], Data["RawBody"]
                if (httpEx.Data.Contains("StatusCode") && httpEx.Data["StatusCode"] is int sc)
                    statusCode = sc;

                if (httpEx.Data.Contains("RawBody") && httpEx.Data["RawBody"] is string rb)
                    rawBody = rb;

                if (!string.IsNullOrWhiteSpace(rawBody))
                {
                    try
                    {
                        using var doc = JsonDocument.Parse(rawBody);
                        var root = doc.RootElement;

                        if (statusCode == 400)
                        {
                            // 400 → first key (scope/loginId/...) ki string value
                            string? firstValue = null;

                            foreach (var prop in root.EnumerateObject())
                            {
                                if (prop.NameEquals("timestamp")) continue;

                                if (prop.Value.ValueKind == JsonValueKind.String)
                                {
                                    firstValue = prop.Value.GetString();
                                    if (!string.IsNullOrWhiteSpace(firstValue))
                                        break;
                                }
                            }

                            if (!string.IsNullOrWhiteSpace(firstValue))
                                message = firstValue;
                        }
                        else if (statusCode == 422)
                        {
                            // 422 → error.message
                            if (root.TryGetProperty("error", out var errEl) &&
                                errEl.ValueKind == JsonValueKind.Object &&
                                errEl.TryGetProperty("message", out var msgEl) &&
                                msgEl.ValueKind == JsonValueKind.String)
                            {
                                var msg = msgEl.GetString();
                                if (!string.IsNullOrWhiteSpace(msg))
                                    message = msg!;
                            }
                        }
                        else if (statusCode == 401 || statusCode == 500)
                        {
                            // 401 / 500 → message + description (if present)
                            string? msg = null;
                            string? desc = null;

                            if (root.TryGetProperty("message", out var mEl) &&
                                mEl.ValueKind == JsonValueKind.String)
                                msg = mEl.GetString();

                            if (root.TryGetProperty("description", out var dEl) &&
                                dEl.ValueKind == JsonValueKind.String)
                                desc = dEl.GetString();

                            if (!string.IsNullOrWhiteSpace(msg) || !string.IsNullOrWhiteSpace(desc))
                            {
                                if (!string.IsNullOrWhiteSpace(msg) && !string.IsNullOrWhiteSpace(desc))
                                    message = $"{msg} - {desc}";
                                else
                                    message = msg ?? desc ?? message;
                            }
                        }
                        // agar koi aur statusCode hai, to generic message hi rehne do
                    }
                    catch
                    {
                        // parsing fail ho gaya to default message hi use karenge
                    }
                }
            }

            var errorResp = new ApiResponse<CreateAbhaResponse>
            {
                StatusCode = statusCode,
                IsSuccess = "false",
                Message = message,
                Data = default
            };

            return Ok(errorResp);
        }
    }

    //[HttpPost("mobileUpdate_sendOtp")]
    //public async Task<IActionResult> SendMobileUpdateOtp([FromBody] MobileOtpInput input, [FromHeader(Name = "Authorization")] string? auth = null)
    //{
    //    try
    //    {
    //        if (input == null || string.IsNullOrWhiteSpace(input.Mobile))
    //            return BadRequest(new { error = "mobile is required" });

    //        var resp = await _abhaService.SendMobileUpdateOtpAsync(input.Mobile, input.TxnId);
    //        if (resp == null) return StatusCode(502, "ABHA gateway error");
    //        return Ok(resp);
    //    }
    //    catch (Exception ex)
    //    {
    //        return HandleExceptionForClient(ex, "ABHA send-mobile-otp failed");
    //        //_logger.LogError(ex, "Error in SendMobileUpdateOtp.");
    //        //return StatusCode(502, new { error = "ABHA send-mobile-otp failed", detail = ex.Message });
    //    }
    //}

    [HttpPost("mobileUpdate_sendOtp")]
    public async Task<IActionResult> SendMobileUpdateOtp([FromBody] MobileOtpInput? input, [FromHeader(Name = "Authorization")] string? auth = null)
    {
        // 1) Input validation -> ApiResponse wrapper
        if (input == null || string.IsNullOrWhiteSpace(input.Mobile))
        {
            var badResp = new ApiResponse<SendOtpResponse_MobileUpdate>
            {
                StatusCode = 400,
                IsSuccess = "false",
                Message = "mobile is required in request body",
                Data = default
            };
            return Ok(badResp);
        }

        try
        {
            // 2) Call service (ye already encryption + ABHA call kar raha hai)
            var gatewayResp = await _abhaService.SendMobileUpdateOtpAsync(input.Mobile, input.TxnId);

            if (gatewayResp == null)
            {
                var apiRespNull = new ApiResponse<SendOtpResponse_MobileUpdate>
                {
                    StatusCode = 502,
                    IsSuccess = "false",
                    Message = "ABHA gateway error",
                    Data = default
                };
                return Ok(apiRespNull);
            }

            // 3) Success -> 200 + message from ABHA
            var apiResp = new ApiResponse<SendOtpResponse_MobileUpdate>
            {
                StatusCode = 200,
                IsSuccess = "true",
                // {"txnId","message"} me se "message"
                Message = gatewayResp.Message,
                Data = gatewayResp
            };

            return Ok(apiResp);
        }
        catch (Exception ex)
        {
            // 4) Error mapping (400, 401, etc.) same pattern as Aadhaar send-otp
            int statusCode = 500;
            string message = "ABHA mobile-update send-otp failed";
            string? rawBody = null;

            if (ex is HttpRequestException httpEx && httpEx.Data != null)
            {
                if (httpEx.Data.Contains("StatusCode") && httpEx.Data["StatusCode"] is int sc)
                    statusCode = sc;

                if (httpEx.Data.Contains("RawBody") && httpEx.Data["RawBody"] is string rb)
                    rawBody = rb;

                if (!string.IsNullOrWhiteSpace(rawBody))
                {
                    try
                    {
                        using var doc = JsonDocument.Parse(rawBody);
                        var root = doc.RootElement;

                        if (statusCode == 401)
                        {
                            // 401 -> message + description merge
                            string? msg = null;
                            string? desc = null;

                            if (root.TryGetProperty("message", out var mEl) && mEl.ValueKind == JsonValueKind.String)
                                msg = mEl.GetString();

                            if (root.TryGetProperty("description", out var dEl) && dEl.ValueKind == JsonValueKind.String)
                                desc = dEl.GetString();

                            if (!string.IsNullOrWhiteSpace(msg) || !string.IsNullOrWhiteSpace(desc))
                            {
                                if (!string.IsNullOrWhiteSpace(msg) && !string.IsNullOrWhiteSpace(desc))
                                    message = $"{msg} - {desc}";
                                else
                                    message = msg ?? desc ?? message;
                            }
                        }
                        else if (statusCode == 400)
                        {
                            // 400 -> pehla key (scope / loginId / etc.) ki string value
                            string? firstValue = null;

                            foreach (var prop in root.EnumerateObject())
                            {
                                if (prop.NameEquals("timestamp")) continue;

                                if (prop.Value.ValueKind == JsonValueKind.String)
                                {
                                    firstValue = prop.Value.GetString();
                                    if (!string.IsNullOrWhiteSpace(firstValue))
                                        break;
                                }
                            }

                            if (!string.IsNullOrWhiteSpace(firstValue))
                                message = firstValue;
                        }
                    }
                    catch
                    {
                        // JSON parse fail ho jaye to default message hi rahe
                    }
                }
            }

            var errorResp = new ApiResponse<SendOtpResponse_MobileUpdate>
            {
                StatusCode = statusCode,
                IsSuccess = "false",
                Message = message,
                Data = default
            };

            // Hamesha 200, andar StatusCode me actual ABHA ka code
            return Ok(errorResp);
        }
    }


    //[HttpPost("mobileUpdate_verifyOTP")]
    //public async Task<IActionResult> VerifyMobileUpdateOtp([FromBody] MobileVerifyInput input, [FromHeader(Name = "Authorization")] string? auth = null)
    //{
    //    try
    //    {
    //        if (input == null || string.IsNullOrWhiteSpace(input.TxnId) || string.IsNullOrWhiteSpace(input.Otp))
    //            return BadRequest(new { error = "txnId and otp are required" });

    //        var resp = await _abhaService.VerifyMobileUpdateOtpAsync(input.TxnId, input.Otp);
    //        if (resp == null) return StatusCode(502, "ABHA gateway error");

    //        return Ok(resp);
    //    }
    //    catch (Exception ex)
    //    {
    //        return HandleExceptionForClient(ex, "ABHA verify-mobile-otp failed");
    //        //_logger.LogError(ex, "Error in VerifyMobileUpdateOtp.");
    //        //return StatusCode(502, new { error = "ABHA verify-mobile-otp failed", detail = ex.Message });
    //    }
    //}

    [HttpPost("mobileUpdate_verifyOTP")]
    public async Task<IActionResult> VerifyMobileUpdateOtp([FromBody] MobileVerifyInput input, [FromHeader(Name = "Authorization")] string? auth = null)
    {
        // ✅ 1. Input validation -> ham 200 + ApiResponse return karenge
        if (input == null || string.IsNullOrWhiteSpace(input.TxnId) || string.IsNullOrWhiteSpace(input.Otp))
        {
            var badResp = new ApiResponse<MobileVerifyResponse>
            {
                StatusCode = 400,
                IsSuccess = "false",
                Message = "txnId and otp are required",
                Data = default
            };
            return Ok(badResp);
        }

        try
        {
            // ✅ 2. Call ABHA service
            var gatewayResp = await _abhaService.VerifyMobileUpdateOtpAsync(input.TxnId, input.Otp);

            if (gatewayResp == null)
            {
                var apiRespNull = new ApiResponse<MobileVerifyResponse>
                {
                    StatusCode = 502,
                    IsSuccess = "false",
                    Message = "ABHA gateway error",
                    Data = default
                };
                return Ok(apiRespNull);
            }

            // ✅ 3. 200 OK
            // authResult = "success" -> IsSuccess = "true"
            // authResult != "success" (e.g. "failed" with "OTP expired") -> IsSuccess = "false"
            var isSuccess = string.Equals(gatewayResp.AuthResult, "success", StringComparison.OrdinalIgnoreCase)
                ? "true"
                : "false";

            var apiResp = new ApiResponse<MobileVerifyResponse>
            {
                StatusCode = 200,
                IsSuccess = isSuccess,
                Message = gatewayResp.Message,   // "Mobile number is now successfully linked..." OR "OTP expired, please try again"
                Data = gatewayResp               // accounts list, ABHANumber etc. 
            };

            return Ok(apiResp);
        }
        catch (Exception ex)
        {
            // ✅ 4. Error handling — same pattern + extra 402/500 logic
            int statusCode = 500;
            string message = "ABHA verify-mobile-otp failed";
            string? rawBody = null;

            if (ex is HttpRequestException httpEx && httpEx.Data != null)
            {
                // HttpClient me StatusCode / RawBody set hona chahiye
                if (httpEx.Data.Contains("StatusCode") && httpEx.Data["StatusCode"] is int sc)
                    statusCode = sc;

                if (httpEx.Data.Contains("RawBody") && httpEx.Data["RawBody"] is string rb)
                    rawBody = rb;

                if (!string.IsNullOrWhiteSpace(rawBody))
                {
                    try
                    {
                        using var doc = JsonDocument.Parse(rawBody);
                        var root = doc.RootElement;

                        if (statusCode == 401)
                        {
                            // 401 ke liye: message + description merge (generic pattern, in case ABHA de de)
                            string? msg = null;
                            string? desc = null;

                            if (root.TryGetProperty("message", out var mEl) && mEl.ValueKind == JsonValueKind.String)
                                msg = mEl.GetString();

                            if (root.TryGetProperty("description", out var dEl) && dEl.ValueKind == JsonValueKind.String)
                                desc = dEl.GetString();

                            if (!string.IsNullOrWhiteSpace(msg) || !string.IsNullOrWhiteSpace(desc))
                            {
                                if (!string.IsNullOrWhiteSpace(msg) && !string.IsNullOrWhiteSpace(desc))
                                    message = $"{msg} - {desc}";
                                else
                                    message = msg ?? desc ?? message;
                            }
                        }
                        else if (statusCode == 400)
                        {
                            // 400 ke liye: pehla key (scope / loginId etc.) ki value, timestamp skip
                            string? firstValue = null;

                            foreach (var prop in root.EnumerateObject())
                            {
                                if (prop.NameEquals("timestamp")) continue;

                                if (prop.Value.ValueKind == JsonValueKind.String)
                                {
                                    firstValue = prop.Value.GetString();
                                    if (!string.IsNullOrWhiteSpace(firstValue))
                                        break;
                                }
                            }

                            if (!string.IsNullOrWhiteSpace(firstValue))
                                message = firstValue;
                        }
                        else if (statusCode == 402 || statusCode == 422)
                        {
                            // 402 / 422:
                            // {
                            //   "error": {
                            //     "code": "ABDM-1204",
                            //     "message": "UIDAI Error code : 400 : Invalid Aadhaar OTP value."
                            //   }
                            // }
                            if (root.TryGetProperty("error", out var errEl) && errEl.ValueKind == JsonValueKind.Object)
                            {
                                if (errEl.TryGetProperty("message", out var msgEl) && msgEl.ValueKind == JsonValueKind.String)
                                {
                                    var msg = msgEl.GetString();
                                    if (!string.IsNullOrWhiteSpace(msg))
                                        message = msg;
                                }
                            }
                        }
                        else if (statusCode == 500)
                        {
                            // 500:
                            // {
                            //   "code": "900900",
                            //   "message": "Unclassified Authentication Failure",
                            //   "description": "Access failure..."
                            // }
                            string? msg = null;
                            string? desc = null;

                            if (root.TryGetProperty("message", out var mEl) && mEl.ValueKind == JsonValueKind.String)
                                msg = mEl.GetString();

                            if (root.TryGetProperty("description", out var dEl) && dEl.ValueKind == JsonValueKind.String)
                                desc = dEl.GetString();

                            if (!string.IsNullOrWhiteSpace(msg) || !string.IsNullOrWhiteSpace(desc))
                            {
                                if (!string.IsNullOrWhiteSpace(msg) && !string.IsNullOrWhiteSpace(desc))
                                    message = $"{msg} - {desc}";
                                else
                                    message = msg ?? desc ?? message;
                            }
                        }
                    }
                    catch
                    {
                        // JSON parse fail ho jaye to default message hi rahe
                    }
                }
            }

            var errorResp = new ApiResponse<MobileVerifyResponse>
            {
                StatusCode = statusCode,
                IsSuccess = "false",
                Message = message,
                Data = default
            };

            // Hamesha 200 (OK) HTTP, andar StatusCode me ABHA ka actual code
            return Ok(errorResp);
        }
    }

    //[HttpPost("email_request_link")]
    //public async Task<IActionResult> RequestEmailVerificationLink([FromBody] EmailVerificationInput input,
    //    [FromHeader(Name = "Authorization")] string? authToken = null)
    //{
    //    try
    //    {
    //        if (input == null || string.IsNullOrWhiteSpace(input.Email))
    //            return BadRequest(new { error = "email is required" });

    //        if (input == null || string.IsNullOrWhiteSpace(input.XToken))
    //            return BadRequest(new { error = "X-Token is required" });

    //        //string xToken = HttpContext.Request.Cookies["X-ABHA-Token"] ?? "";

    //        var resp = await _abhaService.SendEmailVerificationLinkAsync(input.Email, authToken, input.XToken);
    //        if (resp == null) return StatusCode(502, "ABHA gateway error");

    //        return Ok(resp);
    //    }
    //    catch (Exception ex)
    //    {
    //        return HandleExceptionForClient(ex, "ABHA email-verification-link failed");
    //        //_logger.LogError(ex, "Error in RequestEmailVerificationLink.");
    //        //return StatusCode(502, new { error = "ABHA email-verification-link failed", detail = ex.Message });
    //    }
    //}

    [HttpPost("email_request_link")]
    public async Task<IActionResult> RequestEmailVerificationLink(
    [FromBody] EmailVerificationInput input,
    [FromHeader(Name = "Authorization")] string? authToken = null)
    {
        // 1) Basic validation -> ApiResponse style
        if (input == null || string.IsNullOrWhiteSpace(input.Email))
        {
            var badResp = new ApiResponse<EmailVerificationResponse>
            {
                StatusCode = 400,
                IsSuccess = "false",
                Message = "email is required",
                Data = default
            };
            return Ok(badResp);
        }

        if (string.IsNullOrWhiteSpace(input.XToken))
        {
            var badResp = new ApiResponse<EmailVerificationResponse>
            {
                StatusCode = 400,
                IsSuccess = "false",
                Message = "X-Token is required",
                Data = default
            };
            return Ok(badResp);
        }

        try
        {
            // 2) Call service
            var gatewayResp = await _abhaService.SendEmailVerificationLinkAsync(input.Email, authToken, input.XToken);

            if (gatewayResp == null)
            {
                var apiRespNull = new ApiResponse<EmailVerificationResponse>
                {
                    StatusCode = 502,
                    IsSuccess = "false",
                    Message = "ABHA gateway error",
                    Data = default
                };
                return Ok(apiRespNull);
            }

            // 3) Success → 200
            var apiResp = new ApiResponse<EmailVerificationResponse>
            {
                StatusCode = 200,
                IsSuccess = "true",
                // assume gatewayResp.Message exists, warna yahan adjust kar lena
                Message = gatewayResp.Message,
                Data = gatewayResp
            };

            return Ok(apiResp);
        }
        catch (Exception ex)
        {
            // Same pattern like SendOtp
            int statusCode = 500;
            string message = "ABHA email-verification-link failed";
            string? rawBody = null;

            if (ex is HttpRequestException httpEx && httpEx.Data != null)
            {
                // HttpClient me StatusCode / RawBody set hona chahiye
                if (httpEx.Data.Contains("StatusCode") && httpEx.Data["StatusCode"] is int sc)
                    statusCode = sc;

                if (httpEx.Data.Contains("RawBody") && httpEx.Data["RawBody"] is string rb)
                    rawBody = rb;

                if (!string.IsNullOrWhiteSpace(rawBody))
                {
                    try
                    {
                        using var doc = JsonDocument.Parse(rawBody);
                        var root = doc.RootElement;

                        // 401 Unauthorized – error + detail + inner (agar aise shape me ho)
                        if (statusCode == 401)
                        {
                            string? err = null;
                            string? detail = null;
                            string? inner = null;

                            if (root.TryGetProperty("error", out var errEl) && errEl.ValueKind == JsonValueKind.String)
                                err = errEl.GetString();

                            if (root.TryGetProperty("detail", out var detEl) && detEl.ValueKind == JsonValueKind.String)
                                detail = detEl.GetString();

                            if (root.TryGetProperty("inner", out var inEl) && inEl.ValueKind == JsonValueKind.String)
                                inner = inEl.GetString();

                            // Agar ABHA direct message/description de (code/message/description),
                            // toh woh bhi support karein
                            if (string.IsNullOrWhiteSpace(err) &&
                                root.TryGetProperty("message", out var mEl) &&
                                mEl.ValueKind == JsonValueKind.String)
                            {
                                err = mEl.GetString();
                            }

                            if (string.IsNullOrWhiteSpace(detail) &&
                                root.TryGetProperty("description", out var dEl) &&
                                dEl.ValueKind == JsonValueKind.String)
                            {
                                detail = dEl.GetString();
                            }

                            // Final compose
                            var parts = new List<string>();
                            if (!string.IsNullOrWhiteSpace(err)) parts.Add(err);
                            if (!string.IsNullOrWhiteSpace(detail)) parts.Add(detail);
                            if (!string.IsNullOrWhiteSpace(inner)) parts.Add(inner);

                            if (parts.Count > 0)
                                message = string.Join(" - ", parts);
                        }
                        // 500 Internal Server Error – message + description
                        else if (statusCode == 500)
                        {
                            string? msg = null;
                            string? desc = null;

                            if (root.TryGetProperty("message", out var mEl) && mEl.ValueKind == JsonValueKind.String)
                                msg = mEl.GetString();

                            if (root.TryGetProperty("description", out var dEl) && dEl.ValueKind == JsonValueKind.String)
                                desc = dEl.GetString();

                            if (!string.IsNullOrWhiteSpace(msg) || !string.IsNullOrWhiteSpace(desc))
                            {
                                if (!string.IsNullOrWhiteSpace(msg) && !string.IsNullOrWhiteSpace(desc))
                                    message = $"{msg} - {desc}";
                                else
                                    message = msg ?? desc ?? message;
                            }
                        }
                        // 400 Bad Request – first key-value (except timestamp)
                        else if (statusCode == 400)
                        {
                            string? firstValue = null;

                            foreach (var prop in root.EnumerateObject())
                            {
                                if (prop.NameEquals("timestamp")) continue;

                                if (prop.Value.ValueKind == JsonValueKind.String)
                                {
                                    firstValue = prop.Value.GetString();
                                    if (!string.IsNullOrWhiteSpace(firstValue))
                                        break;
                                }
                            }

                            if (!string.IsNullOrWhiteSpace(firstValue))
                                message = firstValue;
                        }
                        // Any other status – try message / error / else first key-value
                        else
                        {
                            string? msg = null;

                            if (root.TryGetProperty("message", out var mEl) && mEl.ValueKind == JsonValueKind.String)
                                msg = mEl.GetString();
                            else if (root.TryGetProperty("error", out var eEl) && eEl.ValueKind == JsonValueKind.String)
                                msg = eEl.GetString();

                            if (!string.IsNullOrWhiteSpace(msg))
                            {
                                message = msg;
                            }
                            else
                            {
                                // fallback: first string property
                                string? firstValue = null;
                                foreach (var prop in root.EnumerateObject())
                                {
                                    if (prop.Value.ValueKind == JsonValueKind.String)
                                    {
                                        firstValue = prop.Value.GetString();
                                        if (!string.IsNullOrWhiteSpace(firstValue))
                                            break;
                                    }
                                }

                                if (!string.IsNullOrWhiteSpace(firstValue))
                                    message = firstValue;
                            }
                        }
                    }
                    catch
                    {
                        // parse fail → default message hi rahega
                    }
                }
            }

            var errorResp = new ApiResponse<EmailVerificationResponse>
            {
                StatusCode = statusCode,
                IsSuccess = "false",
                Message = message,
                Data = default
            };

            // Hamesha 200 HTTP, andar StatusCode me actual ABHA code
            return Ok(errorResp);
        }
    }


    //[HttpGet("enrol-suggestion")]
    //public async Task<IActionResult> GetAbhaSuggestions([FromHeader(Name = "TxnId")] string? txnId)
    //{
    //    try
    //    {
    //        if (string.IsNullOrWhiteSpace(txnId))
    //            return BadRequest(new { error = "Transaction ID is required" });

    //        var resp = await _abhaService.GetAbhaSuggestionsAsync(txnId);
    //        if (resp == null) return StatusCode(502, "ABHA gateway error");

    //        return Ok(resp);
    //    }
    //    catch (Exception ex)
    //    {
    //        return HandleExceptionForClient(ex, "ABHA suggestion failed");
    //        //_logger.LogError(ex, "Error in GetAbhaSuggestions");
    //        //return StatusCode(502, new { error = "ABHA suggestion failed", detail = ex.Message });
    //    }
    //}

    [HttpGet("enrol-suggestion")]
    public async Task<IActionResult> GetAbhaSuggestions([FromHeader(Name = "TxnId")] string? txnId)
    {
        if (string.IsNullOrWhiteSpace(txnId))
        {
            var badResp = new ApiResponse<AbhaSuggestionResponse>
            {
                StatusCode = 400,
                IsSuccess = "false",
                Message = "Transaction ID is required",
                Data = default
            };
            return Ok(badResp);
        }

        try
        {
            var gatewayResp = await _abhaService.GetAbhaSuggestionsAsync(txnId);
            if (gatewayResp == null)
            {
                var apiRespNull = new ApiResponse<AbhaSuggestionResponse>
                {
                    StatusCode = 502,
                    IsSuccess = "false",
                    Message = "ABHA gateway error",
                    Data = default
                };
                return Ok(apiRespNull);
            }

            var apiResp = new ApiResponse<AbhaSuggestionResponse>
            {
                StatusCode = 200,
                IsSuccess = "true",
                // response me message nahi aata, to apna generic success text
                Message = "ABHA address suggestions fetched successfully",
                Data = gatewayResp
            };

            return Ok(apiResp);
        }
        catch (Exception ex)
        {
            int statusCode = 500;
            string message = "ABHA enrol-suggestion failed";
            string? rawBody = null;

            if (ex is HttpRequestException httpEx && httpEx.Data != null)
            {
                // HttpClient me StatusCode / RawBody set hona chahiye (tu already kar raha hai)
                if (httpEx.Data.Contains("StatusCode") && httpEx.Data["StatusCode"] is int sc)
                    statusCode = sc;

                if (httpEx.Data.Contains("RawBody") && httpEx.Data["RawBody"] is string rb)
                    rawBody = rb;

                if (!string.IsNullOrWhiteSpace(rawBody))
                {
                    try
                    {
                        using var doc = JsonDocument.Parse(rawBody);
                        var root = doc.RootElement;

                        if (statusCode == 401)
                        {
                            // 401: error.message prefer, warna top-level message
                            string? msg = null;

                            if (root.TryGetProperty("error", out var errEl) &&
                                errEl.ValueKind == JsonValueKind.Object &&
                                errEl.TryGetProperty("message", out var emEl) &&
                                emEl.ValueKind == JsonValueKind.String)
                            {
                                msg = emEl.GetString(); // e.g. "Invalid Transaction Id"
                            }

                            if (string.IsNullOrWhiteSpace(msg) &&
                                root.TryGetProperty("message", out var mEl) &&
                                mEl.ValueKind == JsonValueKind.String)
                            {
                                msg = mEl.GetString();
                            }

                            if (!string.IsNullOrWhiteSpace(msg))
                                message = msg;
                        }
                        else
                        {
                            // baaki sab status codes:
                            // pehle message, phir error.message, phir first key-value string
                            string? extracted = null;

                            if (root.TryGetProperty("message", out var mEl) &&
                                mEl.ValueKind == JsonValueKind.String)
                            {
                                extracted = mEl.GetString();
                            }
                            else if (root.TryGetProperty("error", out var errEl) &&
                                     errEl.ValueKind == JsonValueKind.Object &&
                                     errEl.TryGetProperty("message", out var emEl) &&
                                     emEl.ValueKind == JsonValueKind.String)
                            {
                                extracted = emEl.GetString();
                            }
                            else
                            {
                                foreach (var prop in root.EnumerateObject())
                                {
                                    if (prop.NameEquals("timestamp")) continue;

                                    if (prop.Value.ValueKind == JsonValueKind.String)
                                    {
                                        extracted = prop.Value.GetString();
                                        if (!string.IsNullOrWhiteSpace(extracted))
                                            break;
                                    }
                                }
                            }

                            if (!string.IsNullOrWhiteSpace(extracted))
                                message = extracted;
                        }
                    }
                    catch
                    {
                        // JSON parse fail ho jaye to default message hi rahe
                    }
                }
            }

            var errorResp = new ApiResponse<AbhaSuggestionResponse>
            {
                StatusCode = statusCode,
                IsSuccess = "false",
                Message = message,
                Data = default
            };

            // hamesha 200, andar StatusCode me ABHA ka code
            return Ok(errorResp);
        }
    }


    //[HttpPost("enrol_abhaAddress")]
    //public async Task<IActionResult> PostAbhaAddress([FromBody] AbhaAddressRequest req)
    //{
    //    try
    //    {
    //        if (string.IsNullOrWhiteSpace(req.TxnId) && string.IsNullOrWhiteSpace(req?.TxnId))
    //            return BadRequest(new { error = "Transaction ID is required either in header or body" });

    //        var resp = await _abhaService.PostAbhaAddressAsync(req);
    //        if (resp == null) return StatusCode(502, "ABHA gateway error");

    //        return Ok(resp);
    //    }
    //    catch (Exception ex)
    //    {
    //        return HandleExceptionForClient(ex, "ABHA enrol abha-address failed");
    //    }
    //}

    // 1) Basic validation – bad request ko bhi ApiResponse me wrap karenge
    [HttpPost("enrol_abhaAddress")]
    public async Task<IActionResult> PostAbhaAddress([FromBody] AbhaAddressRequest dto)
    {
        if (dto == null || string.IsNullOrWhiteSpace(dto.TxnId) || string.IsNullOrWhiteSpace(dto.AbhaAddress))
        {
            var badResp = new ApiResponse<AbhaAddressResponse>
            {
                StatusCode = 400,
                IsSuccess = "false",
                Message = "txnId and abhaAddress are required in request body",
                Data = default
            };
            return Ok(badResp);
        }

        try
        {
            // 2) Service call
            var gatewayResp = await _abhaService.PostAbhaAddressAsync(dto);

            if (gatewayResp == null)
            {
                var apiRespNull = new ApiResponse<AbhaAddressResponse>
                {
                    StatusCode = 502,
                    IsSuccess = "false",
                    Message = "ABHA gateway error",
                    Data = default
                };
                return Ok(apiRespNull);
            }

            // 3) Success – 200 case
            var apiResp = new ApiResponse<AbhaAddressResponse>
            {
                StatusCode = 200,
                IsSuccess = "true",
                // ABHA response me message field nahi hai, to custom success text
                Message = "ABHA address set successfully",
                Data = gatewayResp
            };

            return Ok(apiResp);
        }
        catch (Exception ex)
        {
            // 4) Error mapping (400 / 401 / others)
            int statusCode = 500;
            string message = "ABHA abha-address failed";
            string? rawBody = null;

            if (ex is HttpRequestException httpEx && httpEx.Data != null)
            {
                // HttpClient me ye set hona chahiye: ex.Data["StatusCode"], ex.Data["RawBody"]
                if (httpEx.Data.Contains("StatusCode") && httpEx.Data["StatusCode"] is int sc)
                    statusCode = sc;

                if (httpEx.Data.Contains("RawBody") && httpEx.Data["RawBody"] is string rb)
                    rawBody = rb;

                if (!string.IsNullOrWhiteSpace(rawBody))
                {
                    try
                    {
                        using var doc = JsonDocument.Parse(rawBody);
                        var root = doc.RootElement;

                        if (statusCode == 400)
                        {
                            // 🔸 400: first key-value pair ki value (timestamp ko ignore)
                            string? firstValue = null;

                            foreach (var prop in root.EnumerateObject())
                            {
                                if (prop.NameEquals("timestamp")) continue;

                                if (prop.Value.ValueKind == JsonValueKind.String)
                                {
                                    firstValue = prop.Value.GetString();
                                    if (!string.IsNullOrWhiteSpace(firstValue))
                                        break;
                                }
                            }

                            if (!string.IsNullOrWhiteSpace(firstValue))
                                message = firstValue;
                        }
                        else if (statusCode == 401)
                        {
                            // 🔸 401: given example:
                            // {
                            //   "code": "900901",
                            //   "message": "Invalid Credentials",
                            //   "description": "Invalid JWT token..."
                            // }
                            // yaha sirf "message" lena hai
                            if (root.TryGetProperty("message", out var mEl) && mEl.ValueKind == JsonValueKind.String)
                            {
                                var msg = mEl.GetString();
                                if (!string.IsNullOrWhiteSpace(msg))
                                    message = msg;
                            }
                            else if (root.TryGetProperty("error", out var errEl) && errEl.ValueKind == JsonValueKind.Object)
                            {
                                if (errEl.TryGetProperty("message", out var eMsgEl) && eMsgEl.ValueKind == JsonValueKind.String)
                                {
                                    var msg = eMsgEl.GetString();
                                    if (!string.IsNullOrWhiteSpace(msg))
                                        message = msg;
                                }
                            }
                        }
                        else
                        {
                            // 🔸 Other status codes – generic handling:
                            //  - try "message"
                            //  - else try "error.message"
                            //  - else first key-value string
                            string? msg = null;

                            if (root.TryGetProperty("message", out var mEl) && mEl.ValueKind == JsonValueKind.String)
                                msg = mEl.GetString();

                            if (string.IsNullOrWhiteSpace(msg) &&
                                root.TryGetProperty("error", out var errEl) &&
                                errEl.ValueKind == JsonValueKind.Object &&
                                errEl.TryGetProperty("message", out var emEl) &&
                                emEl.ValueKind == JsonValueKind.String)
                            {
                                msg = emEl.GetString();
                            }

                            if (!string.IsNullOrWhiteSpace(msg))
                            {
                                message = msg;
                            }
                            else
                            {
                                // fallback: first property value
                                foreach (var prop in root.EnumerateObject())
                                {
                                    if (prop.Value.ValueKind == JsonValueKind.String)
                                    {
                                        var v = prop.Value.GetString();
                                        if (!string.IsNullOrWhiteSpace(v))
                                        {
                                            message = v;
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    catch
                    {
                        // JSON parse fail ho jaye to default message hi rahe
                    }
                }
            }

            var errorResp = new ApiResponse<AbhaAddressResponse>
            {
                StatusCode = statusCode,
                IsSuccess = "false",
                Message = message,
                Data = default
            };

            // Hamesha 200 OK HTTP, andar StatusCode me actual ABHA error code
            return Ok(errorResp);
        }
    }

    //[HttpGet("profile-details")]
    //public async Task<IActionResult> GetProfileDetails([FromHeader(Name = "TxnId")] string? txnId, [FromHeader(Name = "XToken")] string? xToken)
    //{
    //    try
    //    {
    //        if (string.IsNullOrWhiteSpace(txnId))
    //            return BadRequest(new { error = "Transaction ID is required" });

    //        var resp = await _abhaService.GetProfileDetailsAsync(txnId, xToken);
    //        if (resp == null) return StatusCode(502, "ABHA gateway error");

    //        return Ok(resp);
    //    }
    //    catch (Exception ex)
    //    {
    //        return HandleExceptionForClient(ex, "Get profile details failed");
    //    }
    //}

    [HttpGet("profile-details")]
    public async Task<IActionResult> GetProfileDetails(
    [FromHeader(Name = "TxnId")] string? txnId,
    [FromHeader(Name = "XToken")] string? xToken)
    {
        // ✅ Local validation failure -> 200 + ApiResponse with StatusCode=400
        if (string.IsNullOrWhiteSpace(txnId))
        {
            var badResp = new ApiResponse<AbhaProfileResponse>
            {
                StatusCode = 400,
                IsSuccess = "false",
                Message = "Transaction ID is required",
                Data = default
            };
            return Ok(badResp);
        }

        try
        {
            var gatewayResp = await _abhaService.GetProfileDetailsAsync(txnId, xToken);

            // ✅ Null from gateway -> 502 wrapped
            if (gatewayResp == null)
            {
                var apiRespNull = new ApiResponse<AbhaProfileResponse>
                {
                    StatusCode = 502,
                    IsSuccess = "false",
                    Message = "ABHA gateway error",
                    Data = default
                };
                return Ok(apiRespNull);
            }

            // ✅ Success 200
            var apiResp = new ApiResponse<AbhaProfileResponse>
            {
                StatusCode = 200,
                IsSuccess = "true",
                Message = "Profile details fetched successfully",
                Data = gatewayResp
            };

            return Ok(apiResp);
        }
        catch (Exception ex)
        {
            // ❌ ABHA / network errors yahan handle
            int statusCode = 500;
            string message = "Get profile details failed";
            string? rawBody = null;

            if (ex is HttpRequestException httpEx && httpEx.Data != null)
            {
                // HttpClient me tumne StatusCode / RawBody set kiya hua hai
                if (httpEx.Data.Contains("StatusCode") && httpEx.Data["StatusCode"] is int sc)
                    statusCode = sc;

                if (httpEx.Data.Contains("RawBody") && httpEx.Data["RawBody"] is string rb)
                    rawBody = rb;

                if (!string.IsNullOrWhiteSpace(rawBody))
                {
                    try
                    {
                        using var doc = JsonDocument.Parse(rawBody);
                        var root = doc.RootElement;

                        if (statusCode == 401)
                        {
                            // 401 -> top-level "message" (900901 Invalid Credentials)
                            if (root.TryGetProperty("message", out var mEl) &&
                                mEl.ValueKind == JsonValueKind.String)
                            {
                                var msgVal = mEl.GetString();
                                if (!string.IsNullOrWhiteSpace(msgVal))
                                    message = msgVal!;
                            }
                        }
                        else if (statusCode == 404)
                        {
                            // 404 -> error.message
                            if (root.TryGetProperty("error", out var errEl) &&
                                errEl.ValueKind == JsonValueKind.Object &&
                                errEl.TryGetProperty("message", out var mEl) &&
                                mEl.ValueKind == JsonValueKind.String)
                            {
                                var msgVal = mEl.GetString();
                                if (!string.IsNullOrWhiteSpace(msgVal))
                                    message = msgVal!;
                            }
                        }
                        else if (statusCode == 400)
                        {
                            // 400 -> first key-value ki value (timestamp skip)
                            string? firstValue = null;

                            foreach (var prop in root.EnumerateObject())
                            {
                                if (prop.NameEquals("timestamp")) continue;

                                if (prop.Value.ValueKind == JsonValueKind.String)
                                {
                                    firstValue = prop.Value.GetString();
                                    if (!string.IsNullOrWhiteSpace(firstValue))
                                        break;
                                }
                            }

                            if (!string.IsNullOrWhiteSpace(firstValue))
                                message = firstValue!;
                        }
                        else
                        {
                            // Baaki sab status codes:
                            // 1) root.message
                            // 2) root.error.message
                            // 3) first string property value
                            string? picked = null;

                            if (root.TryGetProperty("message", out var mEl) &&
                                mEl.ValueKind == JsonValueKind.String)
                            {
                                picked = mEl.GetString();
                            }
                            else if (root.TryGetProperty("error", out var errEl) &&
                                     errEl.ValueKind == JsonValueKind.Object &&
                                     errEl.TryGetProperty("message", out var emEl) &&
                                     emEl.ValueKind == JsonValueKind.String)
                            {
                                picked = emEl.GetString();
                            }
                            else
                            {
                                foreach (var prop in root.EnumerateObject())
                                {
                                    if (prop.Value.ValueKind == JsonValueKind.String)
                                    {
                                        picked = prop.Value.GetString();
                                        if (!string.IsNullOrWhiteSpace(picked))
                                            break;
                                    }
                                }
                            }

                            if (!string.IsNullOrWhiteSpace(picked))
                                message = picked!;
                        }
                    }
                    catch
                    {
                        // JSON parse fail ho jaye to default message hi use kare
                    }
                }
            }

            var errorResp = new ApiResponse<AbhaProfileResponse>
            {
                StatusCode = statusCode,
                IsSuccess = "false",
                Message = message,
                Data = default
            };

            // Humesha 200 return, inner StatusCode me actual ABHA code
            return Ok(errorResp);
        }
    }


    //[HttpGet("profile/account/abha-card")]
    //public async Task<IActionResult> GetAbhaCard([FromHeader(Name = "X-Token")] string? xToken)
    //{
    //    try
    //    {
    //        if (string.IsNullOrWhiteSpace(xToken))
    //            return BadRequest(new { error = "X-Token header is required" });

    //        var card = await _abhaService.GetAbhaCardAsync(xToken);
    //        if (card == null || card.Content == null || card.Content.Length == 0)
    //            return StatusCode(502, "ABHA card not available");

    //        var contentType = string.IsNullOrWhiteSpace(card.ContentType)
    //            ? "application/octet-stream"
    //            : card.ContentType;

    //        var fileName = string.IsNullOrWhiteSpace(card.FileName)
    //            ? "abha-card.png"
    //            : card.FileName;

    //        return File(card.Content, contentType, fileName);
    //    }
    //    catch (Exception ex)
    //    {
    //        return HandleExceptionForClient(ex, "ABHA card download failed");
    //    }
    //}

    [HttpGet("profile/account/abha-card")]
    public async Task<IActionResult> GetAbhaCard([FromHeader(Name = "X-Token")] string? xToken)
    {
        // Client-side validation (ye hamari API ka contract fail hai, isliye yaha direct 400 + json)
        if (string.IsNullOrWhiteSpace(xToken))
        {
            return BadRequest(new
            {
                statusCode = 400,
                isSuccess = "false",
                message = "X-Token header is required",
                data = (object?)null
            });
        }

        try
        {
            var card = await _abhaService.GetAbhaCardAsync(xToken);

            if (card == null || card.Content == null || card.Content.Length == 0)
            {
                // ABHA ne technically 200 diya ho sakta hai, lekin content empty hai
                return StatusCode(502, new
                {
                    statusCode = 502,
                    isSuccess = "false",
                    message = "ABHA card not available",
                    data = (object?)null
                });
            }

            var contentType = string.IsNullOrWhiteSpace(card.ContentType)
                ? "application/octet-stream"
                : card.ContentType;

            var fileName = string.IsNullOrWhiteSpace(card.FileName)
                ? "abha-card.png"
                : card.FileName;

            // ✅ SUCCESS – file download
            return File(card.Content, contentType, fileName);
        }
        catch (Exception ex)
        {
            // Yaha hum generic ABHA error parsing karenge
            int statusCode = 500;
            string message = "ABHA card download failed";
            string? rawBody = null;

            if (ex is HttpRequestException httpEx && httpEx.Data != null)
            {
                // AbhaHttpClient me jo humne Data["StatusCode"], Data["RawBody"] set kiya tha, wo yaha use hoga
                if (httpEx.Data.Contains("StatusCode") && httpEx.Data["StatusCode"] is int sc)
                    statusCode = sc;

                if (httpEx.Data.Contains("RawBody") && httpEx.Data["RawBody"] is string rb)
                    rawBody = rb;

                if (!string.IsNullOrWhiteSpace(rawBody))
                {
                    try
                    {
                        using var doc = JsonDocument.Parse(rawBody);
                        var root = doc.RootElement;

                        // 1) Try: error.message
                        if (root.TryGetProperty("error", out var errEl) && errEl.ValueKind == JsonValueKind.Object)
                        {
                            if (errEl.TryGetProperty("message", out var em) && em.ValueKind == JsonValueKind.String)
                            {
                                message = em.GetString() ?? message;
                            }
                        }
                        // 2) Try: top-level "message"
                        else if (root.TryGetProperty("message", out var mEl) && mEl.ValueKind == JsonValueKind.String)
                        {
                            message = mEl.GetString() ?? message;
                        }
                        // 3) Special: 500/401 – message + description combine karein agar mile
                        if ((statusCode == 500 || statusCode == 401) &&
                            root.TryGetProperty("description", out var dEl) &&
                            dEl.ValueKind == JsonValueKind.String)
                        {
                            var desc = dEl.GetString();
                            if (!string.IsNullOrWhiteSpace(desc))
                            {
                                // Agar message already set hai, toh dono join
                                if (!string.IsNullOrWhiteSpace(message))
                                    message = $"{message} - {desc}";
                                else
                                    message = desc;
                            }
                        }
                        // 4) Agar abhi bhi kuch meaningful nahi mila, first string property ki value lelo
                        if (message == "ABHA card download failed")
                        {
                            string? firstValue = null;
                            foreach (var prop in root.EnumerateObject())
                            {
                                if (prop.Value.ValueKind == JsonValueKind.String)
                                {
                                    firstValue = prop.Value.GetString();
                                    if (!string.IsNullOrWhiteSpace(firstValue))
                                        break;
                                }
                                else if (prop.Value.ValueKind == JsonValueKind.Object)
                                {
                                    // Nested object me "message" ho to bhi use kar sakte
                                    if (prop.Value.TryGetProperty("message", out var nestedMsg) &&
                                        nestedMsg.ValueKind == JsonValueKind.String)
                                    {
                                        firstValue = nestedMsg.GetString();
                                        if (!string.IsNullOrWhiteSpace(firstValue))
                                            break;
                                    }
                                }
                            }

                            if (!string.IsNullOrWhiteSpace(firstValue))
                                message = firstValue;
                        }
                    }
                    catch
                    {
                        // JSON parse fail ho gaya – message default hi rahega
                    }
                }
            }

            // ❌ ERROR – yaha hum JSON bhej rahe hain, file nahi
            return StatusCode(statusCode, new
            {
                statusCode,
                isSuccess = "false",
                message,
                rawBody // optional, debug ke liye; chahe to hata bhi sakta hai
            });
        }
    }


    /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    //[HttpPost("login/aadhaar/send-otp")]
    //public async Task<IActionResult> SendAadhaarLoginOtp([FromBody] AadhaarLoginSendOtpInput? model)
    //{
    //    try
    //    {
    //        if (model == null || string.IsNullOrWhiteSpace(model.AadhaarNumber))
    //            return BadRequest(new { error = "Aadhaar number is required" });

    //        var resp = await _abhaService.SendAadhaarLoginOtpAsync(model.AadhaarNumber);

    //        if (resp == null)
    //            return StatusCode(502, "ABHA gateway error");

    //        return Ok(resp);
    //    }
    //    catch (Exception ex)
    //    {
    //        return HandleExceptionForClient(ex, "Send Aadhaar login OTP failed");
    //    }
    //}

    [HttpPost("login/aadhaar/send-otp")]
    public async Task<IActionResult> SendAadhaarLoginOtp([FromBody] AadhaarLoginSendOtpInput? model)
    {
        // 1) Input validation
        if (model == null || string.IsNullOrWhiteSpace(model.AadhaarNumber))
        {
            var badResp = new ApiResponse<SendOtpResponse_Login>
            {
                StatusCode = 400,
                IsSuccess = "false",
                Message = "aadhaarNumber is required in request body",
                Data = default
            };
            return Ok(badResp);
        }

        try
        {
            // 2) Call ABHA service
            var gatewayResp = await _abhaService.SendAadhaarLoginOtpAsync(model.AadhaarNumber);

            if (gatewayResp == null)
            {
                var apiRespNull = new ApiResponse<SendOtpResponse_Login>
                {
                    StatusCode = 502,
                    IsSuccess = "false",
                    Message = "ABHA gateway error",
                    Data = default
                };
                return Ok(apiRespNull);
            }

            // 3) Success
            var apiResp = new ApiResponse<SendOtpResponse_Login>
            {
                StatusCode = 200,
                IsSuccess = "true",
                Message = gatewayResp.Message,
                Data = gatewayResp
            };

            return Ok(apiResp);
        }
        catch (Exception ex)
        {
            // 4) Error handling
            int statusCode = 500;
            string message = "Send Aadhaar login OTP failed";
            string? rawBody = null;

            if (ex is HttpRequestException httpEx && httpEx.Data != null)
            {
                if (httpEx.Data.Contains("StatusCode") && httpEx.Data["StatusCode"] is int sc)
                    statusCode = sc;

                if (httpEx.Data.Contains("RawBody") && httpEx.Data["RawBody"] is string rb)
                    rawBody = rb;

                if (!string.IsNullOrWhiteSpace(rawBody))
                {
                    try
                    {
                        using var doc = JsonDocument.Parse(rawBody);
                        var root = doc.RootElement;

                        // 401 — message + description
                        if (statusCode == 401)
                        {
                            string? msg = root.GetProperty("message").GetString();
                            string? desc = root.TryGetProperty("description", out var dEl) ? dEl.GetString() : null;

                            if (!string.IsNullOrWhiteSpace(msg) && !string.IsNullOrWhiteSpace(desc))
                                message = $"{msg} - {desc}";
                            else
                                message = msg ?? desc ?? message;
                        }
                        // 400 — first KV’s value
                        else if (statusCode == 400)
                        {
                            foreach (var prop in root.EnumerateObject())
                            {
                                if (prop.NameEquals("timestamp")) continue;

                                if (prop.Value.ValueKind == JsonValueKind.String)
                                {
                                    message = prop.Value.GetString()!;
                                    break;
                                }
                            }
                        }
                        else
                        {
                            // Other codes — message OR error.message
                            if (root.TryGetProperty("message", out var mEl))
                                message = mEl.GetString() ?? message;

                            else if (root.TryGetProperty("error", out var errEl) &&
                                     errEl.TryGetProperty("message", out var emEl))
                                message = emEl.GetString() ?? message;
                        }
                    }
                    catch { }
                }
            }

            var errorResp = new ApiResponse<SendOtpResponse_Login>
            {
                StatusCode = statusCode,
                IsSuccess = "false",
                Message = message,
                Data = default
            };

            return Ok(errorResp);
        }
    }


    //[HttpPost("login/aadhaar/verify-otp")]
    //public async Task<IActionResult> VerifyAadhaarLoginOtp([FromBody] MobileVerifyInput? model)
    //{
    //    try
    //    {
    //        if (model == null || string.IsNullOrWhiteSpace(model.TxnId))
    //            return BadRequest(new { error = "txnId is required" });

    //        if (string.IsNullOrWhiteSpace(model.Otp))
    //            return BadRequest(new { error = "OTP value is required" });

    //        var resp = await _abhaService.VerifyAadhaarLoginOtpAsync(model.TxnId, model.Otp);

    //        if (resp == null)
    //            return StatusCode(502, "ABHA gateway error");

    //        return Ok(resp);
    //    }
    //    catch (Exception ex)
    //    {
    //        return HandleExceptionForClient(ex, "Verify Aadhaar login OTP failed");
    //    }
    //}

    [HttpPost("login/aadhaar/verify-otp")]
    public async Task<IActionResult> VerifyAadhaarLoginOtp([FromBody] MobileVerifyInput? model)
    {
        // 1) Input validation
        if (model == null ||
            string.IsNullOrWhiteSpace(model.TxnId) ||
            string.IsNullOrWhiteSpace(model.Otp))
        {
            var badResp = new ApiResponse<LoginVerifyOtpResponse>
            {
                StatusCode = 400,
                IsSuccess = "false",
                Message = "txnId and otpValue are required",
                Data = default
            };
            return Ok(badResp);
        }

        try
        {
            // 2) Service call
            var gatewayResp = await _abhaService.VerifyAadhaarLoginOtpAsync(model.TxnId, model.Otp);

            if (gatewayResp == null)
            {
                var apiRespNull = new ApiResponse<LoginVerifyOtpResponse>
                {
                    StatusCode = 502,
                    IsSuccess = "false",
                    Message = "ABHA gateway error",
                    Data = default
                };
                return Ok(apiRespNull);
            }

            // 3) Success (OTP success / mismatch / expired — sab 200 me)
            var apiResp = new ApiResponse<LoginVerifyOtpResponse>
            {
                StatusCode = 200,
                IsSuccess = "true",
                Message = gatewayResp.Message, // "OTP verified", "OTP mismatch", "OTP expired"
                Data = gatewayResp
            };

            return Ok(apiResp);
        }
        catch (Exception ex)
        {
            // 4) Error mapping (same as Aadhaar-send-otp)
            int statusCode = 500;
            string message = "Verify Aadhaar login OTP failed";
            string? rawBody = null;

            if (ex is HttpRequestException httpEx)
            {
                if (httpEx.Data.Contains("StatusCode") && httpEx.Data["StatusCode"] is int sc)
                    statusCode = sc;

                if (httpEx.Data.Contains("RawBody") && httpEx.Data["RawBody"] is string rb)
                    rawBody = rb;

                if (!string.IsNullOrWhiteSpace(rawBody))
                {
                    try
                    {
                        using var doc = JsonDocument.Parse(rawBody);
                        var root = doc.RootElement;

                        if (statusCode == 401)
                        {
                            string? msg = root.TryGetProperty("message", out var mEl) ? mEl.GetString() : null;
                            string? desc = root.TryGetProperty("description", out var dEl) ? dEl.GetString() : null;

                            if (!string.IsNullOrWhiteSpace(msg) && !string.IsNullOrWhiteSpace(desc))
                                message = $"{msg} - {desc}";
                            else
                                message = msg ?? desc ?? message;
                        }
                        else if (statusCode == 400)
                        {
                            foreach (var prop in root.EnumerateObject())
                            {
                                if (prop.NameEquals("timestamp")) continue;

                                if (prop.Value.ValueKind == JsonValueKind.String)
                                {
                                    message = prop.Value.GetString()!;
                                    break;
                                }
                            }
                        }
                        else
                        {
                            if (root.TryGetProperty("message", out var mEl))
                                message = mEl.GetString() ?? message;

                            else if (root.TryGetProperty("error", out var errEl) &&
                                     errEl.TryGetProperty("message", out var emEl))
                                message = emEl.GetString() ?? message;
                        }
                    }
                    catch { }
                }
            }

            var errorResp = new ApiResponse<LoginVerifyOtpResponse>
            {
                StatusCode = statusCode,
                IsSuccess = "false",
                Message = message,
                Data = default
            };

            return Ok(errorResp);
        }
    }


    //[HttpPost("login/abha/aadhaar-otp/send-otp")]
    //public async Task<IActionResult> SendAbhaNumberAadhaarOtp([FromBody] AbhaNumberAadhaarOtpSendInput? model)
    //{
    //    try
    //    {
    //        if (model == null || string.IsNullOrWhiteSpace(model.AbhaNumber))
    //            return BadRequest(new { error = "ABHA number is required" });

    //        var resp = await _abhaService.SendAbhaNumberAadhaarOtpAsync(model.AbhaNumber);

    //        if (resp == null)
    //            return StatusCode(502, "ABHA gateway error");

    //        return Ok(resp);
    //    }
    //    catch (Exception ex)
    //    {
    //        return HandleExceptionForClient(ex, "Send ABHA-number Aadhaar OTP failed");
    //    }
    //}

    [HttpPost("login/abha/aadhaar-otp/send-otp")]
    public async Task<IActionResult> SendAbhaNumberAadhaarOtp([FromBody] AbhaNumberAadhaarOtpSendInput dto)
    {
        // 1) Input validation – 400 ko bhi ApiResponse ke through dena
        if (dto == null || string.IsNullOrWhiteSpace(dto.AbhaNumber))
        {
            var badResp = new ApiResponse<SendOtpResponse_Login>
            {
                StatusCode = 400,
                IsSuccess = "false",
                Message = "abhaNumber is required in request body",
                Data = default
            };
            return Ok(badResp);
        }

        try
        {
            // 2) Call service (ye encryption + ABHA call karega)
            var gatewayResp = await _abhaService.SendAbhaNumberAadhaarOtpAsync(dto.AbhaNumber);

            if (gatewayResp == null)
            {
                var apiRespNull = new ApiResponse<SendOtpResponse_Login>
                {
                    StatusCode = 502,
                    IsSuccess = "false",
                    Message = "ABHA gateway error",
                    Data = default
                };
                return Ok(apiRespNull);
            }

            // 3) Success → ABHA ke message ko upar leke aao
            var apiResp = new ApiResponse<SendOtpResponse_Login>
            {
                StatusCode = 200,
                IsSuccess = "true",
                Message = gatewayResp.Message,   // {"txnId","message"} me se message
                Data = gatewayResp
            };

            return Ok(apiResp);
        }
        catch (Exception ex)
        {
            // 4) Error mapping – same style jaisa pehle send-otp me kiya tha
            int statusCode = 500;
            string message = "ABHA send-otp (abha-number + aadhaar-otp) failed";
            string? rawBody = null;

            if (ex is HttpRequestException httpEx && httpEx.Data != null)
            {
                if (httpEx.Data.Contains("StatusCode") && httpEx.Data["StatusCode"] is int sc)
                    statusCode = sc;

                if (httpEx.Data.Contains("RawBody") && httpEx.Data["RawBody"] is string rb)
                    rawBody = rb;

                if (!string.IsNullOrWhiteSpace(rawBody))
                {
                    try
                    {
                        using var doc = JsonDocument.Parse(rawBody);
                        var root = doc.RootElement;

                        if (statusCode == 401)
                        {
                            // 401: message + description merge (same as pehle)
                            string? msg = null;
                            string? desc = null;

                            if (root.TryGetProperty("message", out var mEl) && mEl.ValueKind == JsonValueKind.String)
                                msg = mEl.GetString();

                            if (root.TryGetProperty("description", out var dEl) && dEl.ValueKind == JsonValueKind.String)
                                desc = dEl.GetString();

                            // kuch APIs error object ke andar bhi message bhej sakti hain
                            if ((msg == null || msg.Trim().Length == 0) &&
                                root.TryGetProperty("error", out var errEl) &&
                                errEl.ValueKind == JsonValueKind.Object &&
                                errEl.TryGetProperty("message", out var emEl) &&
                                emEl.ValueKind == JsonValueKind.String)
                            {
                                msg = emEl.GetString();
                            }

                            if (!string.IsNullOrWhiteSpace(msg) || !string.IsNullOrWhiteSpace(desc))
                            {
                                if (!string.IsNullOrWhiteSpace(msg) && !string.IsNullOrWhiteSpace(desc))
                                    message = $"{msg} - {desc}";
                                else
                                    message = msg ?? desc ?? message;
                            }
                        }
                        else if (statusCode == 400)
                        {
                            // 400: pehla key (scope / loginId / etc.) ki value
                            string? firstValue = null;

                            foreach (var prop in root.EnumerateObject())
                            {
                                if (prop.NameEquals("timestamp")) continue;

                                if (prop.Value.ValueKind == JsonValueKind.String)
                                {
                                    firstValue = prop.Value.GetString();
                                    if (!string.IsNullOrWhiteSpace(firstValue))
                                        break;
                                }
                            }

                            if (!string.IsNullOrWhiteSpace(firstValue))
                                message = firstValue;
                        }
                        else
                        {
                            // Other status codes: try root.message / error.message
                            string? msg = null;

                            if (root.TryGetProperty("message", out var mEl) && mEl.ValueKind == JsonValueKind.String)
                                msg = mEl.GetString();

                            if (msg == null &&
                                root.TryGetProperty("error", out var errEl) &&
                                errEl.ValueKind == JsonValueKind.Object &&
                                errEl.TryGetProperty("message", out var emEl) &&
                                emEl.ValueKind == JsonValueKind.String)
                            {
                                msg = emEl.GetString();
                            }

                            if (!string.IsNullOrWhiteSpace(msg))
                                message = msg!;
                        }
                    }
                    catch
                    {
                        // parsing fail ho jaaye to default message hi rahega
                    }
                }
            }

            var errorResp = new ApiResponse<SendOtpResponse_Login>
            {
                StatusCode = statusCode,
                IsSuccess = "false",
                Message = message,
                Data = default
            };

            // Humesha 200, andar StatusCode me ABHA ka code
            return Ok(errorResp);
        }
    }


    //[HttpPost("login/abha/aadhaar-otp/verify")]
    //public async Task<IActionResult> VerifyAbhaNumberAadhaarOtp([FromBody] MobileVerifyInput input)
    //{
    //    try
    //    {
    //        if (input == null ||
    //            string.IsNullOrWhiteSpace(input.TxnId) ||
    //            string.IsNullOrWhiteSpace(input.Otp))
    //        {
    //            return BadRequest(new { error = "txnId and otpValue are required" });
    //        }

    //        var resp = await _abhaService.VerifyAbhaNumberAadhaarOtpAsync(input.TxnId, input.Otp);

    //        if (resp == null)
    //            return StatusCode(502, "ABHA gateway error");

    //        return Ok(resp);
    //    }
    //    catch (Exception ex)
    //    {
    //        return HandleExceptionForClient(ex, "Verify ABHA-number Aadhaar OTP failed");
    //    }
    //}

    [HttpPost("login/abha/aadhaar-otp/verify")]
    public async Task<IActionResult> VerifyAbhaNumberAadhaarOtp([FromBody] MobileVerifyInput input)
    {
        // 1) Input validation → standardized ApiResponse
        if (input == null ||
            string.IsNullOrWhiteSpace(input.TxnId) ||
            string.IsNullOrWhiteSpace(input.Otp))
        {
            var badResp = new ApiResponse<LoginVerifyOtpResponse>
            {
                StatusCode = 400,
                IsSuccess = "false",
                Message = "txnId and otpValue are required",
                Data = default
            };
            return Ok(badResp);
        }

        try
        {
            // 2) Call service
            var gatewayResp = await _abhaService.VerifyAbhaNumberAadhaarOtpAsync(input.TxnId, input.Otp);

            if (gatewayResp == null)
            {
                var apiRespNull = new ApiResponse<LoginVerifyOtpResponse>
                {
                    StatusCode = 502,
                    IsSuccess = "false",
                    Message = "ABHA gateway error",
                    Data = default
                };
                return Ok(apiRespNull);
            }

            // 3) 200 OK (including OTP failed / expired) → resp.Message use karo
            var apiResp = new ApiResponse<LoginVerifyOtpResponse>
            {
                StatusCode = 200,
                IsSuccess = "true",
                // ABHA verify response me hamesha "message" hai:
                // - "OTP verified successfully"
                // - "OTP did not match, please try again"
                // - "OTP expired, please try again"
                Message = gatewayResp.Message,
                Data = gatewayResp
            };

            return Ok(apiResp);
        }
        catch (Exception ex)
        {
            // 4) Error handling: same pattern as send-otp
            int statusCode = 500;
            string message = "Verify ABHA-number Aadhaar OTP failed";
            string? rawBody = null;

            if (ex is HttpRequestException httpEx && httpEx.Data != null)
            {
                if (httpEx.Data.Contains("StatusCode") && httpEx.Data["StatusCode"] is int sc)
                    statusCode = sc;

                if (httpEx.Data.Contains("RawBody") && httpEx.Data["RawBody"] is string rb)
                    rawBody = rb;

                if (!string.IsNullOrWhiteSpace(rawBody))
                {
                    try
                    {
                        using var doc = JsonDocument.Parse(rawBody);
                        var root = doc.RootElement;

                        if (statusCode == 401)
                        {
                            // 401 → message + description merge
                            string? msg = null;
                            string? desc = null;

                            if (root.TryGetProperty("message", out var mEl) &&
                                mEl.ValueKind == JsonValueKind.String)
                                msg = mEl.GetString();

                            if (root.TryGetProperty("description", out var dEl) &&
                                dEl.ValueKind == JsonValueKind.String)
                                desc = dEl.GetString();

                            if (!string.IsNullOrWhiteSpace(msg) || !string.IsNullOrWhiteSpace(desc))
                            {
                                if (!string.IsNullOrWhiteSpace(msg) && !string.IsNullOrWhiteSpace(desc))
                                    message = $"{msg} - {desc}";
                                else
                                    message = msg ?? desc ?? message;
                            }
                        }
                        else if (statusCode == 400)
                        {
                            // 400 → pehle key (scope / loginId / etc.) ki string value
                            string? firstValue = null;

                            foreach (var prop in root.EnumerateObject())
                            {
                                if (prop.NameEquals("timestamp")) continue;

                                if (prop.Value.ValueKind == JsonValueKind.String)
                                {
                                    firstValue = prop.Value.GetString();
                                    if (!string.IsNullOrWhiteSpace(firstValue))
                                        break;
                                }
                            }

                            if (!string.IsNullOrWhiteSpace(firstValue))
                                message = firstValue;
                        }
                        else
                        {
                            // Baaki status codes ke liye best-effort:
                            // direct "message" ya "error.message" try karo
                            if (root.TryGetProperty("message", out var mEl) &&
                                mEl.ValueKind == JsonValueKind.String)
                            {
                                message = mEl.GetString() ?? message;
                            }
                            else if (root.TryGetProperty("error", out var errEl) &&
                                     errEl.ValueKind == JsonValueKind.Object &&
                                     errEl.TryGetProperty("message", out var emEl) &&
                                     emEl.ValueKind == JsonValueKind.String)
                            {
                                message = emEl.GetString() ?? message;
                            }
                        }
                    }
                    catch
                    {
                        // JSON parse fail ho jaye to default message hi rahega
                    }
                }
            }

            var errorResp = new ApiResponse<LoginVerifyOtpResponse>
            {
                StatusCode = statusCode,
                IsSuccess = "false",
                Message = message,
                Data = default
            };

            // Hamesha 200 HTTP, andar actual ABHA statusCode
            return Ok(errorResp);
        }
    }


    //[HttpPost("login/abha/abha-otp/send-otp")]
    //public async Task<IActionResult> SendAbhaNumberAbhaOtp([FromBody] AbhaNumberAadhaarOtpSendInput? model)
    //{
    //    try
    //    {
    //        if (model == null || string.IsNullOrWhiteSpace(model.AbhaNumber))
    //            return BadRequest(new { error = "ABHA number is required" });

    //        var resp = await _abhaService.SendAbhaNumberAbhaOtpAsync(model.AbhaNumber);

    //        if (resp == null)
    //            return StatusCode(502, "ABHA gateway error");

    //        return Ok(resp);
    //    }
    //    catch (Exception ex)
    //    {
    //        return HandleExceptionForClient(ex, "Send ABHA-number ABHA OTP failed");
    //    }
    //}

    [HttpPost("login/abha/abha-otp/send-otp")]
    public async Task<IActionResult> SendAbhaNumberAbhaOtp([FromBody] AbhaNumberAadhaarOtpSendInput? model)
    {
        // 1) Input validation → ApiResponse style
        if (model == null || string.IsNullOrWhiteSpace(model.AbhaNumber))
        {
            var badResp = new ApiResponse<SendOtpResponse_Login>
            {
                StatusCode = 400,
                IsSuccess = "false",
                Message = "abhaNumber is required in request body",
                Data = default
            };
            return Ok(badResp);
        }

        try
        {
            // 2) Service call (encryption + ABHA API)
            var gatewayResp = await _abhaService.SendAbhaNumberAbhaOtpAsync(model.AbhaNumber);

            if (gatewayResp == null)
            {
                var apiRespNull = new ApiResponse<SendOtpResponse_Login>
                {
                    StatusCode = 502,
                    IsSuccess = "false",
                    Message = "ABHA gateway error",
                    Data = default
                };
                return Ok(apiRespNull);
            }

            // 3) 200 OK – ABHA message upar bubble
            var apiResp = new ApiResponse<SendOtpResponse_Login>
            {
                StatusCode = 200,
                IsSuccess = "true",
                Message = gatewayResp.Message,   // {"txnId","message"} me se "message"
                Data = gatewayResp
            };

            return Ok(apiResp);
        }
        catch (Exception ex)
        {
            // 4) Error mapping – same pattern as Aadhaar-OTP send-otp
            int statusCode = 500;
            string message = "ABHA send-otp (abha-number + abha-otp) failed";
            string? rawBody = null;

            if (ex is HttpRequestException httpEx && httpEx.Data != null)
            {
                if (httpEx.Data.Contains("StatusCode") && httpEx.Data["StatusCode"] is int sc)
                    statusCode = sc;

                if (httpEx.Data.Contains("RawBody") && httpEx.Data["RawBody"] is string rb)
                    rawBody = rb;

                if (!string.IsNullOrWhiteSpace(rawBody))
                {
                    try
                    {
                        using var doc = JsonDocument.Parse(rawBody);
                        var root = doc.RootElement;

                        if (statusCode == 401)
                        {
                            // 401: message + description merge
                            string? msg = null;
                            string? desc = null;

                            if (root.TryGetProperty("message", out var mEl) && mEl.ValueKind == JsonValueKind.String)
                                msg = mEl.GetString();

                            if (root.TryGetProperty("description", out var dEl) && dEl.ValueKind == JsonValueKind.String)
                                desc = dEl.GetString();

                            // Kuch cases me error.message ke andar hota hai
                            if ((msg == null || msg.Trim().Length == 0) &&
                                root.TryGetProperty("error", out var errEl) &&
                                errEl.ValueKind == JsonValueKind.Object &&
                                errEl.TryGetProperty("message", out var emEl) &&
                                emEl.ValueKind == JsonValueKind.String)
                            {
                                msg = emEl.GetString();
                            }

                            if (!string.IsNullOrWhiteSpace(msg) || !string.IsNullOrWhiteSpace(desc))
                            {
                                if (!string.IsNullOrWhiteSpace(msg) && !string.IsNullOrWhiteSpace(desc))
                                    message = $"{msg} - {desc}";
                                else
                                    message = msg ?? desc ?? message;
                            }
                        }
                        else if (statusCode == 400)
                        {
                            // 400: first non-timestamp string value (scope/loginId etc.)
                            string? firstValue = null;

                            foreach (var prop in root.EnumerateObject())
                            {
                                if (prop.NameEquals("timestamp")) continue;

                                if (prop.Value.ValueKind == JsonValueKind.String)
                                {
                                    firstValue = prop.Value.GetString();
                                    if (!string.IsNullOrWhiteSpace(firstValue))
                                        break;
                                }
                            }

                            if (!string.IsNullOrWhiteSpace(firstValue))
                                message = firstValue;
                        }
                        else
                        {
                            // Other status codes: try root.message / error.message
                            string? msg = null;

                            if (root.TryGetProperty("message", out var mEl) && mEl.ValueKind == JsonValueKind.String)
                                msg = mEl.GetString();

                            if (msg == null &&
                                root.TryGetProperty("error", out var errEl) &&
                                errEl.ValueKind == JsonValueKind.Object &&
                                errEl.TryGetProperty("message", out var emEl) &&
                                emEl.ValueKind == JsonValueKind.String)
                            {
                                msg = emEl.GetString();
                            }

                            if (!string.IsNullOrWhiteSpace(msg))
                                message = msg!;
                        }
                    }
                    catch
                    {
                        // JSON parse fail → default message
                    }
                }
            }

            var errorResp = new ApiResponse<SendOtpResponse_Login>
            {
                StatusCode = statusCode,
                IsSuccess = "false",
                Message = message,
                Data = default
            };

            // Always HTTP 200, inner StatusCode me ABHA ka code
            return Ok(errorResp);
        }
    }

    //[HttpPost("login/abha/abha-otp/verify")]
    //public async Task<IActionResult> VerifyAbhaNumberAbhaOtp([FromBody] MobileVerifyInput input)
    //{
    //    try
    //    {
    //        if (input == null ||
    //            string.IsNullOrWhiteSpace(input.TxnId) ||
    //            string.IsNullOrWhiteSpace(input.Otp))
    //        {
    //            return BadRequest(new { error = "txnId and otpValue are required" });
    //        }

    //        var resp = await _abhaService.VerifyAbhaNumberAbhaOtpAsync(input.TxnId, input.Otp);

    //        if (resp == null)
    //            return StatusCode(502, "ABHA gateway error");

    //        return Ok(resp);
    //    }
    //    catch (Exception ex)
    //    {
    //        return HandleExceptionForClient(ex, "Verify ABHA-number ABHA OTP failed");
    //    }
    //}

    [HttpPost("login/abha/abha-otp/verify")]
    public async Task<IActionResult> VerifyAbhaNumberAbhaOtp([FromBody] MobileVerifyInput input)
    {
        // 1) Input validation → ApiResponse
        if (input == null ||
            string.IsNullOrWhiteSpace(input.TxnId) ||
            string.IsNullOrWhiteSpace(input.Otp))
        {
            var badResp = new ApiResponse<LoginVerifyOtpResponse>
            {
                StatusCode = 400,
                IsSuccess = "false",
                Message = "txnId and otpValue are required",
                Data = default
            };
            return Ok(badResp);
        }

        try
        {
            // 2) Service call
            var gatewayResp = await _abhaService.VerifyAbhaNumberAbhaOtpAsync(input.TxnId, input.Otp);

            if (gatewayResp == null)
            {
                var apiRespNull = new ApiResponse<LoginVerifyOtpResponse>
                {
                    StatusCode = 502,
                    IsSuccess = "false",
                    Message = "ABHA gateway error",
                    Data = default
                };
                return Ok(apiRespNull);
            }

            // 3) 200 OK (success + failed/expired – sab me message aata hai)
            var apiResp = new ApiResponse<LoginVerifyOtpResponse>
            {
                StatusCode = 200,
                IsSuccess = "true",
                // message:
                //  - "OTP verified successfully"
                //  - "OTP did not match, please try again"
                //  - "OTP expired, please try again"
                Message = gatewayResp.Message,
                Data = gatewayResp
            };

            return Ok(apiResp);
        }
        catch (Exception ex)
        {
            // 4) Error mapping (same pattern as Aadhaar-OTP verify)
            int statusCode = 500;
            string message = "Verify ABHA-number ABHA OTP failed";
            string? rawBody = null;

            if (ex is HttpRequestException httpEx && httpEx.Data != null)
            {
                if (httpEx.Data.Contains("StatusCode") && httpEx.Data["StatusCode"] is int sc)
                    statusCode = sc;

                if (httpEx.Data.Contains("RawBody") && httpEx.Data["RawBody"] is string rb)
                    rawBody = rb;

                if (!string.IsNullOrWhiteSpace(rawBody))
                {
                    try
                    {
                        using var doc = JsonDocument.Parse(rawBody);
                        var root = doc.RootElement;

                        if (statusCode == 401)
                        {
                            // 401 → message + description merge
                            string? msg = null;
                            string? desc = null;

                            if (root.TryGetProperty("message", out var mEl) &&
                                mEl.ValueKind == JsonValueKind.String)
                                msg = mEl.GetString();

                            if (root.TryGetProperty("description", out var dEl) &&
                                dEl.ValueKind == JsonValueKind.String)
                                desc = dEl.GetString();

                            if (!string.IsNullOrWhiteSpace(msg) || !string.IsNullOrWhiteSpace(desc))
                            {
                                if (!string.IsNullOrWhiteSpace(msg) && !string.IsNullOrWhiteSpace(desc))
                                    message = $"{msg} - {desc}";
                                else
                                    message = msg ?? desc ?? message;
                            }
                        }
                        else if (statusCode == 400)
                        {
                            // 400 → first non-timestamp string value
                            string? firstValue = null;

                            foreach (var prop in root.EnumerateObject())
                            {
                                if (prop.NameEquals("timestamp")) continue;

                                if (prop.Value.ValueKind == JsonValueKind.String)
                                {
                                    firstValue = prop.Value.GetString();
                                    if (!string.IsNullOrWhiteSpace(firstValue))
                                        break;
                                }
                            }

                            if (!string.IsNullOrWhiteSpace(firstValue))
                                message = firstValue;
                        }
                        else
                        {
                            // Other codes → message / error.message
                            if (root.TryGetProperty("message", out var mEl) &&
                                mEl.ValueKind == JsonValueKind.String)
                            {
                                message = mEl.GetString() ?? message;
                            }
                            else if (root.TryGetProperty("error", out var errEl) &&
                                     errEl.ValueKind == JsonValueKind.Object &&
                                     errEl.TryGetProperty("message", out var emEl) &&
                                     emEl.ValueKind == JsonValueKind.String)
                            {
                                message = emEl.GetString() ?? message;
                            }
                        }
                    }
                    catch
                    {
                        // parsing fail → default message
                    }
                }
            }

            var errorResp = new ApiResponse<LoginVerifyOtpResponse>
            {
                StatusCode = statusCode,
                IsSuccess = "false",
                Message = message,
                Data = default
            };

            // Hamesha 200 HTTP, andar actual ABHA StatusCode
            return Ok(errorResp);
        }
    }


    //[HttpPost("login/mobile/send-otp")]
    //public async Task<IActionResult> SendMobileLoginOtp([FromBody] MobileLoginSendOtpInput? model)
    //{
    //    try
    //    {
    //        if (model == null || string.IsNullOrWhiteSpace(model.MobileNumber))
    //            return BadRequest(new { error = "Mobile number is required" });

    //        var resp = await _abhaService.SendMobileLoginOtpAsync(model.MobileNumber);

    //        if (resp == null)
    //            return StatusCode(502, "ABHA gateway error");

    //        return Ok(resp);
    //    }
    //    catch (Exception ex)
    //    {
    //        return HandleExceptionForClient(ex, "Send mobile login OTP failed");
    //    }
    //}

    [HttpPost("login/mobile/send-otp")]
    public async Task<IActionResult> SendMobileLoginOtp([FromBody] MobileLoginSendOtpInput? model)
    {
        // 1) Input validation -> ApiResponse ke through
        if (model == null || string.IsNullOrWhiteSpace(model.MobileNumber))
        {
            var badResp = new ApiResponse<SendOtpResponse_Login>
            {
                StatusCode = 400,
                IsSuccess = "false",
                Message = "mobileNumber is required in request body",
                Data = default
            };
            return Ok(badResp);
        }

        try
        {
            // 2) Service call (encryption + ABHA call)
            var gatewayResp = await _abhaService.SendMobileLoginOtpAsync(model.MobileNumber);

            if (gatewayResp == null)
            {
                var apiRespNull = new ApiResponse<SendOtpResponse_Login>
                {
                    StatusCode = 502,
                    IsSuccess = "false",
                    Message = "ABHA gateway error",
                    Data = default
                };
                return Ok(apiRespNull);
            }

            // 3) Success → ABHA ka message upar
            var apiResp = new ApiResponse<SendOtpResponse_Login>
            {
                StatusCode = 200,
                IsSuccess = "true",
                // {"txnId","message"} me se "message"
                Message = gatewayResp.Message,
                Data = gatewayResp
            };

            return Ok(apiResp);
        }
        catch (Exception ex)
        {
            // 4) Error mapping (same pattern jaise Aadhaar send-otp)
            int statusCode = 500;
            string message = "ABHA send-otp (mobile login) failed";
            string? rawBody = null;

            if (ex is HttpRequestException httpEx && httpEx.Data != null)
            {
                if (httpEx.Data.Contains("StatusCode") && httpEx.Data["StatusCode"] is int sc)
                    statusCode = sc;

                if (httpEx.Data.Contains("RawBody") && httpEx.Data["RawBody"] is string rb)
                    rawBody = rb;

                if (!string.IsNullOrWhiteSpace(rawBody))
                {
                    try
                    {
                        using var doc = JsonDocument.Parse(rawBody);
                        var root = doc.RootElement;

                        if (statusCode == 401)
                        {
                            // 401 : message + description merge
                            string? msg = null;
                            string? desc = null;

                            if (root.TryGetProperty("message", out var mEl) &&
                                mEl.ValueKind == JsonValueKind.String)
                                msg = mEl.GetString();

                            if (root.TryGetProperty("description", out var dEl) &&
                                dEl.ValueKind == JsonValueKind.String)
                                desc = dEl.GetString();

                            // kuch cases me error.message ke andar bhi ho sakta hai
                            if ((msg == null || msg.Trim().Length == 0) &&
                                root.TryGetProperty("error", out var errEl) &&
                                errEl.ValueKind == JsonValueKind.Object &&
                                errEl.TryGetProperty("message", out var emEl) &&
                                emEl.ValueKind == JsonValueKind.String)
                            {
                                msg = emEl.GetString();
                            }

                            if (!string.IsNullOrWhiteSpace(msg) || !string.IsNullOrWhiteSpace(desc))
                            {
                                if (!string.IsNullOrWhiteSpace(msg) && !string.IsNullOrWhiteSpace(desc))
                                    message = $"{msg} - {desc}";
                                else
                                    message = msg ?? desc ?? message;
                            }
                        }
                        else if (statusCode == 400)
                        {
                            // 400 : first non-timestamp string property ki value
                            string? firstValue = null;

                            foreach (var prop in root.EnumerateObject())
                            {
                                if (prop.NameEquals("timestamp")) continue;

                                if (prop.Value.ValueKind == JsonValueKind.String)
                                {
                                    firstValue = prop.Value.GetString();
                                    if (!string.IsNullOrWhiteSpace(firstValue))
                                        break;
                                }
                            }

                            if (!string.IsNullOrWhiteSpace(firstValue))
                                message = firstValue;
                        }
                        else
                        {
                            // Other codes: root.message ya error.message
                            string? msg = null;

                            if (root.TryGetProperty("message", out var mEl) &&
                                mEl.ValueKind == JsonValueKind.String)
                                msg = mEl.GetString();

                            if (msg == null &&
                                root.TryGetProperty("error", out var errEl) &&
                                errEl.ValueKind == JsonValueKind.Object &&
                                errEl.TryGetProperty("message", out var emEl) &&
                                emEl.ValueKind == JsonValueKind.String)
                            {
                                msg = emEl.GetString();
                            }

                            if (!string.IsNullOrWhiteSpace(msg))
                                message = msg!;
                        }
                    }
                    catch
                    {
                        // parse fail -> default message
                    }
                }
            }

            var errorResp = new ApiResponse<SendOtpResponse_Login>
            {
                StatusCode = statusCode,
                IsSuccess = "false",
                Message = message,
                Data = default
            };

            // HTTP 200, andar ABHA ka actual status
            return Ok(errorResp);
        }
    }


    //[HttpPost("login/mobile/verify-otp")]
    //public async Task<IActionResult> VerifyMobileLoginOtp([FromBody] MobileVerifyInput input)
    //{
    //    try
    //    {
    //        if (input == null ||
    //            string.IsNullOrWhiteSpace(input.TxnId) ||
    //            string.IsNullOrWhiteSpace(input.Otp))
    //        {
    //            return BadRequest(new { error = "txnId and otpValue are required" });
    //        }

    //        var resp = await _abhaService.VerifyMobileLoginOtpAsync(input.TxnId, input.Otp);

    //        if (resp == null)
    //            return StatusCode(502, "ABHA gateway error");

    //        return Ok(resp);
    //    }
    //    catch (Exception ex)
    //    {
    //        return HandleExceptionForClient(ex, "Mobile login OTP verify failed");
    //    }
    //}

    [HttpPost("login/mobile/verify-otp")]
    public async Task<IActionResult> VerifyMobileLoginOtp([FromBody] MobileVerifyInput input)
    {
        // 1) Input validation -> ApiResponse
        if (input == null ||
            string.IsNullOrWhiteSpace(input.TxnId) ||
            string.IsNullOrWhiteSpace(input.Otp))
        {
            var badResp = new ApiResponse<LoginVerifyOtpResponse>
            {
                StatusCode = 400,
                IsSuccess = "false",
                Message = "txnId and otpValue are required",
                Data = default
            };
            return Ok(badResp);
        }

        try
        {
            // 2) Service call
            var gatewayResp = await _abhaService.VerifyMobileLoginOtpAsync(input.TxnId, input.Otp);

            if (gatewayResp == null)
            {
                var apiRespNull = new ApiResponse<LoginVerifyOtpResponse>
                {
                    StatusCode = 502,
                    IsSuccess = "false",
                    Message = "ABHA gateway error",
                    Data = default
                };
                return Ok(apiRespNull);
            }

            // 3) 200 OK (OTP success / mismatch / expired) → message from gateway
            var apiResp = new ApiResponse<LoginVerifyOtpResponse>
            {
                StatusCode = 200,
                IsSuccess = "true",
                // ABHA verify response me "message":
                //  - "OTP verified successfully"
                //  - "OTP did not match, please try again"
                //  - "OTP expired, please try again"
                Message = gatewayResp.Message,
                Data = gatewayResp
            };

            return Ok(apiResp);
        }
        catch (Exception ex)
        {
            // 4) Error mapping (same pattern)
            int statusCode = 500;
            string message = "Mobile login OTP verify failed";
            string? rawBody = null;

            if (ex is HttpRequestException httpEx && httpEx.Data != null)
            {
                if (httpEx.Data.Contains("StatusCode") && httpEx.Data["StatusCode"] is int sc)
                    statusCode = sc;

                if (httpEx.Data.Contains("RawBody") && httpEx.Data["RawBody"] is string rb)
                    rawBody = rb;

                if (!string.IsNullOrWhiteSpace(rawBody))
                {
                    try
                    {
                        using var doc = JsonDocument.Parse(rawBody);
                        var root = doc.RootElement;

                        if (statusCode == 401)
                        {
                            // 401 : message + description
                            string? msg = null;
                            string? desc = null;

                            if (root.TryGetProperty("message", out var mEl) &&
                                mEl.ValueKind == JsonValueKind.String)
                                msg = mEl.GetString();

                            if (root.TryGetProperty("description", out var dEl) &&
                                dEl.ValueKind == JsonValueKind.String)
                                desc = dEl.GetString();

                            if (!string.IsNullOrWhiteSpace(msg) || !string.IsNullOrWhiteSpace(desc))
                            {
                                if (!string.IsNullOrWhiteSpace(msg) && !string.IsNullOrWhiteSpace(desc))
                                    message = $"{msg} - {desc}";
                                else
                                    message = msg ?? desc ?? message;
                            }
                        }
                        else if (statusCode == 400)
                        {
                            // 400 : first non-timestamp string property
                            string? firstValue = null;

                            foreach (var prop in root.EnumerateObject())
                            {
                                if (prop.NameEquals("timestamp")) continue;

                                if (prop.Value.ValueKind == JsonValueKind.String)
                                {
                                    firstValue = prop.Value.GetString();
                                    if (!string.IsNullOrWhiteSpace(firstValue))
                                        break;
                                }
                            }

                            if (!string.IsNullOrWhiteSpace(firstValue))
                                message = firstValue;
                        }
                        else
                        {
                            // Baaki codes: message ya error.message
                            if (root.TryGetProperty("message", out var mEl) &&
                                mEl.ValueKind == JsonValueKind.String)
                            {
                                message = mEl.GetString() ?? message;
                            }
                            else if (root.TryGetProperty("error", out var errEl) &&
                                     errEl.ValueKind == JsonValueKind.Object &&
                                     errEl.TryGetProperty("message", out var emEl) &&
                                     emEl.ValueKind == JsonValueKind.String)
                            {
                                message = emEl.GetString() ?? message;
                            }
                        }
                    }
                    catch
                    {
                        // ignore parse error
                    }
                }
            }

            var errorResp = new ApiResponse<LoginVerifyOtpResponse>
            {
                StatusCode = statusCode,
                IsSuccess = "false",
                Message = message,
                Data = default
            };

            // Always HTTP 200, andar actual ABHA status
            return Ok(errorResp);
        }
    }

    [HttpPost("login/mobile/verify-user")]
    public async Task<IActionResult> VerifyUser([FromBody] VerifyUserRequestDto input)
    {
        // 1) Input Validation
        if (input == null ||
            string.IsNullOrWhiteSpace(input.ABHANumber) ||
            string.IsNullOrWhiteSpace(input.txnId) ||
            string.IsNullOrWhiteSpace(input.tToken))
        {
            var badResp = new ApiResponse<VerifyUserResponseDto>
            {
                StatusCode = 400,
                IsSuccess = "false",
                Message = "ABHANumber, txnId and tToken are required",
                Data = default
            };
            return Ok(badResp);
        }

        try
        {
            // 2) Service call
            var gatewayResp = await _abhaService.VerifyUserAsync(
                input.ABHANumber,
                input.txnId,
                input.tToken
            );

            if (gatewayResp == null)
            {
                var nullResp = new ApiResponse<VerifyUserResponseDto>
                {
                    StatusCode = 502,
                    IsSuccess = "false",
                    Message = "ABHA gateway error",
                    Data = null
                };
                return Ok(nullResp);
            }

            // 3) Return success format
            return Ok(new ApiResponse<VerifyUserResponseDto>
            {
                StatusCode = 200,
                IsSuccess = "true",
                Message = "User verification successful",
                Data = gatewayResp
            });
        }
        catch (Exception ex)
        {
            // EXACT SAME ERROR MAPPING AS YOUR MOBILE-OTP VERIFY CODE
            int statusCode = 500;
            string message = "User verification failed";
            string? rawBody = null;

            if (ex is HttpRequestException httpEx)
            {
                if (httpEx.Data.Contains("StatusCode") && httpEx.Data["StatusCode"] is int sc)
                    statusCode = sc;

                if (httpEx.Data.Contains("RawBody") && httpEx.Data["RawBody"] is string rb)
                    rawBody = rb;

                if (!string.IsNullOrWhiteSpace(rawBody))
                {
                    try
                    {
                        using var doc = JsonDocument.Parse(rawBody);
                        var root = doc.RootElement;

                        if (statusCode == 401)
                        {
                            string? msg = root.TryGetProperty("message", out var m1) ? m1.GetString() : null;
                            string? desc = root.TryGetProperty("description", out var d1) ? d1.GetString() : null;
                            message = string.Join(" - ", new[] { msg, desc }.Where(x => !string.IsNullOrWhiteSpace(x)));
                        }
                        else if (statusCode == 400)
                        {
                            foreach (var prop in root.EnumerateObject())
                            {
                                if (prop.NameEquals("timestamp")) continue;

                                if (prop.Value.ValueKind == JsonValueKind.String)
                                {
                                    var val = prop.Value.GetString();
                                    if (!string.IsNullOrWhiteSpace(val))
                                    {
                                        message = val;
                                        break;
                                    }
                                }
                            }
                        }
                        else
                        {
                            if (root.TryGetProperty("message", out var mEl))
                                message = mEl.GetString() ?? message;
                            else if (root.TryGetProperty("error", out var errEl) &&
                                     errEl.TryGetProperty("message", out var emEl))
                                message = emEl.GetString() ?? message;
                        }
                    }
                    catch { }
                }
            }

            return Ok(new ApiResponse<VerifyUserResponseDto>
            {
                StatusCode = statusCode,
                IsSuccess = "false",
                Message = message,
                Data = null
            });
        }
    }

}

// small DTO for encrypt endpoint
public record EncryptRequest(string PublicKeyPem, string PlainText);
