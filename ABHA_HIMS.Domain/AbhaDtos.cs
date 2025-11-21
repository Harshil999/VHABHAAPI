using System.Text.Json;
using System.Text.Json.Serialization;

namespace ABHA_HIMS.Domain;

public class AbhaDtos
{
    public record SessionRequest(
        [property: JsonPropertyName("clientId")] string ClientId,
        [property: JsonPropertyName("clientSecret")] string ClientSecret,
        [property: JsonPropertyName("grantType")] string GrantType = "client_credentials"
    );

    public record SessionResponse(
        [property: JsonPropertyName("accessToken")] string AccessToken,
        [property: JsonPropertyName("expiresIn")] int ExpiresIn,
        [property: JsonPropertyName("refreshExpiresIn")] int? RefreshExpiresIn = null,
        [property: JsonPropertyName("refreshToken")] string? RefreshToken = null,
        [property: JsonPropertyName("tokenType")] string? TokenType = null
    );

    // ---------- Send OTP request/response that match Postman ----------
    public class SendOtpRequest
    {
        [JsonPropertyName("txnId")]
        public string? TxnId { get; set; }

        [JsonPropertyName("scope")]
        public string[] Scope { get; set; } = Array.Empty<string>();

        [JsonPropertyName("loginHint")]
        public string LoginHint { get; set; } = "aadhaar";

        // encrypted aadhaar base64
        [JsonPropertyName("loginId")]
        public string LoginId { get; set; } = string.Empty;

        [JsonPropertyName("otpSystem")]
        public string? OtpSystem { get; set; }
    }

    public class SendOtpResponse
    {
        [JsonPropertyName("txnId")]
        public string? TxnId { get; set; }

        [JsonPropertyName("message")]
        public string? Message { get; set; }
    }

    public record VerifyOtpRequest([property: JsonPropertyName("scope")] string[] Scope,
                                   [property: JsonPropertyName("auth")] AuthData AuthData);

    public record AuthData([property: JsonPropertyName("authMethods")] string[] AuthMethods,
                           [property: JsonPropertyName("otp")] OtpPayload Otp);

    public record OtpPayload([property: JsonPropertyName("txnId")] string TxnId,
                             [property: JsonPropertyName("otpValue")] string OtpValue,
                             [property: JsonPropertyName("mobile")] string? Mobile);


    public class CreateAbhaResponse
    {
        [JsonPropertyName("message")]
        public string? Message { get; set; }

        [JsonPropertyName("txnId")]
        public string? TxnId { get; set; }

        [JsonPropertyName("tokens")]
        public AbhaTokens? Tokens { get; set; }

        [JsonPropertyName("ABHAProfile")]
        public AbhaProfile? ABHAProfile { get; set; }

        [JsonPropertyName("isNew")]
        public bool IsNew { get; set; }
    }

    public class AbhaTokens
    {
        [JsonPropertyName("token")]
        public string? Token { get; set; }

        [JsonPropertyName("expiresIn")]
        public int? ExpiresIn { get; set; }

        [JsonPropertyName("refreshToken")]
        public string? RefreshToken { get; set; }

        [JsonPropertyName("refreshExpiresIn")]
        public int? RefreshExpiresIn { get; set; }
    }

    public class AbhaProfile
    {
        [JsonPropertyName("preferredAddress")]
        public string? PreferredAddress { get; set; }

        [JsonPropertyName("firstName")]
        public string? FirstName { get; set; }

        [JsonPropertyName("middleName")]
        public string? MiddleName { get; set; }

        [JsonPropertyName("lastName")]
        public string? LastName { get; set; }

        [JsonPropertyName("dob")]
        public string? Dob { get; set; }

        [JsonPropertyName("gender")]
        public string? Gender { get; set; }

        [JsonPropertyName("photo")]
        public string? PhotoBase64 { get; set; }

        [JsonPropertyName("mobile")]
        public string? Mobile { get; set; }

        [JsonPropertyName("mobileVerified")]
        public bool? MobileVerified { get; set; }

        [JsonPropertyName("email")]
        public string? Email { get; set; }

        [JsonPropertyName("phrAddress")]
        public string[]? PhrAddress { get; set; }

        [JsonPropertyName("address")]
        public string? Address { get; set; }

        [JsonPropertyName("districtCode")]
        public string? DistrictCode { get; set; }

        [JsonPropertyName("stateCode")]
        public string? StateCode { get; set; }

        [JsonPropertyName("pinCode")]
        public string? PinCode { get; set; }

        [JsonPropertyName("abhaType")]
        public string? AbhaType { get; set; }

        [JsonPropertyName("stateName")]
        public string? StateName { get; set; }

        [JsonPropertyName("districtName")]
        public string? DistrictName { get; set; }

        [JsonPropertyName("ABHANumber")]
        public string? ABHANumber { get; set; }

        [JsonPropertyName("abhaStatus")]
        public string? AbhaStatus { get; set; }
    }

    public class PublicCertResponse
    {
        [JsonPropertyName("publicKey")]
        public string PublicKey { get; set; } = "";

        [JsonPropertyName("encryptionAlgorithm")]
        public string? EncryptionAlgorithm { get; set; }   // e.g. "RSA/ECB/OAEPWithSHA-1AndMGF1Padding"
    }

    public class SendMobileOtpRequest
    {
        [JsonPropertyName("txnId")]
        public string? TxnId { get; set; } = ""; // ABHA will create if blank

        [JsonPropertyName("scope")]
        public string[]? Scope { get; set; }

        [JsonPropertyName("loginHint")]
        public string? LoginHint { get; set; }

        [JsonPropertyName("loginId")]
        public string? LoginId { get; set; } // encrypted mobile

        [JsonPropertyName("otpSystem")]
        public string? OtpSystem { get; set; }
    }

    // SendOtpResponse.cs
    public class SendOtpResponse_MobileUpdate
    {
        [JsonPropertyName("txnId")]
        public string? TxnId { get; set; }

        [JsonPropertyName("message")]
        public string? Message { get; set; }

        // Add other fields if ABHA returns more - keep minimal for now
    }

    public class MobileVerifyResponse
    {
        [JsonPropertyName("txnId")]
        public string? TxnId { get; set; }

        [JsonPropertyName("authResult")]
        public string? AuthResult { get; set; }

        [JsonPropertyName("message")]
        public string? Message { get; set; }

        [JsonPropertyName("accounts")]
        public MobileVerifyAccount[]? Accounts { get; set; }
    }

    public class MobileVerifyAccount
    {
        [JsonPropertyName("ABHANumber")]
        public string? ABHANumber { get; set; }
    }

    public class EmailVerificationRequest
    {
        [JsonPropertyName("scope")]
        public string[] Scope { get; set; } = new[] { "abha-profile", "email-link-verify" };

        [JsonPropertyName("loginHint")]
        public string LoginHint { get; set; } = "email";

        [JsonPropertyName("loginId")]
        public string? LoginId { get; set; } // encrypted email

        [JsonPropertyName("otpSystem")]
        public string OtpSystem { get; set; } = "abdm";
    }

    public class EmailVerificationResponse
    {
        [JsonPropertyName("txnId")]
        public string? TxnId { get; set; }

        [JsonPropertyName("message")]
        public string? Message { get; set; }
    }

    public class AbhaSuggestionRequest
    {
        [JsonPropertyName("txnId")]
        public string? TxnId { get; set; }
    }

    public class AbhaSuggestionResponse
    {
        [JsonPropertyName("txnId")]
        public string? TxnId { get; set; }

        [JsonPropertyName("abhaAddressList")]
        public List<string>? AbhaAddressList { get; set; }
    }

    public class AbhaAddressRequest
    {
        [JsonPropertyName("txnId")]
        public string? TxnId { get; set; }

        [JsonPropertyName("abhaAddress")]
        public string? AbhaAddress { get; set; }

        [JsonPropertyName("preferred")]
        public int Preferred { get; set; } = 1;
    }

    public class AbhaAddressResponse
    {
        [JsonPropertyName("txnId")]
        public string? TxnId { get; set; }

        [JsonPropertyName("healthIdNumber")]
        public string? HealthIdNumber { get; set; }

        [JsonPropertyName("preferredAbhaAddress")]
        public string? PreferredAbhaAddress { get; set; }
    }



    public class AbhaProfileResponse
    {
        [JsonPropertyName("ABHANumber")]
        public string? ABHANumber { get; set; }

        [JsonPropertyName("preferredAbhaAddress")]
        public string? PreferredAbhaAddress { get; set; }

        [JsonPropertyName("mobile")]
        public string? Mobile { get; set; }

        [JsonPropertyName("mobileVerified")]
        public bool? MobileVerified { get; set; }

        [JsonPropertyName("firstName")]
        public string? FirstName { get; set; }

        [JsonPropertyName("middleName")]
        public string? MiddleName { get; set; }

        [JsonPropertyName("lastName")]
        public string? LastName { get; set; }

        [JsonPropertyName("name")]
        public string? Name { get; set; }

        [JsonPropertyName("yearOfBirth")]
        public string? YearOfBirth { get; set; }

        [JsonPropertyName("dayOfBirth")]
        public string? DayOfBirth { get; set; }

        [JsonPropertyName("monthOfBirth")]
        public string? MonthOfBirth { get; set; }

        [JsonPropertyName("gender")]
        public string? Gender { get; set; }

        // Base64 image string
        [JsonPropertyName("profilePhoto")]
        public string? ProfilePhotoBase64 { get; set; }

        [JsonPropertyName("status")]
        public string? Status { get; set; }

        [JsonPropertyName("stateCode")]
        public string? StateCode { get; set; }

        [JsonPropertyName("districtCode")]
        public string? DistrictCode { get; set; }

        [JsonPropertyName("townCode")]
        public string? TownCode { get; set; }

        [JsonPropertyName("pincode")]
        public string? Pincode { get; set; }

        [JsonPropertyName("address")]
        public string? Address { get; set; }

        [JsonPropertyName("kycPhoto")]
        public string? KycPhotoBase64 { get; set; }

        [JsonPropertyName("stateName")]
        public string? StateName { get; set; }

        [JsonPropertyName("districtName")]
        public string? DistrictName { get; set; }

        [JsonPropertyName("subdistrictName")]
        public string? SubdistrictName { get; set; }

        [JsonPropertyName("townName")]
        public string? TownName { get; set; }

        [JsonPropertyName("authMethods")]
        public List<string>? AuthMethods { get; set; }

        [JsonPropertyName("tags")]
        public Dictionary<string, object>? Tags { get; set; }

        [JsonPropertyName("kycVerified")]
        public bool? KycVerified { get; set; }

        [JsonPropertyName("verificationStatus")]
        public string? VerificationStatus { get; set; }

        [JsonPropertyName("verificationType")]
        public string? VerificationType { get; set; }

        [JsonPropertyName("source")]
        public string? Source { get; set; }

        [JsonPropertyName("localizedDetails")]
        public LocalizedDetails? LocalizedDetails { get; set; }

        // keep raw string, helper below to parse to DateTime
        [JsonPropertyName("createdDate")]
        public string? CreatedDateRaw { get; set; }

        // Helper (not serialized) to parse created date if needed
        [JsonIgnore]
        public DateTime? CreatedDate
        {
            get
            {
                if (string.IsNullOrWhiteSpace(CreatedDateRaw)) return null;
                // expecting dd-MM-yyyy as in sample "07-10-2025"
                if (DateTime.TryParseExact(CreatedDateRaw, "dd-MM-yyyy", System.Globalization.CultureInfo.InvariantCulture,
                    System.Globalization.DateTimeStyles.None, out var dt))
                {
                    return dt;
                }
                // fallback
                if (DateTime.TryParse(CreatedDateRaw, out dt)) return dt;
                return null;
            }
        }

        // Helpers to convert base64 to bytes
        public byte[]? GetProfilePhotoBytes()
        {
            if (string.IsNullOrWhiteSpace(ProfilePhotoBase64)) return null;
            try { return Convert.FromBase64String(ProfilePhotoBase64); } catch { return null; }
        }

        public byte[]? GetKycPhotoBytes()
        {
            if (string.IsNullOrWhiteSpace(KycPhotoBase64)) return null;
            try { return Convert.FromBase64String(KycPhotoBase64); } catch { return null; }
        }
    }

    public class LocalizedDetails
    {
        [JsonPropertyName("name")]
        public string? Name { get; set; }

        [JsonPropertyName("stateName")]
        public string? StateName { get; set; }

        [JsonPropertyName("districtName")]
        public string? DistrictName { get; set; }

        [JsonPropertyName("villageName")]
        public string? VillageName { get; set; }

        [JsonPropertyName("wardName")]
        public string? WardName { get; set; }

        [JsonPropertyName("gender")]
        public string? Gender { get; set; }

        [JsonPropertyName("localizedLabels")]
        public Dictionary<string, string>? LocalizedLabels { get; set; }
    }

    public class AbhaCardFile
    {
        public byte[] Content { get; set; } = Array.Empty<byte>();
        public string? ContentType { get; set; }
        public string? FileName { get; set; }
    }

    /////////////////////////////////////////////////////////////////////////////////////////////

    public class SendAadhaarLoginOtpRequest
    {
        [JsonPropertyName("scope")]
        public string[] Scope { get; set; } = Array.Empty<string>();

        [JsonPropertyName("loginHint")]
        public string? LoginHint { get; set; }

        [JsonPropertyName("loginId")]
        public string? LoginId { get; set; }

        [JsonPropertyName("otpSystem")]
        public string? OtpSystem { get; set; }
    }

    public class SendOtpResponse_Login
    {
        [JsonPropertyName("txnId")]
        public string? TxnId { get; set; }

        [JsonPropertyName("message")]
        public string? Message { get; set; }

        //[JsonPropertyName("mobileLinked")]
        //public bool? MobileLinked { get; set; }

        // kuch extra fields aayen to bhi handle ho jaayega
        [JsonExtensionData]
        public Dictionary<string, JsonElement>? Extra { get; set; }
    }

    public class LoginVerifyOtpRequest
    {
        [JsonPropertyName("scope")]
        public string[] Scope { get; set; } = Array.Empty<string>();

        [JsonPropertyName("authData")]
        public LoginVerifyAuthData AuthData { get; set; } = new();
    }

    public class LoginVerifyAuthData
    {
        [JsonPropertyName("authMethods")]
        public string[] AuthMethods { get; set; } = Array.Empty<string>();

        [JsonPropertyName("otp")]
        public LoginVerifyOtpBlock Otp { get; set; } = new();
    }

    public class LoginVerifyOtpBlock
    {
        [JsonPropertyName("txnId")]
        public string? TxnId { get; set; }

        [JsonPropertyName("otpValue")]
        public string? OtpValue { get; set; }
    }

    //public class LoginVerifyOtpResponse
    //{
    //    [JsonPropertyName("token")]
    //    public string? Token { get; set; }

    //    [JsonPropertyName("expiresIn")]
    //    public int? ExpiresIn { get; set; }

    //    [JsonPropertyName("refreshToken")]
    //    public string? RefreshToken { get; set; }

    //    [JsonExtensionData]
    //    public Dictionary<string, JsonElement>? Extra { get; set; }
    //}

    public class LoginVerifyOtpResponse
    {
        [JsonPropertyName("txnId")]
        public string? TxnId { get; set; }

        [JsonPropertyName("authResult")]
        public string? AuthResult { get; set; }

        [JsonPropertyName("message")]
        public string? Message { get; set; }

        [JsonPropertyName("token")]
        public string? Token { get; set; }

        [JsonPropertyName("expiresIn")]
        public int? ExpiresIn { get; set; }

        [JsonPropertyName("refreshToken")]
        public string? RefreshToken { get; set; }

        [JsonPropertyName("refreshExpiresIn")]
        public int? RefreshExpiresIn { get; set; }

        [JsonPropertyName("accounts")]
        public List<LoginVerifyAccount>? Accounts { get; set; }

        // extra fields agar future me kuch aur aaye
        [JsonExtensionData]
        public Dictionary<string, JsonElement>? Extra { get; set; }
    }

    public class LoginVerifyAccount
    {
        [JsonPropertyName("ABHANumber")]
        public string? ABHANumber { get; set; }

        [JsonPropertyName("preferredAbhaAddress")]
        public string? PreferredAbhaAddress { get; set; }

        [JsonPropertyName("name")]
        public string? Name { get; set; }

        [JsonPropertyName("status")]
        public string? Status { get; set; }

        [JsonPropertyName("profilePhoto")]
        public string? ProfilePhoto { get; set; }
    }

}
