using ABHA_HIMS.Domain;
using System.Text.Json;
using System.Threading.Tasks;
using static ABHA_HIMS.Domain.AbhaDtos;

namespace ABHA_HIMS.Application.Interfaces
{
    // keep it minimal — only methods your service needs
    public interface IAbhaService
    {
        Task<SessionResponse> GetSessionAsync(); // config-based
        Task<SessionResponse> GetSessionAsync(string clientId, string clientSecret); // explicit
        Task<PublicCertResponse> GetPublicKeyAsync();
        Task<SendOtpResponse?> SendOtpAsync(string aadhaarPlain); // changed to accept plain aadhaar for simplicity
        Task<CreateAbhaResponse?> CreateAbhaAsync(object reqBody);
        Task<SendOtpResponse_MobileUpdate?> SendMobileUpdateOtpAsync(string mobilePlain, string? txnId = null);
        Task<MobileVerifyResponse?> VerifyMobileUpdateOtpAsync(string txnId, string otpPlainOrEncrypted);
        Task<EmailVerificationResponse?> SendEmailVerificationLinkAsync(string emailPlain, string? authToken, string? xToken);
        Task<AbhaSuggestionResponse?> GetAbhaSuggestionsAsync(string txnId);
        Task<AbhaAddressResponse?> PostAbhaAddressAsync(AbhaAddressRequest request);
        Task<AbhaProfileResponse?> GetProfileDetailsAsync(string txnId, string xToken);
        Task<AbhaCardFile?> GetAbhaCardAsync(string xToken);

        ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

        Task<SendOtpResponse_Login?> SendAadhaarLoginOtpAsync(string aadhaarPlain);
        Task<LoginVerifyOtpResponse?> VerifyAadhaarLoginOtpAsync(string txnId, string otpPlain);
        Task<SendOtpResponse_Login?> SendAbhaNumberAadhaarOtpAsync(string abhaNumberPlain);
        Task<LoginVerifyOtpResponse?> VerifyAbhaNumberAadhaarOtpAsync(string txnId, string otpPlain);
        Task<SendOtpResponse_Login?> SendAbhaNumberAbhaOtpAsync(string abhaNumberPlain);
        Task<LoginVerifyOtpResponse?> VerifyAbhaNumberAbhaOtpAsync(string txnId, string otpPlain);
        Task<SendOtpResponse_Login?> SendMobileLoginOtpAsync(string mobilePlain);
        Task<LoginVerifyOtpResponse?> VerifyMobileLoginOtpAsync(string txnId, string otpPlain);
    }
}
