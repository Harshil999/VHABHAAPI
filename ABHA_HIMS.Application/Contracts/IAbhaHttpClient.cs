using ABHA_HIMS.Domain;
using System.Text.Json;
using System.Threading.Tasks;
using static ABHA_HIMS.Domain.AbhaDtos;

namespace ABHA_HIMS.Application.External
{
    // keep it minimal — only methods your service needs
    public interface IAbhaHttpClient
    {
        Task<SessionResponse> GetSessionAsync(string clientId, string clientSecret);
        Task<PublicCertResponse> GetPublicKeyAsync(string accessToken);
        Task<SendOtpResponse?> SendOtpAsync(SendOtpRequest req, string accessToken);
        Task<CreateAbhaResponse?> CreateAbhaByAadhaarAsync(object reqBody, string accessToken);
        Task<SendOtpResponse_MobileUpdate?> CreateMobileUpdateOtpAsync(SendMobileOtpRequest reqBody, string accessToken);
        Task<MobileVerifyResponse?> CreateMobileUpdateVerifyOtpAsync(object reqBody, string accessToken);
        Task<EmailVerificationResponse?> SendEmailVerificationLinkAsync(EmailVerificationRequest reqBody, string? authToken, string? xToken);
        Task<AbhaSuggestionResponse?> GetAbhaSuggestionsAsync(string txnId, string authToken);
        Task<AbhaAddressResponse?> PostAbhaAddressAsync(AbhaAddressRequest request, string accessToken);
        Task<AbhaProfileResponse?> GetProfileDetailsAsync(string txnId, string authToken, string xToken);
        Task<AbhaCardFile?> GetAbhaCardAsync(string xToken, string accessToken);
        Task<SendOtpResponse_Login?> CreateAadhaarLoginOtpAsync(SendAadhaarLoginOtpRequest request, string accessToken);
        Task<LoginVerifyOtpResponse?> VerifyAadhaarLoginOtpAsync(LoginVerifyOtpRequest request, string accessToken);
        Task<SendOtpResponse_Login?> CreateAbhaNumberAadhaarOtpAsync(SendAadhaarLoginOtpRequest request, string accessToken);
        Task<LoginVerifyOtpResponse?> VerifyAbhaNumberAadhaarOtpAsync(LoginVerifyOtpRequest request, string accessToken);
        Task<SendOtpResponse_Login?> CreateAbhaNumberAbhaOtpAsync(SendAadhaarLoginOtpRequest request, string accessToken);
        Task<LoginVerifyOtpResponse?> VerifyAbhaNumberAbhaOtpAsync(LoginVerifyOtpRequest request, string accessToken);
        Task<SendOtpResponse_Login?> CreateMobileLoginOtpAsync(SendAadhaarLoginOtpRequest request, string accessToken);
        Task<LoginVerifyOtpResponse?> VerifyMobileLoginOtpAsync(LoginVerifyOtpRequest request, string accessToken);
    }
}
