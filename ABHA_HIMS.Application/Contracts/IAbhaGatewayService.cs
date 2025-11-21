using ABHA_HIMS.Domain;
using System.Text.Json;
using System.Threading.Tasks;
using static ABHA_HIMS.Domain.AbhaDtos;

namespace ABHA_HIMS.Application.Interfaces
{
    public interface IAbhaGatewayService
    {
        Task<SessionResponse> GetSessionTokenAsync();
        Task<SessionResponse> GetSessionTokenAsync(string clientId, string clientSecret);
        Task<PublicCertResponse> GetPublicKeyAsync();
        Task<SendOtpResponse?> SendOtpAsync(SendOtpRequest req);
        Task<CreateAbhaResponse?> CreateAbhaByAadhaarAsync(object reqBody);
        Task<SendOtpResponse_MobileUpdate?> CreateMobileUpdateOtpAsync(SendMobileOtpRequest req);
        Task<MobileVerifyResponse?> VerifyMobileUpdateOtpAsync(object reqBody);
        Task<EmailVerificationResponse?> SendEmailVerificationLinkAsync(EmailVerificationRequest req, string? authToken, string? xToken);
        Task<AbhaSuggestionResponse?> GetAbhaSuggestionsAsync(string txnId);
        Task<AbhaAddressResponse?> PostAbhaAddressAsync(AbhaAddressRequest request);
        Task<AbhaProfileResponse?> GetProfileDetailsAsync(string txnId, string xtoken);
        Task<AbhaCardFile?> GetAbhaCardAsync(string xToken);
        Task<SendOtpResponse_Login?> CreateAadhaarLoginOtpAsync(SendAadhaarLoginOtpRequest request);
        Task<LoginVerifyOtpResponse?> VerifyAadhaarLoginOtpAsync(LoginVerifyOtpRequest request);
        Task<SendOtpResponse_Login?> CreateAbhaNumberAadhaarOtpAsync(SendAadhaarLoginOtpRequest request);
        Task<LoginVerifyOtpResponse?> VerifyAbhaNumberAadhaarOtpAsync(LoginVerifyOtpRequest request);
        Task<SendOtpResponse_Login?> CreateAbhaNumberAbhaOtpAsync(SendAadhaarLoginOtpRequest request);
        Task<LoginVerifyOtpResponse?> VerifyAbhaNumberAbhaOtpAsync(LoginVerifyOtpRequest request);
        Task<SendOtpResponse_Login?> CreateMobileLoginOtpAsync(SendAadhaarLoginOtpRequest request);
        Task<LoginVerifyOtpResponse?> VerifyMobileLoginOtpAsync(LoginVerifyOtpRequest request);
    }
}
