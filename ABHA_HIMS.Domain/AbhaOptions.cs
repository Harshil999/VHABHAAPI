namespace ABHA_HIMS.Domain
{
    public class AbhaOptions
    {
        public string BaseUrl { get; set; } = "https://abhasbx.abdm.gov.in/abha/api";
        public string SessionUrl { get; set; } = "https://dev.abdm.gov.in/api/hiecm/gateway/v3/sessions";
        public string PublicCertUrl { get; set; } = "https://abhasbx.abdm.gov.in/abha/api/v3/profile/public/certificate";
        public string ClientId { get; set; } = "SBXID_010330";
        public string ClientSecret { get; set; } = "a22927a9-3a4f-4974-b99f-597ba4bc0251";
        public string GrantType { get; set; } = "client_credentials";
        public string? XCMID { get; set; } = "sbx";
        public string MobileUpdateSendOtpPath { get; set; } = "";
    }
}
