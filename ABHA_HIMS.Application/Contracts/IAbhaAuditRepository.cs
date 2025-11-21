using System.Threading.Tasks;

namespace ABHA_HIMS.Application.Interfaces
{
    public interface IAbhaAuditRepository
    {
        Task LogRequestAsync(string endpoint, string requestBody, string responseBody, string txnId);
    }
}
