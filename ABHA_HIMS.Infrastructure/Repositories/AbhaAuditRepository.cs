using Dapper;
using System.Data;
using ABHA_HIMS.Application.Interfaces; // add this if missing

namespace ABHA_HIMS.Infrastructure.Repositories
{
    public class AbhaAuditRepository : IAbhaAuditRepository
    {
        private readonly IDbConnection _conn;
        public AbhaAuditRepository(IDbConnection conn) => _conn = conn;

        public Task LogRequestAsync(string endpoint, string requestBody, string responseBody, string txnId)
        {
            var p = new DynamicParameters();
            p.Add("@Endpoint", endpoint);
            p.Add("@RequestBody", requestBody);
            p.Add("@ResponseBody", responseBody);
            p.Add("@TxnId", txnId);

            // stored proc name - change to your actual proc
            return _conn.ExecuteAsync("sp_Abha_Audit_Insert", p, commandType: CommandType.StoredProcedure);
        }
    }
}
