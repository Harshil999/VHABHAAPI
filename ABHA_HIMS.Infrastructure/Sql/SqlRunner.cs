using Dapper;
using System.Collections.Generic;
using System.Data;

namespace ABHA_HIMS.Infrastructure.Sql
{
    public interface ISqlRunner
    {
        Task<T?> QuerySingleAsync<T>(string sp, DynamicParameters p, IDbTransaction? tx = null);
        Task<IEnumerable<T>> QueryAsync<T>(string sp, DynamicParameters p, IDbTransaction? tx = null);
        Task<int> ExecuteAsync(string sp, DynamicParameters p, IDbTransaction? tx = null);
    }

    public class SqlRunner : ISqlRunner
    {
        private readonly IDbConnection _conn;
        public SqlRunner(IDbConnection conn) => _conn = conn;

        public Task<T?> QuerySingleAsync<T>(string sp, DynamicParameters p, IDbTransaction? tx = null)
            => _conn.QueryFirstOrDefaultAsync<T>(sp, p, tx, commandType: CommandType.StoredProcedure);

        public Task<IEnumerable<T>> QueryAsync<T>(string sp, DynamicParameters p, IDbTransaction? tx = null)
            => _conn.QueryAsync<T>(sp, p, tx, commandType: CommandType.StoredProcedure);

        public Task<int> ExecuteAsync(string sp, DynamicParameters p, IDbTransaction? tx = null)
            => _conn.ExecuteAsync(sp, p, tx, commandType: CommandType.StoredProcedure);
    }
}
