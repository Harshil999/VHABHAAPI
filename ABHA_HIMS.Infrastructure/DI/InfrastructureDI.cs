using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Data;
using ABHA_HIMS.Infrastructure.Sql;
using ABHA_HIMS.Infrastructure.Repositories;
using ABHA_HIMS.Application.Interfaces;

namespace ABHA_HIMS.Infrastructure.DI
{
    public static class InfrastructureDI
    {
        public static IServiceCollection AddInfrastructure(this IServiceCollection services, IConfiguration config)
        {
            var connStr = config.GetConnectionString("HimsDb")
                          ?? throw new InvalidOperationException("Connection string 'HimsDb' not found.");

            // register IDbConnection as scoped (new SqlConnection per request)
            services.AddScoped<IDbConnection>(_ => new SqlConnection(connStr));

            // register SqlRunner & repositories (namespaces above)
            services.AddScoped<ISqlRunner, SqlRunner>();
            services.AddScoped<IAbhaAuditRepository, AbhaAuditRepository>();

            return services;
        }
    }
}
