using System.Net.Http.Headers;
using Polly;
using Polly.Extensions.Http;
using ABHA_HIMS.Infrastructure.DI;
using ABHA_HIMS.Infrastructure.Abha;
using ABHA_HIMS.Application.External;
using ABHA_HIMS.Application.Services;
using Microsoft.OpenApi.Models;
using ABHA_HIMS.Domain;
using ABHA_HIMS.Application.Interfaces;

var builder = WebApplication.CreateBuilder(args);

// --- Configuration & Options ---
builder.Services.Configure<AbhaOptions>(builder.Configuration.GetSection("Abha"));

// --- Memory cache (for token/publicKey caching) ---
builder.Services.AddMemoryCache();

// --- Helper: Polly retry policy ---
static IAsyncPolicy<HttpResponseMessage> GetRetryPolicy()
{
    return HttpPolicyExtensions
        .HandleTransientHttpError()
        .WaitAndRetryAsync(new[]
        {
            TimeSpan.FromSeconds(1),
            TimeSpan.FromSeconds(2),
            TimeSpan.FromSeconds(3)
        });
}

// --- Register typed HttpClient implementing the application interface ---
// This wires ABHA_HIMS.Application.External.IAbhaHttpClient -> ABHA_HIMS.Infrastructure.Abha.AbhaHttpClient
builder.Services.AddHttpClient<IAbhaHttpClient, AbhaHttpClient>(client =>
{
    var baseUrl = builder.Configuration["Abha:BaseUrl"] ?? throw new InvalidOperationException("Abha:BaseUrl not configured");
    client.BaseAddress = new Uri(baseUrl);
    client.Timeout = TimeSpan.FromSeconds(30);
    client.DefaultRequestHeaders.Accept.Clear();
    client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
})
.AddPolicyHandler(GetRetryPolicy());

// (Optional) keep a generic named client if other parts need it
builder.Services.AddHttpClient("AbhaClient", client =>
{
    client.Timeout = TimeSpan.FromSeconds(60);
    client.DefaultRequestHeaders.Accept.Clear();
    client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
});

// --- Register infrastructure wiring (IDbConnection, repos etc) ---
builder.Services.AddInfrastructure(builder.Configuration);

// --- Register application services ---
// AbhaGatewayService (in Infrastructure) implementing IAbhaGatewayService
builder.Services.AddScoped<IAbhaGatewayService, AbhaGatewayService>();

// AbhaService (application-level service) implementing IAbhaService
builder.Services.AddScoped<IAbhaService, AbhaService>();

// NOTE: AbhaAuditRepository is already registered inside AddInfrastructure — avoid duplicate registrations
// If you registered it separately earlier, it's okay but not required here.

// --- Controllers, Swagger, JSON options ---
builder.Services.AddControllers()
    .AddJsonOptions(o => { o.JsonSerializerOptions.PropertyNamingPolicy = null; });

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "ABHA_HIMS API", Version = "v1" });
});

// Health checks
builder.Services.AddHealthChecks();

var app = builder.Build();

try
{
    var opt = app.Services.GetRequiredService<Microsoft.Extensions.Options.IOptions<ABHA_HIMS.Domain.AbhaOptions>>().Value;
    Console.WriteLine($"[DEBUG] Abha.BaseUrl = {opt.BaseUrl}");
    Console.WriteLine($"[DEBUG] Abha.SessionUrl = {opt.SessionUrl}");
    Console.WriteLine($"[DEBUG] Abha.PublicCertUrl = {opt.PublicCertUrl}");
    Console.WriteLine($"[DEBUG] Abha.ClientId = {(string.IsNullOrWhiteSpace(opt.ClientId) ? "<EMPTY>" : opt.ClientId)}");
    var masked = string.IsNullOrWhiteSpace(opt.ClientSecret) ? "<EMPTY>" : (opt.ClientSecret.Length <= 4 ? opt.ClientSecret : opt.ClientSecret.Substring(0, 4) + "****");
    Console.WriteLine($"[DEBUG] Abha.ClientSecret (masked) = {masked}");
}
catch (Exception ex)
{
    Console.WriteLine("[DEBUG] Failed to read AbhaOptions: " + ex.Message);
}

// Middlewares
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c => c.SwaggerEndpoint("/swagger/v1/swagger.json", "ABHA_HIMS API v1"));
}

app.UseHttpsRedirection();

// Correlation ID middleware (optional)
app.Use(async (ctx, next) =>
{
    if (!ctx.Request.Headers.ContainsKey("X-Correlation-ID"))
        ctx.Request.Headers["X-Correlation-ID"] = Guid.NewGuid().ToString();
    ctx.Response.Headers["X-Correlation-ID"] = ctx.Request.Headers["X-Correlation-ID"];
    await next();
});

app.UseAuthorization();

app.MapHealthChecks("/health");
app.MapControllers();

app.Run();



//BELOW DEFAULT CODE
//var builder = WebApplication.CreateBuilder(args);

//// Add services to the container.

//builder.Services.AddControllers();
//// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
//builder.Services.AddEndpointsApiExplorer();
//builder.Services.AddSwaggerGen();

//var app = builder.Build();

//// Configure the HTTP request pipeline.
//if (app.Environment.IsDevelopment())
//{
//    app.UseSwagger();
//    app.UseSwaggerUI();
//}

//app.UseHttpsRedirection();

//app.UseAuthorization();

//app.MapControllers();

//app.Run();
