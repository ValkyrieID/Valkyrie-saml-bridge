using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using ValkyrieSamlBridge.Core.Configuration;
using ValkyrieSamlBridge.Core.OpenIdConnect;
using ValkyrieSamlBridge.Core.Saml;
using ValkyrieSamlBridge.Core.Security;
using ValkyrieSamlBridge.Data;
using ValkyrieSamlBridge.Web.Cli;
using ValkyrieSamlBridge.Web.Sso;

if (args.Length > 0 && args[0] is "apps" or "keys")
{
    return await CliApp.RunAsync(args);
}

// All configuration comes from environment variables only. CreateBuilder reads appsettings*.json and the command-line
// arguments while it is constructed, and clearing the sources afterwards has no effect. So the builder starts with no defaults,
// and only the environment and the defaults the bridge needs are added back.
var builder = WebApplication.CreateEmptyBuilder(new WebApplicationOptions());
builder.Configuration.AddEnvironmentVariables();
builder.Configuration.AddEnvironmentVariables(prefix: "ASPNETCORE_");
builder.WebHost.UseKestrelCore();
builder.Services.AddRoutingCore();
builder.Logging.AddConfiguration(builder.Configuration.GetSection("Logging"));
builder.Logging.AddConsole();
builder.Logging.AddFilter("Microsoft.AspNetCore", LogLevel.Warning);
// Read at startup, so a missing or malformed key stops the host before it serves requests. Only the environment is read.
builder.Services.AddSingleton(MasterKey.FromEnvironment());

var bridge = BridgeSettings.ParseBridge(BridgeSettings.ReadPublicUrl());
var oidc = BridgeSettings.ParseOidc(
    BridgeSettings.ReadIssuer(),
    BridgeSettings.ReadClientId(),
    BridgeSettings.ReadClientSecret(),
    new Uri(bridge.CallbackUrl));

var databasePath = BridgeSettings.ResolveDatabasePath(BridgeSettings.ReadDatabase());
builder.Services.AddDbContext<BridgeDbContext>(options =>
    options.UseSqlite(new SqliteConnectionStringBuilder { DataSource = databasePath }.ToString()));

builder.Services.AddSingleton(bridge);
builder.Services.AddSingleton(oidc);
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton<SigningIdentity>();
builder.Services.AddHostedService<BridgeStartup>();
builder.Services.AddHostedService<PendingLoginCleanupService>();

builder.Services.AddHttpClient("oidc");
builder.Services.AddSingleton(sp => new OidcClient(
    sp.GetRequiredService<IHttpClientFactory>().CreateClient("oidc"),
    sp.GetRequiredService<OidcClientOptions>(),
    sp.GetRequiredService<TimeProvider>(),
    sp.GetRequiredService<BridgeOptions>().ClockSkew));

builder.Services.AddScoped<AppStore>();
builder.Services.AddScoped<PendingLoginStore>();
builder.Services.AddScoped<SigningKeyStore>();
builder.Services.AddScoped(sp => new ResponseBuilder(
    sp.GetRequiredService<SigningIdentity>().Certificate,
    sp.GetRequiredService<BridgeOptions>(),
    sp.GetRequiredService<TimeProvider>()));
builder.Services.AddScoped<SpSsoService>();
builder.Services.AddScoped<IdpSsoService>();
builder.Services.AddScoped<LoginCallbackService>();

var app = builder.Build();

app.Use(async (context, next) =>
{
    context.Response.OnStarting(() =>
    {
        var headers = context.Response.Headers;
        headers["X-Content-Type-Options"] = "nosniff";
        headers["X-Frame-Options"] = "DENY";
        headers["Referrer-Policy"] = "no-referrer";
        headers["Cache-Control"] = "no-store";
        headers["Cross-Origin-Resource-Policy"] = "same-origin";
        if (!headers.ContainsKey("Content-Security-Policy"))
        {
            headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'";
        }
        return Task.CompletedTask;
    });
    await next();
});

app.MapGet("/healthz", () => Results.Ok());
app.MapSamlEndpoints();

app.Run();

return 0;

public partial class Program { }
