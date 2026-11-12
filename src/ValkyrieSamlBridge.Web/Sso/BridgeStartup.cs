using System.Security.Cryptography.X509Certificates;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using ValkyrieSamlBridge.Core.Configuration;
using ValkyrieSamlBridge.Core.OpenIdConnect;
using ValkyrieSamlBridge.Data;

namespace ValkyrieSamlBridge.Web.Sso;

// Only Certificate signs. Published has the active certificate first, then the inactive ones.
public sealed class SigningIdentity
{
    private X509Certificate2? _certificate;
    private IReadOnlyList<byte[]>? _published;

    public X509Certificate2 Certificate => _certificate ?? throw new InvalidOperationException("The signing key is not loaded yet.");

    public IReadOnlyList<byte[]> Published => _published ?? throw new InvalidOperationException("The signing key is not loaded yet.");

    public void Set(SigningKeySet keys)
    {
        _certificate = keys.Active;
        _published = keys.Published;
    }
}

// Runs before the host starts listening: applies the SQLite migrations, loads or creates the
// signing key, and checks the OIDC provider's discovery document. A failure here stops the host, so the bridge never
// serves without a key or a valid provider (fail closed).
public sealed class BridgeStartup(IServiceProvider services, SigningIdentity identity, BridgeOptions options, OidcClient oidc) : IHostedService
{
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        await using var scope = services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<BridgeDbContext>();
        await db.Database.MigrateAsync(cancellationToken);
        var keys = scope.ServiceProvider.GetRequiredService<SigningKeyStore>();
        identity.Set(await keys.LoadOrCreateAsync(options.PublicUrl.Host, cancellationToken));
        await oidc.CheckDiscoveryAsync(cancellationToken);
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}

