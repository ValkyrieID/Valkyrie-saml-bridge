using System.Linq.Expressions;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using ValkyrieSamlBridge.Core.Apps;
using ValkyrieSamlBridge.Core.Metadata;
using ValkyrieSamlBridge.Core.Saml;
using ValkyrieSamlBridge.Data.Entities;

namespace ValkyrieSamlBridge.Data;

public sealed class AppStoreException(string message) : Exception(message);

// Settings the admin sets with `apps set`. Null values leave a setting unchanged.
public sealed record AppSettingsUpdate(
    bool? Enabled,
    string? NameIdClaim,
    string? NameIdFormat,
    IReadOnlyList<AttributeSettingInput>? Attributes,
    IReadOnlyList<string>? RelayStates,
    IReadOnlyList<string>? Scopes = null,
    bool ResetScopes = false);

public sealed record AttributeSettingInput(string Name, string Claim, bool Required);

public sealed class AppStore(BridgeDbContext db, TimeProvider time)
{
    public async Task<SamlApp> AddAsync(string slug, SpMetadata metadata, string source, CancellationToken cancellationToken)
    {
        if (!AppSlug.IsValid(slug))
        {
            throw new AppStoreException("The slug must be 1 to 64 characters: lowercase letters, digits, and inner hyphens.");
        }

        if (await db.Apps.AnyAsync(a => a.Slug == slug, cancellationToken))
        {
            throw new AppStoreException("An app with that slug already exists.");
        }

        if (await db.Apps.AnyAsync(a => a.EntityId == metadata.EntityId, cancellationToken))
        {
            throw new AppStoreException("An app with that entity ID is already registered.");
        }

        var now = time.GetUtcNow();
        var app = new SamlApp
        {
            Slug = slug,
            EntityId = metadata.EntityId,
            MetadataSource = source,
            RegisteredAt = now,
            AuthnRequestsSigned = metadata.AuthnRequestsSigned,
            AcsEndpoints = metadata.AcsEndpoints
                .Select(e => new SamlAppEndpoint { Location = e.Location, Index = e.Index, IsDefault = e.IsDefault })
                .ToList(),
            Certificates = metadata.SigningCertificates
                .Select(der => (Fingerprint: MetadataParser.Fingerprint(der), Der: der))
                .DistinctBy(c => c.Fingerprint)
                .Select(c => new SamlAppCertificate { Fingerprint = c.Fingerprint, Der = c.Der })
                .ToList(),
        };

        db.Apps.Add(app);

        await SaveAsync(cancellationToken);
        return app;
    }

    // The admin must type every fingerprint shown by `apps add`. The set has to match the stored
    // certificates exactly; a partial or extra fingerprint confirms nothing.
    public async Task ConfirmAsync(string slug, IReadOnlyCollection<string> fingerprints, CancellationToken cancellationToken)
    {
        var app = await db.Apps.Include(a => a.Certificates).FirstOrDefaultAsync(a => a.Slug == slug, cancellationToken)
            ?? throw new AppStoreException("No app with that slug.");

        var provided = fingerprints.Select(MetadataParser.NormalizeFingerprint).ToHashSet(StringComparer.Ordinal);
        var stored = app.Certificates.Select(c => c.Fingerprint).ToHashSet(StringComparer.Ordinal);
        if (!provided.SetEquals(stored) || provided.Count != fingerprints.Count)
        {
            throw new AppStoreException("The confirmed fingerprints do not match the app's signing certificates exactly. Nothing was confirmed.");
        }

        var now = time.GetUtcNow();
        foreach (var certificate in app.Certificates)
        {
            certificate.Confirmed = true;
            certificate.ConfirmedAt = now;
        }

        await SaveAsync(cancellationToken);
    }

    // Applies `apps set` changes. Each value is checked against the allow-lists before it's
    // stored, so an unknown claim is refused at configuration time.
    public async Task SetAsync(string slug, AppSettingsUpdate update, CancellationToken cancellationToken)
    {
        var app = await db.Apps.Include(a => a.AcsEndpoints).Include(a => a.Certificates)
            .Include(a => a.Attributes).Include(a => a.RelayStates)
            .FirstOrDefaultAsync(a => a.Slug == slug, cancellationToken)
            ?? throw new AppStoreException("No app with that slug.");

        var changes = new List<string>();
        if (update.Enabled is { } enabled && app.Enabled != enabled)
        {
            app.Enabled = enabled;
            changes.Add($"enabled={enabled}");
        }

        if (update.NameIdClaim is not null || update.NameIdFormat is not null)
        {
            var claim = update.NameIdClaim ?? app.NameIdClaim ?? throw new AppStoreException("Set --nameid-claim with --nameid-format.");
            var format = update.NameIdFormat ?? app.NameIdFormat ?? throw new AppStoreException("Set --nameid-format with --nameid-claim.");
            if (!ClaimMapper.IsValidClaimName(claim))
            {
                throw new AppStoreException("A claim name is 1 to 64 letters, digits, and underscores, and starts with a letter. Nothing was saved.");
            }
            if (!SamlNames.SupportedNameIdFormats.Contains(format, StringComparer.Ordinal))
            {
                throw new AppStoreException("The NameID format is not supported.");
            }
            app.NameIdClaim = claim;
            app.NameIdFormat = format;
            changes.Add($"nameId={claim}/{format}");
        }

        if (update.Attributes is { } attributes)
        {
            // Fail closed on ambiguity: a repeated name, even in another case, would make the app's attributes unclear.
            if (attributes.Select(a => a.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count() != attributes.Count)
            {
                throw new AppStoreException("Each attribute name must be unique. Nothing was saved.");
            }

            app.Attributes.Clear();
            foreach (var attribute in attributes)
            {
                if (!ClaimMapper.IsValidClaimName(attribute.Claim))
                {
                    throw new AppStoreException($"The claim '{attribute.Claim}' is not a valid claim name: 1 to 64 letters, digits, and underscores, starting with a letter. Nothing was saved.");
                }
                app.Attributes.Add(new SamlAppClaimMapping
                {
                    Name = attribute.Name,
                    Claim = attribute.Claim,
                    Required = attribute.Required,
                });
            }
            changes.Add($"attributes={attributes.Count}");
        }

        if (update.RelayStates is { } relayStates)
        {
            app.RelayStates.Clear();
            foreach (var value in relayStates.Distinct(StringComparer.Ordinal))
            {
                app.RelayStates.Add(new SamlAppRelayState { Value = value });
            }
            changes.Add($"relayStates={relayStates.Count}");
        }

        if (update.Scopes is { Count: > 0 } scopes)
        {
            var names = scopes.Distinct(StringComparer.Ordinal).ToList();
            if (names.Any(s => !ClaimMapper.IsValidScopeName(s)))
            {
                throw new AppStoreException("A scope is 1 to 64 letters, digits, underscores, hyphens, colons, or dots. Nothing was saved.");
            }
            app.RequestedScopes = string.Join(' ', names);
            changes.Add($"scopes={app.RequestedScopes}");
        }
        else if (update.ResetScopes)
        {
            app.RequestedScopes = null;
            changes.Add("scopes=default");
        }

        if (changes.Count == 0)
        {
            throw new AppStoreException("Nothing to change. Give at least one setting.");
        }

        // An app is enabled only when a response can actually be built for it. Disabling is always allowed.
        if (update.Enabled is true)
        {
            ValidateReadyToEnable(app);
        }

        await SaveAsync(cancellationToken);
    }

    // Hard delete. The app's rows and its pending logins go in one transaction, so an in-progress
    // login can't finish after removal.
    public async Task RemoveAsync(string slug, CancellationToken cancellationToken)
    {
        var app = await db.Apps.Include(a => a.AcsEndpoints).Include(a => a.Certificates)
            .Include(a => a.Attributes).Include(a => a.RelayStates)
            .FirstOrDefaultAsync(a => a.Slug == slug, cancellationToken)
            ?? throw new AppStoreException("No app with that slug.");

        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
        await db.PendingLogins.Where(p => p.AppEntityId == app.EntityId).ExecuteDeleteAsync(cancellationToken);

        db.Apps.Remove(app);

        await SaveAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
    }

    private static void ValidateReadyToEnable(SamlApp app)
    {
        if (app.AcsEndpoints.Count == 0)
        {
            throw new AppStoreException("Cannot enable the app: it has no AssertionConsumerService endpoint. Nothing was saved.");
        }
        if (app.NameIdClaim is null || app.NameIdFormat is null)
        {
            throw new AppStoreException("Cannot enable the app: set --nameid-claim and --nameid-format first. Nothing was saved.");
        }
        if (app.Certificates.Count == 0 || app.Certificates.Any(c => !c.Confirmed))
        {
            throw new AppStoreException("Cannot enable the app: every signing certificate must be confirmed first. Nothing was saved.");
        }
    }

    public Task<List<SamlApp>> ListAsync(CancellationToken cancellationToken) =>
        Query().OrderBy(a => a.Slug).ToListAsync(cancellationToken);

    public Task<SamlApp?> FindAsync(string slug, CancellationToken cancellationToken) =>
        Query().FirstOrDefaultAsync(a => a.Slug == slug, cancellationToken);

    // Loads the settings the SAML flows need, with only the confirmed signing certificates.
    public Task<AppRegistration?> FindRegistrationByEntityIdAsync(string entityId, CancellationToken cancellationToken) =>
        FindRegistrationAsync(a => a.EntityId == entityId, cancellationToken);

    public Task<AppRegistration?> FindRegistrationBySlugAsync(string slug, CancellationToken cancellationToken) =>
        FindRegistrationAsync(a => a.Slug == slug, cancellationToken);

    private async Task<AppRegistration?> FindRegistrationAsync(Expression<Func<SamlApp, bool>> match, CancellationToken cancellationToken)
    {
        var app = await db.Apps.AsNoTracking()
            .Include(a => a.AcsEndpoints)
            .Include(a => a.Certificates)
            .Include(a => a.Attributes)
            .Include(a => a.RelayStates)
            .FirstOrDefaultAsync(match, cancellationToken);
        if (app is null)
        {
            return null;
        }

        var nameId = app.NameIdClaim is { } claim && app.NameIdFormat is { } format
            ? new NameIdSetting(claim, format)
            : (NameIdSetting?)null;

        return new AppRegistration(
            Slug: app.Slug,
            EntityId: app.EntityId,
            Enabled: app.Enabled,
            AuthnRequestsSigned: app.AuthnRequestsSigned,
            AcsEndpoints: app.AcsEndpoints.Select(e => new AppAcsEndpoint(e.Location, e.Index, e.IsDefault)).ToList(),
            ConfirmedSigningCertificates: app.Certificates.Where(c => c.Confirmed).Select(c => c.Der).ToList(),
            NameId: nameId,
            Attributes: app.Attributes.Select(a => new AttributeSetting(a.Name, a.Claim, a.Required)).ToList(),
            RelayStates: app.RelayStates.Select(r => r.Value).ToList(),
            RequestedScopes: app.RequestedScopes);
    }

    public static string NormalizeFingerprint(string value) => MetadataParser.NormalizeFingerprint(value);


    private IQueryable<SamlApp> Query() =>
        db.Apps.AsNoTracking()
            .Include(a => a.AcsEndpoints)
            .Include(a => a.Certificates)
            .Include(a => a.Attributes)
            .Include(a => a.RelayStates);

    private async Task SaveAsync(CancellationToken cancellationToken)
    {
        try
        {
            await db.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateException)
        {
            // Unique indexes catch races between two admins; report that without leaking detail.
            throw new AppStoreException("The change conflicts with an existing app. Nothing was saved.");
        }
    }
}

// Pending logins are single use: Take marks the row consumed and returns it, so a second callback with the
// same cookie finds nothing. Consumed rows stay until they expire, so their AuthnRequest IDs stay blocked.
public sealed class PendingLoginStore(BridgeDbContext db, TimeProvider time)
{
    public async Task<bool> PutAsync(PendingLogin login, CancellationToken cancellationToken)
    {
        db.PendingLogins.Add(login);
        try
        {
            await db.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateException error) when (error.InnerException is SqliteException { SqliteErrorCode: 19 })
        {
            // The unique RequestId index: another pending login already uses this AuthnRequest ID.
            db.ChangeTracker.Clear();
            return false;
        }
        db.ChangeTracker.Clear();
        return true;
    }

    public async Task<PendingLogin?> TakeAsync(string id, CancellationToken cancellationToken)
    {
        var nowMs = time.GetUtcNow().ToUnixTimeMilliseconds();
        // Only one caller flips Consumed, so only one caller gets the record.
        var consumed = await db.PendingLogins.Where(p => p.Id == id && !p.Consumed && p.ExpiresAtUnixMs >= nowMs)
            .ExecuteUpdateAsync(s => s.SetProperty(p => p.Consumed, true), cancellationToken);
        if (consumed != 1)
        {
            return null;
        }
        return await db.PendingLogins.AsNoTracking().FirstOrDefaultAsync(p => p.Id == id, cancellationToken);
    }

    // The silent retry reuses a consumed row, since its AuthnRequest ID is still in the unique index. It
    // gets the new OIDC values and becomes pending again.
    public async Task<bool> ResumeAsync(PendingLogin login, CancellationToken cancellationToken)
    {
        var resumed = await db.PendingLogins.Where(p => p.Id == login.Id && p.Consumed)
            .ExecuteUpdateAsync(s => s
                .SetProperty(p => p.OidcState, login.OidcState)
                .SetProperty(p => p.Nonce, login.Nonce)
                .SetProperty(p => p.CodeVerifier, login.CodeVerifier)
                .SetProperty(p => p.SilentAttemptPending, false)
                .SetProperty(p => p.Consumed, false), cancellationToken);
        return resumed == 1;
    }

    public Task<int> PurgeExpiredAsync(CancellationToken cancellationToken)
    {
        var nowMs = time.GetUtcNow().ToUnixTimeMilliseconds();
        return db.PendingLogins.Where(p => p.ExpiresAtUnixMs < nowMs).ExecuteDeleteAsync(cancellationToken);
    }
}



