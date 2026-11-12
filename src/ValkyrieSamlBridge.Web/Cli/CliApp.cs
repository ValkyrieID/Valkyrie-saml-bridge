using System.CommandLine;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using ValkyrieSamlBridge.Core.Configuration;
using ValkyrieSamlBridge.Core.Metadata;
using ValkyrieSamlBridge.Core.Saml;
using ValkyrieSamlBridge.Core.Security;
using ValkyrieSamlBridge.Data;
using ValkyrieSamlBridge.Data.Entities;

namespace ValkyrieSamlBridge.Web.Cli;

public static class CliApp
{
    public const string DatabaseVariable = "SAMLBRIDGE_DATABASE";

    // Runs the CLI. Settings come from environment variables only. An argument that names the master key or the
    // client secret is refused before parsing, with or without "=" and in any case, so the value is never echoed by the parser
    // or printed.
    public static Task<int> RunAsync(string[] args)
    {
        if (args.Any(NamesSecret))
        {
            Console.Error.WriteLine("The master key and client secret are read from environment variables only. Set them in the environment, not on the command line.");
            return Task.FromResult(1);
        }
        return Build().Parse(args).InvokeAsync();
    }

    private static readonly string[] SecretVariables = [MasterKey.EnvironmentVariable, BridgeSettings.ClientSecretVariable];

    // Matches "--NAME", "--NAME=value", and a bare "NAME", where NAME is a secret variable name in any case.
    private static bool NamesSecret(string argument)
    {
        var name = argument.TrimStart('-');
        var equals = name.IndexOf('=');
        if (equals >= 0)
        {
            name = name[..equals];
        }
        return SecretVariables.Any(secret => string.Equals(name, secret, StringComparison.OrdinalIgnoreCase));
    }

    private static RootCommand Build()
    {
        var root = new RootCommand("admin: administration");
        var apps = new Command("apps", "Register and inspect SAML apps");
        apps.Subcommands.Add(BuildAdd());
        apps.Subcommands.Add(BuildConfirm());
        apps.Subcommands.Add(BuildList());
        apps.Subcommands.Add(BuildShow());
        apps.Subcommands.Add(BuildSet());
        apps.Subcommands.Add(BuildDisable());
        apps.Subcommands.Add(BuildRemove());
        root.Subcommands.Add(apps);
        root.Subcommands.Add(BuildKeys());
        return root;
    }

    // `keys rotate` and `keys retire`. Both need the master key to be set, because the key store is built with it.
    // Neither creates the database: a missing file is an error, so no empty database appears.
    private static Command BuildKeys()
    {
        var keys = new Command("keys", "Rotate and retire the bridge signing key");
        keys.Subcommands.Add(BuildRotate());
        keys.Subcommands.Add(BuildRetire());
        return keys;
    }

    private static Command BuildRotate()
    {
        var command = new Command("rotate", "Create a new signing key and make it active. The old certificate stays published until `keys retire`. The bridge must be restarted to sign with the new key.");
        command.SetAction((_, cancellationToken) => Guard(async () =>
        {
            var bridge = ParseBridge();
            using var masterKey = ReadMasterKey();
            await using var db = OpenExistingDatabase();
            await db.Database.MigrateAsync(cancellationToken);
            var rotated = await new SigningKeyStore(db, masterKey, TimeProvider.System).RotateAsync(bridge.PublicUrl.Host, cancellationToken);

            Console.WriteLine($"Created signing key {rotated.KeyId} (SHA-256 {Display(MetadataParser.Fingerprint(rotated.CertificateDer))}). It is active from the next start of the bridge.");
            Console.WriteLine("Restart the bridge now. The running bridge keeps signing with the old key until it restarts.");
            Console.WriteLine("After the restart, /saml/metadata lists the new certificate first and the old one after it. Check that both are there.");
            Console.WriteLine("Give the new certificate to each SP and wait until every SP trusts it. Then run: admin keys retire");
            return 0;
        }));
        return command;
    }

    private static Command BuildRetire()
    {
        var command = new Command("retire", "Delete every inactive signing key. The active key is never deleted. Restart the bridge afterwards so /saml/metadata stops listing the retired certificates.");
        command.SetAction((_, cancellationToken) => Guard(async () =>
        {
            using var masterKey = ReadMasterKey();
            await using var db = OpenExistingDatabase();
            await db.Database.MigrateAsync(cancellationToken);
            var retired = await new SigningKeyStore(db, masterKey, TimeProvider.System).RetireInactiveAsync(cancellationToken);

            Console.WriteLine($"Retired {retired.Count} inactive signing key(s): {string.Join(", ", retired)}.");
            Console.WriteLine("Restart the bridge so /saml/metadata stops listing the retired certificates. Only the active key remains.");
            return 0;
        }));
        return command;
    }

    private static BridgeOptions ParseBridge()
    {
        try
        {
            return BridgeSettings.ParseBridge(BridgeSettings.ReadPublicUrl());
        }
        catch (InvalidOperationException error)
        {
            throw new CliException(error.Message);
        }
    }

    private static MasterKey ReadMasterKey()
    {
        try
        {
            return MasterKey.FromEnvironment();
        }
        catch (InvalidOperationException error)
        {
            throw new CliException(error.Message);
        }
    }

    private static BridgeDbContext OpenExistingDatabase()
    {
        ExistingDatabasePath();
        return OpenDatabase();
    }

    // A missing file is an error, so no empty database appears.
    private static string ExistingDatabasePath()
    {
        var path = BridgeSettings.ResolveDatabasePath(BridgeSettings.ReadDatabase());
        if (!File.Exists(path))
        {
            throw new CliException("The database file does not exist. Start the bridge once to create it.");
        }
        return path;
    }

    private static Command BuildAdd()
    {
        var slug = new Option<string>("--slug") { Description = "Short name for the app, e.g. payroll", Required = true };
        var metadata = new Option<FileInfo>("--metadata") { Description = "SP metadata XML file", Required = true };

        var command = new Command("add", "Register an app from its metadata and show the certificate fingerprints");
        command.Options.Add(slug);
        command.Options.Add(metadata);
        command.SetAction((result, cancellationToken) => Guard(async () =>
        {
            var (xml, source) = await ReadFileAsync(result.GetValue(metadata)!, cancellationToken);

            var parsed = MetadataParser.Parse(xml);
            await using var db = OpenDatabase();
            await db.Database.MigrateAsync(cancellationToken);
            var app = await new AppStore(db, TimeProvider.System).AddAsync(result.GetValue(slug)!, parsed, source, cancellationToken);

            Console.WriteLine($"Registered '{app.Slug}' ({app.EntityId}).");
            Console.WriteLine("Confirm each signing certificate fingerprint (SHA-256) against the app vendor's documentation:");
            foreach (var certificate in app.Certificates)
            {
                Console.WriteLine($"  {Display(certificate.Fingerprint)}");
            }
            Console.WriteLine($"Then run: admin apps confirm {app.Slug} --fingerprint <fingerprint> (once per certificate)");
            return 0;
        }));
        return command;
    }

    private static Command BuildConfirm()
    {
        var slug = new Argument<string>("slug") { Description = "App slug" };
        var fingerprint = new Option<string[]>("--fingerprint") { Description = "A fingerprint from `apps add`; repeat for each certificate", Required = true };

        var command = new Command("confirm", "Record that the admin checked the signing certificate fingerprints");
        command.Arguments.Add(slug);
        command.Options.Add(fingerprint);
        command.SetAction((result, cancellationToken) => Guard(async () =>
        {
            await using var db = OpenDatabase();
            await db.Database.MigrateAsync(cancellationToken);
            await new AppStore(db, TimeProvider.System).ConfirmAsync(
                result.GetValue(slug)!, result.GetValue(fingerprint)!, cancellationToken);
            Console.WriteLine($"Confirmed the fingerprints for '{result.GetValue(slug)}'.");
            return 0;
        }));
        return command;
    }

    private static Command BuildList()
    {
        var command = new Command("list", "List registered apps");
        command.SetAction((_, cancellationToken) => Guard(async () =>
        {
            await using var db = OpenDatabase();
            await db.Database.MigrateAsync(cancellationToken);
            var apps = await new AppStore(db, TimeProvider.System).ListAsync(cancellationToken);
            foreach (var app in apps)
            {
                Console.WriteLine($"{app.Slug}\t{(app.Enabled ? "enabled" : "disabled")}\t{Confirmed(app)}\t{app.EntityId}");
            }
            return 0;
        }));
        return command;
    }

    private static Command BuildShow()
    {
        var slug = new Argument<string>("slug") { Description = "App slug" };

        var command = new Command("show", "Show one registered app");
        command.Arguments.Add(slug);
        command.SetAction((result, cancellationToken) => Guard(async () =>
        {
            await using var db = OpenDatabase();
            await db.Database.MigrateAsync(cancellationToken);
            var app = await new AppStore(db, TimeProvider.System).FindAsync(result.GetValue(slug)!, cancellationToken)
                ?? throw new CliException("No app with that slug.");

            Console.WriteLine($"Slug: {app.Slug}");
            Console.WriteLine($"Entity ID: {app.EntityId}");
            Console.WriteLine($"Source: {app.MetadataSource}");
            Console.WriteLine($"Registered: {app.RegisteredAt:O}");
            Console.WriteLine($"Enabled: {app.Enabled}");
            Console.WriteLine($"Scopes: {app.RequestedScopes ?? "default (openid, plus profile and email as the claims need)"}");
            Console.WriteLine("ACS endpoints:");
            foreach (var endpoint in app.AcsEndpoints.OrderBy(e => e.Index))
            {
                Console.WriteLine($"  [{endpoint.Index}]{(endpoint.IsDefault ? " default" : "")} {endpoint.Location}");
            }
            Console.WriteLine("Signing certificates:");
            foreach (var certificate in app.Certificates)
            {
                var state = certificate.Confirmed ? $"confirmed {certificate.ConfirmedAt:O}" : "not confirmed";
                Console.WriteLine($"  {Display(certificate.Fingerprint)} ({state})");
            }
            return 0;
        }));
        return command;
    }

    private static string Confirmed(SamlApp app) =>
        app.Certificates.All(c => c.Confirmed) && app.Certificates.Count > 0 ? "confirmed" : "unconfirmed";

    private static Command BuildSet()
    {
        var slug = new Argument<string>("slug") { Description = "App slug" };
        var nameIdClaim = new Option<string>("--nameid-claim") { Description = "OIDC claim for the NameID, e.g. sub" };
        var nameIdFormat = new Option<string>("--nameid-format") { Description = "NameID format: persistent, transient, unspecified, or email" };
        var attribute = new Option<string[]>("--attribute") { Description = "name=claim[,required]; repeat for each attribute. Replaces the attribute list when given." };
        var relayState = new Option<string[]>("--relay-state") { Description = "A RelayState value an IdP-initiated login may use; repeat for each. Replaces the list when given." };
        var scope = new Option<string[]>("--scope") { Description = "A scope the bridge requests from the OIDC provider for this app: letters, digits, underscores, hyphens, colons, or dots; 1 to 64 characters. Repeat for each. Replaces the list when given. Without it, the default is used." };
        var defaultScopes = new Option<bool>("--default-scopes") { Description = "Return the app to the default scope list" };
        var enable = new Option<bool>("--enable") { Description = "Enable the app for SSO. Refused unless the app has a NameID claim and format, a default ACS endpoint, and every signing certificate confirmed." };
        var disable = new Option<bool>("--disable") { Description = "Disable the app" };

        var command = new Command("set", "Set NameID, attributes, RelayState values, and enabled state for an app");
        command.Arguments.Add(slug);
        command.Options.Add(nameIdClaim);
        command.Options.Add(nameIdFormat);
        command.Options.Add(attribute);
        command.Options.Add(relayState);
        command.Options.Add(scope);
        command.Options.Add(defaultScopes);
        command.Options.Add(enable);
        command.Options.Add(disable);
        command.SetAction((result, cancellationToken) => Guard(async () =>
        {
            var enabled = result.GetValue(enable);
            var disabled = result.GetValue(disable);
            if (enabled && disabled)
            {
                throw new CliException("Give either --enable or --disable, not both.");
            }
            var resetScopes = result.GetValue(defaultScopes);
            if (resetScopes && result.GetValue(scope) is { Length: > 0 })
            {
                throw new CliException("Give either --scope or --default-scopes, not both.");
            }

            var claim = result.GetValue(nameIdClaim);
            if (claim is not null && ClaimMapper.MutableClaims.Contains(claim))
            {
                Console.WriteLine($"Warning: '{claim}' can change at the OIDC provider. A change makes the app see a new user.");
            }

            var attributes = result.GetValue(attribute) is { Length: > 0 } attributeValues ? attributeValues.Select(ParseAttribute).ToList() : null;
            var update = new AppSettingsUpdate(
                Enabled: enabled ? true : disabled ? false : null,
                NameIdClaim: claim,
                NameIdFormat: result.GetValue(nameIdFormat) is { } format ? ParseNameIdFormat(format) : null,
                Attributes: attributes,
                RelayStates: result.GetValue(relayState) is { Length: > 0 } relayValues ? relayValues.ToList() : null,
                Scopes: result.GetValue(scope) is { Length: > 0 } scopeValues ? scopeValues.ToList() : null,
                ResetScopes: resetScopes);

            await using var db = OpenDatabase();
            await db.Database.MigrateAsync(cancellationToken);
            await new AppStore(db, TimeProvider.System).SetAsync(result.GetValue(slug)!, update, cancellationToken);
            Console.WriteLine($"Updated '{result.GetValue(slug)}'.");
            return 0;
        }));
        return command;
    }

    // `apps disable <slug>` is `apps set <slug> --disable`: both call AppStore.SetAsync with the same update.
    private static Command BuildDisable()
    {
        var slug = new Argument<string>("slug") { Description = "App slug" };

        var command = new Command("disable", "Turn SSO off for an app. Same as `apps set <slug> --disable`");
        command.Arguments.Add(slug);
        command.SetAction((result, cancellationToken) => Guard(async () =>
        {
            await using var db = OpenDatabase();
            await db.Database.MigrateAsync(cancellationToken);
            await new AppStore(db, TimeProvider.System).SetAsync(result.GetValue(slug)!, new AppSettingsUpdate(Enabled: false, NameIdClaim: null, NameIdFormat: null, Attributes: null, RelayStates: null), cancellationToken);
            Console.WriteLine($"Updated '{result.GetValue(slug)}'.");
            return 0;
        }));
        return command;
    }

    private static Command BuildRemove()
    {
        var slug = new Argument<string>("slug") { Description = "App slug" };

        var command = new Command("remove", "Delete an app and its settings, and remove its pending logins.");
        command.Arguments.Add(slug);
        command.SetAction((result, cancellationToken) => Guard(async () =>
        {
            await using var db = OpenDatabase();
            await db.Database.MigrateAsync(cancellationToken);
            await new AppStore(db, TimeProvider.System).RemoveAsync(result.GetValue(slug)!, cancellationToken);
            Console.WriteLine($"Removed '{result.GetValue(slug)}'.");
            return 0;
        }));
        return command;
    }

    private static AttributeSettingInput ParseAttribute(string value)
    {
        var equals = value.IndexOf('=');
        if (equals <= 0)
        {
            throw new CliException("--attribute must look like name=claim[,required].");
        }

        var name = value[..equals];
        var parts = value[(equals + 1)..].Split(',', StringSplitOptions.TrimEntries);
        var claim = parts[0];
        var required = parts.Contains("required", StringComparer.Ordinal);
        return new AttributeSettingInput(name, claim, required);
    }

    private static string ParseNameIdFormat(string value) => value switch
    {
        "persistent" => SamlNames.NameIdPersistent,
        "transient" => SamlNames.NameIdTransient,
        "unspecified" => SamlNames.NameIdUnspecified,
        "email" => SamlNames.NameIdEmail,
        _ => throw new CliException("--nameid-format must be persistent, transient, unspecified, or email."),
    };

    private static async Task<(string Xml, string Source)> ReadFileAsync(FileInfo file, CancellationToken cancellationToken)
    {
        if (!file.Exists)
        {
            throw new CliException("The metadata file does not exist.");
        }
        if (file.Length > MetadataParser.MaxBytes)
        {
            throw new CliException("The metadata file is too large.");
        }
        return (await File.ReadAllTextAsync(file.FullName, cancellationToken), file.Name);
    }

    private static BridgeDbContext OpenDatabase()
    {
        var path = BridgeSettings.ResolveDatabasePath(BridgeSettings.ReadDatabase());
        var connection = new SqliteConnectionStringBuilder { DataSource = path }.ToString();
        return new BridgeDbContext(new DbContextOptionsBuilder<BridgeDbContext>().UseSqlite(connection).Options);
    }

    private static string Display(string fingerprint) => string.Join(':', fingerprint.Chunk(2).Select(p => new string(p)));

    private static async Task<int> Guard(Func<Task<int>> action)
    {
        try
        {
            return await action();
        }
        catch (CliException error)
        {
            Console.Error.WriteLine(error.Message);
        }
        catch (MetadataException error)
        {
            Console.Error.WriteLine(error.Message);
        }
        catch (AppStoreException error)
        {
            Console.Error.WriteLine(error.Message);
        }
        catch (SigningKeyException error)
        {
            Console.Error.WriteLine(error.Message);
        }
        return 1;
    }

    private sealed class CliException(string message) : Exception(message);
}
