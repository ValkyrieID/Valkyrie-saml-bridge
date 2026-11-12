using Microsoft.EntityFrameworkCore;

namespace ValkyrieSamlBridge.Integration.Tests;

public sealed class MigrationTests : IDisposable
{
    private readonly TempDatabase _database = new();

    public void Dispose() => _database.Dispose();

    [Fact]
    public async Task AFreshDatabaseMigratesToTheCurrentModel()
    {
        await using var db = _database.OpenDbContext();

        await db.Database.MigrateAsync(TestContext.Current.CancellationToken);

        Assert.Empty(await db.Database.GetPendingMigrationsAsync(TestContext.Current.CancellationToken));
        Assert.Equal(0, await db.Apps.CountAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task TheAuditTableIsGone()
    {
        await using var db = _database.OpenDbContext();

        await db.Database.MigrateAsync(TestContext.Current.CancellationToken);

        var tables = await db.Database.SqlQuery<string>($"SELECT name FROM sqlite_master WHERE type = 'table'").ToListAsync(TestContext.Current.CancellationToken);
        Assert.DoesNotContain("AuditEntries", tables);
        Assert.Contains("Apps", tables);
    }
}
