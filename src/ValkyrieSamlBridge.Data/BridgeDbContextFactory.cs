using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace ValkyrieSamlBridge.Data;

// Used by `dotnet ef` to create migrations. The runtime path comes from SAMLBRIDGE_DATABASE.
public sealed class BridgeDbContextFactory : IDesignTimeDbContextFactory<BridgeDbContext>
{
    public BridgeDbContext CreateDbContext(string[] args) =>
        new(new DbContextOptionsBuilder<BridgeDbContext>()
            .UseSqlite("Data Source=saml-bridge-design.db")
            .Options);
}
