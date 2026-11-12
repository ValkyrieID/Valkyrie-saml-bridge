using Microsoft.EntityFrameworkCore;
using ValkyrieSamlBridge.Data.Entities;

namespace ValkyrieSamlBridge.Data;

public sealed class BridgeDbContext(DbContextOptions<BridgeDbContext> options) : DbContext(options)
{
    public DbSet<SamlApp> Apps => Set<SamlApp>();
    public DbSet<SigningKey> SigningKeys => Set<SigningKey>();
    public DbSet<PendingLogin> PendingLogins => Set<PendingLogin>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<SamlApp>(app =>
        {
            app.HasIndex(a => a.Slug).IsUnique();
            app.HasIndex(a => a.EntityId).IsUnique();
            app.Property(a => a.Slug).HasMaxLength(64);
            app.Property(a => a.EntityId).HasMaxLength(2048);
            app.Property(a => a.MetadataSource).HasMaxLength(2048);
            app.Property(a => a.NameIdClaim).HasMaxLength(64);
            app.Property(a => a.NameIdFormat).HasMaxLength(256);
            app.Property(a => a.RequestedScopes).HasMaxLength(256);
            app.HasMany(a => a.AcsEndpoints).WithOne().HasForeignKey(e => e.SamlAppId).OnDelete(DeleteBehavior.Cascade);
            app.HasMany(a => a.Certificates).WithOne().HasForeignKey(c => c.SamlAppId).OnDelete(DeleteBehavior.Cascade);
            app.HasMany(a => a.Attributes).WithOne().HasForeignKey(a => a.SamlAppId).OnDelete(DeleteBehavior.Cascade);
            app.HasMany(a => a.RelayStates).WithOne().HasForeignKey(r => r.SamlAppId).OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<SamlAppClaimMapping>(attribute =>
        {
            attribute.HasIndex(a => new { a.SamlAppId, a.Name }).IsUnique();
            attribute.Property(a => a.Name).HasMaxLength(256);
            attribute.Property(a => a.Claim).HasMaxLength(64);
        });

        modelBuilder.Entity<SamlAppRelayState>(relay =>
        {
            relay.HasIndex(r => new { r.SamlAppId, r.Value }).IsUnique();
            relay.Property(r => r.Value).HasMaxLength(512);
        });

        modelBuilder.Entity<PendingLogin>(login =>
        {
            login.HasKey(p => p.Id);
            login.Property(p => p.Id).HasMaxLength(64);
            login.Property(p => p.Flow).HasMaxLength(16).HasDefaultValue(LoginFlows.SpInitiated);
            login.Property(p => p.AcsUrl).HasMaxLength(2048);
            login.Property(p => p.RequestId).HasMaxLength(256);
            login.Property(p => p.RelayState).HasMaxLength(512);
            login.HasIndex(p => p.ExpiresAtUnixMs);
            // Null for IdP-initiated logins. A unique index on the rest makes a second pending login for one AuthnRequest fail.
            login.HasIndex(p => p.RequestId).IsUnique();
        });

        modelBuilder.Entity<SamlAppEndpoint>(endpoint =>
        {
            endpoint.HasIndex(e => new { e.SamlAppId, e.Index }).IsUnique();
            endpoint.Property(e => e.Location).HasMaxLength(2048);
        });

        modelBuilder.Entity<SamlAppCertificate>(certificate =>
        {
            certificate.HasIndex(c => new { c.SamlAppId, c.Fingerprint }).IsUnique();
            certificate.Property(c => c.Fingerprint).HasMaxLength(64);
        });

        modelBuilder.Entity<SigningKey>(key =>
        {
            key.HasIndex(k => k.KeyId).IsUnique();
            key.Property(k => k.KeyId).HasMaxLength(64);
        });
    }
}


