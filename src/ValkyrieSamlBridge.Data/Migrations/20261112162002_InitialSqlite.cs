using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ValkyrieSamlBridge.Data.Migrations;

/// <inheritdoc />
public partial class _20261112162002_InitialSqlite : Migration
{
    /// <inheritdoc />
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.CreateTable(
            name: "Apps",
            columns: table => new
            {
                Id = table.Column<int>(type: "INTEGER", nullable: false)
                    .Annotation("Sqlite:Autoincrement", true),
                Slug = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                EntityId = table.Column<string>(type: "TEXT", maxLength: 2048, nullable: false),
                MetadataSource = table.Column<string>(type: "TEXT", maxLength: 2048, nullable: false),
                RegisteredAt = table.Column<DateTimeOffset>(type: "TEXT", nullable: false),
                Enabled = table.Column<bool>(type: "INTEGER", nullable: false),
                AuthnRequestsSigned = table.Column<bool>(type: "INTEGER", nullable: false),
                NameIdClaim = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                NameIdFormat = table.Column<string>(type: "TEXT", maxLength: 256, nullable: true),
                RequestedScopes = table.Column<string>(type: "TEXT", maxLength: 256, nullable: true)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_Apps", x => x.Id);
            });

        migrationBuilder.CreateTable(
            name: "PendingLogins",
            columns: table => new
            {
                Id = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                Consumed = table.Column<bool>(type: "INTEGER", nullable: false),
                Flow = table.Column<string>(type: "TEXT", maxLength: 16, nullable: false, defaultValue: "sp-initiated"),
                AppEntityId = table.Column<string>(type: "TEXT", nullable: false),
                AcsUrl = table.Column<string>(type: "TEXT", maxLength: 2048, nullable: false),
                RequestId = table.Column<string>(type: "TEXT", maxLength: 256, nullable: true),
                RelayState = table.Column<string>(type: "TEXT", maxLength: 512, nullable: true),
                OidcState = table.Column<string>(type: "TEXT", nullable: false),
                Nonce = table.Column<string>(type: "TEXT", nullable: false),
                CodeVerifier = table.Column<string>(type: "TEXT", nullable: false),
                SilentAttemptPending = table.Column<bool>(type: "INTEGER", nullable: false),
                IsPassive = table.Column<bool>(type: "INTEGER", nullable: false),
                ForceAuthn = table.Column<bool>(type: "INTEGER", nullable: false),
                RequestedClasses = table.Column<string>(type: "TEXT", nullable: false),
                RequestedComparison = table.Column<string>(type: "TEXT", nullable: true),
                CreatedAt = table.Column<DateTimeOffset>(type: "TEXT", nullable: false),
                ExpiresAtUnixMs = table.Column<long>(type: "INTEGER", nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_PendingLogins", x => x.Id);
            });

        migrationBuilder.CreateTable(
            name: "SigningKeys",
            columns: table => new
            {
                Id = table.Column<int>(type: "INTEGER", nullable: false)
                    .Annotation("Sqlite:Autoincrement", true),
                KeyId = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                CreatedAt = table.Column<DateTimeOffset>(type: "TEXT", nullable: false),
                Active = table.Column<bool>(type: "INTEGER", nullable: false),
                EncryptedPrivateKey = table.Column<byte[]>(type: "BLOB", nullable: false),
                CertificateDer = table.Column<byte[]>(type: "BLOB", nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_SigningKeys", x => x.Id);
            });

        migrationBuilder.CreateTable(
            name: "SamlAppCertificate",
            columns: table => new
            {
                Id = table.Column<int>(type: "INTEGER", nullable: false)
                    .Annotation("Sqlite:Autoincrement", true),
                SamlAppId = table.Column<int>(type: "INTEGER", nullable: false),
                Fingerprint = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                Der = table.Column<byte[]>(type: "BLOB", nullable: false),
                Confirmed = table.Column<bool>(type: "INTEGER", nullable: false),
                ConfirmedAt = table.Column<DateTimeOffset>(type: "TEXT", nullable: true)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_SamlAppCertificate", x => x.Id);
                table.ForeignKey(
                    name: "FK_SamlAppCertificate_Apps_SamlAppId",
                    column: x => x.SamlAppId,
                    principalTable: "Apps",
                    principalColumn: "Id",
                    onDelete: ReferentialAction.Cascade);
            });

        migrationBuilder.CreateTable(
            name: "SamlAppClaimMapping",
            columns: table => new
            {
                Id = table.Column<int>(type: "INTEGER", nullable: false)
                    .Annotation("Sqlite:Autoincrement", true),
                SamlAppId = table.Column<int>(type: "INTEGER", nullable: false),
                Name = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                Claim = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                Required = table.Column<bool>(type: "INTEGER", nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_SamlAppClaimMapping", x => x.Id);
                table.ForeignKey(
                    name: "FK_SamlAppClaimMapping_Apps_SamlAppId",
                    column: x => x.SamlAppId,
                    principalTable: "Apps",
                    principalColumn: "Id",
                    onDelete: ReferentialAction.Cascade);
            });

        migrationBuilder.CreateTable(
            name: "SamlAppEndpoint",
            columns: table => new
            {
                Id = table.Column<int>(type: "INTEGER", nullable: false)
                    .Annotation("Sqlite:Autoincrement", true),
                SamlAppId = table.Column<int>(type: "INTEGER", nullable: false),
                Location = table.Column<string>(type: "TEXT", maxLength: 2048, nullable: false),
                Index = table.Column<int>(type: "INTEGER", nullable: false),
                IsDefault = table.Column<bool>(type: "INTEGER", nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_SamlAppEndpoint", x => x.Id);
                table.ForeignKey(
                    name: "FK_SamlAppEndpoint_Apps_SamlAppId",
                    column: x => x.SamlAppId,
                    principalTable: "Apps",
                    principalColumn: "Id",
                    onDelete: ReferentialAction.Cascade);
            });

        migrationBuilder.CreateTable(
            name: "SamlAppRelayState",
            columns: table => new
            {
                Id = table.Column<int>(type: "INTEGER", nullable: false)
                    .Annotation("Sqlite:Autoincrement", true),
                SamlAppId = table.Column<int>(type: "INTEGER", nullable: false),
                Value = table.Column<string>(type: "TEXT", maxLength: 512, nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_SamlAppRelayState", x => x.Id);
                table.ForeignKey(
                    name: "FK_SamlAppRelayState_Apps_SamlAppId",
                    column: x => x.SamlAppId,
                    principalTable: "Apps",
                    principalColumn: "Id",
                    onDelete: ReferentialAction.Cascade);
            });

        migrationBuilder.CreateIndex(
            name: "IX_Apps_EntityId",
            table: "Apps",
            column: "EntityId",
            unique: true);

        migrationBuilder.CreateIndex(
            name: "IX_Apps_Slug",
            table: "Apps",
            column: "Slug",
            unique: true);

        migrationBuilder.CreateIndex(
            name: "IX_PendingLogins_ExpiresAtUnixMs",
            table: "PendingLogins",
            column: "ExpiresAtUnixMs");

        migrationBuilder.CreateIndex(
            name: "IX_PendingLogins_RequestId",
            table: "PendingLogins",
            column: "RequestId",
            unique: true);

        migrationBuilder.CreateIndex(
            name: "IX_SamlAppCertificate_SamlAppId_Fingerprint",
            table: "SamlAppCertificate",
            columns: new[] { "SamlAppId", "Fingerprint" },
            unique: true);

        migrationBuilder.CreateIndex(
            name: "IX_SamlAppClaimMapping_SamlAppId_Name",
            table: "SamlAppClaimMapping",
            columns: new[] { "SamlAppId", "Name" },
            unique: true);

        migrationBuilder.CreateIndex(
            name: "IX_SamlAppEndpoint_SamlAppId_Index",
            table: "SamlAppEndpoint",
            columns: new[] { "SamlAppId", "Index" },
            unique: true);

        migrationBuilder.CreateIndex(
            name: "IX_SamlAppRelayState_SamlAppId_Value",
            table: "SamlAppRelayState",
            columns: new[] { "SamlAppId", "Value" },
            unique: true);

        migrationBuilder.CreateIndex(
            name: "IX_SigningKeys_KeyId",
            table: "SigningKeys",
            column: "KeyId",
            unique: true);
    }

    /// <inheritdoc />
    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropTable(
            name: "PendingLogins");

        migrationBuilder.DropTable(
            name: "SamlAppCertificate");

        migrationBuilder.DropTable(
            name: "SamlAppClaimMapping");

        migrationBuilder.DropTable(
            name: "SamlAppEndpoint");

        migrationBuilder.DropTable(
            name: "SamlAppRelayState");

        migrationBuilder.DropTable(
            name: "SigningKeys");

        migrationBuilder.DropTable(
            name: "Apps");
    }
}
