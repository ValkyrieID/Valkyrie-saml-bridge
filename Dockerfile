# syntax=docker/dockerfile:1

FROM mcr.microsoft.com/dotnet/sdk:11.0.100 AS build
WORKDIR /src
COPY .editorconfig global.json Directory.Build.props Directory.Packages.props ./
COPY src ./src
RUN dotnet publish src/ValkyrieSamlBridge.Web/ValkyrieSamlBridge.Web.csproj \
        --configuration Release \
        --output /app \
        -p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:11.0 AS runtime
WORKDIR /app
COPY --from=build /app .
RUN printf '#!/bin/sh\nexec dotnet /app/ValkyrieSamlBridge.Web.dll "$@"\n' > /usr/local/bin/admin \
    && chmod 755 /usr/local/bin/admin

# The database lives on a volume so it survives container replacement.
# The operator must pass these at run time (see docs/docker.md). The image has no defaults for them, and the container
# refuses to start when one is missing or invalid:
#   SAMLBRIDGE_MASTER_KEY, SAMLBRIDGE_PUBLIC_URL, SAMLBRIDGE_OIDC_ISSUER, SAMLBRIDGE_OIDC_CLIENT_ID, SAMLBRIDGE_OIDC_CLIENT_SECRET
# Only the non-secret defaults below are set here.
ENV ASPNETCORE_URLS=http://+:8080 \
    ASPNETCORE_ENVIRONMENT=Production \
    SAMLBRIDGE_DATABASE=/data/saml-bridge.db
RUN mkdir /data && chown app:app /data
VOLUME ["/data"]
USER app
EXPOSE 8080

ENTRYPOINT ["dotnet", "ValkyrieSamlBridge.Web.dll"]
