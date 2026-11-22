# Optional Container Deployment for Digital Connect+ Server (.NET 10)
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY src/DigitalConnectPlus.Server/DigitalConnectPlus.Server.csproj src/DigitalConnectPlus.Server/
RUN dotnet restore src/DigitalConnectPlus.Server/DigitalConnectPlus.Server.csproj
COPY src/DigitalConnectPlus.Server/ src/DigitalConnectPlus.Server/
RUN dotnet publish src/DigitalConnectPlus.Server/DigitalConnectPlus.Server.csproj -c Release -o /app/publish /p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:10.0
WORKDIR /app
COPY --from=build /app/publish .
VOLUME ["/data"]
ENV DCP_DATA_DIR=/data
ENV LISTEN_INTERFACE=0.0.0.0
ENV PORT=8443
ENV TLS_MODE=ReverseProxyHttp
EXPOSE 8443
ENTRYPOINT ["dotnet", "DigitalConnectPlus.Server.dll"]
