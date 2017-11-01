#FROM microsoft/aspnetcore:2.0
#ARG source
#WORKDIR /app
#EXPOSE 80
#COPY ${source:-obj/Docker/publish} .
#ENTRYPOINT ["dotnet", "AspNetCoreLinux.dll"]



FROM microsoft/aspnetcore-build:latest AS build-env
WORKDIR /app

# Copy csproj and restore as distinct layers
# This makes it faster as docker can see if things changed for this step.
COPY *.csproj ./
RUN dotnet restore

# Copy everything else and build
COPY . ./
RUN dotnet publish -c Release -o out

# Build runtime image
FROM microsoft/aspnetcore:latest
WORKDIR /app

# Configure the listening port
ARG APP_PORT=5000
ENV ASPNETCORE_URLS http://*:$APP_PORT
EXPOSE $APP_PORT

COPY --from=build-env /app/out .
ENTRYPOINT ["dotnet", "api.dll"]