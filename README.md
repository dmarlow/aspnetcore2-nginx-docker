# aspnetcore2-nginx-docker

Simple ASP.NET Core 2 behind nginx using docker.

## Build

`docker build -t api ./api` to build the *api*

`docker build -t nginx ./nginx` to build the *api*

## Run
`docker-compose up`

## Profit
`http://localhost:5100/api/values`

Refresh a few times to see the "Machine=<Hostname>" change values as it hits different API instances behind proxy.
