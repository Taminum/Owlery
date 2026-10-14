FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY migrations ./migrations
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/api ./cmd/api \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/mockpanel ./cmd/mockpanel \
 && mkdir /certs /state

FROM gcr.io/distroless/static-debian12:nonroot AS api
COPY --from=build /out/api /api
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/api"]

# Development only: two pretend Remnawave panels with their own CA. Not for production images.
FROM gcr.io/distroless/static-debian12:nonroot AS mockpanel
COPY --from=build /out/mockpanel /mockpanel
COPY --from=build --chown=65532:65532 /certs /certs
COPY --from=build --chown=65532:65532 /state /state
USER nonroot:nonroot
ENTRYPOINT ["/mockpanel"]
