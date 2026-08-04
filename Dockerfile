FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/envbank ./cmd/envbank
RUN mkdir -p /data && chown 65532:65532 /data

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/envbank /envbank
COPY --from=build --chown=65532:65532 /data /data
USER 65532:65532
VOLUME ["/data"]
EXPOSE 7337
ENTRYPOINT ["/envbank"]
CMD ["serve", "--listen", "0.0.0.0:7337", "--state", "/data/server.json"]
