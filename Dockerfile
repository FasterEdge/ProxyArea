# ---- Build stage ----
FROM golang:1.24-alpine AS build

WORKDIR /src

# 缓存依赖
COPY go.mod ./
RUN go mod download

COPY . .

# CGO_ENABLED=0 保证静态二进制, GOOS=linux 避免在 Alpine 上需要 musl 之外的 libc
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags='-s -w' -o /out/proxyarea .

# ---- Runtime stage ----
# alpine:latest 会随上游漂移导致不可复现构建; 固定 minor 版本。
FROM alpine:3.21

RUN apk --no-cache add ca-certificates wget && \
    addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup

WORKDIR /app

COPY --from=build /out/proxyarea ./proxyarea

RUN chmod +x proxyarea && \
    chown -R appuser:appgroup /app

USER appuser

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/ || exit 1

ENTRYPOINT ["./proxyarea"]
CMD ["--addr=:8080"]