FROM --platform=$BUILDPLATFORM golang:1.26 AS builder

ARG TARGETOS TARGETARCH

COPY . /go/src/app
WORKDIR /go/src/app

RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -o app

RUN git log -1 --oneline > version.txt

FROM alpine:latest
WORKDIR /root/
COPY --from=builder /go/src/app/app .
COPY --from=builder /go/src/app/version.txt .

EXPOSE 80 443 8080

ENTRYPOINT ["./app"]
