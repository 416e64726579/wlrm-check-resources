FROM golang:1.13-alpine as builder

RUN apk add --no-cache git

WORKDIR /go/src/wlrm-check-resources
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN GO111MODULE=on CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -installsuffix cgo -ldflags '-w -extldflags "-static"' -o wlrm .

FROM alpine:3.18.6
LABEL version=0.3
LABEL wlrm=check
ENV WALLARM_API='api.wallarm.com' \
    USER_UID=1001

WORKDIR /etc/wlrm
COPY --from=builder /go/src/wlrm-check-resources/wlrm /bin/wlrm
COPY --from=builder /go/src/wlrm-check-resources/domains.conf /etc/wlrm/domains.conf

USER ${USER_UID}
CMD ["wlrm"]