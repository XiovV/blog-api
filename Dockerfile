FROM golang:1.19.4-alpine3.17 as build

WORKDIR /go/src/app
COPY . .

RUN go mod download

RUN cd /go/src/app/cmd && CGO_ENABLED=0 go build -o /go/bin/app

FROM gcr.io/distroless/static-debian11

COPY --from=build /go/bin/app /
COPY --from=build /go/src/app/rbac /rbac
CMD ["/app"]