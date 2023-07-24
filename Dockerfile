FROM golang:1.20 as builder

WORKDIR /go/src/trivy-extractor

# pre-copy/cache go.mod for pre-downloading dependencies and only redownloading them in subsequent builds if they change
COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY data ./data
COPY internal ./internal
COPY main.go .

RUN CGO_ENABLED=0 go build -o trivy-extractor


FROM  gcr.io/distroless/static:nonroot
COPY --from=builder /go/src/trivy-extractor/trivy-extractor /usr/bin/trivy-extractor

USER 65532:65532

CMD [ "/usr/bin/trivy-extractor" ]
