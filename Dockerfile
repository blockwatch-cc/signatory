FROM golang:alpine
ARG COLLECTOR_PKG 
ARG GIT_REVISION 
ARG GIT_BRANCH
RUN apk --no-cache add git gcc musl-dev linux-headers
WORKDIR /build/app
COPY go.mod ./
RUN go mod download
COPY . .
# Build app
RUN CGO_ENABLED=1 go build -ldflags "-X ${COLLECTOR_PKG}.GitRevision=${GIT_REVISION} -X ${COLLECTOR_PKG}.GitBranch=${GIT_BRANCH}" ./cmd/signatory
RUN CGO_ENABLED=1 go build -ldflags "-X ${COLLECTOR_PKG}.GitRevision=${GIT_REVISION} -X ${COLLECTOR_PKG}.GitBranch=${GIT_BRANCH}" ./cmd/signatory-cli

FROM alpine:3
RUN apk --no-cache add ca-certificates
COPY --from=0 /build/app/signatory /bin
COPY --from=0 /build/app/signatory-cli /bin

ENTRYPOINT ["/bin/signatory"]
