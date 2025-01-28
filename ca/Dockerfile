FROM golang:1.23

WORKDIR /go/src/app/

# Copy dependencies first to take advantage of Docker caching
COPY go.mod ./
COPY go.sum ./
RUN go mod download

COPY . ./

# Insert version using git tag and latest commit hash
# Build Go Binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o ./server ./cmd/server/main.go;

ARG API_PORT
EXPOSE $API_PORT

CMD ["/go/src/app/server"]