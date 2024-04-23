ARG branch=pocl


FROM golang:latest as build-stage

# Set the working directory
WORKDIR /app

# Download Go modules
COPY go.mod go.sum ./
RUN go mod download

COPY . . 

# Build the Go project
RUN CGO_ENABLED=0 GOOS=linux go build -o /cipherswarmagent ./main.go

# Run the tests in the container
FROM build-stage AS run-test-stage
RUN go test -v ./...

FROM dizcza/docker-hashcat:$branch as build-release-stage

WORKDIR /

ENV API_URL=http://localhost:3000/api/v1/client/
ENV API_TOKEN=1234567890

COPY --from=build-stage /cipherswarmagent /cipherswarmagent

# Set the startup command
CMD ["./cipherswarmagent"]
