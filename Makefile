.PHONY: test coverage lint vet clean build

build:
	CGO_ENABLED=0 go build \
       -ldflags="-s -w" tls-tool.go
lint:
	go fmt ./...
vet:
	go vet ./...
test:
	go test -race -cover -v ./...
coverage:
	go test -v -cover -coverprofile=coverage.out ./... &&\
	go tool cover -html=coverage.out -o coverage.html
clean:
	rm -f build/* dist/* *.pem
