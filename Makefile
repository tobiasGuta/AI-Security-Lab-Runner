.PHONY: build test doctor docker-image clean fmt vet

BINARY_NAME=lab-runner

build:
	go build -o $(BINARY_NAME) ./cmd/lab-runner

test:
	go test -v -race ./...

doctor: build
	./$(BINARY_NAME) doctor

docker-image:
	docker build -t ai-security-agent-runner:latest ./runner

fmt:
	gofmt -w .

vet:
	go vet ./...

clean:
	rm -f $(BINARY_NAME) $(BINARY_NAME).exe
