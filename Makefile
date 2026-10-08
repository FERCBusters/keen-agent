GO ?= go
.PHONY: build test release clean
build:
	CGO_ENABLED=0 $(GO) build -buildvcs=false -trimpath -ldflags='-s -w' -o dist/keen-agent ./cmd/keen-agent

test:
	$(GO) test -race ./...
	$(GO) vet ./...

release: test
	mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -buildvcs=false -trimpath -ldflags='-s -w' -o dist/keen-agent-linux-amd64 ./cmd/keen-agent
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -buildvcs=false -trimpath -ldflags='-s -w' -o dist/keen-agent-linux-arm64 ./cmd/keen-agent
	cd dist && sha256sum keen-agent-linux-* > SHA256SUMS

clean:
	rm -rf dist
