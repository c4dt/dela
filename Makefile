generate:
	go get -u github.com/golang/protobuf/protoc-gen-go@v1.3.5
	go generate ./...

# Some packages are exluded from staticcheck due to deprecated warnings: #208.
lint:
	# Coding style static check.
	@go install honnef.co/go/tools/cmd/staticcheck@latest
	@go mod tidy
	staticcheck `go list ./... | grep -Ev "(github.com/c4dt/dela/internal/testing|github.com/c4dt/dela/mino/minogrpc/ptypes)"`

vet:
	@echo "⚠️ Warning: the following only works with go >= 1.14" && \
	go install ./internal/mcheck && \
	go vet -vettool=`go env GOPATH`/bin/mcheck -commentLen -ifInit ./...

# target to run all the possible checks; it's a good habit to run it before
# pushing code
check: lint vet
	go test ./...

# https://pkg.go.dev/github.com/c4dt/dela needs to be updated on the Go proxy side
# to get the latest main. This command refreshes the proxy with the latest
# commit on the upstream main branch.
# Note: CURL must be installed
pushdoc:
	@echo "Requesting the proxy..."
	@curl "https://proxy.golang.org/github.com/c4dt/dela/@v/$(shell git log origin/master -1 --format=format:%H).info"
	@echo "\nDone."