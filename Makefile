BINARY := tld
COVERPROFILE := coverage.out

.PHONY: build run clean coverage

build:
	go build -o $(BINARY) ./cmd

run: build
	./$(BINARY) $(ARGS)

coverage:
	go test -coverprofile=$(COVERPROFILE) .
	go tool cover -func=$(COVERPROFILE)

clean:
	rm -f $(BINARY) $(COVERPROFILE)
