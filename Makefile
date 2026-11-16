BIN    ?= agpass
PREFIX ?= $(HOME)/.local/bin

.PHONY: build install test clean

# Hardened runtime (-o runtime): other processes, even under your user,
# cannot attach a debugger to read the server's memory or inject dylibs.
build:
	go build -trimpath -o $(BIN) .
	codesign -f -s - -o runtime $(BIN)

install: build
	install -d $(PREFIX)
	install -m 755 $(BIN) $(PREFIX)/$(BIN)
	codesign -dv $(PREFIX)/$(BIN) 2>&1 | grep -q runtime && echo "installed $(PREFIX)/$(BIN) (hardened runtime)"

test:
	go vet ./...
	go test ./...

clean:
	rm -f $(BIN)
