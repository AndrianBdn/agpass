BIN    ?= agpass
PREFIX ?= $(HOME)/.local/bin

.PHONY: build install install-skill test clean

# Hardened runtime (-o runtime): other processes, even under your user,
# cannot attach a debugger to read the server's memory or inject dylibs.
build:
	go build -trimpath -o $(BIN) .
	codesign -f -s - -o runtime $(BIN)

install: build
	install -d $(PREFIX)
	install -m 755 $(BIN) $(PREFIX)/$(BIN)
	codesign -dv $(PREFIX)/$(BIN) 2>&1 | grep -q runtime && echo "installed $(PREFIX)/$(BIN) (hardened runtime)"
	@$(MAKE) --no-print-directory install-skill

# Links the Claude Code skill, so edits in this repo take effect immediately.
SKILLS ?= $(HOME)/.claude/skills
install-skill:
	install -d $(SKILLS)
	ln -sfn $(CURDIR)/.claude/skills/agpass $(SKILLS)/agpass
	@echo "linked $(SKILLS)/agpass -> $(CURDIR)/.claude/skills/agpass"

test:
	go vet ./...
	go test ./...

clean:
	rm -f $(BIN)
