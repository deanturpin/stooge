# Makefile for stooge - network traffic replayer
# All builds run in Docker containers to ensure consistent environment

.PHONY: all build run run-text run-quick live test clean deploy format install kill

IMAGE := deanturpin/stooge

# Default target: build and run with sample PCAP
all: build run

# Auto-format C++ source files using clang-format
format:
	clang-format -i src/*.cxx src/*.hxx

# Build Docker image
build:
	docker build -t $(IMAGE) .

# Run container with sample PCAP file (interactive TUI mode)
run:
	docker run --rm -it -v $(PWD):/data $(IMAGE) /data/laptop.pcapng

# Run container in text mode (no TTY required)
text:
	docker run --rm -v $(PWD):/data --entrypoint /app/build/stooge $(IMAGE) --no-tui /data/laptop.pcapng

# Quick replay test in text mode (3 second timeout for rapid iteration)
quick: build
	timeout 100 docker run --rm -v $(PWD):/data --entrypoint /app/build/stooge $(IMAGE) --no-tui /data/laptop.pcapng || true

# Run unit tests
test: build
	docker run --rm $(IMAGE) /bin/sh -c "cd /app/build && ctest --output-on-failure"

# Run live capture (requires elevated privileges)
live: build
	@echo "Starting live capture (requires sudo/elevated privileges)..."
	# docker run --rm -it --cap-add=NET_ADMIN --cap-add=NET_RAW --net=host $(IMAGE)
	docker run --rm -it --network=host $(IMAGE)

# Run with GDB for debugging crashes
gdb: build
	@echo "Starting GDB debugging session..."
	docker run --rm -it --cap-add=SYS_PTRACE --security-opt seccomp=unconfined \
		-v $(PWD):/data --entrypoint /bin/bash $(IMAGE) \
		-c "gdb -ex run --args /app/build/stooge /data/laptop.pcapng"

# Remove Docker image
clean:
	docker rmi $(IMAGE) || true

# Kill all running stooge containers
kill:
	@echo "Killing all running stooge containers..."
	@docker ps -q --filter ancestor=$(IMAGE) | xargs -r docker kill 2>/dev/null || true
	@docker ps -aq --filter ancestor=$(IMAGE) | xargs -r docker rm 2>/dev/null || true
	@echo "Done."

# Install Lua dissectors to Wireshark user plugins directory
install:
	@echo "Installing Lua dissectors to Wireshark plugins directory..."
	@mkdir -p ~/.local/lib/wireshark/plugins
	@cp -v dissectors/*.lua ~/.local/lib/wireshark/plugins/
	@echo "Dissectors installed successfully!"
	@echo "Restart Wireshark or verify with: Help → About Wireshark → Plugins"

# Commit all changes and push to remote
deploy:
	git add -A && git commit -m "Auto-commit from make deploy 🤖" && git push
