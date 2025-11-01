# Makefile for stooge - network traffic replayer
# All builds run in Docker containers to ensure consistent environment

.PHONY: all build run live test clean deploy format install

IMAGE := deanturpin/stooge

# Default target: build and run with sample PCAP
all: build run

# Auto-format C++ source files using clang-format
format:
	docker run --rm -v $(PWD):/app -w /app ubuntu:latest bash -c "apt-get update && apt-get install -y clang-format && clang-format -i src/*.cxx src/*.hxx"

# Build Docker image
build:
	docker build -t $(IMAGE) .

# Run container with sample PCAP file
run:
	docker run --rm -t -v $(PWD):/data $(IMAGE) /data/laptop.pcapng

# Run live capture (requires elevated privileges)
live:
	@echo "Starting live capture (requires sudo/elevated privileges)..."
	docker run --rm -t --cap-add=NET_ADMIN --cap-add=NET_RAW --net=host $(IMAGE)

# Run tests (not yet implemented)
test:
	@echo "Tests not yet implemented"

# Remove Docker image
clean:
	docker rmi $(IMAGE) 2>/dev/null || true

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
