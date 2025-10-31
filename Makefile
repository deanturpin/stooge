# Makefile for stooge - network traffic replayer
# All builds run in Docker containers to ensure consistent environment

.PHONY: all build run test clean deploy format

IMAGE := deanturpin/stooge

# Default target: build and run with sample PCAP
all: build run

# Auto-format C++ source files using clang-format
format:
	docker run --rm -v $(PWD):/app -w /app ubuntu:latest bash -c "apt-get update && apt-get install -y clang-format && clang-format -i src/*.cxx src/*.hxx"

# Build Docker image (formats code first)
build: format
	docker build -t $(IMAGE) .

# Run container with sample PCAP file
run:
	docker run --rm -v $(PWD):/data $(IMAGE) /data/laptop.pcapng

# Run tests (not yet implemented)
test:
	@echo "Tests not yet implemented"

# Remove Docker image
clean:
	docker rmi $(IMAGE) 2>/dev/null || true

# Commit all changes and push to remote
deploy:
	git add -A && git commit -m "Auto-commit from make deploy 🤖" && git push
