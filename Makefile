.PHONY: all build run test clean deploy format

IMAGE := deanturpin/stooge

all: build run

format:
	docker run --rm -v $(PWD):/app -w /app ubuntu:latest bash -c "apt-get update && apt-get install -y clang-format && clang-format -i src/*.cxx src/*.hxx"

build: format
	docker build -t $(IMAGE) .

run:
	docker run --rm -v $(PWD):/data $(IMAGE) /data/laptop.pcapng

test:
	@echo "Tests not yet implemented"

clean:
	docker rmi $(IMAGE) 2>/dev/null || true

deploy:
	git add -A && git commit -m "Auto-commit from make deploy 🤖" && git push
