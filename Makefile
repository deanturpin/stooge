.PHONY: all build run test clean deploy

all: build run

build:
	docker build -t stooge .

run:
	docker run --rm stooge

test:
	@echo "Tests not yet implemented"

clean:
	docker rmi stooge 2>/dev/null || true

deploy:
	git add -A && git commit -m "Auto-commit from make deploy 🤖" && git push
