.PHONY: all build run test clean deploy

IMAGE := deanturpin/stooge

all: build run

build:
	docker build -t $(IMAGE) .

run:
	docker run --rm $(IMAGE)

test:
	@echo "Tests not yet implemented"

clean:
	docker rmi $(IMAGE) 2>/dev/null || true

deploy:
	git add -A && git commit -m "Auto-commit from make deploy 🤖" && git push
