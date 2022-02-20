IMAGE_REPO ?= docker.io/awallarm
IMAGE_NAME ?= wlrm-check
IMAGE_TAG ?= latest

build-linux:
	@echo "Building the binary..."
	@GO111MODULE=on CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -installsuffix cgo -ldflags '-w -extldflags "-static"' -o ./bin/linux/w *.go
	@echo "Binary has been built to $(dir $(abspath $(firstword $(MAKEFILE_LIST))))bin/linux/"

build-darwin:
	@echo "Building the binary..."
	@GO111MODULE=on CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -a -installsuffix cgo -ldflags '-w -extldflags "-static"' -o ./bin/darwin/w *.go
	@echo "Binary has been built to $(dir $(abspath $(firstword $(MAKEFILE_LIST))))bin/darwin/"

build: build-linux build-darwin

build-testing-image:
	@echo "Building the docker image: $(IMAGE_REPO)/$(IMAGE_NAME):test..."
	@docker build -t $(IMAGE_REPO)/$(IMAGE_NAME):test -f Dockerfile-testing .

build-image:
	@echo "Building the docker image: $(IMAGE_REPO)/$(IMAGE_NAME):$(IMAGE_TAG)..."
	@docker build -t $(IMAGE_REPO)/$(IMAGE_NAME):$(IMAGE_TAG) -f Dockerfile .

push-image: build-image
	@echo "Pushing the docker image for $(IMAGE_REPO)/$(IMAGE_NAME):$(IMAGE_TAG) and $(IMAGE_REPO)/$(IMAGE_NAME):latest..."
	@docker tag $(IMAGE_REPO)/$(IMAGE_NAME):$(IMAGE_TAG) $(IMAGE_REPO)/$(IMAGE_NAME):latest
	@docker push $(IMAGE_REPO)/$(IMAGE_NAME):$(IMAGE_TAG)
	@docker push $(IMAGE_REPO)/$(IMAGE_NAME):latest

.PHONY: build build-linux build-darwin build-testing-image build-image push-image