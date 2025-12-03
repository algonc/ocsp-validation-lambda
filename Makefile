# Copyright (c) 2025 André Gonçalves. All rights reserved.
# Use of this source code is governed by the MIT License that can be found in the LICENSE file.


# -----------------------------
# Config
# -----------------------------
AWS_REGION   ?= eu-central-1
IMAGE_TAG    ?= latest

ECR_PREFIX   ?= your-prefix

ACCOUNT_ID := $(shell aws sts get-caller-identity --query Account --output text)

ECR_BASE := $(ACCOUNT_ID).dkr.ecr.$(AWS_REGION).amazonaws.com

LAMBDAS := \
	ocsp-validation-lambda \

# -----------------------------
# Public targets
# -----------------------------
.PHONY: all login build push deploy

all: deploy

deploy: login build push
	@echo "All lambdas built and pushed"

login:
	@echo "Logging into ECR"
	@aws ecr get-login-password --region $(AWS_REGION) | docker login \
		--username AWS \
		--password-stdin $(ECR_BASE)

build: $(LAMBDAS:%=build-%)

push: $(LAMBDAS:%=push-%)

# -----------------------------
# Per-lambda targets
# -----------------------------
build-%:
	@echo "Building $*"
	docker build \
		-f docker/$*.Dockerfile \
		-t $*:$(IMAGE_TAG) \
		.

push-%: ensure-repo-%
	@echo "Pushing $*"
	docker tag $*:$(IMAGE_TAG) $(ECR_BASE)/$(ECR_PREFIX)-$*:$(IMAGE_TAG)
	docker push $(ECR_BASE)/$(ECR_PREFIX)-$*:$(IMAGE_TAG)
	@echo "Pushed $(ECR_BASE)/$(ECR_PREFIX)-$*:$(IMAGE_TAG)"

ensure-repo-%:
	@aws ecr describe-repositories \
		--repository-names $(ECR_PREFIX)-$* \
		--region $(AWS_REGION) \
		>/dev/null 2>&1 || \
	aws ecr create-repository \
		--repository-name $(ECR_PREFIX)-$* \
		--image-scanning-configuration scanOnPush=true \
		--region $(AWS_REGION)
