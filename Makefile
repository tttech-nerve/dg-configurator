TOOL_NAME := configurator
PACKAGE := dg_configurator
CLI := dg-configurator
SRC_DIR := src
TESTS_DIR := tests

# interpreter used to create the virtual environment (override e.g. with PYTHON=$$(pyenv which python3.14))
PYTHON ?= python3.14

# temporary directories and files for development and testing
VENV_DIR := .venv
REPORTS_DIR := reports
LINT_REPORTS_DIR := $(REPORTS_DIR)/lint
BUILD_DIR := build
DIST_DIR := $(BUILD_DIR)/dist
# indicator file for a completed setup (used as precondition by many targets)
READY := .ready

# reports
LINT_REPORT := $(LINT_REPORTS_DIR)/ruff.txt
FORMAT_REPORT := $(LINT_REPORTS_DIR)/ruff-format.txt
TEST_REPORT := $(REPORTS_DIR)/testreport.html
JUNIT_REPORT := $(REPORTS_DIR)/junit.xml

# extra arguments for `make run`
ARGS ?=

.DEFAULT_GOAL := help

.PHONY: help
help:  ## Show this help message
	@echo "Available commands:"
	@grep -hE '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

$(VENV_DIR):
	poetry env use $(PYTHON)
	poetry install

# build/ is not a make target on purpose: it would clash with the phony `build` goal
$(REPORTS_DIR) $(LINT_REPORTS_DIR):
	mkdir -p $@

.PHONY: setup
setup: $(VENV_DIR) $(REPORTS_DIR) $(LINT_REPORTS_DIR)  ## Set up the development environment (.venv, reports/)
	touch $(READY)

$(READY):
	$(MAKE) setup

.PHONY: cleanup
cleanup:  ## Clean up the development environment
	rm -f $(READY)
	rm -rf $(VENV_DIR) $(REPORTS_DIR) $(BUILD_DIR) dist
	rm -rf .pytest_cache/ .ruff_cache/ .hypothesis/
	find . -type d -name "__pycache__" -prune -exec rm -rf {} +
	find . -type d -name "*.egg-info" -prune -exec rm -rf {} +

.PHONY: lint
lint: $(READY) | $(LINT_REPORTS_DIR)  ## Lint (ruff check + ruff format --check); fails on findings
	@status=0; \
	poetry run ruff check $(SRC_DIR) $(TESTS_DIR) --output-format full > $(LINT_REPORT) 2>&1 || status=1; \
	poetry run ruff format --check --diff $(SRC_DIR) $(TESTS_DIR) > $(FORMAT_REPORT) 2>&1 || status=1; \
	cat $(LINT_REPORT) $(FORMAT_REPORT); \
	echo "Linter reports generated at $(LINT_REPORT) and $(FORMAT_REPORT)"; \
	exit $$status

.PHONY: format
format: $(READY)  ## Auto-format the code and apply safe ruff fixes
	poetry run ruff format $(SRC_DIR) $(TESTS_DIR)
	poetry run ruff check --fix $(SRC_DIR) $(TESTS_DIR)

.PHONY: test
test: $(READY) | $(REPORTS_DIR)  ## Run the test suite with coverage (fails below the coverage threshold)
	poetry run pytest --cov --cov-report=term-missing --cov-report=html --cov-report=xml \
		--html=$(TEST_REPORT) --self-contained-html --junitxml=$(JUNIT_REPORT) $(TESTS_DIR)
	@echo "Test report generated at $(TEST_REPORT)"
	@echo "Coverage HTML report generated at $(REPORTS_DIR)/coverage/index.html"

.PHONY: check
check: lint test vendor-check  ## Run lint + test + vendor checksum check (definition of done for every change)

.PHONY: build
build: $(READY)  ## Build wheel + sdist into build/dist/
	poetry build --clean --output $(DIST_DIR)

.PHONY: run
run: $(READY)  ## Run the tool, e.g. make run ARGS="--help"
	poetry run $(CLI) $(ARGS)

IMAGE := dg-configurator
VERSION := $(shell poetry version -s)

.PHONY: serve
serve: $(READY)  ## Run the web UI, e.g. make serve ARGS="--port 9090"
	poetry run $(CLI) serve $(ARGS)

.PHONY: vendor-check
vendor-check:  ## Verify the vendored Drawflow files against their recorded checksums
	cd $(SRC_DIR)/$(PACKAGE)/web/static/vendor/drawflow && sha256sum -c SHA256SUMS

.PHONY: dockerbuild
dockerbuild:  ## Build the Docker image
	docker build -f docker/Dockerfile -t $(IMAGE):$(VERSION) -t $(IMAGE):latest .

.PHONY: dockerrun
dockerrun:  ## Run the Docker image locally (binds 127.0.0.1:8080 only)
	docker run --rm --read-only --tmpfs /tmp -p 127.0.0.1:8080:8080 $(IMAGE):latest
