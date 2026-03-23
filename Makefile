PYTHON ?= python3
OUTPUT_DIR ?= output
CATEGORY ?=
CATEGORY_ARG := $(if $(strip $(CATEGORY)),--category $(CATEGORY),)
CLI := $(PYTHON) -m app_control.cli

.PHONY: help check validate status build-prod build-canary build-network-prod build-network-canary build-host-prod build-host-canary build-by-category-prod build-by-category-canary clean-output

help:
	@printf '%s\n' \
	  'Supported commands:' \
	  '  make validate                     Validate catalog YAML files' \
	  '  make status                       Report catalog coverage and readiness' \
	  '  make build-prod                   Generate validated production artifacts' \
	  '  make build-canary                 Generate reviewed+ canary artifacts' \
	  '  make build-by-category-prod       Generate validated per-category artifacts' \
	  '  make build-by-category-canary     Generate reviewed+ per-category artifacts' \
	  '  make build-prod CATEGORY=GENAI_CODING' \
	  '  python3 -m app_control.cli status' \
	  '  scripts/app-control status' \
	  '  make clean-output                 Remove generated artifacts from output/'

check: validate status

validate:
	$(CLI) validate

status:
	$(CLI) status

build-prod: build-network-prod build-host-prod

build-canary: build-network-canary build-host-canary

build-network-prod:
	@mkdir -p $(OUTPUT_DIR)
	$(CLI) generate-network --min-status validated $(CATEGORY_ARG) > $(OUTPUT_DIR)/network_rules.esql

build-network-canary:
	@mkdir -p $(OUTPUT_DIR)
	$(CLI) generate-network --min-status reviewed $(CATEGORY_ARG) > $(OUTPUT_DIR)/network_rules_canary.esql

build-host-prod:
	@mkdir -p $(OUTPUT_DIR)
	$(CLI) generate-host --min-status validated $(CATEGORY_ARG) > $(OUTPUT_DIR)/host_scan.sh

build-host-canary:
	@mkdir -p $(OUTPUT_DIR)
	$(CLI) generate-host --min-status reviewed $(CATEGORY_ARG) > $(OUTPUT_DIR)/host_scan_canary.sh

build-by-category-prod:
	@mkdir -p $(OUTPUT_DIR)
	$(CLI) generate-category-alerts --min-status validated $(CATEGORY_ARG) --output-dir $(OUTPUT_DIR)

build-by-category-canary:
	@mkdir -p $(OUTPUT_DIR)
	$(CLI) generate-category-alerts --min-status reviewed $(CATEGORY_ARG) --output-dir $(OUTPUT_DIR)

clean-output:
	rm -f $(OUTPUT_DIR)/*.esql $(OUTPUT_DIR)/*.sh $(OUTPUT_DIR)/*.md $(OUTPUT_DIR)/*.json
