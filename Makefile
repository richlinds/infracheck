.PHONY: help test lint format fix pre-push

help: ## Show available commands
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

test: ## Run the test suite
	uv run pytest

lint: ## Check code style with ruff
	uv run ruff check .

format: ## Format code with ruff
	uv run ruff format .

fix: ## Auto-fix lint errors and format
	uv run ruff check --fix .
	uv run ruff format .

pre-push: lint test ## Run lint and tests before pushing
