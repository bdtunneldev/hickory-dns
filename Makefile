# Hickory DNS pipeline deployment helpers
# Maintainer: RAHMAT AL ZAMI

COMPOSE := docker compose
IMAGE   := hickory-dns:latest

.PHONY: help build up down restart logs ps health test test-pipeline test-load metrics prometheus reload-config

help:
	@echo "Targets:"
	@echo "  build          Build Docker image"
	@echo "  up             Start 3 Hickory instances + HAProxy + Prometheus"
	@echo "  down           Stop all services"
	@echo "  restart        Restart Hickory backends"
	@echo "  logs           Follow all service logs"
	@echo "  ps             Show service status"
	@echo "  health         Check metrics endpoints on all instances"
	@echo "  test-pipeline  Run Rust pipeline integration tests"
	@echo "  test-load      Run 10k PROXY v2 load test via HAProxy (:53)"
	@echo "  metrics        Print Prometheus scrape URLs"
	@echo "  prometheus     Open Prometheus UI hint"
	@echo "  reload-config  Restart backends to pick up config changes"

build:
	$(COMPOSE) build

up: build
	$(COMPOSE) up -d

down:
	$(COMPOSE) down

restart:
	$(COMPOSE) restart hickory-dns-1 hickory-dns-2 hickory-dns-3

logs:
	$(COMPOSE) logs -f

ps:
	$(COMPOSE) ps

health:
	@for port in 9101 9102 9103; do \
		echo "=== :$$port/metrics ==="; \
		curl -sf "http://127.0.0.1:$$port/metrics" | head -5 || echo "FAIL"; \
	done
	@echo "=== HAProxy DNS :53 TCP (PROXY v2) ==="
	@python3 scripts/proxy_dns_query.py 127.0.0.1 53 google.com || true

test-pipeline:
	cargo test -p hickory-server --features pipeline,blocklist,resolver,metrics,remote-blocklist pipeline_chain --
	cargo test -p hickory-server --features pipeline,blocklist,resolver,metrics rate_limiter_allows_then_refuses --
	cargo test -p hickory-server --features pipeline,resolver,metrics test_build_forwarded_response_preserves_refused -- catalog::tests

test-load:
	python3 scripts/load_test_proxy.py 127.0.0.1 53 10000 80

metrics:
	@echo "Prometheus targets:"
	@echo "  http://127.0.0.1:9101/metrics  (instance 1)"
	@echo "  http://127.0.0.1:9102/metrics  (instance 2)"
	@echo "  http://127.0.0.1:9103/metrics  (instance 3)"
	@echo "Prometheus UI: http://127.0.0.1:9090"

prometheus: metrics

reload-config: restart
