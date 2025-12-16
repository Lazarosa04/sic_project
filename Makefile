# Makefile - Projeto SIC

.PHONY: help install check test clean certs sink node test-ble

help:
	@echo "================================================"
	@echo "  Projeto SIC - Comandos Disponíveis"
	@echo "================================================"
	@echo ""
	@echo "  make install     - Instalar dependências"
	@echo "  make check       - Verificar sistema"
	@echo "  make certs       - Gerar certificados"
	@echo "  make test        - Executar testes"
	@echo "  make test-ble    - Testar BLE rapidamente"
	@echo "  make sink        - Executar Sink"
	@echo "  make node        - Executar Node"
	@echo "  make clean       - Limpar certificados"
	@echo ""

install:
	@echo "📦 Instalando dependências..."
	pip install -r requirements.txt
	@echo "✅ Dependências instaladas!"

check:
	@echo "🔍 Verificando sistema..."
	python3 scripts/check_dependencies.py

certs:
	@echo "🔐 Gerando certificados..."
	python3 support/ca_manager.py
	@echo "✅ Certificados gerados!"

test:
	@echo "🧪 Executando suite de testes..."
	python3 examples/test_ble_connection.py

test-ble:
	@echo "📡 Teste rápido de BLE..."
	python3 examples/quick_ble_test.py

sink:
	@echo "🌐 Iniciando Sink..."
	python3 sink/sink_app.py

node:
	@echo "📱 Iniciando Node..."
	python3 node/iot_node.py

clean:
	@echo "🧹 Limpando certificados..."
	rm -rf support/certs/*
	@echo "✅ Certificados removidos!"

setup: install certs check
	@echo ""
	@echo "✅ Setup completo!"
	@echo "🚀 Execute: make test-ble"
