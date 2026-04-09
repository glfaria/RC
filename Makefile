# Nome do virtual environment
VENV = venv

# Interface padrão (pode mudar conforme o sistema)
INTERFACE = eth0

# Modo de execução: live, log ou ambos
MODE = live

# --- Cria o ambiente virtual ---
venv:
	python3 -m venv $(VENV)
	$(VENV)/bin/pip install --upgrade pip
	$(VENV)/bin/pip install -r requirements.txt

# --- Ativa o venv e corre a main.py ---
run:
	@echo "A correr o sniffer..."
	$(VENV)/bin/python3 src/main.py --interface $(INTERFACE) --mode $(MODE)

# --- Limpa venv (opcional) ---
clean:
	rm -rf $(VENV)
