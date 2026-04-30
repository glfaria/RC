# Nome do virtual environment
VENV = venv

# Interface padrão
INTERFACE = wlo1

# Ficheiro de log
LOGFILE = logs/sniffer_log.json

# --- Cria o ambiente virtual ---
venv:
	python3 -m venv $(VENV)
	$(VENV)/bin/pip install --upgrade pip
	$(VENV)/bin/pip install -r requirements.txt

run-tui-live:
	$(VENV)/bin/python3 src/main.py --interface $(INTERFACE) --mode live --ui tui

run-tui-log:
	$(VENV)/bin/python3 src/main.py --interface $(INTERFACE) --mode log --ui tui --logfile $(LOGFILE)

run-tui-both:
	$(VENV)/bin/python3 src/main.py --interface $(INTERFACE) --mode both --ui tui --logfile $(LOGFILE)

run-gui-live:
	$(VENV)/bin/python3 src/main.py --interface $(INTERFACE) --mode live --ui gui

run-gui-log:
	$(VENV)/bin/python3 src/main.py --interface $(INTERFACE) --mode log --ui gui --logfile $(LOGFILE)

run-gui-both:
	$(VENV)/bin/python3 src/main.py --interface $(INTERFACE) --mode both --ui gui --logfile $(LOGFILE)

# --- Clean venv ---
clean:
	rm -rf $(VENV)

# --- Clean logs ---
cleanlogs:
	rm -rf logs/*