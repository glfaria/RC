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

# --- Run live (console) ---
runlive:
	@echo "Running sniffer in LIVE mode..."
	$(VENV)/bin/python3 src/main.py --interface $(INTERFACE) --mode live

# --- Run log (file only) ---
runlog:
	@echo "Running sniffer in LOG mode..."
	$(VENV)/bin/python3 src/main.py --interface $(INTERFACE) --mode log --logfile $(LOGFILE)

# --- Run both ---
runboth:
	@echo "Running sniffer in LIVE + LOG mode..."
	$(VENV)/bin/python3 src/main.py --interface $(INTERFACE) --mode both --logfile $(LOGFILE)

# --- Clean venv ---
clean:
	rm -rf $(VENV)

# --- Clean logs ---
cleanlogs:
	rm -rf logs/*