# Network Packet Sniffer

Sniffer de rede desenvolvido em Python no âmbito da UC de Redes de Computadores.

## Funcionalidades

* Captura de pacotes numa interface de rede
* Parsing manual de protocolos:
  * Ethernet
  * ARP
  * IPv4
  * IPV6
  * STP
  * ICMP
  * TCP
  * UDP
* Visualização em tempo real (modo live)
* Registo de pacotes em ficheiro (modo log)
* Modo combinado (live + log)
* Interface:
  * TUI (Terminal)
  * GUI (Gráfica)
* Filtros:
  * por protocolo
  * por IP
  * por MAC
* Estatísticas por protocolo
* Visualização detalhada por pacote 


## Dependências

Instalar automaticamente com:

```bash
make venv
```

Ou manualmente:

```bash
python3 -m venv venv
venv/bin/pip install -r requirements.txt
```

Dependências principais:

* `scapy` (apenas para captura de pacotes)
* `PySide6` (para GUI, se aplicável)  


# Como executar

## 1. Criar ambiente virtual

```bash
make venv
```

## 2. Selecionar interface de rede

Listar interfaces disponíveis:

```bash
ip a
```

Exemplo:

* `wlo1` 
* `eth0` 


## 3. Executar o sniffer

### Execução manual

```bash
venv/bin/python3 src/main.py \
  --interface wlo1 \
  --mode live \
  --ui tui
```

Parâmetros:

| Argumento     | Descrição                  |
| ------------- | -------------------------- |
| `--interface` | Interface de rede          |
| `--mode`      | `live`, `log`, `both`      |
| `--ui`        | `tui` ou `gui`             |
| `--logfile`   | Caminho do ficheiro de log |



### Permissões

Correr com sudo. Por exemplo:


```bash
sudo venv/bin/python3 src/main.py ...
```

### Limpeza

Remover ambiente virtual:

```bash
make clean
```

### Logs

* Formato: JSON

Limpar logs:

```bash
make cleanlogs
```

# Uso da TUI

Comandos disponíveis:

```
start   → iniciar captura
stop    → parar captura
list    → listar pacotes
view ID → ver detalhes de um pacote
filter  → aplicar filtros
stats   → estatísticas por protocolo
clear   → limpar lista
help    → listar comandos disponíveis
exit    → sair
```


### Filtros

Durante execução:

```
filter
```

Permite definir:

* protocolo (ex: TCP, UDP, ICMP)
* IP
* MAC

# Autores

Gabriel Faria  
Ricardo Rodrigues  
Rui Gomes 