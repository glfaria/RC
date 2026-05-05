"""
gui.py — Interface gráfica PySide6 para o Network Sniffer
Requer: pip install PySide6

Uso:
    from gui import run_gui
    run_gui(manager, capturer)

Ou standalone para demo (sem manager/capturer):
    python gui.py
"""

import sys
import random
import threading
from datetime import datetime

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLineEdit, QLabel, QTableWidget, QTableWidgetItem,
    QHeaderView, QFrame, QAbstractItemView,
)
from PySide6.QtCore import Qt, QTimer, Signal, QObject, QThread
from PySide6.QtGui import QColor


# ─── Paleta ──────────────────────────────────────────────────────────────────

C = {
    "bg":       "#0d1117",
    "bg2":      "#161b22",
    "bg3":      "#1c2128",
    "border":   "#30363d",
    "text":     "#cdd5db",
    "muted":    "#6e7681",
    "green":    "#1dbe80",
    "green_bg": "#0f3d2a",
    "red":      "#e24b4a",
    "red_bg":   "#3d1212",
    "amber":    "#ef9f27",
    "blue":     "#378add",
    "white":    "#f0f6fc",
}

PROTO_COLORS = {
    "TCP":   ("#378add", "#0c2d4a"),
    "UDP":   ("#1dbe80", "#0a2e1f"),
    "ICMP":  ("#ef9f27", "#3d2a08"),
    "DNS":   ("#d4537e", "#3d1828"),
    "HTTP":  ("#af9eed", "#2a2550"),
    "HTTPS": ("#af9eed", "#2a2550"),
    "ARP":   ("#5dcaa5", "#0e2e26"),
    "TLS":   ("#63b3ed", "#0e2740"),
}

STYLESHEET = f"""
QMainWindow, QWidget {{
    background: {C["bg"]};
    color: {C["text"]};
    font-family: "Courier New", monospace;
    font-size: 12px;
}}

#topbar {{
    background: {C["bg2"]};
    border-bottom: 1px solid {C["border"]};
}}
#brand {{
    font-size: 13px;
    font-weight: bold;
    color: {C["white"]};
    letter-spacing: 2px;
}}
#badge {{
    font-size: 10px;
    font-weight: bold;
    letter-spacing: 1px;
    color: {C["muted"]};
    background: {C["bg3"]};
    border: 1px solid {C["border"]};
    border-radius: 10px;
    padding: 3px 12px;
}}
#badge[running=true] {{
    color: {C["green"]};
    border-color: {C["green"]};
    background: {C["green_bg"]};
}}

#panel {{
    background: transparent;
    border: 1px solid {C["border"]};
    border-radius: 8px;
}}
#panel_label {{
    font-size: 9px;
    font-weight: bold;
    letter-spacing: 2px;
    color: {C["muted"]};
}}

QPushButton {{
    font-family: "Courier New", monospace;
    font-size: 11px;
    font-weight: bold;
    padding: 6px 18px;
    border-radius: 6px;
    border: 1px solid {C["border"]};
    background: {C["bg3"]};
    color: {C["text"]};
}}
QPushButton:hover   {{ background: {C["bg"]}; }}
QPushButton:pressed {{ background: {C["bg"]}; }}
QPushButton:disabled {{ color: {C["muted"]}; border-color: {C["bg3"]}; }}

#btn_start {{ color: {C["green"]}; border-color: #1a6644; }}
#btn_start:hover {{ background: {C["green_bg"]}; }}
#btn_start:disabled {{ color: {C["muted"]}; border-color: {C["bg3"]}; background: {C["bg3"]}; }}

#btn_stop {{ color: {C["red"]}; border-color: #6e2020; }}
#btn_stop:hover {{ background: {C["red_bg"]}; }}
#btn_stop:disabled {{ color: {C["muted"]}; border-color: {C["bg3"]}; background: {C["bg3"]}; }}

#btn_apply {{
    color: {C["green"]};
    border-color: #1a6644;
    padding: 5px 14px;
    font-size: 10px;
}}
#btn_apply:hover {{ background: {C["green_bg"]}; }}

#btn_clear {{
    color: {C["muted"]};
    border: none;
    background: transparent;
    padding: 2px 8px;
    font-size: 10px;
}}
#btn_clear:hover {{ color: {C["text"]}; }}

QLineEdit {{
    font-family: "Courier New", monospace;
    font-size: 11px;
    background: {C["bg3"]};
    border: 1px solid {C["border"]};
    border-radius: 5px;
    color: {C["text"]};
    padding: 5px 9px;
}}
QLineEdit:focus {{ border-color: {C["muted"]}; }}

QLabel#brand {{
    background: transparent;
}}

QTableWidget {{
    background: {C["bg"]};
    border: none;
    gridline-color: {C["bg2"]};
    alternate-background-color: {C["bg2"]};
    color: {C["text"]};
    font-family: "Courier New", monospace;
    font-size: 11px;
    selection-background-color: #1d3040;
    selection-color: {C["white"]};
    outline: none;
}}
QTableWidget::item {{ padding: 4px 10px; border: none; }}
QHeaderView::section {{
    background: {C["bg3"]};
    color: {C["muted"]};
    font-size: 9px;
    font-weight: bold;
    letter-spacing: 2px;
    padding: 6px 10px;
    border: none;
    border-right: 1px solid {C["border"]};
    border-bottom: 1px solid {C["border"]};
}}
QScrollBar:vertical {{
    background: {C["bg2"]};
    width: 6px;
    border: none;
}}
QScrollBar::handle:vertical {{
    background: {C["border"]};
    border-radius: 3px;
    min-height: 20px;
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}

#stat_card {{
    background: transparent;
    border: 1px solid {C["border"]};
    border-radius: 6px;
}}
#stat_val {{
    font-size: 26px;
    font-weight: bold;
    color: {C["white"]};
}}
#stat_sub {{
    font-size: 9px;
    font-weight: bold;
    letter-spacing: 2px;
    color: {C["muted"]};
}}
"""


# ─── Worker de demo ───────────────────────────────────────────────────────────

class DemoWorker(QObject):
    packet_ready = Signal(dict)

    def __init__(self):
        super().__init__()
        self._running = False
        self._freeze_table = False

    def start(self):
        import time
        PROTOS = ["TCP", "UDP", "ICMP", "DNS", "HTTP", "ARP", "TLS", "HTTPS"]
        IPS    = ["10.0.0.1", "192.168.1.14", "172.16.0.3",
                  "8.8.8.8", "1.1.1.1", "10.10.0.2", "185.199.108.1"]
        self._running = True
        while self._running:
            time.sleep(random.uniform(0.3, 1.0))
            if not self._running:
                break
            self.packet_ready.emit({
                "timestamp": datetime.now().strftime("%H:%M:%S.%f")[:-3],
                "protocol":  random.choice(PROTOS),
                "src":       random.choice(IPS),
                "dst":       random.choice(IPS),
                "length":    random.randint(40, 1460),
            })

    def stop(self):
        self._running = False


# ─── Indicador pulsante ───────────────────────────────────────────────────────

class DotIndicator(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(10, 10)
        self._active = False
        self._bright = True
        self._timer  = QTimer(self)
        self._timer.timeout.connect(self._blink)

    def setActive(self, val: bool):
        self._active = val
        if val:
            self._bright = True
            self._timer.start(700)
        else:
            self._timer.stop()
        self.update()

    def _blink(self):
        self._bright = not self._bright
        self.update()

    def paintEvent(self, _):
        from PySide6.QtGui import QPainter, QBrush
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        if self._active:
            color = QColor(C["green"]) if self._bright else QColor(C["green_bg"])
        else:
            color = QColor(C["muted"])
        p.setBrush(QBrush(color))
        p.setPen(Qt.NoPen)
        p.drawEllipse(0, 0, 10, 10)


# ─── Janela principal ─────────────────────────────────────────────────────────

class SnifferGUI(QMainWindow):
    _new_packet = Signal(dict)

    def __init__(self, manager=None, capturer=None):
        super().__init__()
        self.manager   = manager
        self.capturer  = capturer
        self._running  = False
        self._pkt_buf  = []
        self._pkt_count    = 0
        self._proto_counts = {}
        self._demo_thread  = None
        self._demo_worker  = None

        self.setWindowTitle("PKT SNIFFER")
        self.resize(1060, 680)
        self.setMinimumSize(760, 500)
        self.setStyleSheet(STYLESHEET)

        self._build_ui()

        self._refresh_timer = QTimer(self)
        self._refresh_timer.timeout.connect(self._update_table)
        self._refresh_timer.start(400)

        self._new_packet.connect(self._add_packet)

    # ── Build ─────────────────────────────────────────────────────────────────

    def _build_ui(self):
        root = QWidget()
        self.setCentralWidget(root)
        vbox = QVBoxLayout(root)
        vbox.setContentsMargins(0, 0, 0, 0)
        vbox.setSpacing(0)

        vbox.addWidget(self._make_topbar())

        body = QWidget()
        body_v = QVBoxLayout(body)
        body_v.setContentsMargins(12, 12, 12, 12)
        body_v.setSpacing(10)
        body_v.addLayout(self._make_controls_row())
        body_v.addWidget(self._make_table_panel())

        vbox.addWidget(body)

    def _make_topbar(self):
        bar = QWidget()
        bar.setObjectName("topbar")
        bar.setFixedHeight(48)
        h = QHBoxLayout(bar)
        h.setContentsMargins(14, 6, 14, 6)

        left = QHBoxLayout()
        left.setSpacing(10)
        self.dot = DotIndicator()
        left.addWidget(self.dot)
        brand = QLabel("PKT SNIFFER")
        brand.setObjectName("brand")
        left.addWidget(brand)
        h.addLayout(left)
        h.addStretch()

        self.badge = QLabel("PARADO")
        self.badge.setObjectName("badge")
        self.badge.setProperty("running", False)
        h.addWidget(self.badge)
        return bar

    def _make_controls_row(self):
        row = QHBoxLayout()
        row.setSpacing(10)

        # Captura
        cap = self._panel("CAPTURA", height=76)
        cap_h = QHBoxLayout()
        cap_h.setSpacing(8)
        self.btn_start = QPushButton("▶  start")
        self.btn_start.setObjectName("btn_start")
        self.btn_start.clicked.connect(self.start)
        self.btn_stop = QPushButton("■  stop")
        self.btn_stop.setObjectName("btn_stop")
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self.stop)
        cap_h.addWidget(self.btn_start)
        cap_h.addWidget(self.btn_stop)
        cap_h.addStretch()
        cap.layout().addLayout(cap_h)
        row.addWidget(cap, 2)

        # Filtros
        flt = self._panel("FILTROS", height=76)
        flt_h = QHBoxLayout()
        flt_h.setSpacing(8)
        self.proto_input = self._input("Protocolo")
        self.ip_input    = self._input("Endereço IP")
        self.mac_input   = self._input("MAC")
        btn_apply = QPushButton("aplicar")
        btn_apply.setObjectName("btn_apply")
        btn_apply.clicked.connect(self.apply_filters)
        for w in [self.proto_input, self.ip_input, self.mac_input, btn_apply]:
            flt_h.addWidget(w)
        flt.layout().addLayout(flt_h)
        row.addWidget(flt, 4)

        # Stats
        self.stat_pkts   = self._stat_card("PACOTES", "0")
        self.stat_protos = self._stat_card("TOP PROTOS", "—")
        row.addWidget(self.stat_pkts,   1)
        row.addWidget(self.stat_protos, 1)

        return row

    def _make_table_panel(self):
        panel = QFrame()
        panel.setObjectName("panel")
        v = QVBoxLayout(panel)
        v.setContentsMargins(12, 8, 12, 10)
        v.setSpacing(8)

        header = QHBoxLayout()
        lbl = QLabel("LOG DE PACOTES")
        lbl.setObjectName("panel_label")
        btn_clear = QPushButton("limpar")
        btn_clear.setObjectName("btn_clear")
        btn_clear.clicked.connect(self._clear_table)
        header.addWidget(lbl)
        header.addStretch()
        header.addWidget(btn_clear)
        v.addLayout(header)

        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(["HORA", "PROTO", "ORIGEM", "DESTINO", "LEN"])
        self.table.verticalHeader().setVisible(False)
        self.table.setShowGrid(False)
        self.table.setAlternatingRowColors(True)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSortingEnabled(False)
        self.table.setFocusPolicy(Qt.NoFocus)

        hh = self.table.horizontalHeader()
        hh.setSectionResizeMode(0, QHeaderView.Fixed);       self.table.setColumnWidth(0, 100)
        hh.setSectionResizeMode(1, QHeaderView.Fixed);       self.table.setColumnWidth(1, 80)
        hh.setSectionResizeMode(2, QHeaderView.Stretch)
        hh.setSectionResizeMode(3, QHeaderView.Stretch)
        hh.setSectionResizeMode(4, QHeaderView.Fixed);       self.table.setColumnWidth(4, 70)
        self.table.verticalHeader().setDefaultSectionSize(28)

        v.addWidget(self.table)
        return panel

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _panel(self, title="", height=None):
        w = QFrame()
        w.setObjectName("panel")
        if height:
            w.setFixedHeight(height)
        v = QVBoxLayout(w)
        v.setContentsMargins(12, 8, 12, 10)
        v.setSpacing(8)
        lbl = QLabel(title)
        lbl.setObjectName("panel_label")
        v.addWidget(lbl)
        return w

    def _input(self, placeholder):
        e = QLineEdit()
        e.setPlaceholderText(placeholder)
        e.setFixedHeight(30)
        return e

    def _stat_card(self, label, value):
        card = QFrame()
        card.setObjectName("stat_card")
        card.setFixedHeight(76)
        v = QVBoxLayout(card)
        v.setContentsMargins(12, 8, 12, 10)
        v.setSpacing(2)
        lbl = QLabel(label)
        lbl.setObjectName("stat_sub")
        val = QLabel(value)
        val.setObjectName("stat_val")
        val.setWordWrap(True)
        v.addWidget(lbl)
        v.addWidget(val)
        card._val_lbl = val
        return card

    # ── Lógica pública ────────────────────────────────────────────────────────

    def start(self):
        if self._running:
            return
        self._running = True
        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.dot.setActive(True)
        self.badge.setText("A CAPTURAR")
        self.badge.setProperty("running", True)
        self.badge.setStyle(self.badge.style())

        if self.capturer and self.manager:
            threading.Thread(
                target=self.capturer.start,
                args=(self.on_packet,),
                daemon=True,
            ).start()
        else:
            self._start_demo()

    def stop(self):
        if not self._running:
            return
        self._running = False
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.dot.setActive(False)
        self.badge.setText("PARADO")
        self.badge.setProperty("running", False)
        self.badge.setStyle(self.badge.style())

        if self.capturer:
            self.capturer.stop()
        if self._demo_worker:
            self._demo_worker.stop()

    def apply_filters(self):
        proto = self.proto_input.text().strip() or None
        ip    = self.ip_input.text().strip()    or None
        mac   = self.mac_input.text().strip()   or None

        if self.manager:
            self.manager.set_filters(protocol=proto, ip=ip, mac=mac)

        self._update_table()

    def on_packet(self, pkt):
        """Callback do capturer (thread externa)."""
        if self.manager:
            packet = self.manager.handle_packet(pkt)
            if packet:
                self.manager.store(packet)
                if hasattr(self.manager.output, "write_packet"):
                    self.manager.output.write_packet(packet)
        else:
            self._new_packet.emit(pkt if isinstance(pkt, dict) else {})

    # ── Slots internos ────────────────────────────────────────────────────────

    def _add_packet(self, d: dict):
        self._pkt_buf.append(d)
        proto = d.get("protocol", "?").upper()
        self._pkt_count += 1
        self._proto_counts[proto] = self._proto_counts.get(proto, 0) + 1

    def _update_table(self):
        
        if self.manager:
            packets = self.manager.get_filtered_packets()
            rows = [{"timestamp": str(p.timestamp), "protocol": p.protocol,
                     "src": p.src, "dst": p.dst, "length": str(p.length)}
                    for p in packets]
        else:
            rows = list(self._pkt_buf)

        if not rows:
            return

        self.table.setRowCount(len(rows))
        for i, d in enumerate(rows):
            proto = d.get("protocol", "?").upper()
            fg, bg = PROTO_COLORS.get(proto, (C["muted"], C["bg3"]))

            def _item(text):
                it = QTableWidgetItem(str(text))
                it.setForeground(QColor(C["text"]))
                it.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)
                return it

            def _proto_item(text, fg=fg, bg=bg):
                it = QTableWidgetItem(text)
                it.setForeground(QColor(fg))
                it.setBackground(QColor(bg))
                it.setTextAlignment(Qt.AlignCenter)
                it.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)
                return it

            self.table.setItem(i, 0, _item(d.get("timestamp", "")))
            self.table.setItem(i, 1, _proto_item(proto))
            self.table.setItem(i, 2, _item(d.get("src", "")))
            self.table.setItem(i, 3, _item(d.get("dst", "")))
            self.table.setItem(i, 4, _item(str(d.get("length", ""))))

        self.table.scrollToBottom()

        # Stats
        total = self._pkt_count if not self.manager else len(rows)
        self.stat_pkts._val_lbl.setText(str(total))

        if self.manager:
            proto_data = self.manager.count_by_protocol(
                self.manager.get_filtered_packets()
            )
            if isinstance(proto_data, dict):
                self._proto_counts = proto_data

        top = sorted(self._proto_counts.items(), key=lambda x: -x[1])[:3]
        self.stat_protos._val_lbl.setText(
            "\n".join(f"{p}  {c}" for p, c in top) or "—"
        )
        self.stat_protos._val_lbl.setStyleSheet(
            f"font-size: 11px; color: {C['green']}; font-weight: bold; letter-spacing: 1px;"
        )

    def _clear_table(self):
        if self.manager:
            self.manager.packets.clear()
        self.table.setRowCount(0)
        self._pkt_buf.clear()
        self._pkt_count = 0
        self._proto_counts = {}
        self.stat_pkts._val_lbl.setText("0")
        self.stat_protos._val_lbl.setText("—")
        self.stat_protos._val_lbl.setStyleSheet("")

    # ── Demo mode ─────────────────────────────────────────────────────────────

    def _start_demo(self):
        self._demo_worker = DemoWorker()
        self._demo_thread = QThread(self)
        self._demo_worker.moveToThread(self._demo_thread)
        self._demo_worker.packet_ready.connect(self._add_packet)
        self._demo_thread.started.connect(self._demo_worker.start)
        self._demo_thread.start()

    def closeEvent(self, event):
        if self._demo_worker:
            self._demo_worker.stop()
        if self._demo_thread:
            self._demo_thread.quit()
            self._demo_thread.wait(1000)
        if self.capturer:
            try:
                self.capturer.stop()
            except Exception:
                pass
        event.accept()


# ─── Entrypoint ───────────────────────────────────────────────────────────────

def run_gui(manager=None, capturer=None):
    app = QApplication.instance() or QApplication(sys.argv)
    window = SnifferGUI(manager, capturer)
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    run_gui()