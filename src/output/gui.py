import sys
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QTableWidget, QTableWidgetItem,
    QVBoxLayout, QWidget, QPushButton, QLineEdit, QHBoxLayout
)
from PySide6.QtCore import QTimer


class SnifferGUI(QMainWindow):
    def __init__(self, manager, capturer):
        super().__init__()

        self.manager = manager
        self.capturer = capturer

        self.setWindowTitle("Packet Sniffer")
        self.resize(1000, 600)

        layout = QVBoxLayout()

        # filters
        filter_layout = QHBoxLayout()

        self.protocol_input = QLineEdit()
        self.protocol_input.setPlaceholderText("Protocol")

        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("IP")

        self.mac_input = QLineEdit()
        self.mac_input.setPlaceholderText("MAC")

        apply_btn = QPushButton("Apply")
        apply_btn.clicked.connect(self.apply_filters)

        start_btn = QPushButton("Start")
        stop_btn = QPushButton("Stop")

        start_btn.clicked.connect(self.start)
        stop_btn.clicked.connect(self.stop)

        for w in [
            self.protocol_input,
            self.ip_input,
            self.mac_input,
            apply_btn,
            start_btn,
            stop_btn
        ]:
            filter_layout.addWidget(w)

        layout.addLayout(filter_layout)

        # table
        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(["Time", "Proto", "Src", "Dst", "Len"])

        layout.addWidget(self.table)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

        self.timer = QTimer()
        self.timer.timeout.connect(self.update_table)
        self.timer.start(500)

    def start(self):
        self.capturer.start(self.on_packet)

    def stop(self):
        self.capturer.stop()

    def apply_filters(self):
        self.manager.set_filters(
            protocol=self.protocol_input.text() or None,
            ip=self.ip_input.text() or None,
            mac=self.mac_input.text() or None
        )

    def on_packet(self, pkt):
        packet = self.manager.handle_packet(pkt)
        if packet:
            self.manager.store(packet)
            if hasattr(self.manager.output, "write_packet"):
                self.manager.output.write_packet(packet)

    def update_table(self):
        packets = self.manager.get_filtered_packets()

        self.table.setRowCount(len(packets))

        for i, p in enumerate(packets):
            self.table.setItem(i, 0, QTableWidgetItem(str(p.timestamp)))
            self.table.setItem(i, 1, QTableWidgetItem(p.protocol))
            self.table.setItem(i, 2, QTableWidgetItem(p.src))
            self.table.setItem(i, 3, QTableWidgetItem(p.dst))
            self.table.setItem(i, 4, QTableWidgetItem(str(p.length)))


def run_gui(manager, capturer):
    app = QApplication(sys.argv)
    window = SnifferGUI(manager, capturer)
    window.show()
    sys.exit(app.exec())