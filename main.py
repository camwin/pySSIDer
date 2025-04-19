import sys
import numpy as np
from PyQt6.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QHBoxLayout, QWidget, QPushButton, QTableWidget, QTableWidgetItem, QSpacerItem, QSizePolicy, QLabel
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QColor
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
from scipy.ndimage import gaussian_filter1d
from wifi_scanner import get_scanner, WiFiNetwork

class NumericTableWidgetItem(QTableWidgetItem):
    def __lt__(self, other):
        try:
            return float(self.text()) < float(other.text())
        except ValueError:
            return super().__lt__(other)

class WiFiScoutWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("pySSIDer v.01")
        self.setGeometry(100, 100, 1100, 600)  # Increased width for Vendor column

        # Theme state
        self.is_dark_mode = True

        # Main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        # Button and timer layout (horizontal, right-aligned)
        button_layout = QHBoxLayout()
        button_layout.addSpacerItem(QSpacerItem(0, 0, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum))

        # Timer label
        self.refresh_timer_label = QLabel("Next refresh in 60s")
        button_layout.addWidget(self.refresh_timer_label)

        # Scan button
        self.scan_button = QPushButton("Scan")
        self.scan_button.clicked.connect(self.scan_networks)
        self.scan_button.setFixedSize(60, 30)
        button_layout.addWidget(self.scan_button)

        # Auto-scan button
        self.auto_scan_button = QPushButton("Stop")
        self.auto_scan_button.clicked.connect(self.toggle_auto_scan)
        self.auto_scan_button.setFixedSize(60, 30)
        button_layout.addWidget(self.auto_scan_button)

        # Theme toggle button
        self.theme_button = QPushButton("Light Mode")
        self.theme_button.clicked.connect(self.toggle_theme)
        self.theme_button.setFixedSize(80, 30)
        button_layout.addWidget(self.theme_button)

        main_layout.addLayout(button_layout)

        # Table
        self.table = QTableWidget()
        self.table.setColumnCount(13)  # Added Vendor column
        self.table.setHorizontalHeaderLabels([
            "SSID", "Signal (%)", "RSSI (dBm)", "Channel", "Channel Width", "PHY Type",
            "BSSID", "Security", "Frequency (MHz)", "Mode", "SNR (dB)", "Last Seen", "Vendor"
        ])
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.setSortingEnabled(True)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setColumnWidth(0, 150)  # SSID
        self.table.setColumnWidth(1, 80)   # Signal (%)
        self.table.setColumnWidth(2, 80)   # RSSI (dBm)
        self.table.setColumnWidth(3, 80)   # Channel
        self.table.setColumnWidth(4, 100)  # Channel Width
        self.table.setColumnWidth(5, 100)  # PHY Type
        self.table.setColumnWidth(6, 120)  # BSSID
        self.table.setColumnWidth(7, 100)  # Security
        self.table.setColumnWidth(8, 100)  # Frequency (MHz)
        self.table.setColumnWidth(9, 80)   # Mode
        self.table.setColumnWidth(10, 80)  # SNR (dB)
        self.table.setColumnWidth(11, 120) # Last Seen
        self.table.setColumnWidth(12, 100) # Vendor
        self.table.itemSelectionChanged.connect(self.update_graph_for_selection)
        main_layout.addWidget(self.table)

        # Matplotlib canvas for channel graph
        self.figure = Figure()
        self.canvas = FigureCanvas(self.figure)
        main_layout.addWidget(self.canvas)

        # Scanner
        self.scanner = get_scanner()

        # Auto-scan setup
        self.auto_scan_enabled = True
        self.timer = QTimer()
        self.timer.timeout.connect(self.scan_networks)
        self.timer.start(60000)  # 60-second refresh

        # Refresh countdown timer
        self.refresh_interval = 60
        self.seconds_remaining = self.refresh_interval
        self.countdown_timer = QTimer()
        self.countdown_timer.timeout.connect(self.update_countdown)
        self.countdown_timer.start(1000)

        # Network colors
        self.network_colors = [
            "#e57373", "#81c784", "#64b5f6", "#ffb74d", "#ba68c8", "#4dd0e1",
            "#f06292", "#aed581", "#7986cb", "#ffca28", "#ab47bc", "#26c6da",
            "#d32f2f", "#388e3c", "#1976d2", "#f57c00", "#7b1fa2", "#0097a7"
        ]
        self.networks = []
        self.last_successful_networks = []
        self.selected_network = None

        # Apply the initial theme
        self.apply_theme()

        # Initial scan
        self.scan_networks()

    def apply_theme(self):
        if self.is_dark_mode:
            self.setStyleSheet("background-color: #2c2f33;")
            self.refresh_timer_label.setStyleSheet("QLabel { color: #d8dee9; font-size: 14px; font-weight: bold; }")
            self.scan_button.setStyleSheet("QPushButton { background-color: #2e7d32; color: #ffffff; border-radius: 5px; font-size: 12px; }")
            self.auto_scan_button.setStyleSheet("QPushButton { background-color: #1e88e5; color: #ffffff; border-radius: 5px; font-size: 12px; }")
            self.theme_button.setStyleSheet("QPushButton { background-color: #5c6370; color: #ffffff; border-radius: 5px; font-size: 12px; }")
            self.table.setStyleSheet("""
                QTableWidget {
                    background-color: #3a3f44;
                    alternate-background-color: #44494f;
                    gridline-color: #5c6370;
                    font-size: 14px;
                    color: #d8dee9;
                    border: 1px solid #5c6370;
                }
                QTableWidget::item:selected {
                    background-color: #7289da;
                    color: #ffffff;
                }
                QHeaderView::section {
                    background-color: #4b5360;
                    border: 1px solid #5c6370;
                    padding: 4px;
                    font-size: 14px;
                    color: #d8dee9;
                }
            """)
            self.canvas.setStyleSheet("background-color: #2c2f33;")
            self.figure.set_facecolor("#2c2f33")
            self.graph_text_color = "#d8dee9"
            self.graph_grid_color = "#5c6370"
            self.graph_background_color = "#2c2f33"
        else:
            self.setStyleSheet("background-color: #f5f7fa;")
            self.refresh_timer_label.setStyleSheet("QLabel { color: #2c3e50; font-size: 14px; font-weight: bold; }")
            self.scan_button.setStyleSheet("QPushButton { background-color: #4CAF50; color: white; border-radius: 5px; font-size: 12px; }")
            self.auto_scan_button.setStyleSheet("QPushButton { background-color: #3498db; color: white; border-radius: 5px; font-size: 12px; }")
            self.theme_button.setStyleSheet("QPushButton { background-color: #888888; color: white; border-radius: 5px; font-size: 12px; }")
            self.table.setStyleSheet("""
                QTableWidget {
                    background-color: #ffffff;
                    alternate-background-color: #e9ecef;
                    gridline-color: #ced4da;
                    font-size: 14px;
                    color: #2c3e50;
                    border: 1px solid #ced4da;
                }
                QTableWidget::item:selected {
                    background-color: #a8d1ff;
                    color: #000000;
                }
                QHeaderView::section {
                    background-color: #dfe6ed;
                    border: 1px solid #ced4da;
                    padding: 4px;
                    font-size: 14px;
                    color: #2c3e50;
                }
            """)
            self.canvas.setStyleSheet("background-color: #f8f9fa;")
            self.figure.set_facecolor("#f8f9fa")
            self.graph_text_color = "#2c3e50"
            self.graph_grid_color = "#ced4da"
            self.graph_background_color = "#f8f9fa"

        self.update_graph_for_selection()

    def toggle_theme(self):
        self.is_dark_mode = not self.is_dark_mode
        self.theme_button.setText("Light Mode" if self.is_dark_mode else "Dark Mode")
        self.apply_theme()

    def toggle_auto_scan(self):
        self.auto_scan_enabled = not self.auto_scan_enabled
        if self.auto_scan_enabled:
            self.timer.start(60000)
            self.auto_scan_button.setText("Stop")
            self.scan_networks()
            self.seconds_remaining = self.refresh_interval
            self.countdown_timer.start(1000)
            self.apply_theme()
        else:
            self.timer.stop()
            self.auto_scan_button.setText("Start")
            self.countdown_timer.stop()
            self.refresh_timer_label.setText("Auto-refresh paused")
            self.apply_theme()

    def update_countdown(self):
        if self.auto_scan_enabled:
            self.seconds_remaining -= 1
            if self.seconds_remaining <= 0:
                self.seconds_remaining = self.refresh_interval
            self.refresh_timer_label.setText(f"Next refresh in {self.seconds_remaining}s")

    def scan_networks(self):
        print("Starting scan...")
        self.table.setSortingEnabled(False)

        try:
            networks = self.scanner.scan()
            print(f"Found {len(networks)} networks: {[n.ssid for n in networks]}")
            # Merge duplicates by SSID and BSSID, prioritizing non-None security
            unique_networks = {}
            for network in networks:
                key = (network.ssid, network.bssid)
                if key not in unique_networks or (network.security and network.security != "None"):
                    unique_networks[key] = network
            networks = list(unique_networks.values())
            print(f"After merging duplicates: {len(networks)} networks: {[n.ssid for n in networks]}")
            if networks:
                self.last_successful_networks = networks
            else:
                print("Scan returned no networks, using last successful scan.")
                networks = self.last_successful_networks
                if not networks:
                    print("No previous successful scan available. Table will be empty.")
        except Exception as e:
            print(f"Scan failed: {e}, using last successful scan.")
            networks = self.last_successful_networks
            if not networks:
                print("No previous successful scan available. Table will be empty.")

        self.networks = networks
        print(f"Updating table with {len(networks)} networks")
        self.table.setRowCount(len(networks))

        if not networks:
            print("Displaying message: No networks detected.")
            self.table.setRowCount(1)
            self.table.setItem(0, 0, QTableWidgetItem("No networks detected."))
            for col in range(1, 13):
                self.table.setItem(0, col, QTableWidgetItem(""))
        else:
            for row, network in enumerate(networks):
                print(f"Adding row {row}: SSID={network.ssid}, Channel={network.channel}, Security={network.security}, Vendor={network.vendor}, RSSI={network.rssi}, BSSID={network.bssid}")
                self.table.setItem(row, 0, QTableWidgetItem(network.ssid))
                self.table.setItem(row, 1, NumericTableWidgetItem(str(network.signal)))
                self.table.setItem(row, 2, NumericTableWidgetItem(f"{network.rssi:.1f}"))
                self.table.setItem(row, 3, NumericTableWidgetItem(str(network.channel)))
                self.table.setItem(row, 4, QTableWidgetItem(network.channel_width))
                self.table.setItem(row, 5, QTableWidgetItem(network.phy_type))
                self.table.setItem(row, 6, QTableWidgetItem(network.bssid))
                self.table.setItem(row, 7, QTableWidgetItem(network.security or "None"))
                self.table.setItem(row, 8, NumericTableWidgetItem(str(network.frequency)))
                self.table.setItem(row, 9, QTableWidgetItem(network.mode))
                self.table.setItem(row, 10, NumericTableWidgetItem(f"{network.snr:.1f}"))
                self.table.setItem(row, 11, QTableWidgetItem(network.last_seen))
                self.table.setItem(row, 12, QTableWidgetItem(network.vendor or "Unknown"))

        self.table.setSortingEnabled(True)
        self.table.sortItems(2, Qt.SortOrder.DescendingOrder)
        self.table.resizeRowsToContents()  # Ensure all rows are visible
        self.table.scrollToTop()  # Scroll to top to show high RSSI networks

        if not self.selected_network:
            self.update_graph_for_selection()

        if self.auto_scan_enabled:
            self.seconds_remaining = self.refresh_interval
            self.refresh_timer_label.setText(f"Next refresh in {self.seconds_remaining}s")

    def update_graph_for_selection(self):
        selected_items = self.table.selectedItems()
        if selected_items:
            row = selected_items[0].row()
            if self.table.item(row, 0).text() == "No networks detected.":
                self.selected_network = None
            else:
                self.selected_network = self.networks[row]
        else:
            self.selected_network = None

        networks_to_plot = [self.selected_network] if self.selected_network else self.networks

        self.figure.clear()
        axes = self.figure.subplots(2, 1, sharex=False)
        ax1, ax2 = axes

        # 2.4GHz
        channels_2_4 = np.arange(1, 15, 0.2)
        for idx, network in enumerate(networks_to_plot):
            if network and 1 <= network.channel <= 14:
                signals_2_4 = np.zeros_like(channels_2_4, dtype=float)
                rssi = network.rssi
                width_mhz = int(network.channel_width.replace("MHz", ""))
                spread = width_mhz / 20
                sigma = spread * 0.5
                channel_idx = np.argmin(np.abs(channels_2_4 - network.channel))
                spread_indices = int(spread * 10)
                start_idx = max(0, channel_idx - spread_indices)
                end_idx = min(len(signals_2_4), channel_idx + spread_indices + 1)
                signals_2_4[start_idx:end_idx] = rssi
                print(f"2.4GHz Network: {network.ssid}, Channel: {network.channel}, RSSI: {rssi}, Width: {network.channel_width}, Sigma: {sigma}")

                smoothed_2_4 = gaussian_filter1d(signals_2_4, sigma=sigma)
                color = self.network_colors[idx % len(self.network_colors)]
                ax1.plot(channels_2_4, smoothed_2_4, color=color, linewidth=2)
                ax1.fill_between(channels_2_4, smoothed_2_4, min(smoothed_2_4), alpha=0.2, color=color)

        ax1.set_title("2.4GHz Channel Usage", fontsize=10, pad=5, color=self.graph_text_color)
        ax1.set_xlabel("Channel", fontsize=8, color=self.graph_text_color)
        ax1.set_ylabel("RSSI (dBm)", fontsize=8, color=self.graph_text_color)
        ax1.set_xticks(np.arange(1, 15))
        ax1.set_ylim(-100, -10)
        ax1.invert_yaxis()
        ax1.grid(True, alpha=0.3, color=self.graph_grid_color)
        ax1.tick_params(axis='both', colors=self.graph_text_color)
        ax1.set_facecolor(self.graph_background_color)

        # 5GHz
        channels_5 = np.arange(20, 165, 0.5)
        for idx, network in enumerate(networks_to_plot):
            if network and network.channel > 14:
                signals_5 = np.zeros_like(channels_5, dtype=float)
                rssi = network.rssi
                width_mhz = int(network.channel_width.replace("MHz", ""))
                spread = width_mhz / 20
                sigma = spread * 1.5
                channel_idx = np.argmin(np.abs(channels_5 - network.channel))
                spread_indices = int(spread * 20)
                start_idx = max(0, channel_idx - spread_indices)
                end_idx = min(len(signals_5), channel_idx + spread_indices + 1)
                signals_5[start_idx:end_idx] = rssi
                print(f"5GHz Network: {network.ssid}, Channel: {network.channel}, RSSI: {rssi}, Width: {network.channel_width}, Sigma: {sigma}")

                smoothed_5 = gaussian_filter1d(signals_5, sigma=sigma)
                color = self.network_colors[idx % len(self.network_colors)]
                ax2.plot(channels_5, smoothed_5, color=color, linewidth=2)
                ax2.fill_between(channels_5, smoothed_5, min(smoothed_5), alpha=0.2, color=color)

        ax2.set_title("5GHz Channel Usage", fontsize=10, pad=5, color=self.graph_text_color)
        ax2.set_xlabel("Channel", fontsize=8, color=self.graph_text_color)
        ax2.set_ylabel("RSSI (dBm)", fontsize=8, color=self.graph_text_color)
        ax2.set_xticks(np.arange(20, 165, 10))
        ax2.set_ylim(-100, -10)
        ax2.invert_yaxis()
        ax2.grid(True, alpha=0.3, color=self.graph_grid_color)
        ax2.tick_params(axis='both', colors=self.graph_text_color)
        ax2.set_facecolor(self.graph_background_color)

        self.figure.tight_layout()
        self.figure.set_facecolor(self.graph_background_color)
        self.canvas.draw()
        self.canvas.flush_events()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = WiFiScoutWindow()
    window.show()
    sys.exit(app.exec())