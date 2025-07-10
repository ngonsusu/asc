import os
import sys
import threading
import time
from PyQt5.QtWidgets import (
    QMainWindow, QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QComboBox, QListWidget, QProgressBar, QTabWidget, QFileDialog,
    QMessageBox, QGroupBox, QGridLayout, QCheckBox, QTableWidget, QTableWidgetItem,
    QAbstractItemView, QHeaderView, QAction, QMenu, QStatusBar
)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal
from PyQt5.QtGui import QIcon, QFont

from main_window import DashboardTab
from network_scanner import NetworkScanner
from parallel_executor import ParallelExecutor
from progress_manager import ProgressManager
from config import SERVICE_PORTS, WORDLISTS_DIR
from error_handler import ErrorHandler
from utils import find_exe_in_dir, get_creation_flags

class NetworkScannerGUI(QMainWindow):
    scan_update_signal = pyqtSignal(list)
    scan_complete_signal = pyqtSignal()
    brute_complete_signal = pyqtSignal()

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Network Scanner & Brute-force Tool")
        self.setGeometry(100, 100, 1200, 800)
        self.is_scanning = False
        self.scan_results = []
        self.scan_progress_manager = None
        self.brute_executor = None
        self.scan_thread = None
        self.brute_thread = None
        self.error_handler = ErrorHandler(self.log)
        self.init_ui()
        self.scan_update_signal.connect(self.update_result_list)
        self.scan_complete_signal.connect(self.on_scan_complete)
        self.brute_complete_signal.connect(self.on_brute_complete)

    def init_ui(self):
        # Create tab widget
        self.tab_widget = QTabWidget()
        self.setCentralWidget(self.tab_widget)

        # Main tab (scan & brute)
        self.main_tab = QWidget()
        self.setup_main_tab()
        self.tab_widget.addTab(self.main_tab, "Scan & Brute-force")

        # Dashboard tab
        self.dashboard_tab = DashboardTab(self)
        self.tab_widget.addTab(self.dashboard_tab, "Dashboard")

        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)

        # Menu bar
        self.create_menu()

    def create_menu(self):
        menu_bar = self.menuBar()
        file_menu = menu_bar.addMenu("File")

        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        help_menu = menu_bar.addMenu("Help")
        about_action = QAction("About", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)

    def show_about(self):
        QMessageBox.information(self, "About",
            "Network Scanner and Brute-force Tool\nVersion 1.0\n© 2023")

    def setup_main_tab(self):
        layout = QVBoxLayout(self.main_tab)

        # Target input
        target_group = QGroupBox("Target")
        target_layout = QHBoxLayout()
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("Enter IP, CIDR range, or file path...")
        target_layout.addWidget(self.target_input, 4)

        self.browse_button = QPushButton("Browse...")
        self.browse_button.clicked.connect(self.browse_target_file)
        target_layout.addWidget(self.browse_button, 1)

        target_group.setLayout(target_layout)
        layout.addWidget(target_group)

        # Service selection
        service_group = QGroupBox("Service")
        service_layout = QGridLayout()

        self.service_combo = QComboBox()
        self.service_combo.addItems(SERVICE_PORTS.keys())
        self.service_combo.currentIndexChanged.connect(self.update_port_input)
        service_layout.addWidget(QLabel("Service:"), 0, 0)
        service_layout.addWidget(self.service_combo, 0, 1)

        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText("Port (default based on service)")
        service_layout.addWidget(QLabel("Port:"), 1, 0)
        service_layout.addWidget(self.port_input, 1, 1)

        self.auto_brute_checkbox = QCheckBox("Auto brute-force when open service found")
        service_layout.addWidget(self.auto_brute_checkbox, 2, 0, 1, 2)

        service_group.setLayout(service_layout)
        layout.addWidget(service_group)

        # Scan control
        scan_control_layout = QHBoxLayout()
        self.scan_button = QPushButton("Start Scan")
        self.scan_button.clicked.connect(self.toggle_scan)
        scan_control_layout.addWidget(self.scan_button)

        self.stop_button = QPushButton("Stop Scan")
        self.stop_button.clicked.connect(self.stop_scan)
        self.stop_button.setEnabled(False)
        scan_control_layout.addWidget(self.stop_button)

        layout.addLayout(scan_control_layout)

        # Progress bar
        self.scan_progress = QProgressBar()
        self.scan_progress.setRange(0, 100)
        layout.addWidget(self.scan_progress)

        # Result list
        result_group = QGroupBox("Scan Results")
        result_layout = QVBoxLayout()
        self.result_list = QListWidget()
        self.result_list.setSelectionMode(QAbstractItemView.ExtendedSelection)
        result_layout.addWidget(self.result_list)

        # Brute-force control
        brute_control_layout = QHBoxLayout()
        self.brute_button = QPushButton("Brute-force Selected Targets")
        self.brute_button.clicked.connect(self.start_brute_force)
        brute_control_layout.addWidget(self.brute_button)

        result_layout.addLayout(brute_control_layout)
        result_group.setLayout(result_layout)
        layout.addWidget(result_group)

        # Log area
        log_group = QGroupBox("Log")
        log_layout = QVBoxLayout()
        self.log_area = QTableWidget()
        self.log_area.setColumnCount(3)
        self.log_area.setHorizontalHeaderLabels(["Time", "Source", "Message"])
        self.log_area.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.log_area.verticalHeader().setVisible(False)
        self.log_area.setEditTriggers(QTableWidget.NoEditTriggers)
        log_layout.addWidget(self.log_area)
        log_group.setLayout(log_layout)
        layout.addWidget(log_group)

    def browse_target_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Target File", "", "Text Files (*.txt);;All Files (*)")
        if file_path:
            self.target_input.setText(file_path)

    def update_port_input(self):
        service = self.service_combo.currentText()
        if service in SERVICE_PORTS:
            self.port_input.setText(SERVICE_PORTS[service])

    def toggle_scan(self):
        if self.is_scanning:
            self.stop_scan()
        else:
            self.start_scan()

    def on_scan_started(self):
        self.dashboard_tab.add_activity("System", 0, "Scan started")
        self.status_bar.showMessage("Scan in progress...")

    def start_scan(self):
        target = self.target_input.text().strip()
        service = self.service_combo.currentText()
        port = self.port_input.text().strip()
        auto_brute = self.auto_brute_checkbox.isChecked()

        if not target:
            self.log("Error", "Please enter a target")
            return

        if not port:
            port = SERVICE_PORTS.get(service, "1-65535")
            self.port_input.setText(port)

        # Parse targets
        all_targets = []
        if os.path.isfile(target):
            try:
                with open(target, 'r') as f:
                    all_targets = [line.strip() for line in f if line.strip()]
            except Exception as e:
                self.log("Error", f"Cannot read target file: {str(e)}")
                return
        else:
            all_targets = [t.strip() for t in target.split(',') if t.strip()]

        if not all_targets:
            self.log("Error", "No valid targets found")
            return

        self.log("Info", f"Starting scan for {len(all_targets)} targets...")
        self.on_scan_started()
        self.is_scanning = True
        self.scan_button.setText("Stop Scan")
        self.stop_button.setEnabled(True)
        self.result_list.clear()
        self.scan_results = []

        # Initialize progress manager
        self.scan_progress_manager = ProgressManager(len(all_targets))
        for target_spec in all_targets:
            self.scan_progress_manager.add_target(target_spec)

        # Create scanner
        nmap_path = self.find_nmap()
        if not nmap_path:
            self.log("Error", "Nmap not found! Please install Nmap and add it to PATH.")
            self.stop_scan()
            return

        scanner = NetworkScanner(nmap_path, self.log)

        # Start scan in a separate thread
        self.scan_thread = threading.Thread(
            target=self.run_scan,
            args=(scanner, all_targets, port, service, auto_brute)
        )
        self.scan_thread.daemon = True
        self.scan_thread.start()

        # Start progress timer
        self.progress_timer = QTimer()
        self.progress_timer.timeout.connect(self.update_scan_progress)
        self.progress_timer.start(1000)

    def run_scan(self, scanner, targets, port, service, auto_brute):
        for target in targets:
            if not self.is_scanning:
                break
            try:
                results = scanner.scan_network(target, port, service, auto_brute)
                if results:
                    self.scan_results.extend(results)
                    self.scan_update_signal.emit(results)
            except Exception as e:
                self.log("Error", f"Error scanning {target}: {str(e)}")
        self.scan_complete_signal.emit()

    def update_scan_progress(self):
        if self.scan_progress_manager:
            progress = self.scan_progress_manager.get_progress()
            
            # Calculate percentage safely
            if progress["total_targets"] > 0:
                percent = (progress["completed_targets"] / progress["total_targets"]) * 100
            else:
                percent = 0
                
            self.scan_progress.setValue(int(percent))

            # Update dashboard
            dashboard_stats = {
                "total_targets": progress["total_targets"],
                "scanned_targets": progress["completed_targets"],
                "remaining_targets": progress["remaining_targets"],
                "open_services": progress["open_ports"],
                "brute_success": 0,  # Will be updated separately
                "ip_progress": int(percent),
                "scanned_ips": progress["completed_targets"],
                "total_ips": progress["total_targets"],
                "current_target": progress["completed_list"][-1] if progress["completed_list"] else "None"
            }
            self.dashboard_tab.update_stats(dashboard_stats)
            self.dashboard_tab.update_chart(progress["service_distribution"])

            # Add recent activity
            if progress["completed_list"]:
                last_target = progress["completed_list"][-1]
                self.dashboard_tab.add_activity(
                    last_target,
                    self.port_input.text(),
                    f"Scan completed, found {progress['service_distribution'].get(self.service_combo.currentText(), 0)} services"
                )

    def update_result_list(self, results):
        for ip, port, service in results:
            item_text = f"{ip}:{port} ({service})"
            item = QListWidgetItem(item_text)
            item.setData(Qt.UserRole, (ip, port, service))
            self.result_list.addItem(item)

    def stop_scan(self):
        self.is_scanning = False
        self.scan_button.setText("Start Scan")
        self.stop_button.setEnabled(False)
        self.log("Info", "Scan stopped by user")
        if hasattr(self, 'progress_timer') and self.progress_timer.isActive():
            self.progress_timer.stop()

    def on_scan_complete(self):
        self.is_scanning = False
        self.scan_button.setText("Start Scan")
        self.stop_button.setEnabled(False)
        self.log("Info", "Scan completed successfully")
        if hasattr(self, 'progress_timer') and self.progress_timer.isActive():
            self.progress_timer.stop()

    def on_brute_started(self):
        self.dashboard_tab.add_activity("System", 0, "Brute-force started")
        self.status_bar.showMessage("Brute-force in progress...")

    def start_brute_force(self):
        selected_items = self.result_list.selectedItems()
        if not selected_items:
            self.log("Warning", "Please select at least one target from the list")
            return

        # Prepare brute-force tasks
        self.brute_executor = ParallelExecutor(max_threads=5, log_function=self.log)
        for item in selected_items:
            ip, port, service = item.data(Qt.UserRole)
            # Build command based on service
            cmd = []
            wordlist_dir = WORDLISTS_DIR
            
            if service == "SSH":
                user_file = os.path.join(wordlist_dir, "ssh_users.txt")
                pass_file = os.path.join(wordlist_dir, "ssh_pass.txt")
                if os.path.exists(user_file) and os.path.exists(pass_file):
                    cmd = ["hydra", "-L", user_file, "-P", pass_file, "ssh://" + ip]
            elif service == "FTP":
                user_file = os.path.join(wordlist_dir, "ftp_users.txt")
                pass_file = os.path.join(wordlist_dir, "ftp_pass.txt")
                if os.path.exists(user_file) and os.path.exists(pass_file):
                    cmd = ["hydra", "-L", user_file, "-P", pass_file, "ftp://" + ip]
            elif service == "RDP":
                user_file = os.path.join(wordlist_dir, "rdp_users.txt")
                pass_file = os.path.join(wordlist_dir, "rdp_pass.txt")
                if os.path.exists(user_file) and os.path.exists(pass_file):
                    cmd = ["hydra", "-L", user_file, "-P", pass_file, "rdp://" + ip]
            else:
                self.log("Warning", f"Brute-force not supported for {service}")
                continue
            
            if cmd:  # Only add if command is valid
                self.brute_executor.add_task(id(item), cmd, service)
                self.log("Info", f"Added {ip}:{port} ({service}) to brute-force queue")

        if self.brute_executor.task_queue.empty():
            self.log("Warning", "No valid brute-force tasks created")
            return

        # Start brute-force
        self.on_brute_started()
        self.brute_executor.start()
        self.brute_button.setEnabled(False)
        self.dashboard_tab.update_parallel_status(
            self.brute_executor.active_threads, 
            self.brute_executor.task_queue.qsize()
        )

        # Start monitoring thread
        self.brute_thread = threading.Thread(target=self.monitor_brute_progress)
        self.brute_thread.daemon = True
        self.brute_thread.start()

    def monitor_brute_progress(self):
        try:
            results = self.brute_executor.wait_completion()
            self.brute_complete_signal.emit()

            # Process results
            success_count = 0
            for item_id, result in results.items():
                for i in range(self.result_list.count()):
                    item = self.result_list.item(i)
                    if id(item) == item_id:
                        if result.get("success", False):
                            credentials = result.get("credentials", [])
                            if credentials:
                                # Append credentials without replacing original text
                                new_text = f"{item.text()} [Credentials: {', '.join(credentials)}]"
                                item.setText(new_text)
                                success_count += len(credentials)
                                
                                # Add to dashboard
                                for cred in credentials:
                                    self.dashboard_tab.add_activity(
                                        result["service"],
                                        "N/A",
                                        f"Brute success: {cred}"
                                    )
                        break

            # Update dashboard
            stats = self.dashboard_tab.stats.copy()
            stats["brute_success"] = stats.get("brute_success", 0) + success_count
            self.dashboard_tab.update_stats(stats)
            self.dashboard_tab.update_parallel_status(0, 0)
        except Exception as e:
            self.log("Error", f"Error monitoring brute-force: {str(e)}")

    def on_brute_complete(self):
        self.brute_button.setEnabled(True)
        self.status_bar.showMessage("Brute-force completed", 5000)

    def log(self, source, message):
        try:
            timestamp = time.strftime("%H:%M:%S")
            row_position = self.log_area.rowCount()
            self.log_area.insertRow(row_position)
            self.log_area.setItem(row_position, 0, QTableWidgetItem(timestamp))
            self.log_area.setItem(row_position, 1, QTableWidgetItem(source))
            self.log_area.setItem(row_position, 2, QTableWidgetItem(message))
            self.log_area.scrollToBottom()

            # Also update dashboard activity for important events
            if "success" in message.lower() or "error" in message.lower() or "warning" in message.lower():
                # Extract IP if possible
                ip = "System"
                if "://" in message:
                    parts = message.split("://")
                    if len(parts) > 1:
                        ip = parts[1].split('/')[0].split(':')[0]
                self.dashboard_tab.add_activity(ip, "N/A", message)
        except Exception as e:
            print(f"Logging error: {str(e)}")

    def find_nmap(self):
        # Try to find nmap in PATH
        if sys.platform == "win32":
            nmap_exe = "nmap.exe"
        else:
            nmap_exe = "nmap"

        for path in os.environ["PATH"].split(os.pathsep):
            full_path = os.path.join(path, nmap_exe)
            if os.path.isfile(full_path):
                return full_path
        
        # Check common installation paths
        common_paths = [
            "/usr/bin/nmap",
            "/usr/local/bin/nmap",
            "C:\\Program Files (x86)\\Nmap\\nmap.exe",
            "C:\\Program Files\\Nmap\\nmap.exe"
        ]
        
        for path in common_paths:
            if os.path.isfile(path):
                return path
                
        return None

    def closeEvent(self, event):
        # Stop scan if running
        if self.is_scanning:
            self.stop_scan()
            reply = QMessageBox.question(self, "Scan in Progress",
                                         "Scan was stopped. Are you sure you want to exit?",
                                         QMessageBox.Yes | QMessageBox.No)
            if reply == QMessageBox.No:
                event.ignore()
                return

        # Stop brute-force if running
        if self.brute_executor and self.brute_executor.active_threads > 0:
            self.brute_executor.stop()
            reply = QMessageBox.question(self, "Brute-force in Progress",
                                         "Brute-force was stopped. Are you sure you want to exit?",
                                         QMessageBox.Yes | QMessageBox.No)
            if reply == QMessageBox.No:
                event.ignore()
                return

        # Wait for threads to finish
        if self.scan_thread and self.scan_thread.is_alive():
            self.scan_thread.join(1.0)  # Wait max 1 second

        if self.brute_thread and self.brute_thread.is_alive():
            self.brute_thread.join(1.0)
            
        event.accept()