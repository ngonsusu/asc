from PyQt5.QtGui import QPainter 
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QGroupBox, QTableWidget, 
    QTableWidgetItem, QHeaderView, QProgressBar, QFrame, QGridLayout
)
from PyQt5.QtCore import Qt, QDateTime
from PyQt5.QtGui import QColor, QFont

# Check if QtChart is available
try:
    from PyQt5.QtChart import QChart, QChartView, QBarSet, QBarSeries, QBarCategoryAxis
    QTCHART_AVAILABLE = True
except ImportError:
    QTCHART_AVAILABLE = False

class DashboardTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.stats = {
            "total_targets": 0,
            "scanned_targets": 0,
            "open_services": 0,
            "brute_success": 0,
            "current_target": "",
            "remaining_targets": 0,
            "ip_progress": 0,
            "scanned_ips": 0,
            "total_ips": 0
        }
        self.service_distribution = {}
        self.init_ui()
        
    def init_ui(self):
        main_layout = QVBoxLayout()
        main_layout.setSpacing(15)
        
        # Summary Stats Section
        summary_frame = QFrame()
        summary_frame.setFrameShape(QFrame.StyledPanel)
        summary_frame.setStyleSheet("background-color: #f8f9fa; border-radius: 8px; padding: 10px;")
        summary_layout = QVBoxLayout(summary_frame)
        
        # Title
        title = QLabel("Scan Statistics")
        title_font = QFont()
        title_font.setBold(True)
        title_font.setPointSize(14)
        title.setFont(title_font)
        summary_layout.addWidget(title)
        
        # Stats grid
        grid_layout = QGridLayout()
        grid_layout.setHorizontalSpacing(30)
        grid_layout.setVerticalSpacing(10)
        
        # Row 1
        grid_layout.addWidget(QLabel("Total Targets:"), 0, 0)
        self.total_targets_label = QLabel("0")
        grid_layout.addWidget(self.total_targets_label, 0, 1)
        
        grid_layout.addWidget(QLabel("Scanned Targets:"), 0, 2)
        self.scanned_targets_label = QLabel("0")
        grid_layout.addWidget(self.scanned_targets_label, 0, 3)
        
        # Row 2
        grid_layout.addWidget(QLabel("Remaining Targets:"), 1, 0)
        self.remaining_targets_label = QLabel("0")
        grid_layout.addWidget(self.remaining_targets_label, 1, 1)
        
        grid_layout.addWidget(QLabel("Open Services:"), 1, 2)
        self.open_services_label = QLabel("0")
        grid_layout.addWidget(self.open_services_label, 1, 3)
        
        # Row 3
        grid_layout.addWidget(QLabel("Brute-force Success:"), 2, 0)
        self.brute_success_label = QLabel("0")
        grid_layout.addWidget(self.brute_success_label, 2, 1)
        
        grid_layout.addWidget(QLabel("Scanned IPs:"), 2, 2)
        self.scanned_ips_label = QLabel("0/0")
        grid_layout.addWidget(self.scanned_ips_label, 2, 3)
        
        summary_layout.addLayout(grid_layout)
        
        # IP Progress bar
        self.ip_progress_bar = QProgressBar()
        self.ip_progress_bar.setRange(0, 100)
        self.ip_progress_bar.setFormat("%p%")
        self.ip_progress_bar.setStyleSheet("""
            QProgressBar {
                border: 1px solid #ccc;
                border-radius: 4px;
                text-align: center;
                background-color: #f0f0f0;
            }
            QProgressBar::chunk {
                background-color: #4CAF50;
                width: 10px;
            }
        """)
        summary_layout.addWidget(QLabel("IP Scan Progress:"))
        summary_layout.addWidget(self.ip_progress_bar)
        
        # Current target
        self.current_target_label = QLabel("Scanning: None")
        self.current_target_label.setStyleSheet("font-style: italic; color: #555;")
        summary_layout.addWidget(self.current_target_label)
        
        main_layout.addWidget(summary_frame)
        
        # Service Distribution and Activity
        h_layout = QHBoxLayout()
        h_layout.setSpacing(15)
        
        # Service distribution chart
        chart_frame = QFrame()
        chart_frame.setFrameShape(QFrame.StyledPanel)
        chart_frame.setStyleSheet("background-color: #ffffff; border-radius: 8px; padding: 10px;")
        chart_layout = QVBoxLayout(chart_frame)
        
        chart_title = QLabel("Open Service Distribution")
        chart_title.setFont(title_font)
        chart_layout.addWidget(chart_title)
        
        if QTCHART_AVAILABLE:
            self.chart = QChart()
            self.chart.setTitle("")
            self.chart.setAnimationOptions(QChart.SeriesAnimations)
            self.chart.legend().setVisible(True)
            self.chart.legend().setAlignment(Qt.AlignBottom)
            
            self.chart_view.setRenderHint(QPainter.Antialiasing)  # Sử dụng QPainter thay vì QChartView
            self.chart_view.setRenderHint(QChartView.Antialiasing)
            self.chart_view.setMinimumHeight(300)
            
            chart_layout.addWidget(self.chart_view)
        else:
            warning_label = QLabel("Charts unavailable. Please install PyQtChart.")
            warning_label.setStyleSheet("color: red; font-style: italic;")
            chart_layout.addWidget(warning_label)
        
        h_layout.addWidget(chart_frame, 1)
        
        # Recent activity table
        activity_frame = QFrame()
        activity_frame.setFrameShape(QFrame.StyledPanel)
        activity_frame.setStyleSheet("background-color: #ffffff; border-radius: 8px; padding: 10px;")
        activity_layout = QVBoxLayout(activity_frame)
        
        activity_title = QLabel("Recent Activity")
        activity_title.setFont(title_font)
        activity_layout.addWidget(activity_title)
        
        self.activity_table = QTableWidget()
        self.activity_table.setColumnCount(4)
        self.activity_table.setHorizontalHeaderLabels(["Time", "IP Address", "Port", "Action"])
        self.activity_table.setColumnWidth(0, 120)
        self.activity_table.setColumnWidth(1, 120)
        self.activity_table.setColumnWidth(2, 60)
        self.activity_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.activity_table.verticalHeader().setVisible(False)
        self.activity_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.activity_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.activity_table.setStyleSheet("""
            QTableWidget {
                gridline-color: #e0e0e0;
                border: none;
            }
            QHeaderView::section {
                background-color: #f0f0f0;
                padding: 4px;
                border: none;
            }
        """)
        
        activity_layout.addWidget(self.activity_table)
        h_layout.addWidget(activity_frame, 1)
        
        main_layout.addLayout(h_layout)
        
        # Parallel Execution Status
        parallel_frame = QFrame()
        parallel_frame.setFrameShape(QFrame.StyledPanel)
        parallel_frame.setStyleSheet("background-color: #f8f9fa; border-radius: 8px; padding: 10px;")
        parallel_layout = QVBoxLayout(parallel_frame)
        
        parallel_title = QLabel("Parallel Brute-force Status")
        parallel_title.setFont(title_font)
        parallel_layout.addWidget(parallel_title)
        
        self.parallel_status_label = QLabel("No brute-force running")
        parallel_layout.addWidget(self.parallel_status_label)
        
        main_layout.addWidget(parallel_frame)
        
        self.setLayout(main_layout)
    
    def update_stats(self, stats):
        self.stats = stats
        
        self.total_targets_label.setText(str(stats.get("total_targets", 0)))
        self.scanned_targets_label.setText(str(stats.get("scanned_targets", 0)))
        self.remaining_targets_label.setText(str(stats.get("remaining_targets", 0)))
        self.open_services_label.setText(str(stats.get("open_services", 0)))
        self.brute_success_label.setText(str(stats.get("brute_success", 0)))
        self.scanned_ips_label.setText(f"{stats.get('scanned_ips', 0)}/{stats.get('total_ips', 0)}")
        self.ip_progress_bar.setValue(stats.get("ip_progress", 0))
        
        current_target = stats.get("current_target", "")
        if current_target:
            self.current_target_label.setText(f"Scanning: {current_target}")
        else:
            self.current_target_label.setText("Scanning: None")
    
    def update_chart(self, service_distribution):
        if not QTCHART_AVAILABLE or not hasattr(self, 'chart'):
            return
            
        self.chart.removeAllSeries()
        
        if not service_distribution:
            return
        
        bar_set = QBarSet("Count")
        categories = []
        colors = [
            QColor(70, 130, 180),   # Steel blue
            QColor(46, 204, 113),    # Emerald green
            QColor(241, 196, 15),    # Sunflower yellow
            QColor(231, 76, 60),     # Alizarin red
            QColor(155, 89, 182),    # Amethyst purple
            QColor(26, 188, 156)     # Turquoise
        ]
        
        # Sort services by count
        sorted_services = sorted(service_distribution.items(), key=lambda x: x[1], reverse=True)
        
        for i, (service, count) in enumerate(sorted_services):
            bar_set.append(count)
            categories.append(service)
            if i < len(colors):
                bar_set.setColor(colors[i])
        
        bar_series = QBarSeries()
        bar_series.append(bar_set)
        bar_series.setLabelsVisible(True)
        bar_series.setLabelsPosition(QBarSeries.LabelsCenter)
        
        self.chart.addSeries(bar_series)
        
        axis_x = QBarCategoryAxis()
        axis_x.append(categories)
        self.chart.createDefaultAxes()
        self.chart.setAxisX(axis_x, bar_series)
        max_value = max(service_distribution.values()) * 1.2 if service_distribution else 1
        self.chart.axisY().setRange(0, max_value)
    
    def add_activity(self, ip, port, action):
        try:
            timestamp = QDateTime.currentDateTime().toString("HH:mm:ss")
            row_position = self.activity_table.rowCount()
            self.activity_table.insertRow(row_position)
            
            self.activity_table.setItem(row_position, 0, QTableWidgetItem(timestamp))
            self.activity_table.setItem(row_position, 1, QTableWidgetItem(str(ip)))
            self.activity_table.setItem(row_position, 2, QTableWidgetItem(str(port)))
            self.activity_table.setItem(row_position, 3, QTableWidgetItem(action))
            
            # Apply row coloring based on action
            if "success" in action.lower():
                color = QColor(220, 255, 220)  # Green for success
            elif "error" in action.lower() or "timeout" in action.lower():
                color = QColor(255, 220, 220)  # Red for errors
            elif "warning" in action.lower():
                color = QColor(255, 255, 200)  # Yellow for warnings
            else:
                color = QColor(240, 240, 240)  # Default
            
            for col in range(4):
                if self.activity_table.item(row_position, col):
                    self.activity_table.item(row_position, col).setBackground(color)
            
            # Scroll to bottom
            self.activity_table.scrollToBottom()
        except Exception as e:
            print(f"Error adding activity: {str(e)}")
    
    def update_parallel_status(self, active, queue_size):
        if active > 0 or queue_size > 0:
            status = f"Running: {active} threads | Queue: {queue_size} tasks"
            self.parallel_status_label.setText(status)
        else:
            self.parallel_status_label.setText("No brute-force running")