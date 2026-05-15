import sys
import os
import json
import subprocess
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QPushButton, QLineEdit, QFileDialog, QLabel, QProgressBar,
                             QTextEdit, QComboBox, QCheckBox, QGroupBox, QTabWidget,
                             QTableWidget, QTableWidgetItem, QHeaderView, QMessageBox,
                             QSpinBox, QSplitter, QAction, QToolBar)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QObject, QTimer
from PyQt5.QtGui import QIcon, QFont

from evtx_parser import EVTXParser, LogAnalyzer, OutputExporter, LogCompressor

class ParseThread(QThread):
    progress = pyqtSignal(int)
    message = pyqtSignal(str)
    completed = pyqtSignal(list)
    error = pyqtSignal(str)
    stats = pyqtSignal(int, int, int)
    
    def __init__(self, file_paths, batch_size):
        super().__init__()
        self.file_paths = file_paths
        self.batch_size = batch_size
        self.running = True
        self.total_events = 0
        self.error_count = 0
    
    def run(self):
        try:
            parser = EVTXParser()
            all_events = []
            total_files = len(self.file_paths)
            processed_files = 0
            
            for idx, file_path in enumerate(self.file_paths):
                if not self.running:
                    return
                    
                processed_files += 1
                self.message.emit(f"正在解析 [{processed_files}/{total_files}]: {os.path.basename(file_path)}")
                
                try:
                    file_events = []
                    for batch in parser.parse_file(file_path, self.batch_size):
                        if not self.running:
                            return
                        file_events.extend(batch)
                        self.total_events += len(batch)
                        
                        progress = int((((idx + len(file_events) / (self.batch_size * 10)) / total_files)) * 100)
                        self.progress.emit(min(progress, 95))
                        self.stats.emit(self.total_events, self.error_count, processed_files)
                    
                    all_events.extend(file_events)
                    self.message.emit(f"  已处理: {len(file_events):,} 条记录")
                    
                except Exception as e:
                    self.error_count += 1
                    self.message.emit(f"  警告: {str(e)}")
            
            if parser.parse_errors:
                self.error_count += len(parser.parse_errors)
                self.message.emit(f"解析完成，共 {len(all_events):,} 条记录，{len(parser.parse_errors)} 条错误")
            else:
                self.message.emit(f"解析完成，共 {len(all_events):,} 条记录")
                
            self.progress.emit(100)
            self.completed.emit(all_events)
            
        except Exception as e:
            self.error.emit(str(e))
    
    def stop(self):
        self.running = False

class ExportThread(QThread):
    progress = pyqtSignal(int)
    message = pyqtSignal(str)
    completed = pyqtSignal(str, list)
    error = pyqtSignal(str)
    
    def __init__(self, events, output_format, output_prefix, batch_size, generate_report, compress):
        super().__init__()
        self.events = events
        self.output_format = output_format
        self.output_prefix = output_prefix
        self.batch_size = batch_size
        self.generate_report = generate_report
        self.compress = compress
        self.file_paths = []
    
    def run(self):
        try:
            exporter = OutputExporter()
            self.message.emit("开始导出...")
            
            if self.output_format == 'csv':
                exported = exporter.export_csv(self.events, self.output_prefix, self.batch_size)
                self.message.emit(f"CSV导出完成: {len(exported)} 个文件")
                if len(exported) == 1:
                    self.file_paths = [os.path.join('output', f"{self.output_prefix}.csv")]
                else:
                    self.file_paths = [os.path.join('output', f"{self.output_prefix}_{i}.csv") for i in range(len(exported))]
            
            elif self.output_format == 'excel':
                exported = exporter.export_excel(self.events, self.output_prefix)
                self.message.emit(f"Excel导出完成: {exported}")
                self.file_paths = [exported]
            
            elif self.output_format == 'json':
                exported = exporter.export_json(self.events, self.output_prefix)
                self.message.emit(f"JSON导出完成: {exported}")
                self.file_paths = [exported]
            
            elif self.output_format == 'sqlite':
                exported = exporter.export_sqlite(self.events, self.output_prefix)
                self.message.emit(f"SQLite导出完成: {exported}")
                self.file_paths = [exported]
            
            self.progress.emit(50)
            
            if self.generate_report:
                analyzer = LogAnalyzer()
                analyzer.analyze_events(self.events)
                report_path = exporter.generate_html_report(analyzer, self.events, self.output_prefix)
                self.message.emit(f"HTML报告已生成: {report_path}")
                self.file_paths.append(report_path)
            
            self.progress.emit(80)
            
            if self.compress:
                archive_path = LogCompressor.compress_logs(self.file_paths)
                self.message.emit(f"文件已压缩: {archive_path}")
            
            self.progress.emit(100)
            self.completed.emit("导出完成", self.file_paths)
            
        except Exception as e:
            self.error.emit(str(e))

class LogAnalysisGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("WinEvt2CSV-v3.1_Shark")
        self.setGeometry(100, 100, 1000, 650)
        self.setMinimumSize(800, 500)
        
        self.events = []
        self.total_events = 0
        self.error_count = 0
        self.processed_files = 0
        
        self.init_ui()
    
    def init_ui(self):
        self.create_toolbar()
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QHBoxLayout(central_widget)
        
        left_panel = QWidget()
        left_panel.setFixedWidth(320)
        left_layout = QVBoxLayout(left_panel)
        
        stats_group = QGroupBox("解析统计")
        stats_layout = QHBoxLayout(stats_group)
        
        self.stats_labels = {
            'events': QLabel("记录数: 0"),
            'errors': QLabel("错误数: 0"),
            'files': QLabel("文件数: 0")
        }
        
        for label in self.stats_labels.values():
            stats_layout.addWidget(label)
        
        left_layout.addWidget(stats_group)
        
        file_group = QGroupBox("文件选择")
        file_layout = QVBoxLayout(file_group)
        
        self.file_path_edit = QLineEdit()
        self.file_path_edit.setPlaceholderText("选择evtx文件或目录")
        
        browse_btn = QPushButton("浏览")
        browse_btn.clicked.connect(self.browse_files)
        
        self.file_list_label = QLabel("已选择: 0 个文件")
        
        file_layout.addWidget(self.file_path_edit)
        file_layout.addWidget(browse_btn)
        file_layout.addWidget(self.file_list_label)
        
        left_layout.addWidget(file_group)
        
        log_type_group = QGroupBox("日志通道选择")
        log_type_layout = QVBoxLayout(log_type_group)
        
        self.log_type_checkboxes = {}
        for log_type in ['Security', 'System', 'Application', 'Setup', 'ForwardedEvents']:
            cb = QCheckBox(log_type)
            cb.setChecked(True)
            self.log_type_checkboxes[log_type] = cb
            log_type_layout.addWidget(cb)
        
        left_layout.addWidget(log_type_group)
        
        options_group = QGroupBox("输出选项")
        options_layout = QVBoxLayout(options_group)
        
        format_layout = QHBoxLayout()
        format_layout.addWidget(QLabel("输出格式:"))
        self.format_combo = QComboBox()
        self.format_combo.addItems(['csv', 'excel', 'json', 'sqlite'])
        format_layout.addWidget(self.format_combo)
        options_layout.addLayout(format_layout)
        
        prefix_layout = QHBoxLayout()
        prefix_layout.addWidget(QLabel("输出前缀:"))
        self.output_prefix_edit = QLineEdit("result")
        prefix_layout.addWidget(self.output_prefix_edit)
        options_layout.addLayout(prefix_layout)
        
        batch_layout = QHBoxLayout()
        batch_layout.addWidget(QLabel("批量大小:"))
        self.batch_spin = QSpinBox()
        self.batch_spin.setRange(10000, 500000)
        self.batch_spin.setValue(100000)
        batch_layout.addWidget(self.batch_spin)
        options_layout.addLayout(batch_layout)
        
        self.report_checkbox = QCheckBox("生成HTML报告")
        self.report_checkbox.setChecked(True)
        options_layout.addWidget(self.report_checkbox)
        
        self.compress_checkbox = QCheckBox("压缩原始日志")
        options_layout.addWidget(self.compress_checkbox)
        
        self.open_folder_checkbox = QCheckBox("导出后打开目录")
        self.open_folder_checkbox.setChecked(True)
        options_layout.addWidget(self.open_folder_checkbox)
        
        left_layout.addWidget(options_group)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setAlignment(Qt.AlignCenter)
        left_layout.addWidget(self.progress_bar)
        
        button_layout = QHBoxLayout()
        
        self.parse_btn = QPushButton("开始解析")
        self.parse_btn.clicked.connect(self.start_parse)
        button_layout.addWidget(self.parse_btn)
        
        self.stop_btn = QPushButton("停止")
        self.stop_btn.clicked.connect(self.stop_parse)
        self.stop_btn.setEnabled(False)
        button_layout.addWidget(self.stop_btn)
        
        left_layout.addLayout(button_layout)
        
        self.export_btn = QPushButton("导出结果")
        self.export_btn.clicked.connect(self.start_export)
        self.export_btn.setEnabled(False)
        left_layout.addWidget(self.export_btn)
        
        main_layout.addWidget(left_panel)
        
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        
        self.tabs = QTabWidget()
        
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.tabs.addTab(self.log_text, "日志")
        
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(7)
        self.results_table.setHorizontalHeaderLabels(['事件ID', '时间', '级别', '来源', '账户', 'IP', '类型'])
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.results_table.setAlternatingRowColors(True)
        self.tabs.addTab(self.results_table, "结果预览")
        
        self.error_tab = QTextEdit()
        self.error_tab.setReadOnly(True)
        self.tabs.addTab(self.error_tab, "错误日志")
        
        right_layout.addWidget(self.tabs)
        main_layout.addWidget(right_panel)
        
        self.status_bar = self.statusBar()
        self.status_bar.showMessage("就绪")
    
    def create_toolbar(self):
        toolbar = QToolBar("工具栏")
        self.addToolBar(toolbar)
        
        clear_action = QAction("清空日志", self)
        clear_action.triggered.connect(self.clear_log)
        toolbar.addAction(clear_action)
        
        save_log_action = QAction("保存日志", self)
        save_log_action.triggered.connect(self.save_log)
        toolbar.addAction(save_log_action)
        
        toolbar.addSeparator()
        
        about_action = QAction("关于", self)
        about_action.triggered.connect(self.show_about)
        toolbar.addAction(about_action)
    
    def browse_files(self):
        dialog = QFileDialog()
        dialog.setFileMode(QFileDialog.ExistingFiles)
        dialog.setNameFilter("EVTX文件 (*.evtx)")
        
        if dialog.exec_():
            files = dialog.selectedFiles()
            self.selected_files = files
            self.file_path_edit.setText("; ".join(files))
            self.file_list_label.setText(f"已选择: {len(files)} 个文件")
    
    def start_parse(self):
        if not hasattr(self, 'selected_files') or not self.selected_files:
            QMessageBox.warning(self, "警告", "请先选择日志文件")
            return
        
        self.log_text.clear()
        self.error_tab.clear()
        self.log_text.append("开始解析日志文件...")
        self.total_events = 0
        self.error_count = 0
        self.processed_files = 0
        
        self.parse_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.export_btn.setEnabled(False)
        self.progress_bar.setValue(0)
        
        self.parse_thread = ParseThread(self.selected_files, self.batch_spin.value())
        self.parse_thread.progress.connect(self.update_progress)
        self.parse_thread.message.connect(self.log_message)
        self.parse_thread.completed.connect(self.on_parse_completed)
        self.parse_thread.error.connect(self.on_error)
        self.parse_thread.stats.connect(self.update_stats)
        self.parse_thread.start()
    
    def stop_parse(self):
        if hasattr(self, 'parse_thread') and self.parse_thread.isRunning():
            self.parse_thread.stop()
            self.log_text.append("正在停止解析...")
            self.stop_btn.setEnabled(False)
    
    def update_progress(self, value):
        self.progress_bar.setValue(value)
    
    def update_stats(self, events, errors, files):
        self.total_events = events
        self.error_count = errors
        self.processed_files = files
        self.stats_labels['events'].setText(f"记录数: {events:,}")
        self.stats_labels['errors'].setText(f"错误数: {errors:,}")
        self.stats_labels['files'].setText(f"文件数: {files}")
    
    def log_message(self, msg):
        self.log_text.append(msg)
        self.status_bar.showMessage(msg)
        if "错误" in msg or "警告" in msg:
            self.error_tab.append(msg)
    
    def on_parse_completed(self, events):
        self.events = events
        self.log_text.append(f"解析完成，共 {len(events):,} 条记录")
        self.parse_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.export_btn.setEnabled(True)
        self.progress_bar.setValue(100)
        self.stats_labels['events'].setText(f"记录数: {len(events):,}")
        
        self.update_results_table(events[:100])
    
    def on_error(self, msg):
        QMessageBox.critical(self, "错误", f"解析失败: {msg}")
        self.log_text.append(f"错误: {msg}")
        self.error_tab.append(f"错误: {msg}")
        self.parse_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
    
    def update_results_table(self, events):
        self.results_table.setRowCount(len(events))
        for row, event in enumerate(events):
            self.results_table.setItem(row, 0, QTableWidgetItem(str(event.get('EventID', ''))))
            self.results_table.setItem(row, 1, QTableWidgetItem(str(event.get('TimeCreated', ''))))
            self.results_table.setItem(row, 2, QTableWidgetItem(str(event.get('Level', ''))))
            self.results_table.setItem(row, 3, QTableWidgetItem(str(event.get('ProviderName', ''))))
            self.results_table.setItem(row, 4, QTableWidgetItem(str(event.get('TargetUserName', event.get('SubjectUserName', '')))))
            self.results_table.setItem(row, 5, QTableWidgetItem(str(event.get('IpAddress', ''))))
            self.results_table.setItem(row, 6, QTableWidgetItem(str(event.get('日志类型', ''))))
    
    def start_export(self):
        if not self.events:
            QMessageBox.warning(self, "警告", "没有可导出的数据")
            return
        
        self.export_btn.setEnabled(False)
        self.progress_bar.setValue(0)
        
        self.export_thread = ExportThread(
            self.events,
            self.format_combo.currentText(),
            self.output_prefix_edit.text(),
            self.batch_spin.value(),
            self.report_checkbox.isChecked(),
            self.compress_checkbox.isChecked()
        )
        self.export_thread.progress.connect(self.update_progress)
        self.export_thread.message.connect(self.log_message)
        self.export_thread.completed.connect(self.on_export_completed)
        self.export_thread.error.connect(self.on_export_error)
        self.export_thread.start()
    
    def on_export_completed(self, msg, file_paths):
        self.log_text.append(msg)
        self.export_btn.setEnabled(True)
        
        if self.open_folder_checkbox.isChecked() and file_paths:
            output_dir = os.path.dirname(os.path.abspath(file_paths[0]))
            try:
                if os.name == 'nt':
                    subprocess.run(['explorer', output_dir], check=True)
                else:
                    subprocess.run(['open', output_dir], check=True)
            except Exception as e:
                self.log_text.append(f"无法打开目录: {e}")
        
        QMessageBox.information(self, "完成", "导出完成！")
    
    def on_export_error(self, msg):
        QMessageBox.critical(self, "错误", f"导出失败: {msg}")
        self.log_text.append(f"错误: {msg}")
        self.error_tab.append(f"导出错误: {msg}")
        self.export_btn.setEnabled(True)
    
    def clear_log(self):
        self.log_text.clear()
        self.error_tab.clear()
    
    def save_log(self):
        if not self.log_text.toPlainText():
            QMessageBox.warning(self, "警告", "没有日志可保存")
            return
        
        file_path, _ = QFileDialog.getSaveFileName(self, "保存日志", "parse_log.txt", "Text Files (*.txt)")
        if file_path:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(self.log_text.toPlainText())
            self.log_text.append(f"日志已保存到: {file_path}")
    
    def show_about(self):
        QMessageBox.information(self, "关于", 
            "Windows日志分析工具 v2.0\n\n"
            "功能:\n"
            "- 支持EVTX日志文件解析\n"
            "- 多格式输出（CSV、Excel、JSON、SQLite）\n"
            "- HTML报告自动生成\n"
            "- 异常行为检测\n"
            "- 时间时区自动转换")

def main():
    app = QApplication(sys.argv)
    window = LogAnalysisGUI()
    window.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
