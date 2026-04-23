import os
import sys
import json
import sqlite3
import zipfile
import math
import csv
import re
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from typing import List, Dict, Any, Optional, Tuple

try:
    from Evtx.Evtx import Evtx
    from Evtx.Views import evtx_file_xml_view
    import xml.etree.ElementTree as ET
except ImportError:
    print("Error: python-evtx library not installed")
    sys.exit(1)

import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

class EVTXParser:
    def __init__(self):
        self.all_fields = set()
        self.event_count = 0
        self.parse_errors = []
        self.log_type_mapping = {
            'Security': 'Security',
            'System': 'System',
            'Application': 'Application',
            'Setup': 'Setup',
            'ForwardedEvents': 'ForwardedEvents'
        }
    
    def _xml_to_dict(self, element):
        result = {}
        tag = element.tag.split('}')[-1] if '}' in element.tag else element.tag
        
        if element.text and element.text.strip():
            result['#text'] = element.text.strip()
        
        for key, value in element.attrib.items():
            result['@' + key] = value
        
        for child in element:
            child_result = self._xml_to_dict(child)
            child_tag = child.tag.split('}')[-1] if '}' in child.tag else child.tag
            if child_tag in result:
                if isinstance(result[child_tag], list):
                    result[child_tag].append(child_result)
                else:
                    result[child_tag] = [result[child_tag], child_result]
            else:
                result[child_tag] = child_result
        
        return result
    
    def extract_event_data(self, xml_string: str) -> Dict[str, Any]:
        data = {}
        try:
            root = ET.fromstring(xml_string)
            
            ns = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}
            
            system_elem = root.find('ns:System', ns)
            if system_elem is not None:
                system_data = self._xml_to_dict(system_elem)
                
                event_id_val = system_data.get('EventID', '')
                if isinstance(event_id_val, dict):
                    event_id_val = event_id_val.get('#text', '')
                data['EventID'] = str(event_id_val)
                
                time_created_val = system_data.get('TimeCreated', {})
                if isinstance(time_created_val, dict):
                    time_created_val = time_created_val.get('@SystemTime', '')
                data['TimeCreated'] = time_created_val
                
                level_val = system_data.get('Level', '')
                if isinstance(level_val, dict):
                    level_val = level_val.get('#text', '')
                data['Level'] = str(level_val)
                
                provider_val = system_data.get('Provider', {})
                if isinstance(provider_val, dict):
                    provider_val = provider_val.get('@Name', '')
                data['ProviderName'] = provider_val
                
                channel_val = system_data.get('Channel', '')
                if isinstance(channel_val, dict):
                    channel_val = channel_val.get('#text', '')
                data['Channel'] = channel_val
                
                computer_val = system_data.get('Computer', '')
                if isinstance(computer_val, dict):
                    computer_val = computer_val.get('#text', '')
                data['Computer'] = computer_val
                
                security_val = system_data.get('Security', {})
                if isinstance(security_val, dict):
                    security_val = security_val.get('@UserID', '')
                data['Security'] = security_val
                
                record_id_val = system_data.get('EventRecordID', '')
                if isinstance(record_id_val, dict):
                    record_id_val = record_id_val.get('#text', '')
                elif callable(record_id_val):
                    record_id_val = ''
                data['EventRecordID'] = str(record_id_val)
                
                exec_val = system_data.get('Execution', {})
                if isinstance(exec_val, dict):
                    data['ProcessID'] = exec_val.get('@ProcessID', '')
                    data['ThreadID'] = exec_val.get('@ThreadID', '')
                else:
                    data['ProcessID'] = ''
                    data['ThreadID'] = ''
                
                keywords_val = system_data.get('Keywords', '')
                if isinstance(keywords_val, dict):
                    keywords_val = keywords_val.get('#text', '')
                data['Keywords'] = keywords_val
            
            event_data_elem = root.find('ns:EventData', ns)
            if event_data_elem is not None:
                event_data = self._xml_to_dict(event_data_elem)
                data['Data'] = json.dumps(event_data, ensure_ascii=False)
                
                data_items = event_data.get('Data', [])
                if isinstance(data_items, list):
                    for item in data_items:
                        if isinstance(item, dict) and '@Name' in item:
                            name = item['@Name']
                            value = item.get('#text', item.get('$', ''))
                            data[name] = value
                elif isinstance(data_items, dict) and '@Name' in data_items:
                    name = data_items['@Name']
                    value = data_items.get('#text', data_items.get('$', ''))
                    data[name] = value
            
            self.all_fields.update(data.keys())
            
        except Exception as e:
            self.parse_errors.append({
                'record_id': 'unknown',
                'error': str(e)
            })
        
        return data
    
    def parse_file(self, file_path: str, batch_size: int = 100000):
        events = []
        log_type = self._detect_log_type(file_path)
        
        try:
            with Evtx(file_path) as evtx:
                for record in evtx.records():
                    try:
                        xml_string = record.xml()
                        event_data = self.extract_event_data(xml_string)
                        event_data['日志类型'] = log_type
                        event_data['通道名称'] = event_data.get('Channel', log_type)
                        event_data['主机名'] = event_data.get('Computer', '')
                        event_data['EventRecordID'] = str(record.record_num())
                        
                        events.append(event_data)
                        self.event_count += 1
                        
                        if len(events) >= batch_size:
                            yield events
                            events = []
                            
                    except Exception as e:
                        self.parse_errors.append({
                            'record_id': record.record_num() if hasattr(record, 'record_num') else 'unknown',
                            'error': str(e)
                        })
            
            if events:
                yield events
                
        except Exception as e:
            self.parse_errors.append({
                'record_id': 'file_error',
                'error': str(e)
            })
    
    def _detect_log_type(self, file_path: str) -> str:
        filename = os.path.basename(file_path).lower()
        for key in self.log_type_mapping:
            if key.lower() in filename:
                return key
        return 'Unknown'

class LogAnalyzer:
    def __init__(self):
        self.login_events = []
        self.event_id_stats = Counter()
        self.anomaly_records = []
        self.anonymous_logins = []
        self.brute_force_attempts = []
        self.lateral_movement = []
        
        self.work_hours_start = 9
        self.work_hours_end = 18
        
        self.suspicious_accounts = {'guest', 'anonymous', '', 'null'}
        self.sensitive_commands = {'Invoke-Mimikatz', 'powershell -enc', '-nop', '-w hidden'}
    
    def analyze_events(self, events: List[Dict[str, Any]]):
        for event in events:
            self._analyze_event_id(event)
            
            log_type = event.get('日志类型', event.get('Channel', '')).lower()
            
            if log_type in ['security', 'security.evtx']:
                self._analyze_login_behavior(event)
                self._detect_anonymous_login(event)
                self._detect_anomaly_account(event)
            elif log_type in ['application', 'application.evtx']:
                self._detect_application_anomaly(event)
            elif log_type in ['system', 'system.evtx']:
                self._detect_system_anomaly(event)
    
    def _analyze_event_id(self, event: Dict[str, Any]):
        event_id = event.get('EventID')
        if event_id:
            self.event_id_stats[event_id] += 1
    
    def _analyze_login_behavior(self, event: Dict[str, Any]):
        event_id = event.get('EventID')
        if event_id in ['4624', '4625', 4624, 4625]:
            login_info = {
                'event_id': event_id,
                'time': event.get('TimeCreated'),
                'account': event.get('TargetUserName', event.get('SubjectUserName', '')),
                'ip': event.get('IpAddress', event.get('IpAddr', '')),
                'logon_type': event.get('LogonType', event.get('Logon_Type', '')),
                'computer': event.get('Computer', ''),
                'status': 'success' if str(event_id) == '4624' else 'failure'
            }
            self.login_events.append(login_info)
    
    def _detect_anonymous_login(self, event: Dict[str, Any]):
        event_id = event.get('EventID')
        account = event.get('TargetUserName', event.get('SubjectUserName', '')).lower()
        
        if account in self.suspicious_accounts:
            self.anonymous_logins.append({
                'time': event.get('TimeCreated'),
                'account': account,
                'event_id': event_id,
                'computer': event.get('Computer', ''),
                'ip': event.get('IpAddress', '')
            })
            self.anomaly_records.append({
                'type': 'anonymous_login',
                'severity': 'high',
                **event
            })
        
        logon_type = event.get('LogonType', event.get('Logon_Type', ''))
        if str(logon_type) in ['3', '10'] and not account:
            self.anonymous_logins.append({
                'time': event.get('TimeCreated'),
                'account': 'empty',
                'event_id': event_id,
                'computer': event.get('Computer', ''),
                'logon_type': logon_type
            })
    
    def _detect_anomaly_account(self, event: Dict[str, Any]):
        account = event.get('TargetUserName', event.get('SubjectUserName', '')).lower()
        
        if account and (len(account) < 3 or len(account) > 50 or 
                       re.search(r'[^a-zA-Z0-9_\-]', account)):
            self.anomaly_records.append({
                'type': 'suspicious_account_name',
                'severity': 'medium',
                **event
            })
        
        cmdline = event.get('CommandLine', '').lower()
        for cmd in self.sensitive_commands:
            if cmd.lower() in cmdline:
                self.anomaly_records.append({
                    'type': 'sensitive_command',
                    'severity': 'high',
                    **event
                })
                break
    
    def _detect_application_anomaly(self, event: Dict[str, Any]):
        event_id = event.get('EventID')
        
        if event_id in ['1000', 1000]:
            self.anomaly_records.append({
                'type': 'application_crash',
                'severity': 'medium',
                **event
            })
        
        elif event_id in ['1026', 1026]:
            self.anomaly_records.append({
                'type': 'dotnet_error',
                'severity': 'medium',
                **event
            })
    
    def _detect_system_anomaly(self, event: Dict[str, Any]):
        event_id = event.get('EventID')
        
        if event_id in ['7031', '7034', 7031, 7034]:
            source = event.get('SourceName', '').lower()
            if 'defend' in source or 'sam' in source or 'security' in source:
                self.anomaly_records.append({
                    'type': 'security_service_crash',
                    'severity': 'high',
                    **event
                })
            else:
                self.anomaly_records.append({
                    'type': 'service_crash',
                    'severity': 'medium',
                    **event
                })
        
        elif event_id in ['1074', 1074]:
            self.anomaly_records.append({
                'type': 'system_shutdown',
                'severity': 'low',
                **event
            })
        
        elif event_id in ['41', 41]:
            self.anomaly_records.append({
                'type': 'unexpected_shutdown',
                'severity': 'high',
                **event
            })
        
        elif event_id in ['10016', 10016]:
            self.anomaly_records.append({
                'type': 'dcom_permission_error',
                'severity': 'medium',
                **event
            })
    
    def detect_brute_force(self, threshold: int = 10, time_window_minutes: int = 5):
        failure_counts = defaultdict(list)
        
        for login in self.login_events:
            if login['status'] == 'failure':
                key = login['ip'] if login['ip'] else 'unknown'
                failure_counts[key].append(login['time'])
        
        results = []
        for ip, times in failure_counts.items():
            if len(times) >= threshold:
                times.sort()
                first_time = self._parse_time(times[0])
                last_time = self._parse_time(times[-1])
                
                if first_time and last_time:
                    duration = (last_time - first_time).total_seconds() / 60
                    if duration <= time_window_minutes:
                        self.brute_force_attempts.append({
                            'ip': ip,
                            'attempts': len(times),
                            'first_attempt': times[0],
                            'last_attempt': times[-1]
                        })
                        results.append(ip)
        
        return results
    
    def _parse_time(self, time_str: str) -> Optional[datetime]:
        if not time_str:
            return None
        formats = ['%Y-%m-%d %H:%M:%S.%f', '%Y-%m-%dT%H:%M:%S.%fZ', 
                   '%Y-%m-%d %H:%M:%S', '%Y-%m-%dT%H:%M:%SZ']
        for fmt in formats:
            try:
                return datetime.strptime(time_str, fmt)
            except ValueError:
                continue
        return None

class OutputExporter:
    def __init__(self):
        self.output_dir = 'output'
        os.makedirs(self.output_dir, exist_ok=True)
    
    def export_csv(self, events: List[Dict[str, Any]], filename: str, batch_size: int = 100000):
        if not events:
            return []
        
        all_fields = set()
        for event in events:
            all_fields.update(event.keys())
        
        sorted_fields = sorted(list(all_fields))
        
        file_paths = []
        total_batches = math.ceil(len(events) / batch_size)
        
        for batch_idx in range(total_batches):
            start = batch_idx * batch_size
            end = min(start + batch_size, len(events))
            batch_events = events[start:end]
            
            if total_batches > 1:
                batch_filename = f"{filename}_part{batch_idx + 1}.csv"
            else:
                batch_filename = f"{filename}.csv"
            
            filepath = os.path.join(self.output_dir, batch_filename)
            
            with open(filepath, 'w', encoding='utf-8-sig', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=sorted_fields)
                writer.writeheader()
                writer.writerows(batch_events)
            
            file_paths.append(filepath)
        
        return file_paths
    
    def export_excel(self, events: List[Dict[str, Any]], filename: str):
        if not events:
            return None
        
        df = pd.DataFrame(events)
        filepath = os.path.join(self.output_dir, f"{filename}.xlsx")
        df.to_excel(filepath, index=False, encoding='utf-8-sig')
        return filepath
    
    def export_json(self, events: List[Dict[str, Any]], filename: str):
        filepath = os.path.join(self.output_dir, f"{filename}.json")
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(events, f, ensure_ascii=False, indent=2)
        return filepath
    
    def export_sqlite(self, events: List[Dict[str, Any]], filename: str):
        filepath = os.path.join(self.output_dir, f"{filename}.db")
        
        with sqlite3.connect(filepath) as conn:
            df = pd.DataFrame(events)
            df.to_sql('events', conn, if_exists='replace', index=False)
        
        return filepath
    
    def generate_html_report(self, analyzer: LogAnalyzer, events: List[Dict[str, Any]], 
                            filename: str = 'report') -> str:
        report_data = {
            'total_events': len(events),
            'event_id_stats': analyzer.event_id_stats.most_common(20),
            'anonymous_logins': analyzer.anonymous_logins[:50],
            'brute_force_attempts': analyzer.brute_force_attempts[:20],
            'anomaly_count': len(analyzer.anomaly_records),
            'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        html_content = self._generate_html_content(report_data)
        filepath = os.path.join(self.output_dir, f"{filename}.html")
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return filepath
    
    def _generate_html_content(self, data: Dict[str, Any]) -> str:
        return f"""
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Windows日志分析报告</title>
    <style>
        body {{ font-family: 'Microsoft YaHei', sans-serif; margin: 20px; background: #f5f5f5; }}
        .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 8px; }}
        .section {{ background: white; padding: 20px; margin: 15px 0; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h2 {{ color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
        th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        th {{ background: #3498db; color: white; }}
        tr:nth-child(even) {{ background: #f2f2f2; }}
        .summary {{ display: flex; gap: 20px; flex-wrap: wrap; }}
        .summary-item {{ background: #ecf0f1; padding: 15px 25px; border-radius: 8px; }}
        .severity-high {{ color: #e74c3c; font-weight: bold; }}
        .severity-medium {{ color: #f39c12; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Windows日志分析报告</h1>
        <p>生成时间: {data['generated_at']}</p>
    </div>
    
    <div class="section">
        <h2>概览</h2>
        <div class="summary">
            <div class="summary-item"><strong>日志总数:</strong> {data['total_events']:,}</div>
            <div class="summary-item"><strong>检测到异常:</strong> {data['anomaly_count']}</div>
            <div class="summary-item"><strong>匿名登录:</strong> {len(data['anonymous_logins'])}</div>
            <div class="summary-item"><strong>疑似爆破:</strong> {len(data['brute_force_attempts'])}</div>
        </div>
    </div>
    
    <div class="section">
        <h2>事件ID统计 (Top 20)</h2>
        <table>
            <tr><th>事件ID</th><th>数量</th><th>占比</th></tr>
            {''.join([f'<tr><td>{eid}</td><td>{cnt}</td><td>{(cnt/data["total_events"]*100):.2f}%</td></tr>' 
                     for eid, cnt in data['event_id_stats']])}
        </table>
    </div>
    
    <div class="section">
        <h2>匿名登录记录</h2>
        {self._render_table(data['anonymous_logins'], ['time', 'account', 'event_id', 'computer', 'ip']) if data['anonymous_logins'] else '<p>无记录</p>'}
    </div>
    
    <div class="section">
        <h2>疑似暴力破解</h2>
        {self._render_table(data['brute_force_attempts'], ['ip', 'attempts', 'first_attempt', 'last_attempt']) if data['brute_force_attempts'] else '<p>无记录</p>'}
    </div>
</body>
</html>
"""
    
    def _render_table(self, data: List[Dict], columns: List[str]) -> str:
        if not data:
            return '<p>无记录</p>'
        
        header = ''.join([f'<th>{col}</th>' for col in columns])
        rows = []
        for item in data:
            cells = ''.join([f'<td>{item.get(col, "")}</td>' for col in columns])
            rows.append(f'<tr>{cells}</tr>')
        
        return f"""
<table>
    <tr>{header}</tr>
    {''.join(rows)}
</table>
"""

class LogCompressor:
    @staticmethod
    def compress_logs(file_paths: List[str], output_dir: str = 'archive') -> str:
        os.makedirs(output_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        archive_path = os.path.join(output_dir, f'logs_{timestamp}.zip')
        
        with zipfile.ZipFile(archive_path, 'w', zipfile.ZIP_DEFLATED) as zf:
            for filepath in file_paths:
                if os.path.exists(filepath):
                    zf.write(filepath, os.path.basename(filepath))
        
        return archive_path

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Windows日志分析工具')
    parser.add_argument('input', help='输入evtx文件路径或目录')
    parser.add_argument('-o', '--output', default='result', help='输出文件名前缀')
    parser.add_argument('-f', '--format', choices=['csv', 'excel', 'json', 'sqlite'], 
                        default='csv', help='输出格式')
    parser.add_argument('-b', '--batch', type=int, default=100000, help='批量处理大小')
    parser.add_argument('--report', action='store_true', help='生成HTML报告')
    parser.add_argument('--compress', action='store_true', help='压缩原始日志')
    
    args = parser.parse_args()
    
    input_path = args.input
    all_events = []
    
    if os.path.isfile(input_path):
        files = [input_path]
    elif os.path.isdir(input_path):
        files = [os.path.join(input_path, f) for f in os.listdir(input_path) 
                 if f.lower().endswith('.evtx')]
    else:
        print(f"错误: 路径不存在 {input_path}")
        sys.exit(1)
    
    print(f"发现 {len(files)} 个日志文件")
    
    parser = EVTXParser()
    analyzer = LogAnalyzer()
    
    for file_path in files:
        print(f"正在解析: {file_path}")
        for batch in parser.parse_file(file_path, args.batch):
            all_events.extend(batch)
            analyzer.analyze_events(batch)
            print(f"已解析: {len(all_events):,} 条记录")
    
    analyzer.detect_brute_force()
    
    exporter = OutputExporter()
    
    if args.format == 'csv':
        exported_files = exporter.export_csv(all_events, args.output, args.batch)
        print(f"CSV文件已导出: {exported_files}")
    elif args.format == 'excel':
        exported_file = exporter.export_excel(all_events, args.output)
        print(f"Excel文件已导出: {exported_file}")
    elif args.format == 'json':
        exported_file = exporter.export_json(all_events, args.output)
        print(f"JSON文件已导出: {exported_file}")
    elif args.format == 'sqlite':
        exported_file = exporter.export_sqlite(all_events, args.output)
        print(f"SQLite文件已导出: {exported_file}")
    
    if args.report:
        report_path = exporter.generate_html_report(analyzer, all_events, args.output)
        print(f"HTML报告已生成: {report_path}")
    
    if args.compress:
        archive_path = LogCompressor.compress_logs(files)
        print(f"日志已压缩: {archive_path}")
    
    if parser.parse_errors:
        error_file = os.path.join('output', 'parse_errors.txt')
        with open(error_file, 'w', encoding='utf-8') as f:
            for error in parser.parse_errors:
                f.write(f"{error}\n")
        print(f"解析错误已记录: {error_file}")
    
    print("\n分析完成!")

if __name__ == '__main__':
    main()
