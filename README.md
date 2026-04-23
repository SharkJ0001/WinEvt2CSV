# Windows日志分析工具

基于开发要求实现的Windows日志分析工具，支持evtx格式日志文件的解析、分析和报告生成。

## 功能特性

### 核心功能
- **流式解析**：采用python-evtx库实现原生流式解析，支持大文件分段处理
- **多格式输出**：支持CSV、Excel、JSON、SQLite格式导出
- **HTML报告**：自动生成可视化分析报告
- **异常检测**：自动识别匿名登录、暴力破解等安全异常

### 分析能力
- 事件ID统计与占比分析
- 登录行为统计
- 匿名登录自动识别
- 暴力破解行为检测
- 异常账号/IP标记

## 安装依赖

```bash
pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
```

## 使用方法

### 命令行模式

```bash
# 解析单个evtx文件（默认输出CSV）
python evtx_parser.py Security.evtx

# 生成HTML报告
python evtx_parser.py Security.evtx --report

# 指定输出格式为JSON
python evtx_parser.py Security.evtx -f json --report

# 指定输出文件名为 my_report（CSV格式）
python evtx_parser.py Security.evtx -o my_report --report

# 组合使用 -o 和 -f：指定输出文件名和格式
python evtx_parser.py Security.evtx -o audit_log -f excel --report
python evtx_parser.py Security.evtx -o daily_report -f json
python evtx_parser.py Security.evtx -o security_data -f sqlite --report

# 批量解析目录中的evtx文件
python evtx_parser.py ./logs/ -o result --report

# 完整示例：所有参数组合
python evtx_parser.py Security.evtx -o my_analysis -f excel -b 50000 --report --compress
```

### 命令行参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| input | 输入文件路径或目录 | 必需 |
| -o, --output | 输出文件名前缀 | result |
| -f, --format | 输出格式 (csv/excel/json/sqlite) | csv |
| -b, --batch | 批量处理大小（仅对CSV格式生效） | 100000 |
| --report | 生成HTML报告 | 否 |
| --compress | 压缩原始日志文件 | 否 |

#### 参数说明

- **-b, --batch**：指定CSV文件的分块大小。当日志条数超过此值时，会自动分成多个文件（如 `output_part1.csv`, `output_part2.csv`）。**日常使用建议保持默认值，不要手动指定小数值**。
- **-o, --output**：指定输出文件名前缀，所有输出文件都会使用此前缀。
- **-f, --format**：指定输出格式，支持 `csv`（默认）、`excel`、`json`、`sqlite`。

### GUI模式

```bash
python gui_app.py
```
GUI选择日志文件，设置前缀，默认前缀为result可自定义，待解析完成导出文件
<img width="989" height="732" alt="image" src="https://github.com/user-attachments/assets/5f60a8b9-26f9-442b-b578-4e26b2462fd3" />

## 输出文件

输出文件名会跟随 `-o` 参数指定的前缀：

```bash
# 示例：使用 -o my_report
python evtx_parser.py Security.evtx -o my_report --report
```

生成的文件：
- `output/my_report.csv` - CSV格式日志数据
- `output/my_report.html` - HTML分析报告（使用 `--report` 参数）
- `output/my_report.json` - JSON格式输出（使用 `-f json` 参数）
- `output/my_report.db` - SQLite数据库（使用 `-f sqlite` 参数）
- `output/my_report.xlsx` - Excel文件（使用 `-f excel` 参数）

### 默认输出（不指定 -o 参数）

- `output/result.csv` - 解析后的日志数据
- `output/result.html` - HTML分析报告（使用 `--report` 参数）
- 输出的结果有两个文件一个是csv另一个是html报告
- csv可以用表格条件筛选也可以用脚本处理数据
- html报告是简单总结相关的日志ID数量，其他有功能需求可以自己加
<img width="1920" height="777" alt="image" src="https://github.com/user-attachments/assets/88e47e3d-da43-4b70-a52e-d51e79f9c24b" />
<img width="1920" height="891" alt="image" src="https://github.com/user-attachments/assets/ad410340-5937-4075-8233-ed9f15e6bbf4" />


### CSV分块输出机制

当日志条数较多时，CSV文件会自动分块输出：

```bash
# 日志条数 < 100,000 → 单个文件
output/my_report.csv

# 日志条数 >= 100,000 → 自动分块
output/my_report_part1.csv
output/my_report_part2.csv
output/my_report_part3.csv
...
```

**注意**：
- 分块大小由 `-b` 参数控制，默认值为 100,000
- 分块机制仅对CSV格式生效，其他格式始终生成单个文件
- **日常使用请保持 `-b` 参数默认值，不要手动设置小数值**（如 `-b 1000`），否则会生成大量小文件

### 文件类型说明

- CSV文件在Windows系统中会显示为"XLS工作表"类型，这是正常现象，双击可直接用Excel打开
- HTML报告可使用任何浏览器打开查看

## 常见问题

### Q: 为什么生成了很多 part 文件？

**A:** 这是因为使用了过小的 `-b` 参数值。例如 `-b 1000` 会强制每1000条日志生成一个文件。**日常使用请省略 `-b` 参数，使用默认值 100,000**。

### Q: CSV文件显示为XLS类型？

**A:** 这是Windows系统的正常行为，CSV文件被系统自动识别为Excel格式，双击可直接用Excel打开。

### Q: 如何清理多余的 part 文件？

**A:** 使用以下命令删除所有分块文件：
```bash
del output\*_part*.csv
```

### Q: EventRecordID 在CSV中是什么格式？

**A:** CSV中存储的是纯数字格式（如 `164909`），而不是XML标签格式。搜索时请直接搜索数字。

## 技术标准

- **编码标准**：UTF-8编码解析，UTF-8+BOM输出
- **容错机制**：遇到损坏日志自动跳过并记录异常
- **大数据量适配**：日志≥10万条时自动分页CSV导出
- **字段规范**：统一字段命名，支持Excel/WPS直接打开

## 支持的日志类型

- Security（安全日志）
- System（系统日志）
- Application（应用程序日志）
- Setup（安装日志）
- ForwardedEvents（转发日志）
