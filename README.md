# 🔍 Real-Time System Monitor

A powerful, high-performance command-line tool for real-time system analysis, process monitoring, and network traffic inspection. Built with Python and featuring a beautiful terminal UI using the Rich library.

## ✨ Features

- **Real-Time System Analysis**
  - CPU usage (overall and per-core)
  - Memory and swap usage
  - Disk usage for all partitions
  - System load averages

- **Process Monitoring**
  - Top processes sorted by CPU or memory usage
  - Process details: PID, name, CPU%, memory%, threads, status
  - Real-time updates with color-coded indicators
  - Customizable number of processes displayed

- **Network Traffic Inspection**
  - Network I/O statistics (bytes sent/received, packets)
  - Active network connections
  - Connection details: local/remote addresses, status, type
  - Error and drop statistics

- **Beautiful Terminal UI**
  - Modern, colorful interface with Rich library
  - Real-time updates with smooth refresh
  - Color-coded metrics (green/yellow/red thresholds)
  - Organized layout with panels and tables

- **High Performance**
  - Efficient data collection using psutil
  - Optimized refresh rates
  - Minimal resource overhead
  - Fast and responsive

## 🚀 Installation

1. **Clone or download this repository**

2. **Install Python dependencies:**
   
   **Windows:**
   ```bash
   setup.bat
   ```
   
   **Linux/macOS:**
   ```bash
   chmod +x setup.sh
   ./setup.sh
   ```
   
   **Or manually:**
   ```bash
   pip install -r requirements.txt
   ```
   
   Or install packages individually:
   ```bash
   pip install rich psutil click
   ```

## 📖 Usage

### Basic Usage

Run the monitor with default settings:
```bash
python system_monitor.py
```

### Command-Line Options

```bash
python system_monitor.py [OPTIONS]
```

**Options:**
- `-r, --refresh FLOAT` - Refresh rate in seconds (default: 1.0)
- `-s, --sort [cpu|memory]` - Sort processes by CPU or memory (default: cpu)
- `-p, --processes INTEGER` - Number of top processes to display (default: 10)
- `-c, --connections INTEGER` - Number of network connections to display (default: 10)
- `-f, --filter TEXT` - Filter processes by name (case-insensitive)

### Examples

**Monitor with 0.5 second refresh rate:**
```bash
python system_monitor.py --refresh 0.5
```

**Sort processes by memory usage:**
```bash
python system_monitor.py --sort memory
```

**Display top 20 processes:**
```bash
python system_monitor.py --processes 20
```

**Show 30 network connections:**
```bash
python system_monitor.py --connections 30
```

**Filter processes by name:**
```bash
python system_monitor.py --filter chrome
```

**Combined options:**
```bash
python system_monitor.py --refresh 0.5 --sort memory --processes 15 --connections 20 --filter python
```

## 🎨 UI Overview

The interface is divided into several sections:

1. **System Overview Panel** (Top Right)
   - CPU usage with visual bar
   - Memory usage with visual bar
   - Swap usage
   - System information

2. **Top Processes Table** (Top Left)
   - Real-time process monitoring
   - Color-coded CPU and memory usage
   - Process details and status

3. **Network Statistics** (Bottom Left)
   - Network I/O metrics
   - Real-time send/receive speeds
   - Packet statistics
   - Error counts

4. **Disk Usage Table** (Bottom Right)
   - All mounted partitions
   - Usage percentages with color coding
   - Read/write statistics

5. **Active Network Connections** (Optional)
   - Current network connections
   - Local and remote addresses
   - Connection status

## 🎯 Color Coding

- **Green**: Normal/low usage (< 50% for CPU/memory, < 60% for disk)
- **Yellow**: Moderate usage (50-80% for CPU/memory, 60-80% for disk)
- **Red**: High usage (> 80% for CPU/memory, > 80% for disk)

## ⚙️ Requirements

- Python 3.7+
- Windows, Linux, or macOS
- Administrator/root privileges (recommended for full process and network access)

## 🔧 Technical Details

- **Libraries Used:**
  - `rich`: Beautiful terminal UI and formatting (v13.7.0+)
  - `psutil`: Cross-platform system and process utilities (v5.9.8+)
  - `click`: Command-line interface creation (v8.1.7+)

- **Performance:**
  - Efficient data collection with minimal overhead
  - Optimized refresh rates
  - Fast process enumeration
  - Low memory footprint

## 🛑 Exiting

Press `Ctrl+C` to stop the monitor and exit gracefully.

## 📝 Notes

- Some system information may require administrator/root privileges
- Network connection details may be limited on some systems
- Disk I/O statistics depend on system capabilities
- Process information may be restricted for system processes

## 🤝 Contributing

Feel free to submit issues, fork the repository, and create pull requests for any improvements.

## 📄 License

This project is open source and available for personal and commercial use.

---

**Enjoy monitoring your system in real-time!** 🚀

