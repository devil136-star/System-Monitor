"""
Real-time System Monitor - A powerful command-line tool for system analysis,
process monitoring, and network traffic inspection.
"""

import time
import psutil
import click
from rich.console import Console
from rich.table import Table
from rich.layout import Layout
from rich.panel import Panel
from rich.live import Live
from rich.text import Text
from collections import deque
from datetime import datetime
from typing import Dict, List, Optional
import signal
import sys

console = Console()


class SystemMonitor:
    """Main system monitoring class with real-time data collection."""
    
    def __init__(self, refresh_rate: float = 1.0):
        self.refresh_rate = refresh_rate
        self.running = True
        self.cpu_history = deque(maxlen=60)
        self.memory_history = deque(maxlen=60)
        self.network_history = deque(maxlen=60)
        self.process_cache = {}
        self.last_net_io = None
        self.last_net_time = None
        
    def get_cpu_info(self) -> Dict:
        """Get comprehensive CPU information."""
        cpu_percent = psutil.cpu_percent(interval=None, percpu=True)
        cpu_count = psutil.cpu_count(logical=True)
        cpu_freq = psutil.cpu_freq()
        
        return {
            'percent': sum(cpu_percent) / len(cpu_percent),
            'per_cpu': cpu_percent,
            'count': cpu_count,
            'frequency': cpu_freq.current if cpu_freq else 0,
            'load_avg': psutil.getloadavg() if hasattr(psutil, 'getloadavg') else (0, 0, 0)
        }
    
    def get_memory_info(self) -> Dict:
        """Get comprehensive memory information."""
        mem = psutil.virtual_memory()
        swap = psutil.swap_memory()
        
        return {
            'total': mem.total,
            'available': mem.available,
            'used': mem.used,
            'percent': mem.percent,
            'swap_total': swap.total,
            'swap_used': swap.used,
            'swap_percent': swap.percent
        }
    
    def get_disk_info(self) -> List[Dict]:
        """Get disk usage information for all partitions."""
        disks = []
        partitions = psutil.disk_partitions()
        
        for partition in partitions:
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                io = psutil.disk_io_counters(perdisk=True).get(partition.device.replace('\\', ''), None)
                
                disk_info = {
                    'device': partition.device,
                    'mountpoint': partition.mountpoint,
                    'fstype': partition.fstype,
                    'total': usage.total,
                    'used': usage.used,
                    'free': usage.free,
                    'percent': usage.percent,
                    'read_bytes': io.read_bytes if io else 0,
                    'write_bytes': io.write_bytes if io else 0,
                    'read_count': io.read_count if io else 0,
                    'write_count': io.write_count if io else 0
                }
                disks.append(disk_info)
            except PermissionError:
                continue
        
        return disks
    
    def get_network_info(self) -> Dict:
        """Get network statistics with speed calculation."""
        net_io = psutil.net_io_counters()
        connections = psutil.net_connections(kind='inet')
        current_time = time.time()
        
        # Calculate network speed
        send_speed = 0
        recv_speed = 0
        if self.last_net_io and self.last_net_time:
            time_diff = current_time - self.last_net_time
            if time_diff > 0:
                send_speed = (net_io.bytes_sent - self.last_net_io.bytes_sent) / time_diff
                recv_speed = (net_io.bytes_recv - self.last_net_io.bytes_recv) / time_diff
        
        self.last_net_io = net_io
        self.last_net_time = current_time
        
        return {
            'bytes_sent': net_io.bytes_sent,
            'bytes_recv': net_io.bytes_recv,
            'packets_sent': net_io.packets_sent,
            'packets_recv': net_io.packets_recv,
            'errin': net_io.errin,
            'errout': net_io.errout,
            'dropin': net_io.dropin,
            'dropout': net_io.dropout,
            'connections': len(connections),
            'send_speed': send_speed,
            'recv_speed': recv_speed
        }
    
    def get_top_processes(self, limit: int = 10, sort_by: str = 'cpu', filter_name: Optional[str] = None) -> List[Dict]:
        """Get top processes sorted by CPU or memory usage."""
        processes = []
        
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 
                                        'memory_info', 'status', 'create_time', 'num_threads']):
            try:
                pinfo = proc.info
                if pinfo['cpu_percent'] is None:
                    pinfo['cpu_percent'] = 0
                if pinfo['memory_percent'] is None:
                    pinfo['memory_percent'] = 0
                
                # Filter by process name if specified
                if filter_name and filter_name.lower() not in pinfo['name'].lower():
                    continue
                
                processes.append({
                    'pid': pinfo['pid'],
                    'name': pinfo['name'],
                    'cpu_percent': pinfo['cpu_percent'],
                    'memory_percent': pinfo['memory_percent'],
                    'memory_mb': pinfo['memory_info'].rss / 1024 / 1024 if pinfo['memory_info'] else 0,
                    'status': pinfo['status'],
                    'threads': pinfo['num_threads'],
                    'create_time': pinfo['create_time']
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        
        # Sort processes
        if sort_by == 'cpu':
            processes.sort(key=lambda x: x['cpu_percent'], reverse=True)
        elif sort_by == 'memory':
            processes.sort(key=lambda x: x['memory_percent'], reverse=True)
        
        return processes[:limit]
    
    def get_network_connections(self, limit: int = 20) -> List[Dict]:
        """Get active network connections."""
        connections = []
        
        try:
            for conn in psutil.net_connections(kind='inet'):
                try:
                    conn_info = {
                        'fd': conn.fd,
                        'family': str(conn.family),
                        'type': str(conn.type),
                        'laddr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A",
                        'raddr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A",
                        'status': conn.status,
                        'pid': conn.pid
                    }
                    connections.append(conn_info)
                except (AttributeError, ValueError):
                    continue
        except (psutil.AccessDenied, PermissionError):
            pass
        
        return connections[:limit]
    
    def format_bytes(self, bytes_value: int) -> str:
        """Format bytes to human-readable format."""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_value < 1024.0:
                return f"{bytes_value:.2f} {unit}"
            bytes_value /= 1024.0
        return f"{bytes_value:.2f} PB"
    
    def format_percent_bar(self, percent: float, width: int = 20) -> Text:
        """Create a visual percent bar."""
        filled = int(width * percent / 100)
        bar = "█" * filled + "░" * (width - filled)
        
        if percent < 50:
            color = "green"
        elif percent < 80:
            color = "yellow"
        else:
            color = "red"
        
        return Text(f"{bar} {percent:.1f}%", style=color)
    
    def create_system_panel(self, cpu_info: Dict, mem_info: Dict) -> Panel:
        """Create system overview panel."""
        table = Table.grid(padding=(0, 2))
        table.add_column(style="cyan", justify="right")
        table.add_column(style="magenta")
        
        # CPU Information
        table.add_row("CPU Usage:", self.format_percent_bar(cpu_info['percent']))
        table.add_row("CPU Cores:", f"{cpu_info['count']} logical cores")
        if cpu_info['frequency'] > 0:
            table.add_row("CPU Freq:", f"{cpu_info['frequency']:.0f} MHz")
        
        # Memory Information
        table.add_row("", "")
        table.add_row("Memory:", self.format_percent_bar(mem_info['percent']))
        table.add_row("Used:", f"{self.format_bytes(mem_info['used'])} / {self.format_bytes(mem_info['total'])}")
        table.add_row("Available:", self.format_bytes(mem_info['available']))
        
        # Swap Information
        if mem_info['swap_total'] > 0:
            table.add_row("", "")
            table.add_row("Swap:", self.format_percent_bar(mem_info['swap_percent']))
            table.add_row("Swap Used:", f"{self.format_bytes(mem_info['swap_used'])} / {self.format_bytes(mem_info['swap_total'])}")
        
        return Panel(table, title="[bold cyan]System Overview[/bold cyan]", border_style="cyan")
    
    def create_process_table(self, processes: List[Dict]) -> Table:
        """Create process monitoring table."""
        table = Table(title="[bold yellow]Top Processes[/bold yellow]", show_header=True, header_style="bold yellow")
        table.add_column("PID", style="cyan", width=8)
        table.add_column("Name", style="green", width=20, overflow="ellipsis")
        table.add_column("CPU %", style="yellow", justify="right", width=10)
        table.add_column("Memory %", style="magenta", justify="right", width=12)
        table.add_column("Memory (MB)", style="blue", justify="right", width=12)
        table.add_column("Threads", style="white", justify="right", width=8)
        table.add_column("Status", style="white", width=10)
        
        for proc in processes:
            cpu_color = "red" if proc['cpu_percent'] > 50 else "yellow" if proc['cpu_percent'] > 20 else "green"
            mem_color = "red" if proc['memory_percent'] > 50 else "yellow" if proc['memory_percent'] > 20 else "green"
            
            table.add_row(
                str(proc['pid']),
                proc['name'][:20],
                f"[{cpu_color}]{proc['cpu_percent']:.1f}%[/{cpu_color}]",
                f"[{mem_color}]{proc['memory_percent']:.1f}%[/{mem_color}]",
                f"{proc['memory_mb']:.1f}",
                str(proc['threads']),
                proc['status']
            )
        
        return table
    
    def create_network_table(self, net_info: Dict, connections: List[Dict]) -> Table:
        """Create network information table."""
        table = Table(title="[bold green]Network Statistics[/bold green]", show_header=True, header_style="bold green")
        table.add_column("Metric", style="cyan", width=20)
        table.add_column("Value", style="white", width=25)
        
        table.add_row("Bytes Sent", self.format_bytes(net_info['bytes_sent']))
        table.add_row("Bytes Received", self.format_bytes(net_info['bytes_recv']))
        table.add_row("Send Speed", f"{self.format_bytes(net_info['send_speed'])}/s")
        table.add_row("Recv Speed", f"{self.format_bytes(net_info['recv_speed'])}/s")
        table.add_row("Packets Sent", f"{net_info['packets_sent']:,}")
        table.add_row("Packets Received", f"{net_info['packets_recv']:,}")
        table.add_row("Errors In", f"{net_info['errin']:,}")
        table.add_row("Errors Out", f"{net_info['errout']:,}")
        table.add_row("Active Connections", f"{net_info['connections']:,}")
        
        return table
    
    def create_connections_table(self, connections: List[Dict]) -> Table:
        """Create network connections table."""
        table = Table(title="[bold blue]Active Network Connections[/bold blue]", show_header=True, header_style="bold blue")
        table.add_column("PID", style="cyan", width=8)
        table.add_column("Local Address", style="green", width=25)
        table.add_column("Remote Address", style="yellow", width=25)
        table.add_column("Status", style="magenta", width=15)
        table.add_column("Type", style="white", width=10)
        
        for conn in connections:
            table.add_row(
                str(conn['pid']) if conn['pid'] else "N/A",
                conn['laddr'],
                conn['raddr'],
                conn['status'],
                conn['type']
            )
        
        return table
    
    def create_disk_table(self, disks: List[Dict]) -> Table:
        """Create disk usage table."""
        table = Table(title="[bold magenta]Disk Usage[/bold magenta]", show_header=True, header_style="bold magenta")
        table.add_column("Device", style="cyan", width=15)
        table.add_column("Mount", style="green", width=20)
        table.add_column("Type", style="white", width=10)
        table.add_column("Total", style="yellow", justify="right", width=12)
        table.add_column("Used", style="red", justify="right", width=12)
        table.add_column("Free", style="green", justify="right", width=12)
        table.add_column("Usage %", style="magenta", justify="right", width=10)
        
        for disk in disks:
            usage_color = "red" if disk['percent'] > 80 else "yellow" if disk['percent'] > 60 else "green"
            table.add_row(
                disk['device'],
                disk['mountpoint'][:20],
                disk['fstype'],
                self.format_bytes(disk['total']),
                self.format_bytes(disk['used']),
                self.format_bytes(disk['free']),
                f"[{usage_color}]{disk['percent']:.1f}%[/{usage_color}]"
            )
        
        return table
    
    def create_footer(self) -> Panel:
        """Create footer with author information."""
        footer_text = Text()
        footer_text.append("Developed by ", style="dim white")
        footer_text.append("Himanshu Kumar", style="bold cyan")
        footer_text.append("  |  ", style="dim white")
        footer_text.append("🔗", style="blue")
        footer_text.append(" LinkedIn: ", style="dim white")
        footer_text.append("www.linkedin.com/in/himanshu-kumar-777a50292", style="bright_blue underline")
        footer_text.append("  |  ", style="dim white")
        footer_text.append("🐙", style="white")
        footer_text.append(" GitHub: ", style="dim white")
        footer_text.append("github.com/devil136-star", style="bright_blue underline")
        
        return Panel(footer_text, border_style="dim blue", height=3)
    
    def generate_layout(self, cpu_info: Dict, mem_info: Dict, processes: List[Dict], 
                       net_info: Dict, connections: List[Dict], disks: List[Dict]) -> Layout:
        """Generate the main layout for the TUI."""
        layout = Layout()
        
        # Split into header, body, and footer
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="body"),
            Layout(name="footer", size=3)
        )
        
        # Header with timestamp
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        header_text = Text(f"🔍 System Monitor - {timestamp}", style="bold white on blue")
        layout["header"].update(Panel(header_text, border_style="blue"))
        
        # Split body into main content and sidebar
        layout["body"].split_row(
            Layout(name="main", ratio=2),
            Layout(name="sidebar", ratio=1)
        )
        
        # Main content: processes and network
        layout["main"].split_column(
            Layout(name="processes"),
            Layout(name="network", ratio=1)
        )
        
        # Sidebar: system info and disk
        layout["sidebar"].split_column(
            Layout(name="system", ratio=1),
            Layout(name="disk", ratio=1)
        )
        
        # Update all panels
        layout["system"].update(self.create_system_panel(cpu_info, mem_info))
        layout["processes"].update(self.create_process_table(processes))
        layout["network"].update(self.create_network_table(net_info, connections))
        layout["disk"].update(self.create_disk_table(disks))
        layout["footer"].update(self.create_footer())
        
        return layout
    
    def run(self, sort_by: str = 'cpu', process_limit: int = 10, connection_limit: int = 10, 
            filter_process: Optional[str] = None):
        """Main monitoring loop."""
        def signal_handler(sig, frame):
            self.running = False
            console.print("\n[bold red]Shutting down...[/bold red]")
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        # Initialize network speed calculation
        try:
            _ = psutil.net_io_counters()
            self.last_net_time = time.time()
        except Exception:
            pass
        
        try:
            with Live(console=console, refresh_per_second=1/self.refresh_rate, screen=True) as live:
                while self.running:
                    try:
                        # Collect data
                        cpu_info = self.get_cpu_info()
                        mem_info = self.get_memory_info()
                        processes = self.get_top_processes(limit=process_limit, sort_by=sort_by, 
                                                          filter_name=filter_process)
                        net_info = self.get_network_info()
                        connections = self.get_network_connections(limit=connection_limit)
                        disks = self.get_disk_info()
                        
                        # Update history
                        self.cpu_history.append(cpu_info['percent'])
                        self.memory_history.append(mem_info['percent'])
                        
                        # Generate and update layout
                        layout = self.generate_layout(cpu_info, mem_info, processes, net_info, connections, disks)
                        live.update(layout)
                    except Exception as e:
                        # Continue on errors to maintain real-time monitoring
                        console.print(f"[dim red]Error: {e}[/dim red]")
                    
                    time.sleep(self.refresh_rate)
        except KeyboardInterrupt:
            self.running = False
            console.print("\n[bold red]Monitoring stopped.[/bold red]")
        except Exception as e:
            console.print(f"\n[bold red]Fatal error: {e}[/bold red]")
            sys.exit(1)


@click.command()
@click.option('--refresh', '-r', default=1.0, type=float, help='Refresh rate in seconds (default: 1.0)')
@click.option('--sort', '-s', default='cpu', type=click.Choice(['cpu', 'memory']), 
              help='Sort processes by CPU or memory (default: cpu)')
@click.option('--processes', '-p', default=10, type=int, 
              help='Number of top processes to display (default: 10)')
@click.option('--connections', '-c', default=10, type=int,
              help='Number of network connections to display (default: 10)')
@click.option('--filter', '-f', default=None, type=str,
              help='Filter processes by name (case-insensitive)')
def main(refresh: float, sort: str, processes: int, connections: int, filter: Optional[str]):
    """Real-time System Monitor - A powerful command-line tool for system analysis."""
    console.print("[bold green]Starting System Monitor...[/bold green]")
    filter_text = f" | Filter: {filter}" if filter else ""
    console.print(f"[dim]Refresh rate: {refresh}s | Sort by: {sort} | Processes: {processes} | Connections: {connections}{filter_text}[/dim]\n")
    
    try:
        monitor = SystemMonitor(refresh_rate=refresh)
        monitor.run(sort_by=sort, process_limit=processes, connection_limit=connections, 
                   filter_process=filter)
    except Exception as e:
        console.print(f"[bold red]Failed to start monitor: {e}[/bold red]")
        sys.exit(1)


if __name__ == "__main__":
    main()

