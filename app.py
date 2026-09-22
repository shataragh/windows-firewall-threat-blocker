"""
Windows Defender - Automated Threat Intrusion Blocker & CLI Suite
==================================================================
A real-time security application built with CustomTkinter and PowerShell.
Monitors Windows Security Event Logs for probe/intrusion attempts, 
enforces inbound block rules, and provides an integrated PowerShell CLI console.

Author: Sirvan Abbasbeigi (shataragh)
License: MIT
"""

import os
import sys
import time
import ctypes
import threading
import subprocess
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional
import customtkinter as ctk
from tkinter import messagebox

# Global Appearance Configuration
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")


def is_admin() -> bool:
    """Check if the current process holds administrative privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


class PowerShellEngine:
    """Wrapper class for executing administrative PowerShell commands silently."""

    @staticmethod
    def execute(command: str) -> str:
        """Executes a PowerShell command in a hidden background process."""
        try:
            result = subprocess.run(
                ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            stdout = result.stdout.strip()
            stderr = result.stderr.strip()
            if stderr:
                return f"{stdout}\n[STDERR]\n{stderr}" if stdout else f"[ERROR] {stderr}"
            return stdout
        except Exception as e:
            return f"Execution Error: {str(e)}"


class ThreatDetectorApp(ctk.CTk):
    """Main Application GUI and Threat Engine Controller."""

    def __init__(self) -> None:
        super().__init__()

        # Window Configuration
        self.title("Windows Defender - Automated Threat Intrusion Blocker & CLI")
        self.geometry("980x700")
        self.minsize(850, 600)

        # Operational Parameters
        self.max_attempts: int = 3
        self.block_prefix: str = "ATTACKER_BLOCKED"
        self.is_monitoring: bool = False
        self.monitor_thread: Optional[threading.Thread] = None

        # Build Interface & Load Initial Data
        self._init_ui()
        self.refresh_blocked_rules()

    def _init_ui(self) -> None:
        """Constructs the CustomTkinter Graphical User Interface."""
        # Grid Configuration
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # ==================== SIDEBAR NAVIGATION ====================
        self.sidebar = ctk.CTkFrame(self, width=220, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew", padx=(0, 10), pady=0)

        self.lbl_brand = ctk.CTkLabel(
            self.sidebar, text="ShieldWall AI", font=ctk.CTkFont(size=22, weight="bold")
        )
        self.lbl_brand.pack(padx=20, pady=(25, 5))

        self.lbl_subtitle = ctk.CTkLabel(
            self.sidebar, text="Firewall Intrusion Protection", font=ctk.CTkFont(size=11), text_color="gray"
        )
        self.lbl_subtitle.pack(padx=20, pady=(0, 15))

        self.status_card = ctk.CTkFrame(self.sidebar)
        self.status_card.pack(padx=15, pady=5, fill="x")

        self.lbl_status_title = ctk.CTkLabel(self.status_card, text="Engine Status", font=ctk.CTkFont(size=11, weight="bold"))
        self.lbl_status_title.pack(padx=10, pady=(6, 2))

        self.lbl_status = ctk.CTkLabel(
            self.status_card, text="IDLE", text_color="#FFA500", font=ctk.CTkFont(size=14, weight="bold")
        )
        self.lbl_status.pack(padx=10, pady=(0, 6))

        # Control Buttons
        self.btn_toggle_scan = ctk.CTkButton(
            self.sidebar, text="Start Protection", command=self.toggle_monitoring, fg_color="#2EA043", hover_color="#238636"
        )
        self.btn_toggle_scan.pack(padx=15, pady=(15, 6), fill="x")

        self.btn_scan_now = ctk.CTkButton(
            self.sidebar, text="Run Manual Scan", command=self.run_manual_scan, fg_color="#1F6FEB", hover_color="#1158C7"
        )
        self.btn_scan_now.pack(padx=15, pady=6, fill="x")

        self.btn_refresh = ctk.CTkButton(
            self.sidebar, text="Refresh Rules", command=self.refresh_blocked_rules, fg_color="#30363D", hover_color="#21262D"
        )
        self.btn_refresh.pack(padx=15, pady=6, fill="x")

        # Quick Command Shortcuts in Sidebar
        self.lbl_quick_cmds = ctk.CTkLabel(self.sidebar, text="Quick Network Tools", font=ctk.CTkFont(size=12, weight="bold"))
        self.lbl_quick_cmds.pack(padx=15, pady=(20, 5), anchor="w")

        self.btn_cmd_tcp = ctk.CTkButton(
            self.sidebar, text="Get TCP Connections", command=lambda: self.run_custom_command("Get-NetTCPConnection -State Established | Select-LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess | Format-Table -AutoSize"),
            fg_color="#21262D", hover_color="#30363D"
        )
        self.btn_cmd_tcp.pack(padx=15, pady=4, fill="x")

        self.btn_cmd_routes = ctk.CTkButton(
            self.sidebar, text="Show Active Listening Ports", command=lambda: self.run_custom_command("Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort, OwningProcess | Format-Table -AutoSize"),
            fg_color="#21262D", hover_color="#30363D"
        )
        self.btn_cmd_routes.pack(padx=15, pady=4, fill="x")

        self.btn_cmd_ipconfig = ctk.CTkButton(
            self.sidebar, text="Display Network Adapters", command=lambda: self.run_custom_command("Get-NetIPAddress -AddressFamily IPv4 | Select-Object InterfaceAlias, IPAddress | Format-Table -AutoSize"),
            fg_color="#21262D", hover_color="#30363D"
        )
        self.btn_cmd_ipconfig.pack(padx=15, pady=4, fill="x")

        # ==================== MAIN TABVIEW WORKSPACE ====================
        self.tabview = ctk.CTkTabview(self)
        self.tabview.grid(row=0, column=1, sticky="nsew", padx=10, pady=10)

        # Tab 1: Threat Monitor
        self.tab_monitor = self.tabview.add("Threat Monitor")
        self.tab_monitor.grid_columnconfigure(0, weight=1)
        self.tab_monitor.grid_rowconfigure(1, weight=1)
        self.tab_monitor.grid_rowconfigure(3, weight=1)

        # Real-Time Event Console
        self.lbl_console = ctk.CTkLabel(self.tab_monitor, text="Real-Time Intrusion Logs", font=ctk.CTkFont(size=14, weight="bold"))
        self.lbl_console.grid(row=0, column=0, sticky="w", padx=5, pady=(5, 5))

        self.console_output = ctk.CTkTextbox(self.tab_monitor, font=ctk.CTkFont(family="Consolas", size=12))
        self.console_output.grid(row=1, column=0, sticky="nsew", padx=5, pady=(0, 10))

        # Active Firewall Rules Table
        self.lbl_rules = ctk.CTkLabel(self.tab_monitor, text="Enforced Windows Firewall Block Rules", font=ctk.CTkFont(size=14, weight="bold"))
        self.lbl_rules.grid(row=2, column=0, sticky="w", padx=5, pady=(5, 5))

        self.rules_table = ctk.CTkTextbox(self.tab_monitor, font=ctk.CTkFont(family="Consolas", size=12))
        self.rules_table.grid(row=3, column=0, sticky="nsew", padx=5, pady=(0, 10))

        # Unblock Management Toolbar
        self.action_frame = ctk.CTkFrame(self.tab_monitor)
        self.action_frame.grid(row=4, column=0, sticky="ew", padx=5, pady=5)

        self.entry_unblock_ip = ctk.CTkEntry(self.action_frame, placeholder_text="Enter IP address to remove from firewall...")
        self.entry_unblock_ip.pack(side="left", padx=10, pady=10, fill="x", expand=True)

        self.btn_unblock = ctk.CTkButton(
            self.action_frame, text="Unblock IP", fg_color="#DA3633", hover_color="#B62324", command=self.unblock_ip
        )
        self.btn_unblock.pack(side="right", padx=10, pady=10)

        # Tab 2: Interactive PowerShell CLI
        self.tab_cli = self.tabview.add("PowerShell Terminal")
        self.tab_cli.grid_columnconfigure(0, weight=1)
        self.tab_cli.grid_rowconfigure(0, weight=1)

        self.cli_output = ctk.CTkTextbox(self.tab_cli, font=ctk.CTkFont(family="Consolas", size=12))
        self.cli_output.grid(row=0, column=0, sticky="nsew", padx=5, pady=(5, 5))

        self.cli_input_frame = ctk.CTkFrame(self.tab_cli)
        self.cli_input_frame.grid(row=1, column=0, sticky="ew", padx=5, pady=5)

        self.entry_cli_command = ctk.CTkEntry(self.cli_input_frame, placeholder_text="Type PowerShell command here (e.g., Get-Process, Test-NetConnection -ComputerName 1.1.1.1 -Port 80)...")
        self.entry_cli_command.pack(side="left", padx=10, pady=10, fill="x", expand=True)
        self.entry_cli_command.bind("<Return>", lambda event: self.execute_user_cli())

        self.btn_cli_run = ctk.CTkButton(
            self.cli_input_frame, text="Execute Command", fg_color="#1F6FEB", hover_color="#1158C7", command=self.execute_user_cli
        )
        self.btn_cli_run.pack(side="right", padx=10, pady=10)

    def log(self, message: str) -> None:
        """Appends formatted timestamp messages to the console log."""
        timestamp = time.strftime("[%H:%M:%S]")
        self.console_output.insert("end", f"{timestamp} {message}\n")
        self.console_output.see("end")

    def run_custom_command(self, cmd: str) -> None:
        """Executes a quick command and redirects output to the terminal tab."""
        self.tabview.set("PowerShell Terminal")
        self.entry_cli_command.delete(0, "end")
        self.entry_cli_command.insert(0, cmd)
        self.execute_user_cli()

    def execute_user_cli(self) -> None:
        """Runs the command typed in the CLI tab asynchronously."""
        cmd = self.entry_cli_command.get().strip()
        if not cmd:
            return

        self.cli_output.insert("end", f"\nPS C:\\WINDOWS\\system32> {cmd}\n")
        self.cli_output.see("end")

        def task():
            output = PowerShellEngine.execute(cmd)
            self.cli_output.insert("end", f"{output}\n")
            self.cli_output.see("end")

        threading.Thread(target=task, daemon=True).start()

    def analyze_event_logs(self) -> None:
        """Queries Security Event Log ID 4625 and enforces block rules on threats."""
        self.log("[*] Querying Security Event Logs for unauthorized authentication probes...")

        ps_script = """
        Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 50 -ErrorAction SilentlyContinue | ForEach-Object { $_.ToXml() }
        """
        raw_xml = PowerShellEngine.execute(ps_script)

        if not raw_xml or "Execution Error" in raw_xml or "[ERROR]" in raw_xml:
            self.log("[+] Security check complete: No recent unauthorized probe events recorded.")
            return

        attacker_ips: List[str] = []
        for xml_chunk in raw_xml.split("</Event>"):
            if not xml_chunk.strip():
                continue
            try:
                root = ET.fromstring(xml_chunk + "</Event>")
                for data in root.findall(".//{http://schemas.microsoft.com/win/2004/08/events/event}Data"):
                    if data.attrib.get("Name") == "IpAddress":
                        ip = data.text
                        if ip and ip not in ["-", "127.0.0.1", "::1"]:
                            attacker_ips.append(ip)
            except Exception:
                continue

        # Count Frequency
        ip_counts: Dict[str, int] = {}
        for ip in attacker_ips:
            ip_counts[ip] = ip_counts.get(ip, 0) + 1

        # Enforce Firewall Rules
        threats_detected = False
        for ip, count in ip_counts.items():
            if count >= self.max_attempts:
                threats_detected = True
                rule_name = f"{self.block_prefix}_{ip}"

                existing_rule = PowerShellEngine.execute(
                    f"Get-NetFirewallRule -DisplayName '{rule_name}' -ErrorAction SilentlyContinue"
                )

                if not existing_rule:
                    self.log(f"[!] THREAT DETECTED: {ip} breached threshold ({count} attempts).")
                    cmd_block = (
                        f"New-NetFirewallRule -DisplayName '{rule_name}' -Direction Inbound "
                        f"-Action Block -RemoteAddress '{ip}' -Protocol Any -Description 'Automated threat block.'"
                    )
                    PowerShellEngine.execute(cmd_block)
                    self.log(f"[+] FIREWALL ENFORCED: Inbound traffic from {ip} blocked successfully.")
                else:
                    self.log(f"[=] Threat IP {ip} is already active in firewall block list.")

        if not threats_detected:
            self.log("[+] Security check complete: All remote connection rates within safe thresholds.")

        self.refresh_blocked_rules()

    def refresh_blocked_rules(self) -> None:
        """Retrieves and displays active block rules managed by the application."""
        self.rules_table.delete("0.0", "end")
        cmd_get_rules = f"Get-NetFirewallRule -DisplayName '{self.block_prefix}_*' | Select-Object DisplayName, Enabled, Action | Out-String"
        output = PowerShellEngine.execute(cmd_get_rules)

        if output:
            self.rules_table.insert("0.0", output)
        else:
            self.rules_table.insert("0.0", "No active threat rules currently enforced in Windows Firewall.")

    def unblock_ip(self) -> None:
        """Removes a blocked IP address rule from Windows Defender Firewall."""
        target_ip = self.entry_unblock_ip.get().strip()
        if not target_ip:
            messagebox.showwarning("Input Error", "Please provide a valid IP address to unblock.")
            return

        rule_name = f"{self.block_prefix}_{target_ip}"
        PowerShellEngine.execute(f"Remove-NetFirewallRule -DisplayName '{rule_name}' -ErrorAction SilentlyContinue")
        
        self.log(f"[-] FIREWALL UPDATED: Rule for {target_ip} removed.")
        self.entry_unblock_ip.delete(0, "end")
        self.refresh_blocked_rules()

    def run_manual_scan(self) -> None:
        """Triggers an immediate scan in a dedicated background thread."""
        threading.Thread(target=self.analyze_event_logs, daemon=True).start()

    def toggle_monitoring(self) -> None:
        """Toggles the automated real-time background protection engine."""
        if not self.is_monitoring:
            self.is_monitoring = True
            self.btn_toggle_scan.configure(text="Stop Protection", fg_color="#DA3633", hover_color="#B62324")
            self.lbl_status.configure(text="ACTIVE", text_color="#2EA043")
            self.log("[*] Background real-time protection engine started.")
            self.monitor_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
            self.monitor_thread.start()
        else:
            self.is_monitoring = False
            self.btn_toggle_scan.configure(text="Start Protection", fg_color="#2EA043", hover_color="#238636")
            self.lbl_status.configure(text="IDLE", text_color="#FFA500")
            self.log("[*] Real-time protection engine paused.")

    def _monitoring_loop(self) -> None:
        """Background thread loop executing periodic threat scans."""
        while self.is_monitoring:
            self.analyze_event_logs()
            time.sleep(10)


if __name__ == "__main__":
    if not is_admin():
        # Re-launch with Administrator elevation dialog
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, f'"{os.path.abspath(__file__)}"', None, 1
        )
        sys.exit(0)

    app = ThreatDetectorApp()
    app.mainloop()
