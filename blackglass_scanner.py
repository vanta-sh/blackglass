#!/usr/bin/env python3
import os
import sys
import subprocess
import re
import argparse
import platform
import psutil
import json
import time
import socket
from colorama import init, Fore, Style

# Initialize colorama for cross-platform colored terminal output
init()

class BlackGlassScanner:
    def __init__(self):
        self.os_name = platform.system()
        self.scan_results = {
            "telemetry": []
        }
    
    def print_banner(self):
        banner = """
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║  ██████╗ ██╗      █████╗  ██████╗██╗  ██╗ ██████╗ ██╗       ║
║  ██╔══██╗██║     ██╔══██╗██╔════╝██║ ██╔╝██╔════╝ ██║       ║
║  ██████╔╝██║     ███████║██║     █████╔╝ ██║  ███╗██║       ║
║  ██╔══██╗██║     ██╔══██║██║     ██╔═██╗ ██║   ██║██║       ║
║  ██████╔╝███████╗██║  ██║╚██████╗██║  ██╗╚██████╔╝███████╗  ║
║  ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝  ║
║                                                              ║
║  ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ ║
║  ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗║
║  ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝║
║  ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗║
║  ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║║
║  ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
        """
        print(Fore.CYAN + banner + Style.RESET_ALL)
        print(Fore.GREEN + "BlackGlass Telemetry Scanner - Developed by Vanta" + Style.RESET_ALL)
        print(Fore.YELLOW + "=" * 70 + Style.RESET_ALL)
        print()
    
    def scan_processes(self):
        """Scan running processes for telemetry"""
        print(Fore.CYAN + "[*] Scanning running processes for telemetry..." + Style.RESET_ALL)
        
        telemetry_keywords = [
            "telemetry", "analytics", "tracking", "metrics", "data collection",
            "usage statistics", "diagnostic data"
        ]
        
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                proc_info = proc.info
                proc_name = proc_info['name'].lower() if proc_info['name'] else ""
                cmdline = " ".join(proc_info['cmdline']).lower() if proc_info['cmdline'] else ""
                
                # Check for telemetry
                for keyword in telemetry_keywords:
                    if keyword in proc_name or keyword in cmdline:
                        self.scan_results["telemetry"].append({
                            "type": "process",
                            "pid": proc_info['pid'],
                            "name": proc_info['name'],
                            "cmdline": cmdline,
                            "match": keyword
                        })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
    
    def scan_installed_software(self):
        """Scan installed software for telemetry"""
        print(Fore.CYAN + "[*] Scanning installed software for telemetry..." + Style.RESET_ALL)
        
        if self.os_name == "Windows":
            self._scan_windows_software()
        elif self.os_name == "Linux":
            self._scan_linux_software()
        elif self.os_name == "Darwin":  # macOS
            self._scan_macos_software()
    
    def _scan_windows_software(self):
        """Scan Windows registry for installed software"""
        try:
            import winreg
            
            registry_paths = [
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
            ]
            
            for reg_path in registry_paths:
                try:
                    registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path)
                    for i in range(winreg.QueryInfoKey(registry_key)[0]):
                        try:
                            subkey_name = winreg.EnumKey(registry_key, i)
                            subkey = winreg.OpenKey(registry_key, subkey_name)
                            try:
                                software_name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                                
                                if "telemetry" in software_name.lower() or "analytics" in software_name.lower() or "tracking" in software_name.lower():
                                    self.scan_results["telemetry"].append({
                                        "type": "installed_software",
                                        "name": software_name,
                                        "source": f"Registry: {reg_path}\\{subkey_name}"
                                    })
                            except (WindowsError, FileNotFoundError):
                                pass
                            finally:
                                winreg.CloseKey(subkey)
                        except (WindowsError, FileNotFoundError):
                            continue
                except (WindowsError, FileNotFoundError):
                    continue
        except ImportError:
            print(Fore.RED + "[!] Could not import winreg module. Windows registry scanning skipped." + Style.RESET_ALL)
    
    def _scan_linux_software(self):
        """Scan installed packages on Linux"""
        try:
            # Debian/Ubuntu based
            try:
                result = subprocess.run(["dpkg", "-l"], capture_output=True, text=True)
                if result.returncode == 0:
                    for line in result.stdout.splitlines():
                        if any(keyword in line.lower() for keyword in ["telemetry", "analytics", "tracking", "metrics"]):
                            self.scan_results["telemetry"].append({
                                "type": "installed_software",
                                "details": line.strip(),
                                "source": "dpkg"
                            })
            except FileNotFoundError:
                pass
                
            # Red Hat/CentOS/Fedora based
            try:
                result = subprocess.run(["rpm", "-qa"], capture_output=True, text=True)
                if result.returncode == 0:
                    for line in result.stdout.splitlines():
                        if any(keyword in line.lower() for keyword in ["telemetry", "analytics", "tracking", "metrics"]):
                            self.scan_results["telemetry"].append({
                                "type": "installed_software",
                                "details": line.strip(),
                                "source": "rpm"
                            })
            except FileNotFoundError:
                pass
        except Exception as e:
            print(Fore.RED + f"[!] Error scanning Linux software: {str(e)}" + Style.RESET_ALL)
    
    def _scan_macos_software(self):
        """Scan installed applications on macOS"""
        try:
            app_dir = "/Applications"
            for app in os.listdir(app_dir):
                app_path = os.path.join(app_dir, app)
                if os.path.isdir(app_path) and app.endswith(".app"):
                    app_name = app.replace(".app", "").lower()
                    if any(keyword in app_name for keyword in ["telemetry", "analytics", "tracking", "metrics"]):
                        self.scan_results["telemetry"].append({
                            "type": "installed_software",
                            "name": app,
                            "path": app_path,
                            "source": "Applications directory"
                        })
        except Exception as e:
            print(Fore.RED + f"[!] Error scanning macOS applications: {str(e)}" + Style.RESET_ALL)
    
    def scan_filesystem_for_telemetry(self, paths_to_scan=None):
        """Scan specified paths for telemetry-related files"""
        if not paths_to_scan:
            if self.os_name == "Windows":
                paths_to_scan = ["C:\\Program Files", "C:\\Program Files (x86)"]
            elif self.os_name == "Linux":
                paths_to_scan = ["/opt", "/usr/share"]
            elif self.os_name == "Darwin":  # macOS
                paths_to_scan = ["/Applications", "/usr/local"]
        
        print(Fore.CYAN + f"[*] Scanning filesystem for telemetry in: {', '.join(paths_to_scan)}" + Style.RESET_ALL)
        print(Fore.YELLOW + "    This may take some time..." + Style.RESET_ALL)
        
        telemetry_patterns = [
            "telemetry", "analytics", "tracking", "metrics", "diagnostics",
            "usage data", "data collection", "statistics"
        ]
        
        for path in paths_to_scan:
            if not os.path.exists(path):
                continue
                
            for root, dirs, files in os.walk(path, topdown=True):
                # Skip hidden directories
                dirs[:] = [d for d in dirs if not d.startswith('.')]
                
                for filename in files:
                    if filename.lower().endswith(('.exe', '.dll', '.so', '.dylib', '.sh', '.bat', '.app', '.plist', '.config', '.ini')):
                        try:
                            file_path = os.path.join(root, filename)
                            file_name_lower = filename.lower()
                            
                            for pattern in telemetry_patterns:
                                if pattern in file_name_lower:
                                    self.scan_results["telemetry"].append({
                                        "type": "file",
                                        "name": filename,
                                        "path": file_path,
                                        "match": pattern
                                    })
                                    break
                        except Exception:
                            pass
    
    def scan_network_connections(self):
        """Scan current network connections for potential telemetry servers"""
        print(Fore.CYAN + "[*] Scanning network connections for telemetry..." + Style.RESET_ALL)
        
        try:
            connections = psutil.net_connections(kind='inet')
            for conn in connections:
                try:
                    if not conn.raddr:  # Skip if no remote address
                        continue
                        
                    remote_ip = conn.raddr.ip
                    remote_port = conn.raddr.port
                    
                    # Get process info if available
                    process_info = ""
                    if conn.pid:
                        try:
                            process = psutil.Process(conn.pid)
                            process_info = f"{process.name()} (PID: {conn.pid})"
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            process_info = f"Unknown (PID: {conn.pid})"
                    
                    # Check if connection matches known telemetry endpoints
                    telemetry_domains = [
                        "telemetry", "metrics", "analytics", "tracking", "statistics", 
                        "diagnostic", "data-collection", "insights"
                    ]
                    
                    # This is a simplified check - in a real tool, you'd want to do reverse DNS lookups
                    # and check against a more comprehensive list of known telemetry endpoints
                    if conn.status == 'ESTABLISHED':
                        try:
                            hostname = socket.gethostbyaddr(remote_ip)[0]
                            for domain in telemetry_domains:
                                if domain in hostname.lower():
                                    self.scan_results["telemetry"].append({
                                        "type": "network_connection",
                                        "remote": f"{remote_ip}:{remote_port}",
                                        "hostname": hostname,
                                        "process": process_info,
                                        "status": conn.status
                                    })
                        except socket.herror:
                            # No reverse DNS available, just check the process name
                            if process_info and any(term in process_info.lower() for term in telemetry_domains):
                                self.scan_results["telemetry"].append({
                                    "type": "network_connection",
                                    "remote": f"{remote_ip}:{remote_port}",
                                    "process": process_info,
                                    "status": conn.status
                                })
                except Exception:
                    continue
        except Exception as e:
            print(Fore.RED + f"[!] Error scanning network connections: {str(e)}" + Style.RESET_ALL)
    
    def check_windows_telemetry(self):
        """Check Windows-specific telemetry settings"""
        if self.os_name != "Windows":
            return
            
        print(Fore.CYAN + "[*] Checking Windows telemetry settings..." + Style.RESET_ALL)
        
        try:
            import winreg
            
            # Check DiagTrack service
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\DiagTrack")
                start_value = winreg.QueryValueEx(key, "Start")[0]
                
                if start_value != 4:  # 4 = Disabled
                    self.scan_results["telemetry"].append({
                        "type": "windows_service",
                        "name": "DiagTrack (Connected User Experiences and Telemetry)",
                        "status": "Enabled" if start_value == 2 else "Manual",
                        "recommendation": "Consider disabling this service for privacy"
                    })
            except (WindowsError, FileNotFoundError):
                pass
                
            # Check telemetry settings
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                                    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection")
                allowed_telemetry = winreg.QueryValueEx(key, "AllowTelemetry")[0]
                
                telemetry_levels = {
                    0: "Security (only security data)",
                    1: "Basic (basic device info and quality data)",
                    2: "Enhanced (additional usage and performance data)",
                    3: "Full (all data, including diagnostic data)"
                }
                
                self.scan_results["telemetry"].append({
                    "type": "windows_setting",
                    "name": "Windows Telemetry Level",
                    "value": allowed_telemetry,
                    "description": telemetry_levels.get(allowed_telemetry, "Unknown"),
                    "recommendation": "Consider setting to 0 for maximum privacy"
                })
            except (WindowsError, FileNotFoundError):
                pass
        except ImportError:
            print(Fore.RED + "[!] Could not import winreg module. Windows telemetry checks skipped." + Style.RESET_ALL)
    
    def run_scan(self, quick_scan=False):
        """Run all scans"""
        self.print_banner()
        
        print(Fore.GREEN + f"[+] Starting scan on {self.os_name} system..." + Style.RESET_ALL)
        print()
        
        # Run scans
        self.scan_processes()
        self.scan_installed_software()
        
        if self.os_name == "Windows":
            self.check_windows_telemetry()
        
        try:
            self.scan_network_connections()
        except ImportError:
            print(Fore.RED + "[!] Could not import socket module. Network scanning skipped." + Style.RESET_ALL)
        
        if not quick_scan:
            self.scan_filesystem_for_telemetry()
        
        # Display results
        self.display_results()
    
    def display_results(self):
        """Display scan results"""
        print()
        print(Fore.YELLOW + "=" * 70 + Style.RESET_ALL)
        print(Fore.GREEN + "[+] Scan Results" + Style.RESET_ALL)
        print(Fore.YELLOW + "=" * 70 + Style.RESET_ALL)
        
        # Display Telemetry
        print()
        print(Fore.CYAN + "Telemetry Detected:" + Style.RESET_ALL)
        if not self.scan_results["telemetry"]:
            print(Fore.GREEN + "  No telemetry found." + Style.RESET_ALL)
        else:
            for i, item in enumerate(self.scan_results["telemetry"], 1):
                print(Fore.RED + f"  {i}. Type: {item.get('type', 'Unknown')}" + Style.RESET_ALL)
                for key, value in item.items():
                    if key != "type":
                        print(f"     {key}: {value}")
                print()
        
        # Summary
        print()
        print(Fore.YELLOW + "=" * 70 + Style.RESET_ALL)
        print(Fore.GREEN + "[+] Scan Summary:" + Style.RESET_ALL)
        print(f"  - Telemetry items found: {len(self.scan_results['telemetry'])}")
        print(Fore.YELLOW + "=" * 70 + Style.RESET_ALL)
        
        # Export option
        if any(self.scan_results.values()):
            self.export_results()
    
    def export_results(self):
        """Export results to JSON file"""
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        filename = f"blackglass_scan_{timestamp}.json"
        
        try:
            with open(filename, 'w') as f:
                json.dump(self.scan_results, f, indent=2)
            
            print()
            print(Fore.GREEN + f"[+] Results exported to {filename}" + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + f"[!] Error exporting results: {str(e)}" + Style.RESET_ALL)


def main():
    parser = argparse.ArgumentParser(description="BlackGlass Telemetry Scanner - Developed by Vanta")
    parser.add_argument("--quick", action="store_true", help="Run a quick scan (skip filesystem scan)")
    args = parser.parse_args()
    
    try:
        import colorama
        import psutil
    except ImportError:
        print("Error: Required packages not found.")
        print("Please install required packages using:")
        print("pip install psutil colorama")
        sys.exit(1)
    
    try:
        scanner = BlackGlassScanner()
        scanner.run_scan(quick_scan=args.quick)
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
        sys.exit(0)
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main() 