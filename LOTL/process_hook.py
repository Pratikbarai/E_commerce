import wmi
import threading
import queue
import time

class ProcessInterceptor:
    def __init__(self):
        self.process_queue = queue.Queue()
        self.monitoring = False

        # Extended high-risk LOLBins — used in APT & Volt Typhoon activity
        self.high_risk_processes = {
            # Scripting & Execution
            'powershell.exe': 'PowerShell execution',
            'cmd.exe': 'Command prompt execution',
            'wmic.exe': 'WMI command execution',
            'regsvr32.exe': 'Registry server execution',
            'rundll32.exe': 'DLL execution',
            'mshta.exe': 'HTML application execution',
            'certutil.exe': 'Certificate utility execution',
            'bitsadmin.exe': 'BITS admin execution',

            # Scheduled tasks & persistence
            'schtasks.exe': 'Scheduled task execution',
            'at.exe': 'Legacy task scheduling',

            # Network configuration & proxy abuse
            'netsh.exe': 'Network configuration',
            'proxycfg.exe': 'Proxy manipulation',
            'ipconfig.exe': 'IP configuration view',
            'route.exe': 'Routing table access',
            'arp.exe': 'ARP cache dump',
            'nbtstat.exe': 'NetBIOS network info',
            'sc.exe': 'Service control',

            # Recon & credential gathering
            'net.exe': 'Network info & shares',
            'net1.exe': 'Legacy network info',
            'whoami.exe': 'Identity check',
            'tasklist.exe': 'Process listing',
            'dsquery.exe': 'AD domain queries',
            'nltest.exe': 'Domain trust relationships',
            'quser.exe': 'User session enumeration'
        }

    def start_interception(self):
        """Start process interception using WMI"""
        self.monitoring = True

        def monitor_processes():
            c = wmi.WMI()
            process_watcher = c.Win32_Process.watch_for("creation")

            while self.monitoring:
                try:
                    new_process = process_watcher(timeout_ms=500)
                    if new_process and new_process.Name.lower() in self.high_risk_processes:
                        process_data = {
                            'pid': new_process.ProcessId,
                            'name': new_process.Name,
                            'cmdline': new_process.CommandLine or '',
                            'parent_pid': new_process.ParentProcessId,
                            'risk_level': self._assess_initial_risk(new_process),
                            'timestamp': time.time(),
                            'category': self.high_risk_processes.get(new_process.Name.lower(), 'unknown')
                        }
                        self.process_queue.put(process_data)
                except Exception:
                    continue

        monitor_thread = threading.Thread(target=monitor_processes)
        monitor_thread.daemon = True
        monitor_thread.start()

    def _assess_initial_risk(self, process):
        """Quick initial risk assessment based on command line contents"""
        risk_score = 1.0  # Base risk
        cmdline = (process.CommandLine or '').lower()

        high_risk_patterns = [
            'invoke-expression', 'iex', 'downloadstring', 'webclient',
            'bypass', 'hidden', 'encoded', 'compress-archive',
            'copy-item', 'move-item', 'remove-item', 'del /f /s /q',
            'add-scheduledtask', 'start-process', 'invoke-webrequest'
        ]

        for pattern in high_risk_patterns:
            if pattern in cmdline:
                risk_score += 2.0

        return min(risk_score, 10.0)  # Cap at 10
