import psutil
import networkx as nx
from datetime import datetime

class ProcessTreeAnalyzer:
    def __init__(self):
        # Suspicious parent-child process patterns (including Volt Typhoon & LOLBins)
        self.suspicious_parent_child_patterns = {
            ('winword.exe', 'powershell.exe'): 'Office spawning PowerShell',
            ('excel.exe', 'cmd.exe'): 'Excel spawning Command Prompt',
            ('outlook.exe', 'regsvr32.exe'): 'Outlook spawning RegSvr32',
            ('explorer.exe', 'powershell.exe'): 'Explorer spawning PowerShell',
            ('svchost.exe', 'powershell.exe'): 'Service Host spawning PowerShell',
            ('wmiprvse.exe', 'powershell.exe'): 'WMI Provider spawning PowerShell',

            # Added for Volt Typhoon / LOLBins
            ('explorer.exe', 'mshta.exe'): 'MSHTA used from Explorer (LOLBIN)',
            ('explorer.exe', 'wscript.exe'): 'WScript used from Explorer',
            ('powershell.exe', 'certutil.exe'): 'PowerShell spawning CertUtil',
            ('cmd.exe', 'schtasks.exe'): 'Command Line creating scheduled task',
            ('cmd.exe', 'sc.exe'): 'Command Line manipulating services',
            ('cmd.exe', 'netsh.exe'): 'Command Line configuring proxy',
            ('powershell.exe', 'forfiles.exe'): 'PowerShell launching ForFiles',
            ('powershell.exe', 'debug.exe'): 'PowerShell spawning Debug.exe',
            ('cmd.exe', 'sdbinst.exe'): 'CMD launching SdbInst (LOLBIN)',
            ('cmd.exe', 'makecab.exe'): 'CMD launching MakeCab (compression abuse)',
            ('cmd.exe', 'regsvr32.exe'): 'CMD using Regsvr32 (DLL reg)',
        }

        self.process_graph = nx.DiGraph()

    def build_process_tree(self):
        """Build current process tree"""
        self.process_graph.clear()
        for proc in psutil.process_iter(['pid', 'ppid', 'name', 'cmdline', 'create_time']):
            try:
                proc_info = proc.info
                pid = proc_info['pid']
                ppid = proc_info['ppid']
                self.process_graph.add_node(pid, **proc_info)
                if ppid and ppid != pid:
                    self.process_graph.add_edge(ppid, pid)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    def analyze_process_chain(self, target_pid):
        """Analyze process chain for suspicious patterns"""
        self.build_process_tree()
        if target_pid not in self.process_graph:
            return {'error': 'Process not found'}

        # Trace ancestry
        ancestors = []
        current_pid = target_pid
        while current_pid in self.process_graph:
            node_data = self.process_graph.nodes[current_pid]
            ancestors.append({
                'pid': current_pid,
                'name': node_data.get('name', 'Unknown'),
                'cmdline': node_data.get('cmdline', []),
                'create_time': node_data.get('create_time', 0)
            })
            parents = list(self.process_graph.predecessors(current_pid))
            current_pid = parents[0] if parents else None

        # Analyze patterns
        suspicious_patterns = []
        for i in range(len(ancestors) - 1):
            child_name = ancestors[i]['name'].lower()
            parent_name = ancestors[i + 1]['name'].lower()
            pattern_key = (parent_name, child_name)
            if pattern_key in self.suspicious_parent_child_patterns:
                suspicious_patterns.append({
                    'parent': parent_name,
                    'child': child_name,
                    'description': self.suspicious_parent_child_patterns[pattern_key],
                    'risk_level': 'HIGH'
                })

        # Calculate risk score
        risk_score = len(suspicious_patterns) * 3

        # Additional risk factors
        target_proc = ancestors[0]
        cmdline = ' '.join(target_proc['cmdline']) if target_proc['cmdline'] else ''
        risky_keywords = [
            'bypass', 'hidden', 'encoded', 'schtasks', 'sc ', 'reg add',
            'reg delete', 'dns', 'certutil', 'mshta', 'wscript',
            'sdbinst', 'makecab', 'nltest', 'netsh', 'debug'
        ]
        if any(keyword in cmdline.lower() for keyword in risky_keywords):
            risk_score += 2

        return {
            'process_chain': ancestors,
            'suspicious_patterns': suspicious_patterns,
            'risk_score': min(risk_score, 10),
            'analysis_timestamp': datetime.now().isoformat()
        }

    def detect_process_injection(self, pid):
        """Detect potential process injection"""
        try:
            proc = psutil.Process(pid)
            memory_info = proc.memory_info()
            if memory_info.rss > 500 * 1024 * 1024:
                return {'risk': 'MEDIUM', 'reason': 'High memory usage'}

            connections = proc.connections()
            external_connections = [
                conn for conn in connections
                if conn.status == 'ESTABLISHED' and
                hasattr(conn, 'raddr') and conn.raddr and
                not conn.raddr.ip.startswith(('127.', '10.', '192.168.', '172.'))
            ]

            if external_connections:
                return {
                    'risk': 'HIGH',
                    'reason': 'External network connections',
                    'connections': len(external_connections)
                }

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

        return {'risk': 'LOW', 'reason': 'Normal process behavior'}
