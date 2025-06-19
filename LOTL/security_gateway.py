from entropy_analyzer import EntropyAnalyzer
from vm_manager import HyperVManager
from ml_analyzer import MLThreatAnalyzer
from process_analyzer import ProcessTreeAnalyzer
from process_hook import ProcessInterceptor
import asyncio
import json
import time
import logging
from datetime import datetime
import hashlib

class SecurityGateway:
    def __init__(self):
        self.process_interceptor = ProcessInterceptor()
        self.vm_manager = HyperVManager()
        self.entropy_analyzer = EntropyAnalyzer()
        self.process_analyzer = ProcessTreeAnalyzer()
        self.ml_analyzer = MLThreatAnalyzer()
        
        # Cache for analyzed operations
        self.analysis_cache = {}
        self.cache_ttl = 3600  # 1 hour
        
        # Risk thresholds
        self.risk_thresholds = {
            'allow': 3.0,
            'monitor': 6.0,
            'block': 8.0
        }
        
        # Active monitoring
        self.monitoring_active = False
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('security_gateway.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
    async def start_protection(self):
        """Start the security gateway"""
        self.logger.info("Starting Security Gateway...")
        
        # Load ML model if available
        if not self.ml_analyzer.load_model('ml_model.pkl'):
            self.logger.warning("ML model not found, will train on first run")
            
        # Start process interception
        self.process_interceptor.start_interception()
        self.monitoring_active = True
        
        # Main monitoring loop
        await self._monitoring_loop()
        
    async def _monitoring_loop(self):
        """Main monitoring loop"""
        while self.monitoring_active:
            try:
                # Check for intercepted processes
                if not self.process_interceptor.process_queue.empty():
                    process_info = self.process_interceptor.process_queue.get()
                    await self._handle_intercepted_process(process_info)
                    
                await asyncio.sleep(0.1)  # Small delay to prevent CPU spinning
                
            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}")
                await asyncio.sleep(1)
                
    async def _handle_intercepted_process(self, process_info):
        """Handle an intercepted process"""
        self.logger.info(f"Intercepted process: {process_info['name']} (PID: {process_info['pid']})")
        
        # Generate cache key
        cache_key = self._generate_cache_key(process_info)
        
        # Check cache first
        if cache_key in self.analysis_cache:
            cached_result = self.analysis_cache[cache_key]
            if time.time() - cached_result['timestamp'] < self.cache_ttl:
                self.logger.info(f"Using cached result for {process_info['name']}")
                await self._make_decision(process_info, cached_result['analysis'])
                return
                
        # Perform full analysis
        analysis_result = await self._analyze_process(process_info)
        
        # Cache result
        self.analysis_cache[cache_key] = {
            'analysis': analysis_result,
            'timestamp': time.time()
        }
        
        # Make decision
        await self._make_decision(process_info, analysis_result)
        
    def _generate_cache_key(self, process_info):
        """Generate cache key for process"""
        key_data = f"{process_info['name']}:{process_info.get('cmdline', '')}"
        return hashlib.md5(key_data.encode()).hexdigest()
        
    async def _analyze_process(self, process_info):
        """Comprehensive process analysis"""
        analysis_start = time.time()
        analysis_results = {
            'timestamp': datetime.now().isoformat(),
            'process_info': process_info,
            'analyses': {}
        }
        
        try:
            # 1. Process tree analysis
            tree_analysis = self.process_analyzer.analyze_process_chain(process_info['pid'])
            analysis_results['analyses']['process_tree'] = tree_analysis
            
            # 2. ML-based analysis
            ml_analysis = self.ml_analyzer.predict_threat(process_info)
            analysis_results['analyses']['ml_prediction'] = ml_analysis
            
            # 3. Sandbox testing for high-risk processes
            initial_risk = process_info.get('risk_level', 1.0)
            if initial_risk > 5.0 or tree_analysis.get('risk_score', 0) > 5.0:
                sandbox_result = await self._sandbox_test(process_info)
                analysis_results['analyses']['sandbox'] = sandbox_result
            else:
                analysis_results['analyses']['sandbox'] = {'skipped': True, 'reason': 'Low initial risk'}
                
            # 4. Calculate final risk score
            final_risk = self._calculate_final_risk(analysis_results['analyses'])
            analysis_results['final_risk_score'] = final_risk
            
        except Exception as e:
            self.logger.error(f"Error during analysis: {e}")
            analysis_results['error'] = str(e)
            analysis_results['final_risk_score'] = 10.0  # Assume high risk on error
            
        analysis_results['analysis_time'] = time.time() - analysis_start
        return analysis_results
        
    async def _sandbox_test(self, process_info):
        """Test process in sandbox environment"""
        self.logger.info(f"Starting sandbox test for {process_info['name']}")
        
        try:
            # Create sandbox VM
            vm_name = self.vm_manager.create_sandbox_vm()
            if not vm_name:
                return {'error': 'Failed to create sandbox VM'}
                
            # Prepare command for testing
            test_command = self._prepare_sandbox_command(process_info)
            
            # Execute in sandbox
            execution_result = self.vm_manager.execute_in_vm(vm_name, test_command, timeout=30)
            
            # Analyze results
            sandbox_analysis = self._analyze_sandbox_results(execution_result)
            
            # Cleanup
            self.vm_manager.cleanup_vm(vm_name)
            
            return sandbox_analysis
            
        except Exception as e:
            self.logger.error(f"Sandbox testing error: {e}")
            return {'error': str(e), 'risk_assessment': 'HIGH'}
            
    def _prepare_sandbox_command(self, process_info):
        """Prepare command for sandbox execution"""
        name = process_info['name'].lower()
        cmdline = process_info.get('cmdline', '')
        
        if 'powershell' in name:
            # For PowerShell, create a monitored execution
            return f"""
            # Create baseline file states
            $baseline = Get-ChildItem C:\\temp -Recurse | Measure-Object Length -Sum
            
            # Execute the command with monitoring
            try {{
                {cmdline}
            }} catch {{
                Write-Output "EXECUTION_ERROR: $($_.Exception.Message)"
            }}
            
            # Check for file system changes
            $postExec = Get-ChildItem C:\\temp -Recurse | Measure-Object Length -Sum
            $changeRatio = if ($baseline.Sum -gt 0) {{ ($postExec.Sum - $baseline.Sum) / $baseline.Sum }} else {{ 0 }}
            
            Write-Output "BASELINE_SIZE: $($baseline.Sum)"
            Write-Output "POST_EXEC_SIZE: $($postExec.Sum)"
            Write-Output "CHANGE_RATIO: $changeRatio"
            
            # Check for network activity
            $connections = Get-NetTCPConnection | Where-Object {{ $_.State -eq 'Established' }}
            Write-Output "NETWORK_CONNECTIONS: $($connections.Count)"
            
            # Check for new processes
            $processes = Get-Process | Where-Object {{ $_.StartTime -gt (Get-Date).AddMinutes(-1) }}
            Write-Output "NEW_PROCESSES: $($processes.Count)"
            """
        
        elif 'cmd' in name:
            return f"""
            echo BASELINE_CHECK
            dir C:\\temp /s > baseline.txt
            
            REM Execute the command
            {cmdline}
            
            echo POST_EXEC_CHECK
            dir C:\\temp /s > postexec.txt
            
            REM Simple file count comparison
            for /f %%i in ('type baseline.txt ^| find /c /v ""') do set baseline_count=%%i
            for /f %%i in ('type postexec.txt ^| find /c /v ""') do set postexec_count=%%i
            
            echo BASELINE_FILES: %baseline_count%
            echo POST_EXEC_FILES: %postexec_count%
            """
        
        else:
            # For other executables, wrap in PowerShell monitoring
            return f"""
            $baseline = Get-ChildItem C:\\temp -Recurse -ErrorAction SilentlyContinue | Measure-Object Length -Sum
            
            # Execute the process
            Start-Process -FilePath "{process_info['name']}" -ArgumentList "{cmdline}" -Wait -NoNewWindow
            
            $postExec = Get-ChildItem C:\\temp -Recurse -ErrorAction SilentlyContinue | Measure-Object Length -Sum
            Write-Output "BASELINE_SIZE: $($baseline.Sum)"
            Write-Output "POST_EXEC_SIZE: $($postExec.Sum)"
            """
            
    def _analyze_sandbox_results(self, execution_result):
        """Analyze sandbox execution results"""
        if not execution_result['success']:
            return {
                'risk_level': 'HIGH',
                'reason': 'Execution failed in sandbox',
                'details': execution_result['error']
            }
            
        output = execution_result['output']
        risk_score = 0.0
        risk_factors = []
        
        # Parse output for indicators
        lines = output.split('\n')
        metrics = {}
        
        for line in lines:
            if ':' in line:
                key, value = line.split(':', 1)
                metrics[key.strip()] = value.strip()
                
        # Analyze file system changes
        baseline_size = float(metrics.get('BASELINE_SIZE', 0))
        postexec_size = float(metrics.get('POST_EXEC_SIZE', 0))
        
        if baseline_size > 0:
            change_ratio = abs(postexec_size - baseline_size) / baseline_size
            if change_ratio > 0.5:  # 50% change in file sizes
                risk_score += 3.0
                risk_factors.append(f'Significant file system changes: {change_ratio:.2%}')
                
        # Check for mass file creation/deletion
        baseline_files = int(metrics.get('BASELINE_FILES', 0))
        postexec_files = int(metrics.get('POST_EXEC_FILES', 0))
        
        if baseline_files > 0:
            file_change_ratio = abs(postexec_files - baseline_files) / baseline_files
            if file_change_ratio > 0.3:  # 30% change in file count
                risk_score += 2.0
                risk_factors.append(f'File count change: {file_change_ratio:.2%}')
                
        # Check for network activity
        connections = int(metrics.get('NETWORK_CONNECTIONS', 0))
        if connections > 5:  # More than 5 network connections
            risk_score += 2.0
            risk_factors.append(f'High network activity: {connections} connections')
            
        # Check for process spawning
        new_processes = int(metrics.get('NEW_PROCESSES', 0))
        if new_processes > 3:  # More than 3 new processes
            risk_score += 1.5
            risk_factors.append(f'Multiple process creation: {new_processes} processes')
            
        # Check for execution errors
        if 'EXECUTION_ERROR' in output:
            risk_score += 1.0
            risk_factors.append('Command execution errors detected')
            
        # Determine risk level
        if risk_score >= 6.0:
            risk_level = 'CRITICAL'
        elif risk_score >= 3.0:
            risk_level = 'HIGH'
        elif risk_score >= 1.0:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'
            
        return {
            'risk_level': risk_level,
            'risk_score': min(risk_score, 10.0),
            'risk_factors': risk_factors,
            'sandbox_metrics': metrics,
            'execution_time': execution_result.get('execution_time', 0)
        }
        
    def _calculate_final_risk(self, analyses):
        """Calculate final risk score from all analyses"""
        weights = {
            'process_tree': 0.3,
            'ml_prediction': 0.3,
            'sandbox': 0.4
        }
        
        total_score = 0.0
        total_weight = 0.0
        
        # Process tree analysis
        if 'process_tree' in analyses and 'risk_score' in analyses['process_tree']:
            score = analyses['process_tree']['risk_score']
            total_score += score * weights['process_tree']
            total_weight += weights['process_tree']
            
        # ML prediction
        if 'ml_prediction' in analyses and 'risk_score' in analyses['ml_prediction']:
            score = analyses['ml_prediction']['risk_score']
            total_score += score * weights['ml_prediction']
            total_weight += weights['ml_prediction']
            
        # Sandbox analysis
        if 'sandbox' in analyses and 'risk_score' in analyses['sandbox']:
            score = analyses['sandbox']['risk_score']
            total_score += score * weights['sandbox']
            total_weight += weights['sandbox']
        elif 'sandbox' in analyses and analyses['sandbox'].get('skipped'):
            # If sandbox was skipped, use average of other scores
            if total_weight > 0:
                avg_score = total_score / total_weight
                total_score += avg_score * weights['sandbox']
                total_weight += weights['sandbox']
                
        final_score = total_score / total_weight if total_weight > 0 else 5.0
        return min(final_score, 10.0)
        
    async def _make_decision(self, process_info, analysis_result):
        """Make final decision on process execution"""
        risk_score = analysis_result.get('final_risk_score', 5.0)
        pid = process_info['pid']
        process_name = process_info['name']
        
        decision_data = {
            'timestamp': datetime.now().isoformat(),
            'process': process_name,
            'pid': pid,
            'risk_score': risk_score,
            'analysis_result': analysis_result
        }
        
        if risk_score < self.risk_thresholds['allow']:
            decision = 'ALLOW'
            action = self._allow_process
        elif risk_score < self.risk_thresholds['monitor']:
            decision = 'MONITOR'
            action = self._monitor_process
        elif risk_score < self.risk_thresholds['block']:
            decision = 'QUARANTINE'
            action = self._quarantine_process
        else:
            decision = 'BLOCK'
            action = self._block_process
            
        decision_data['decision'] = decision
        
        self.logger.info(f"Decision for {process_name} (PID: {pid}): {decision} (Risk: {risk_score:.2f})")
        
        # Execute decision
        try:
            await action(process_info, analysis_result)
            decision_data['action_successful'] = True
        except Exception as e:
            self.logger.error(f"Error executing decision {decision}: {e}")
            decision_data['action_successful'] = False
            decision_data['error'] = str(e)
            
        # Log decision
        self._log_decision(decision_data)
        
    async def _allow_process(self, process_info, analysis_result):
        """Allow process to continue normally"""
        self.logger.info(f"Allowing process {process_info['name']} (PID: {process_info['pid']})")
        # Process continues normally, no action needed
        
    async def _monitor_process(self, process_info, analysis_result):
        """Monitor process with enhanced logging"""
        pid = process_info['pid']
        self.logger.info(f"Enhanced monitoring for process {process_info['name']} (PID: {pid})")
        
        # Start enhanced monitoring in background
        asyncio.create_task(self._enhanced_monitoring(pid))
        
    async def _quarantine_process(self, process_info, analysis_result):
        """Quarantine process (suspend and isolate)"""
        pid = process_info['pid']
        self.logger.warning(f"Quarantining process {process_info['name']} (PID: {pid})")
        
        try:
            import psutil
            proc = psutil.Process(pid)
            proc.suspend()
            
            # Log quarantine action
            self.logger.info(f"Process {pid} suspended successfully")
            
        except psutil.NoSuchProcess:
            self.logger.info(f"Process {pid} already terminated")
        except Exception as e:
            self.logger.error(f"Failed to quarantine process {pid}: {e}")
            
    async def _block_process(self, process_info, analysis_result):
        """Block/terminate process immediately"""
        pid = process_info['pid']
        self.logger.error(f"BLOCKING process {process_info['name']} (PID: {pid}) - HIGH RISK DETECTED")
        
        try:
            import psutil
            proc = psutil.Process(pid)
            proc.terminate()
            
            # Wait for termination
            try:
                proc.wait(timeout=5)
            except psutil.TimeoutExpired:
                proc.kill()  # Force kill if terminate doesn't work
                
            self.logger.info(f"Process {pid} terminated successfully")
            
            # Create system snapshot for potential rollback
            await self._create_emergency_snapshot()
            
        except psutil.NoSuchProcess:
            self.logger.info(f"Process {pid} already terminated")
        except Exception as e:
            self.logger.error(f"Failed to block process {pid}: {e}")
            
    async def _enhanced_monitoring(self, pid):
        """Enhanced monitoring for suspicious processes"""
        try:
            import psutil
            proc = psutil.Process(pid)
            
            monitoring_duration = 300  # 5 minutes
            check_interval = 5  # 5 seconds
            
            for _ in range(monitoring_duration // check_interval):
                if not proc.is_running():
                    break
                    
                # Monitor file operations
                try:
                    open_files = proc.open_files()
                    if len(open_files) > 50:  # Unusually high file handle count
                        self.logger.warning(f"Process {pid} has {len(open_files)} open files")
                        
                    # Monitor network connections
                    connections = proc.connections()
                    external_connections = [
                        conn for conn in connections 
                        if hasattr(conn, 'raddr') and conn.raddr and 
                        not conn.raddr.ip.startswith(('127.', '10.', '192.168.', '172.'))
                    ]
                    
                    if external_connections:
                        self.logger.warning(f"Process {pid} has {len(external_connections)} external connections")
                        
                except psutil.AccessDenied:
                    pass
                    
                await asyncio.sleep(check_interval)
                
        except psutil.NoSuchProcess:
            self.logger.info(f"Monitored process {pid} has terminated")
        except Exception as e:
            self.logger.error(f"Error in enhanced monitoring for {pid}: {e}")
            
    async def _create_emergency_snapshot(self):
        """Create emergency system snapshot"""
        try:
            # Create VSS snapshot
            ps_command = """
            $VSSAdmin = "vssadmin create shadow /for=C:"
            Invoke-Expression $VSSAdmin
            """
            
            import subprocess
            result = subprocess.run([
                'powershell', '-ExecutionPolicy', 'Bypass', '-Command', ps_command
            ], capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                self.logger.info("Emergency snapshot created successfully")
            else:
                self.logger.error(f"Failed to create snapshot: {result.stderr}")
                
        except Exception as e:
            self.logger.error(f"Error creating emergency snapshot: {e}")
            
    def _log_decision(self, decision_data):
        """Log decision to file and potentially SIEM"""
        log_entry = json.dumps(decision_data, indent=2)
        
        # Write to decision log
        try:
            with open('security_decisions.json', 'a') as f:
                f.write(log_entry + '\n')
        except Exception as e:
            self.logger.error(f"Failed to write decision log: {e}")
            
        # Send to SIEM/monitoring system (placeholder)
        if decision_data['decision'] in ['QUARANTINE', 'BLOCK']:
            self._send_alert(decision_data)
            
    def _send_alert(self, decision_data):
        """Send alert to monitoring system"""
        # Placeholder for SIEM/alerting integration
        alert_message = f"""
        SECURITY ALERT: {decision_data['decision']} action taken
        Process: {decision_data['process']} (PID: {decision_data['pid']})
        Risk Score: {decision_data['risk_score']:.2f}
        Timestamp: {decision_data['timestamp']}
        """
        
        self.logger.critical(alert_message)
        
        # Here you would integrate with your alerting system:
        # - Send email
        # - Send to Slack/Teams
        # - Send to SIEM
        # - Trigger incident response
        
    def stop_protection(self):
        """Stop the security gateway"""
        self.logger.info("Stopping Security Gateway...")
        self.monitoring_active = False
        
        # Save ML model
        self.ml_analyzer.save_model('ml_model.pkl')
        
        self.logger.info("Security Gateway stopped")

# Main execution
async def main():
    """Main function to run the security gateway"""
    gateway = SecurityGateway()
    
    try:
        await gateway.start_protection()
    except KeyboardInterrupt:
        print("\nShutting down...")
        gateway.stop_protection()
    except Exception as e:
        print(f"Fatal error: {e}")
        gateway.stop_protection()

if __name__ == "__main__":
    asyncio.run(main())