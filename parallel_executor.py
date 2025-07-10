import subprocess
import threading
import time
from queue import Queue
from utils import get_creation_flags

class ParallelExecutor:
    def __init__(self, max_threads=5, log_function=None):
        self.max_threads = max_threads
        self.log = log_function
        self.task_queue = Queue()
        self.results = {}
        self.active_threads = 0
        self.lock = threading.Lock()
    
    def add_task(self, target_id, command, service):
        self.task_queue.put((target_id, command, service))
    
    def worker(self):
        while True:
            target_id, command, service = self.task_queue.get()
            if target_id is None:  # Exit signal
                break
                
            try:
                with self.lock:
                    self.active_threads += 1
                
                if not command:
                    self.log("Error", "Empty command received")
                    continue
                    
                target = command[-1].split('://')[-1] if '://' in command[-1] else command[-1]
                self.log("Info", f"Starting brute-force for {service} on {target}")
                
                # Execute command with timeout
                creation_flags = get_creation_flags()
                timeout = 300  # 5 minutes
                output = ""
                
                try:
                    result = subprocess.run(
                        command,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        encoding="utf-8",
                        errors="ignore",
                        timeout=timeout,
                        creationflags=creation_flags
                    )
                    output = result.stdout
                except subprocess.TimeoutExpired:
                    self.log("Warning", f"Timeout for {service} on {target}")
                except Exception as e:
                    self.log("Error", f"Command execution error: {str(e)}")
                
                found_credentials = []
                if output:
                    # Log the output
                    self.log("Debug", output)
                    
                    # Parse credentials - Hydra output format
                    for line in output.splitlines():
                        line = line.strip()
                        if "login:" in line and "password:" in line:
                            parts = line.split()
                            try:
                                login_index = parts.index("login:")
                                password_index = parts.index("password:")
                                username = parts[login_index + 1]
                                password = parts[password_index + 1]
                                found_credentials.append(f"{username}:{password}")
                            except:
                                # Alternative format
                                if len(parts) >= 4:
                                    found_credentials.append(f"{parts[-2]}:{parts[-1]}")
                
                # Store results
                self.results[target_id] = {
                    "success": bool(found_credentials),
                    "credentials": found_credentials,
                    "service": service
                }
                
            except Exception as e:
                self.log("Error", f"Execution error: {str(e)}")
                self.results[target_id] = {
                    "success": False,
                    "error": str(e)
                }
            finally:
                with self.lock:
                    self.active_threads -= 1
                self.task_queue.task_done()
    
    def start(self):
        # Start worker threads
        for _ in range(self.max_threads):
            thread = threading.Thread(target=self.worker, daemon=True)
            thread.start()
    
    def wait_completion(self):
        self.task_queue.join()
        return self.results
    
    def stop(self):
        # Send stop signal to all threads
        for _ in range(self.max_threads):
            self.task_queue.put((None, None, None))