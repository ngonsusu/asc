import traceback
from PyQt5.QtWidgets import QMessageBox
import subprocess

class ErrorHandler:
    def __init__(self, log_function):
        self.log = log_function
    
    def handle(self, exception, context=""):
        try:
            error_type = type(exception).__name__
            error_msg = str(exception)
            stack_trace = traceback.format_exc()
            
            self.log("Error", f"{error_type}: {error_msg}")
            self.log("Debug", f"Context: {context}")
            self.log("Debug", f"Stack trace:\n{stack_trace}")
            
            # User-friendly messages
            if isinstance(exception, subprocess.TimeoutExpired):
                self.show_warning("Timeout", "Operation took too long to complete.")
            elif isinstance(exception, subprocess.CalledProcessError):
                self.show_warning("Execution Error", f"Command failed with code {exception.returncode}")
            elif "network" in error_msg.lower() or "connection" in error_msg.lower():
                self.show_warning("Network Error", "Cannot connect to target. Check network and firewall settings.")
            elif "permission" in error_msg.lower() or "access" in error_msg.lower():
                self.show_warning("Permission Error", "Insufficient permissions. Try running as administrator.")
            elif "file" in error_msg.lower() or "directory" in error_msg.lower():
                self.show_warning("File Error", "File or directory not found. Please check the path.")
            elif "port" in error_msg.lower() or "service" in error_msg.lower():
                self.show_warning("Service Error", "Service unavailable or port blocked.")
            else:
                self.show_warning("System Error", f"An unexpected error occurred: {error_msg[:200]}")
        except Exception as e:
            print(f"Error handling failed: {str(e)}")
    
    def show_warning(self, title, message):
        try:
            QMessageBox.warning(None, title, message)
        except:
            pass