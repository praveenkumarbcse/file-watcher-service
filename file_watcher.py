import os
import subprocess
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import logging
import time  # Ensure time is imported for timestamp

# Configure logger
logs_directory = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "logs")  # Logs folder outside the current directory
os.makedirs(logs_directory, exist_ok=True)  # Ensure the logs folder exists

log_file = os.path.join(logs_directory, "file_changes.log")  # Log file path

logging.basicConfig(
    filename=log_file,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

class AntivirusHandler(FileSystemEventHandler):
    def __init__(self, scan_directory):
        self.scan_directory = scan_directory

    def on_created(self, event):
        if not event.is_directory:
            print(f"New file created: {event.src_path}")
            logging.info(f"New file created: {event.src_path}")
            self.scan_file(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            print(f"File modified: {event.src_path}")
            logging.info(f"File modified: {event.src_path}")
            self.scan_file(event.src_path)

    def scan_file(self, file_path):
        try:
            print(f"Scanning file: {file_path}")
            logging.info(f"Scanning file: {file_path}")
            # Run clamscan on the file
            result = subprocess.run(
                ['clamscan', file_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            scan_result = result.stdout
            print(f"Scan details for {file_path}:\n{scan_result}")
            logging.debug(f"Scan details for {file_path}:\n{scan_result}")
            
            if result.returncode == 0:
                print(f"File {file_path} is clean.")
                logging.info(f"File {file_path} is clean.")
            else:
                print(f"Warning: Malware detected in file {file_path}.")
                logging.warning(f"Malware detected in file {file_path}.")
        except Exception as e:
            print(f"Error scanning file {file_path}: {e}")
            logging.error(f"Error scanning file {file_path}: {e}")

def start_file_watcher(path_to_watch):
    event_handler = AntivirusHandler(path_to_watch)
    observer = Observer()
    observer.schedule(event_handler, path_to_watch, recursive=True)
    observer.start()
    print(f"Started watching directory: {path_to_watch}")
    logging.info(f"Started watching directory: {path_to_watch}")

    try:
        while True:
            pass  # Keep the service running
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
    print("File watcher service stopped.")
    logging.info("File watcher service stopped.")

if __name__ == "__main__":
    directory_to_watch = os.getcwd()  # Current directory
    
    if not os.path.isdir(directory_to_watch):
        print(f"Error: The directory '{directory_to_watch}' does not exist.")
        logging.error(f"Error: The directory '{directory_to_watch}' does not exist.")
    else:
        start_file_watcher(directory_to_watch)
