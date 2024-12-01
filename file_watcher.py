import os
import subprocess
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Configure logging
log_folder = "logs"
os.makedirs(log_folder, exist_ok=True)
log_file = os.path.join(log_folder, "file_watcher.log")

logging.basicConfig(
    filename=log_file,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

class AntivirusHandler(FileSystemEventHandler):
    def __init__(self, scan_directory):
        self.scan_directory = scan_directory

    def on_created(self, event):
        if not event.is_directory and not event.src_path.startswith(log_folder):
            self.scan_file(event.src_path)

    def on_modified(self, event):
        if not event.is_directory and not event.src_path.startswith(log_folder):
            self.scan_file(event.src_path)

    def scan_file(self, file_path):
        try:
            logging.info(f"Scanning file: {file_path}")
            # Run clamscan on the file
            result = subprocess.run(
                ['clamscan', file_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            if result.returncode == 0:
                logging.info(f"File {file_path} is clean.")
            else:
                logging.warning(f"Malware detected in file {file_path}.\n{result.stdout}")
        except Exception as e:
            logging.error(f"Error scanning file {file_path}: {e}")

def start_file_watcher(path_to_watch):
    event_handler = AntivirusHandler(path_to_watch)
    observer = Observer()
    observer.schedule(event_handler, path_to_watch, recursive=True)
    observer.start()
    logging.info(f"Started watching directory: {path_to_watch}")

    try:
        while True:
            pass  # Keep the service running
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
    logging.info("File watcher service stopped.")

if __name__ == "__main__":
    directory_to_watch = os.getcwd()
    if not os.path.isdir(directory_to_watch):
        print(f"Error: The directory '{directory_to_watch}' does not exist.")
    else:
        start_file_watcher(directory_to_watch)
