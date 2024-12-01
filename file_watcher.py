import os
import subprocess
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import logging
import time  # Ensure time is imported for timestamp

# Configure logger
log_file = "logs/file_changes.log"
os.makedirs("logs", exist_ok=True)  # Ensure the logs folder exists

logging.basicConfig(
    filename=log_file,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# Email sending function
def send_email(subject, body, to_email):
    from_email = "torrentbotonline@gmail.com"  # Replace with your email
    from_password = "qweasd@2506"  # Replace with your email password or use an app password
    
    # Create the message
    msg = MIMEMultipart()
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Subject'] = subject
    
    # Attach the email body
    msg.attach(MIMEText(body, 'plain'))
    
    try:
        # Set up the SMTP server and send the email
        server = smtplib.SMTP('smtp.gmail.com', 587)  # Use your SMTP server (e.g., Gmail)
        server.starttls()
        server.login(from_email, from_password)
        text = msg.as_string()
        server.sendmail(from_email, to_email, text)
        server.quit()
        print(f"Email sent successfully to {to_email}.")
        logging.info(f"Email sent successfully to {to_email}.")
    except Exception as e:
        print(f"Error sending email: {e}")
        logging.error(f"Error sending email: {e}")

class AntivirusHandler(FileSystemEventHandler):
    def __init__(self, scan_directory, user_email):
        self.scan_directory = scan_directory
        self.user_email = user_email
        self.logs_folder = os.path.join(scan_directory, "logs")
        
        # Ensure logs folder exists
        if not os.path.exists(self.logs_folder):
            os.makedirs(self.logs_folder)
            print("Created 'logs' folder.")
            logging.info("Created 'logs' folder.")

    def on_created(self, event):
        if not event.is_directory:
            if event.src_path.startswith(self.logs_folder):
                self.log_event("created", event.src_path)
            else:
                print(f"New file created: {event.src_path}")
                logging.info(f"New file created: {event.src_path}")
                self.scan_file(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            if event.src_path.startswith(self.logs_folder):
                self.log_event("modified", event.src_path)
            else:
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
                # Send an email if malware is detected
                subject = f"Malware Detected in File: {file_path}"
                body = f"Malware was detected in the file: {file_path}\n\nScan Details:\n{scan_result}"
                send_email(subject, body, self.user_email)
        except Exception as e:
            print(f"Error scanning file {file_path}: {e}")
            logging.error(f"Error scanning file {file_path}: {e}")

    def log_event(self, event_type, file_path):
        try:
            print(f"{event_type.upper()} event for file: {file_path}")
            logging.info(f"{event_type.upper()} event for file: {file_path}")
        except Exception as e:
            print(f"Error logging event for {file_path}: {e}")
            logging.error(f"Error logging event for {file_path}: {e}")

def start_file_watcher(path_to_watch, user_email):
    event_handler = AntivirusHandler(path_to_watch, user_email)
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
    user_email = "praveenclg2506@gmail.com"  # Replace with user's email
    
    if not os.path.isdir(directory_to_watch):
        print(f"Error: The directory '{directory_to_watch}' does not exist.")
        logging.error(f"Error: The directory '{directory_to_watch}' does not exist.")
    else:
        start_file_watcher(directory_to_watch, user_email)
