import subprocess
import yara
import sys
import os
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, TimeoutError
import tarfile
import tempfile
import shutil

# Color Codes for terminal output
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"

# Path to watch for new files (change this to the appropriate download folder)
download_folder = "~/Downloads"

def print_success(message):
    print(f"{GREEN}{message}{RESET}")

def print_warning(message):
    print(f"{YELLOW}{message}{RESET}")

def print_error(message):
    print(f"{RED}{message}{RESET}")

def scan_with_yara(file_path):
    """ Use YARA rules to detect suspicious activity """
    try:
        # Load YARA rule
        rules = yara.compile(filepath="keylogger_rule.yara")
        
        # Scan the file
        matches = rules.match(file_path)

        if matches:
            print_warning(f"[ALERT] YARA rule triggered for {file_path}. Suspicious activity detected!")
            return True
    except Exception as e:
        print_error(f"Error with YARA scan: {e}")
    return False

def scan_deb(file_path):
    """ Scan .deb files directly for suspicious scripts without extracting everything """
    print(f"[INFO] Scanning .deb file: {file_path}")

    # Get file size for more detailed output
    file_size = os.path.getsize(file_path) / (1024 * 1024)  # in MB
    print(f"{YELLOW}Scanning file details:{RESET}")
    print(f"  File: {file_path}")
    print(f"  Size: {file_size:.2f} MB")

    try:
        # Extract the .deb file using ar (ar is used for deb file extraction)
        temp_dir = tempfile.mkdtemp()  # Create a temporary directory for extraction
        subprocess.run(['ar', 'x', file_path], check=True, cwd=temp_dir)  # Extract to temp directory

        # Find the .tar.gz (or .tar.xz) file inside the extracted files
        control_tar = [f for f in os.listdir(temp_dir) if f.endswith(('.tar.gz', '.tar.xz'))]

        if not control_tar:
            print_error(f"Error: No control archive found in {file_path}.")
            shutil.rmtree(temp_dir)  # Clean up
            return False

        # Extract the control archive
        with tarfile.open(os.path.join(temp_dir, control_tar[0]), 'r:*') as tar:
            tar.extractall(path=temp_dir)

        # Now look for suspicious files within the extracted files
        suspicious_files = []
        for root, dirs, files in os.walk(temp_dir):
            for file in files:
                if file.endswith((".sh", ".py", ".conf", ".service")):
                    suspicious_files.append(os.path.join(root, file))

        if not suspicious_files:
            print_success("[SAFE] No keylogger detected in the .deb package.")
            shutil.rmtree(temp_dir)  # Clean up
            return False

        # Scan the suspicious files
        with ThreadPoolExecutor() as executor:
            future_to_file = {
                executor.submit(scan_with_yara, file): file
                for file in suspicious_files
            }

            for future in future_to_file:
                if future.result():
                    print_warning("[ALERT] Potential keylogger detected in the .deb package!")
                    shutil.rmtree(temp_dir)  # Clean up
                    return True
    except Exception as e:
        print_error(f"Error while scanning .deb package: {e}")
        shutil.rmtree(temp_dir)  # Clean up

    print_success("[SAFE] No keylogger detected in the .deb package.")
    shutil.rmtree(temp_dir)  # Clean up
    return False

def scan_with_timeout(file_path, timeout=30):
    """ Add timeout to scanning the .deb file """
    try:
        with ThreadPoolExecutor() as executor:
            future = executor.submit(scan_deb, file_path)
            result = future.result(timeout=timeout)  # Set timeout here
            return result
    except TimeoutError:
        print_error("[TIMEOUT] Scanning the .deb file took too long and was terminated.")
        return False

def watch_download_folder(path_to_watch="~/Downloads"):
    """ Watch for new .deb files in the Downloads folder using inotify """
    path_to_watch = os.path.expanduser(path_to_watch)
    command = f'inotifywait -m -e close_write --format "%f" {path_to_watch}'

    try:
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
        print(f"[INFO] Watching folder: {path_to_watch}")
        while True:
            new_file = process.stdout.readline().decode('utf-8').strip()
            if new_file.endswith(".deb"):
                print_success(f"[INFO] New .deb file detected: {new_file}")
                scan_with_timeout(os.path.join(path_to_watch, new_file))  # Run scan with timeout
    except KeyboardInterrupt:
        print("\n[INFO] Scan interrupted by user.")
    except Exception as e:
        print_error(f"Error: {e}")

def main():
    if len(sys.argv) != 2:
        print_error("Usage: python3 keylogger_scanner.py <file.deb>")
        sys.exit(1)

    file_path = sys.argv[1]

    if file_path.endswith(".deb"):
        scan_with_timeout(file_path)  # Run scan with timeout
    else:
        print_error("Unsupported file type. Please scan a .deb file.")
    
    # Automatically watch the download folder for new files
    watch_download_folder(download_folder)

if __name__ == "__main__":
    main()
