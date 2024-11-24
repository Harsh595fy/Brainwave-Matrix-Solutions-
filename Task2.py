import os

import subprocess

import time

import threading

import hashlib

import pefile

from watchdog.observers import Observer

from watchdog.events import FileSystemEventHandler

from scapy.all import sniff



# Specify default monitoring directory

DEFAULT_MONITOR_DIR = "/path/to/sandbox"  # Update this to your desired default directory



class ChangeHandler(FileSystemEventHandler):

    """Handles file system events like creation, modification, and deletion."""

    def on_modified(self, event):

        print(f"[File Modified]: {event.src_path}")



    def on_created(self, event):

        print(f"[File Created]: {event.src_path}")



    def on_deleted(self, event):

        print(f"[File Deleted]: {event.src_path}")



def start_file_monitor():

    """Starts monitoring file changes in the specified directory."""

    monitor_dir = input(f"Enter the directory to monitor (default: {DEFAULT_MONITOR_DIR}): ") or DEFAULT_MONITOR_DIR



    # Validate directory

    if not os.path.exists(monitor_dir):

        print(f"[ERROR] Directory does not exist: {monitor_dir}")

        create_choice = input("[INFO] Would you like to create the directory? (y/n): ").strip().lower()

        if create_choice == "y":

            os.makedirs(monitor_dir)

            print(f"[INFO] Directory created: {monitor_dir}")

        else:

            print("[ERROR] Exiting as the directory does not exist.")

            return



    print(f"[INFO] Monitoring directory: {monitor_dir}")

    event_handler = ChangeHandler()

    observer = Observer()

    observer.schedule(event_handler, path=monitor_dir, recursive=True)

    observer.start()



    print("[INFO] File monitoring started. Press Ctrl+C to stop.")

    try:

        while True:

            time.sleep(1)

    except KeyboardInterrupt:

        print("[INFO] Stopping file monitoring...")

        observer.stop()

    observer.join()



def packet_callback(packet):

    """Callback function to process captured network packets."""

    print(f"[Network Packet]: {packet.summary()}")



def start_network_monitor():

    """Starts monitoring network traffic."""

    print("[INFO] Network traffic monitoring started...")

    try:

        sniff(prn=packet_callback, store=False)

    except PermissionError:

        print("[ERROR] Network monitoring requires root privileges. Please run the script as root.")

    except Exception as e:

        print(f"[ERROR] Unexpected error in network monitoring: {e}")



def execute_sample(sample_path):

    """Executes the malware sample using Wine or native execution."""

    print(f"[INFO] Executing sample: {sample_path}")

    if not os.path.exists(sample_path):

        print(f"[ERROR] File not found: {sample_path}")

        return



    try:

        if sample_path.endswith(".exe"):

            subprocess.run(["wine", sample_path], check=True)

        elif os.access(sample_path, os.X_OK):

            subprocess.run(sample_path, check=True)

        else:

            print(f"[ERROR] File is not executable or unsupported: {sample_path}")

    except subprocess.CalledProcessError:

        print(f"[ERROR] Error executing the sample: {sample_path}")

    except Exception as e:

        print(f"[ERROR] Unexpected error during execution: {e}")



def generate_report(sample_path):

    """Analyzes the .exe file and generates a detailed report."""

    print("[INFO] Starting detailed analysis...")

    if not os.path.exists(sample_path):

        print(f"[ERROR] File not found: {sample_path}")

        return



    try:

        report = f"=== Malware Analysis Report ===\n"

        report += f"File: {sample_path}\n\n"



        # Generate SHA-256 hash

        sha256_hash = hashlib.sha256()

        with open(sample_path, "rb") as f:

            for byte_block in iter(lambda: f.read(4096), b""):

                sha256_hash.update(byte_block)

        report += f"SHA-256 Hash: {sha256_hash.hexdigest()}\n"



        # Perform static analysis using pefile

        if sample_path.endswith(".exe"):

            try:

                pe = pefile.PE(sample_path)

                report += "\n--- PE Metadata ---\n"

                report += f"Entry Point: {hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)}\n"

                report += f"Image Base: {hex(pe.OPTIONAL_HEADER.ImageBase)}\n"

                report += f"Sections:\n"

                for section in pe.sections:

                    report += f"  {section.Name.decode().strip()}: {hex(section.VirtualAddress)}\n"

            except pefile.PEFormatError:

                report += "[WARNING] PE format analysis failed. File may not be a valid PE file.\n"



        # Save analysis report

        report_path = os.path.join(os.path.dirname(sample_path), "analysis_report.txt")

        with open(report_path, "w") as report_file:

            report_file.write(report)



        print(f"[INFO] Analysis complete. Report saved to: {report_path}")

        print(report)



    except Exception as e:

        print(f"[ERROR] Error during analysis: {e}")



def options_menu():

    """Displays the options menu and handles user input."""

    while True:

        print("\n=== Malware Analysis Tool ===")

        print("1. Start file monitoring")

        print("2. Start network monitoring")

        print("3. Execute malware sample")

        print("4. Run all features simultaneously")

        print("5. Advanced analysis (analyze .exe file and generate report)")

        print("6. Exit")

        choice = input("Enter your choice: ")



        if choice == "1":

            start_file_monitor()

        elif choice == "2":

            start_network_monitor()

        elif choice == "3":

            sample_path = input("Enter the malware sample file path (e.g., /path/to/sample.exe): ")

            execute_sample(sample_path)

        elif choice == "4":

            sample_path = input("Enter the malware sample file path (e.g., /path/to/sample.exe): ")

            file_monitor_thread = threading.Thread(target=start_file_monitor, daemon=True)

            network_monitor_thread = threading.Thread(target=start_network_monitor, daemon=True)

            file_monitor_thread.start()

            network_monitor_thread.start()

            execute_sample(sample_path)

        elif choice == "5":

            sample_path = input("Enter the malware sample file path (e.g., /path/to/sample.exe): ")

            generate_report(sample_path)

        elif choice == "6":

            print("[INFO] Exiting the program.")

            break

        else:

            print("[ERROR] Invalid choice. Please try again.")



if __name__ == "__main__":

    options_menu()

