import subprocess
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import os
import winreg
import socket
import threading

class ExamIntegrity:
    def __init__(self, root, password):
        self.root = root
        self.root.title("Exam Integrity Control Panel")

        if not self.check_password(password):
            exit()

        self.setup_notebook()
        self.setup_tabs()
        self.setup_controls()
        self.setup_server()

    def check_password(self, correct_password):
        while True:
            password = simpledialog.askstring("Password", "Enter the password:", show='*')
            if password == correct_password:
                return True
            elif password is None:
                return False
            else:
                messagebox.showerror("Incorrect Password", "Incorrect password. Please try again.")

    def setup_notebook(self):
        self.notebook = ttk.Notebook(self.root)
        self.notebook.grid(row=0, column=0, columnspan=3, padx=10, pady=10, sticky="nsew")

        self.usb_frame = ttk.Frame(self.notebook)
        self.wifi_frame = ttk.Frame(self.notebook)
        self.ethernet_frame = ttk.Frame(self.notebook)

        self.notebook.add(self.usb_frame, text="USB Control")
        self.notebook.add(self.wifi_frame, text="Wi-Fi Control")
        self.notebook.add(self.ethernet_frame, text="Ethernet Control")

    def setup_tabs(self):
        # Setup USB tab
        tk.Label(self.usb_frame, text="USB Control", font=('Helvetica', 14, 'bold')).pack(pady=10)
        ttk.Button(self.usb_frame, text="Enable USB", command=self.enable_usb).pack(pady=5)
        ttk.Button(self.usb_frame, text="Disable USB", command=self.disable_usb).pack()

        # Setup Wi-Fi tab
        tk.Label(self.wifi_frame, text="Wi-Fi Control", font=('Helvetica', 14, 'bold')).pack(pady=10)
        ttk.Button(self.wifi_frame, text="Enable Wi-Fi", command=self.enable_wifi).pack(pady=5)
        ttk.Button(self.wifi_frame, text="Disable Wi-Fi", command=self.disable_wifi).pack()

        # Setup Ethernet tab
        tk.Label(self.ethernet_frame,text="EthernetControl",font=('Helvetica',14, 'bold')).pack(pady=10)
        ttk.Button(self.ethernet_frame,text="Enable_Ethernet",command=self.enable_ethernet).pack(pady=5)
        ttk.Button(self.ethernet_frame, text="Disable Ethernet", command=self.disable_ethernet).pack()

    def setup_controls(self):
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)

    def setup_server(self):
        # Start server socket to listen for commands
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind(('0.0.0.0', 6565))  # Bind to all available interfaces, port 6565
        self.server_socket.listen(5)  # Listen for incoming connections

        print("Server listening on port 6565...")

        # Accept incoming connections in a separate thread
        server_thread = threading.Thread(target=self.handle_clients)
        server_thread.start()

    def handle_clients(self):
        while True:
            client_socket, client_address = self.server_socket.accept()
            print(f"Connection established with {client_address}")

            # Handle client connection in a new thread
            client_handler_thread = threading.Thread(target=self.handle_client, args=(client_socket,))
            client_handler_thread.start()

    def handle_client(self, client_socket):
        while True:
            try:
                command = client_socket.recv(1024).decode()
                if not command:
                    break
                elif command == "enable_usb":
                    self.enable_usb()
                elif command == "disable_usb":
                    self.disable_usb()
                elif command == "enable_wifi":
                    self.enable_wifi()
                elif command == "disable_wifi":
                    self.disable_wifi()
                elif command == "enable_ethernet":
                    self.enable_ethernet()
                elif command == "disable_ethernet":
                    self.disable_ethernet()
                else:
                    print(f"Unknown command received: {command}")
            except Exception as e:
                print(f"Error handling command: {str(e)}")
                break
        client_socket.close()

    def enable_usb(self):
        key_path = r"SYSTEM\CurrentControlSet\Services\USBSTOR"
        key=winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,key_path,0,winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, "Start", 0, winreg.REG_DWORD, 3)
        winreg.CloseKey(key)
        messagebox.showinfo("USB Ports Enabled", "All USB ports are enabled.")

    def disable_usb(self):
        key_path = r"SYSTEM\CurrentControlSet\Services\USBSTOR"
        key=winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,key_path,0,winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, "Start", 0, winreg.REG_DWORD, 4)
        winreg.CloseKey(key)
        messagebox.showinfo("USB Ports Disabled", "All USB ports are disabled.")

   
    def enable_wifi(self):
        result = subprocess.run('netsh interface set interface "Wi-Fi" enable', check=False, shell=True,
        capture_output=True, text=True)
        if result.returncode == 0:
            messagebox.showinfo("Wi-Fi Enabled", "Wi-Fi is enabled.")
        else:
            messagebox.showerror("Error", "Failed to enable Wi-Fi")

    def disable_wifi(self):
        result = subprocess.run('netsh interface set interface "Wi-Fi" disable', check=False, shell=True,
        capture_output=True, text=True)
        if result.returncode == 0:
            messagebox.showinfo("Wi-Fi Disabled", "Wi-Fi is disabled.")
        else:
            messagebox.showerror("Error", "Failed to disable Wi-Fi")

    def enable_ethernet(self):
        result = subprocess.run('netsh interface set interface "ethernet" enable', check=False, shell=True,
         capture_output=True, text=True)
        if result.returncode == 0:
            messagebox.showinfo("Ethernet Enabled", "Ethernet is enabled.")
        else:
            messagebox.showerror("Error", f"Failed to enable Ethernet:\n{result.stdout}\n{result.stderr}")
    def disable_ethernet(self):
        result = subprocess.run('netsh interface set interface "ethernet" disable', check=False, shell=True, capture_output=True, text=True)
       
        if result.returncode == 0:
            messagebox.showinfo("Ethernet Disabled", "Ethernet is disabled.")
        else:
            messagebox.showerror("Error",f"Failed to disable Ethernet:\n{result.stdout}\n{result.stderr}")
if __name__ == "__main__":
    correct_password = "admin"
    root = tk.Tk()
    app = ExamIntegrity(root, correct_password)
    root.mainloop()
