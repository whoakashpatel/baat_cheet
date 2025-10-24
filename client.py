import tkinter as tk
from tkinter import messagebox, scrolledtext, simpledialog, filedialog, Toplevel, Frame, Label, Button, Entry
from getmac import get_mac_address
import socket
import threading
import json
import time
import sys
import os
from pathlib import Path

# --- Constants ---
SERVER_HOST = '10.83.175.161'  # Change to server's IP if not running locally
SERVER_PORT = 12345
DOWNLOAD_DIR = 'downloads' # Directory to save downloaded files


class ChatClient:
    def __init__(self, root):
        self.root = root
        self.root.title("Video Chat")
        self.root.geometry("300x150") # Initial size, will be resized
        self.root.withdraw()  # Hide main window initially

        self.username = None
        self.socket = None
        self.login_window = None # Will hold login window
        self.connecting_window = None # Will hold connecting popup
        self.is_remembered = False # Flag to track if user is in server's list
        self.exit_prompt_window = None # Will hold the exit prompt
        
        # --- Chat Data ---
        self.chat_history = []
        self.chat_display = None
        self.chat_entry = None
        self.listen_thread = None

        # --- File Data ---
        self.download_dir_path = Path(DOWNLOAD_DIR)
        self.setup_download_dir()
        
        self.server_file_list = [] # List of (filename, filesize) from server
        self.local_file_path = None # Path to file selected for upload
        self.upload_button = None
        self.file_list_frame = None # Frame to hold the file list
        self.download_buttons = {} # {filename: button_widget}
        
        # Events to signal port readiness
        self.upload_port_event = threading.Event()
        self.upload_port = None
        self.download_port_event = threading.Event()
        self.download_port = None
        self.download_filesize = 0
        
        # Keep track of what's been downloaded
        self.downloaded_files = set() # Set of filenames
        self.scan_download_directory()

        # Get MAC address
        self.mac_address = get_mac_address()
        if not self.mac_address:
            messagebox.showerror("Fatal Error", "Could not determine MAC address. Exiting.")
            self.root.destroy()
            return
        
        # Start the connection process
        self.show_connecting_window()
        threading.Thread(target=self.try_auto_login, daemon=True).start()

    def setup_download_dir(self):
        """Creates the download directory if it doesn't exist."""
        try:
            self.download_dir_path.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            messagebox.showerror("Client Error", f"Could not create download directory: {e}\nDownloads may fail.")
            
    def scan_download_directory(self):
        """Scans the download directory to see what's already downloaded."""
        self.downloaded_files.clear()
        if not self.download_dir_path.is_dir():
            return
        for f in self.download_dir_path.iterdir():
            if f.is_file():
                self.downloaded_files.add(f.name)

    def show_connecting_window(self):
        """Shows a small 'Connecting...' popup."""
        self.connecting_window = Toplevel(self.root)
        self.connecting_window.title("Connecting")
        self.connecting_window.geometry("250x80")
        
        # Center the prompt
        self.connecting_window.update_idletasks()
        x = self.root.winfo_screenwidth() // 2 - 125
        y = self.root.winfo_screenheight() // 2 - 40
        self.connecting_window.geometry(f"+{x}+{y}")

        self.connecting_window.resizable(False, False)
        self.connecting_window.grab_set()
        
        Label(self.connecting_window, text="Attempting to connect...", pady=10).pack(pady=10)
        
        self.connecting_window.protocol("WM_DELETE_WINDOW", self.root.destroy) # Close all if this is closed

    def try_auto_login(self):
        """Attempts to log in automatically using just the MAC address."""
        try:
            # 1. Create a new socket for this attempt
            temp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            temp_socket.connect((SERVER_HOST, SERVER_PORT))

            # 2. Send AUTO_LOGIN handshake
            handshake_data = {
                "mac": self.mac_address,
                "type": "AUTO_LOGIN"
            }
            temp_socket.sendall(json.dumps(handshake_data).encode('utf-8'))

            # 3. Wait for server's response
            response_raw = temp_socket.recv(4096).decode('utf-8')
            if not response_raw:
                raise ConnectionError("Server closed connection unexpectedly.")
            
            response_data = json.loads(response_raw)

            # 4. Process response
            if response_data.get("status") == "OK":
                # Auto-login successful!
                self.username = response_data.get("username")
                self.is_remembered = response_data.get("remembered", True)
                self.chat_history = response_data.get("chat_history", [])
                self.server_file_list = response_data.get("file_list", [])
                self.socket = temp_socket # Keep this socket
                self.root.after(0, self.show_main_window)
            
            elif response_data.get("status") == "REQUIRE_USERNAME":
                # Server doesn't know this MAC, need manual login
                self.root.after(0, self.show_login_window)
                temp_socket.close() # Close this connection, manual login will make a new one

            elif response_data.get("status") == "ALREADY_CONNECTED":
                # Server says we're already logged in. Show the special error.
                self.root.after(0, self.show_already_connected_error)
                temp_socket.close() # Close this new, redundant socket

            else:
                raise ConnectionError(f"Received invalid response: {response_data.get('status')}")

        except Exception as e:
            print(f"Auto-login failed: {e}")
            
            # --- FIX for server down ---
            # 1. Destroy the "Connecting..." window
            if self.connecting_window:
                self.root.after(0, self.connecting_window.destroy)
                self.connecting_window = None # Prevent other code from trying to destroy it
            
            # 2. Show the error
            self.root.after(0, lambda: messagebox.showerror("Connection Failed", f"Could not connect to server: {e}\n\nIs the server running?"))
            
            # 3. Exit the app
            self.root.after(0, self.root.destroy)
            # --- End Fix ---

    def show_login_window(self):
        """Shows the manual login window."""
        # Close connecting window if it's open
        if self.connecting_window:
            try:
                self.connecting_window.destroy()
            except tk.TclError:
                pass
            self.connecting_window = None

        self.login_window = Toplevel(self.root)
        self.login_window.title("Login")
        
        # Center the prompt
        self.login_window.update_idletasks()
        x = self.root.winfo_screenwidth() // 2 - 150
        y = self.root.winfo_screenheight() // 2 - 100
        self.login_window.geometry(f"300x200+{x}+{y}")
        self.login_window.resizable(False, False)
        
        Label(self.login_window, text=f"Welcome! Please choose a username.", pady=5).pack(pady=(10,5))
        
        Label(self.login_window, text="Username:").pack()
        username_entry = Entry(self.login_window, width=30)
        username_entry.pack(pady=5, padx=20)
        
        remember_var = tk.BooleanVar()
        remember_check = tk.Checkbutton(self.login_window, text="Remember me", variable=remember_var)
        remember_check.pack(pady=5)
        
        self.connect_button = Button(self.login_window, text="Connect", 
                                        command=lambda: self.try_manual_login(username_entry.get(), remember_var.get()))
        self.connect_button.pack(pady=10)
        
        self.login_window.protocol("WM_DELETE_WINDOW", self.root.destroy) # Close all if this is closed
        self.login_window.grab_set()

    def try_manual_login(self, requested_username, remember_me):
        """Attempts to log in manually with a chosen username."""
        if not requested_username.strip():
            messagebox.showerror("Invalid Input", "Username cannot be empty.", parent=self.login_window)
            return
            
        self.connect_button.config(text="Connecting...", state="disabled")
        
        try:
            # 1. Create a new socket for this attempt
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((SERVER_HOST, SERVER_PORT))

            # 2. Send MANUAL_LOGIN handshake
            handshake_data = {
                "mac": self.mac_address,
                "type": "MANUAL_LOGIN",
                "requested_username": requested_username,
                "remember_me": remember_me
            }
            self.socket.sendall(json.dumps(handshake_data).encode('utf-8'))

            # 3. Wait for server's response
            response_raw = self.socket.recv(4096).decode('utf-8')
            if not response_raw:
                raise ConnectionError("Server closed connection unexpectedly.")
            
            response_data = json.loads(response_raw)
            
            # 4. Process response
            if response_data.get("status") == "OK":
                self.username = response_data.get("username")
                self.is_remembered = response_data.get("remembered", False)
                self.chat_history = response_data.get("chat_history", [])
                self.server_file_list = response_data.get("file_list", [])
                
                self.root.after(0, self.login_window.destroy)
                self.login_window = None
                self.root.after(0, self.show_main_window)
            
            elif response_data.get("status") == "ALREADY_CONNECTED":
                # Server says we're already logged in. Show the special error.
                self.root.after(0, self.login_window.destroy)
                self.login_window = None
                self.root.after(0, self.show_already_connected_error)
                if self.socket:
                    self.socket.close()
                    self.socket = None

            elif response_data.get("status") == "USERNAME_TAKEN":
                messagebox.showerror("Login Failed", 
                                     f"The username '{requested_username}' is already taken. Please choose another.", 
                                     parent=self.login_window)
                # Re-enable button and close socket
                self.root.after(0, lambda: self.connect_button.config(text="Connect", state="normal"))
                self.socket.close()
                self.socket = None # Clear the socket
            
            else:
                raise ConnectionError(f"Received invalid response: {response_data.get('status')}")

        except Exception as e:
            print(f"Manual login failed: {e}")
            messagebox.showerror("Connection Failed", f"Could not connect to server: {e}", parent=self.login_window)
            self.root.after(0, lambda: self.connect_button.config(text="Connect", state="normal"))
            if self.socket:
                self.socket.close()
                self.socket = None

    def format_filesize(self, num_bytes):
        """Formats bytes into a human-readable string (KB, MB, GB)."""
        if num_bytes < 1024.0:
            return f"{num_bytes} B"
        elif num_bytes < 1024.0**2:
            return f"{num_bytes/1024.0:.1f} KB"
        elif num_bytes < 1024.0**3:
            return f"{num_bytes/1024.0**2:.1f} MB"
        else:
            return f"{num_bytes/1024.0**3:.1f} GB"

    def show_main_window(self):
        """Shows the main application window (video + chat + files)."""
        # Close connecting window if it's open
        if self.connecting_window:
            try:
                self.connecting_window.destroy()
            except tk.TclError:
                pass
            self.connecting_window = None
        
        self.root.deiconify() # Un-hide the main window
        self.root.title(f"Video Chat - {self.username} (MAC: {self.mac_address})")
        self.root.geometry("800x600")
        self.root.minsize(500, 400) # Set a minimum size

        # --- Top bar for controls ---
        top_frame = Frame(self.root, bg="#f0f0f0")
        top_frame.pack(fill=tk.X, side=tk.TOP)

        Label(top_frame, text=f"Welcome, {self.username}!", font=("Arial", 14), bg="#f0f0f0").pack(side=tk.LEFT, padx=10, pady=5)
        
        exit_button = Button(top_frame, text="Exit", bg="#e63946", fg="white", font=("Arial", 10, "bold"), command=self.handle_exit_click, borderwidth=0, padx=10, pady=2)
        exit_button.pack(side=tk.RIGHT, padx=10, pady=5)
        
        # --- Main content area (PanedWindow) ---
        main_pane = tk.PanedWindow(self.root, orient=tk.HORIZONTAL, sashrelief=tk.RAISED, sashwidth=4, bg="#f0f0f0")
        main_pane.pack(fill=tk.BOTH, expand=True)

        # --- Left Pane (for video) ---
        video_frame = Frame(main_pane, bg="#333333")
        Label(video_frame, 
                 text="Video feeds will go here",
                 font=("Arial", 12), bg="#333333", fg="white").pack(expand=True)
        main_pane.add(video_frame, width=550) # Give it a default width

        # --- Right Pane (Files + Chat) ---
        right_pane = tk.PanedWindow(main_pane, orient=tk.VERTICAL, sashrelief=tk.RAISED, sashwidth=4, bg="#f0f0f0")
        main_pane.add(right_pane, width=250)

        # --- Right-Top Pane (Files) ---
        files_main_frame = Frame(right_pane, bg="white")
        Label(files_main_frame, text="Shared Files", font=("Arial", 12, "bold"), bg="white").pack(pady=5, side=tk.TOP)
        
        # File upload controls (Pack to bottom, *before* the scrollable area)
        file_upload_frame = Frame(files_main_frame, bg="white")
        file_upload_frame.pack(fill=tk.X, padx=5, pady=5, side=tk.BOTTOM)
        
        add_file_btn = Button(file_upload_frame, text="Add File", command=self.add_file, borderwidth=1, relief="raised", padx=5)
        add_file_btn.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        self.upload_button = Button(file_upload_frame, text="Upload", command=self.start_file_upload, state="disabled", borderwidth=1, relief="raised", padx=5)
        self.upload_button.pack(side=tk.RIGHT, fill=tk.X, expand=True, padx=(5,0))

        # File list area (scrollable)
        file_canvas_frame = Frame(files_main_frame, bg="white")
        file_canvas_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=(0,5), side=tk.TOP)
        
        file_canvas = tk.Canvas(file_canvas_frame, bg="white", highlightthickness=0)
        file_scrollbar = tk.Scrollbar(file_canvas_frame, orient="vertical", command=file_canvas.yview)
        
        # This frame will hold the actual file widgets
        self.file_list_frame = Frame(file_canvas, bg="white")
        
        self.file_list_frame.bind("<Configure>", lambda e: file_canvas.configure(scrollregion=file_canvas.bbox("all")))
        
        file_canvas.create_window((0, 0), window=self.file_list_frame, anchor="nw")
        file_canvas.configure(yscrollcommand=file_scrollbar.set)
        
        file_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        file_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        right_pane.add(files_main_frame, height=250) # Default height

        # --- Right-Bottom Pane (Chat) ---
        chat_frame = Frame(right_pane, bg="white")
        
        # Chat input (Pack to bottom *first*)
        chat_input_frame = Frame(chat_frame, bg="white")
        chat_input_frame.pack(fill=tk.X, padx=5, pady=5, side=tk.BOTTOM)
        
        self.chat_entry = Entry(chat_input_frame, font=("Arial", 10), borderwidth=1, relief="solid")
        self.chat_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=3)
        
        send_button = Button(chat_input_frame, text="Send", command=self.send_chat_message, borderwidth=1, relief="raised", padx=5)
        send_button.pack(side=tk.RIGHT, padx=(5,0))
        
        # Bind <Return> key to send message
        self.chat_entry.bind("<Return>", lambda event: self.send_chat_message())
        
        # Chat display (Pack to fill remaining space)
        chat_display_frame = Frame(chat_frame, bg="white")
        chat_display_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=(5,0), side=tk.TOP)
        
        chat_scrollbar = tk.Scrollbar(chat_display_frame)
        chat_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.chat_display = tk.Text(chat_display_frame, 
                                    state='disabled', 
                                    wrap=tk.WORD, 
                                    font=("Arial", 9),
                                    yscrollcommand=chat_scrollbar.set,
                                    borderwidth=0,
                                    highlightthickness=0,
                                    padx=5, pady=5)
        self.chat_display.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        chat_scrollbar.config(command=self.chat_display.yview)

        # Configure tags for chat formatting
        self.chat_display.tag_config("username", font=("Arial", 9, "bold"))
        self.chat_display.tag_config("message", font=("Arial", 9))
        self.chat_display.tag_config("system", font=("Arial", 9, "italic"), foreground="#555555")

        right_pane.add(chat_frame, height=350) # Default height

        # --- Populate initial data ---
        self.root.after(0, self.update_file_list) # Update with self.server_file_list
        
        for username, message in self.chat_history:
            self.append_chat_message(username, message)
        self.append_chat_message("System", "You have joined the chat.", system=True)
        
        # Start listening for new messages
        self.listen_thread = threading.Thread(target=self.listen_for_data, daemon=True)
        self.listen_thread.start()
        
        self.root.protocol("WM_DELETE_WINDOW", self.handle_exit_click)

    def update_file_list(self):
        """Thread-safe way to rebuild the file list GUI."""
        try:
            # Clear old widgets
            for widget in self.file_list_frame.winfo_children():
                widget.destroy()
            self.download_buttons.clear()
            
            if not self.server_file_list:
                Label(self.file_list_frame, text="No files uploaded.", font=("Arial", 9, "italic"), bg="white").pack(pady=10)
                return

            for (filename, filesize) in self.server_file_list:
                file_row = Frame(self.file_list_frame, bg="white")
                file_row.pack(fill=tk.X, padx=2, pady=2)
                
                info_text = f"{filename} ({self.format_filesize(filesize)})"
                Label(file_row, text=info_text, anchor="w", bg="white").pack(side=tk.LEFT, fill=tk.X, expand=True)
                
                dl_btn = Button(file_row, text="Download", 
                                  command=lambda f=filename: self.start_file_download(f), 
                                  font=("Arial", 8), borderwidth=1, relief="raised", padx=2, bg="#f0f0f0")
                
                # Re-downloading is allowed, so no check for downloaded_files
                
                dl_btn.pack(side=tk.RIGHT, padx=5)
                self.download_buttons[filename] = dl_btn
        
        except tk.TclError:
            pass # Window closing

    def add_file(self):
        """Opens a file dialog to select a file for upload."""
        filepath = filedialog.askopenfilename(title="Select a file to upload")
        if filepath:
            self.local_file_path = Path(filepath)
            self.upload_button.config(state="normal", text=f"Upload '{self.local_file_path.name}'", bg="#4CAF50", fg="white")
        else:
            self.local_file_path = None
            self.upload_button.config(state="disabled", text="Upload", bg="#f0f0f0", fg="black")

    def start_file_upload(self):
        """Starts the file upload negotiation process."""
        if not self.local_file_path or not self.socket:
            return
            
        filename = self.local_file_path.name
        filesize = self.local_file_path.stat().st_size
        
        # Check if file with same name already exists
        if any(fname == filename for fname, fsize in self.server_file_list):
            if not messagebox.askyesno("Warning", f"A file named '{filename}' already exists on the server.\nDo you want to overwrite it?"):
                return
        
        self.upload_button.config(text="Uploading...", state="disabled", bg="#007BFF", fg="white")
        
        # Start the uploader thread. It will block until the port is ready.
        threading.Thread(
            target=self.upload_file_thread, 
            args=(filename, filesize), 
            daemon=True
        ).start()

        # Send the request on the main control socket
        try:
            req_msg = {
                "type": "REQUEST_UPLOAD",
                "filename": filename,
                "filesize": filesize
            }
            self.socket.sendall(json.dumps(req_msg).encode('utf-8'))
        except Exception as e:
            self.append_chat_message("System", f"Error requesting upload: {e}", system=True)
            self.upload_button.config(state="normal", text=f"Upload '{filename}'", bg="#4CAF50", fg="white")

    def upload_file_thread(self, filename, filesize):
        """Thread function to send a file to the server."""
        try:
            # 1. Wait for the main thread to set the port
            self.upload_port_event.clear()
            if not self.upload_port_event.wait(timeout=10.0):
                raise socket.timeout("Server did not respond to upload request.")
            
            port = self.upload_port # Get the port set by the listen_thread
            
            # 2. Connect to the new data port
            data_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            data_socket.connect((SERVER_HOST, port))
            
            # 3. Send the file data
            with open(self.local_file_path, 'rb') as f:
                bytes_sent = 0
                while bytes_sent < filesize:
                    chunk = f.read(4096)
                    if not chunk:
                        break # End of file
                    data_socket.sendall(chunk)
                    bytes_sent += len(chunk)
            
            print(f"File {filename} sent successfully.")
            # --- FIX: Add system message on success ---
            self.root.after(0, lambda: self.append_chat_message("System", f"Uploaded '{filename}' successfully.", system=True))

        except Exception as e:
            print(f"File upload error: {e}")
            # --- FIX: Use lambda for system message ---
            self.root.after(0, lambda: self.append_chat_message("System", f"Error uploading {filename}: {e}", system=True))
        finally:
            if 'data_socket' in locals():
                data_socket.close()
            # --- FIX: Reset button state, don't re-open dialog ---
            self.local_file_path = None
            self.root.after(0, lambda: self.upload_button.config(state="disabled", text="Upload", bg="#f0f0f0", fg="black"))


    def start_file_download(self, filename):
        """Starts the file download negotiation process."""
        if not self.socket:
            return
            
        btn = self.download_buttons.get(filename)
        if btn:
            btn.config(text="Downloading...", state="disabled", bg="#007BFF")
            
        # Start the downloader thread. It will block until the port is ready.
        threading.Thread(
            target=self.download_file_thread,
            args=(filename,),
            daemon=True
        ).start()
        
        # Send the request on the main control socket
        try:
            req_msg = {"type": "REQUEST_DOWNLOAD", "filename": filename}
            self.socket.sendall(json.dumps(req_msg).encode('utf-8'))
        except Exception as e:
            self.append_chat_message("System", f"Error requesting download: {e}", system=True)
            if btn:
                btn.config(text="Download", state="normal", bg="#f0f0f0")

    def download_file_thread(self, filename):
        """Thread function to receive a file from the server."""
        btn = self.download_buttons.get(filename)
        filepath = self.download_dir_path / Path(filename).name # Sanitize
        
        try:
            # 1. Wait for the main thread to set the port and filesize
            self.download_port_event.clear()
            if not self.download_port_event.wait(timeout=10.0):
                raise socket.timeout("Server did not respond to download request.")
            
            port = self.download_port
            filesize = self.download_filesize
            
            # 2. Connect to the new data port
            data_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            data_socket.connect((SERVER_HOST, port))
            
            # 3. Receive the file data
            bytes_received = 0
            with open(filepath, 'wb') as f:
                while bytes_received < filesize:
                    chunk_size = min(4096, filesize - bytes_received)
                    chunk = data_socket.recv(chunk_size)
                    if not chunk:
                        break # Server closed connection
                    f.write(chunk)
                    bytes_received += len(chunk)

            if bytes_received == filesize:
                self.downloaded_files.add(filename)
                # --- FIX: Use lambda for system message ---
                self.root.after(0, lambda: self.append_chat_message("System", f"Downloaded '{filename}' successfully.", system=True))
                # Update button on main thread
                if btn:
                    self.root.after(0, lambda: btn.config(text="Download", state="normal", bg="#f0f0f0", relief="raised"))
            else:
                raise ConnectionError(f"Incomplete download. Received {bytes_received}/{filesize} bytes.")

        except Exception as e:
            print(f"File download error: {e}")
            # --- FIX: Use lambda for system message ---
            self.root.after(0, lambda: self.append_chat_message("System", f"Error downloading {filename}: {e}", system=True))
            if btn:
                self.root.after(0, lambda: btn.config(text="Download", state="normal", bg="#f0f0f0", relief="raised"))
            try:
                if filepath.exists():
                    filepath.unlink() # Delete partial file
            except OSError as oe:
                print(f"Could not delete partial download: {oe}")
        finally:
            if 'data_socket' in locals():
                data_socket.close()

    def append_chat_message(self, username, message, system=False):
        """Thread-safe way to add a message to the chat display."""
        try:
            if not self.chat_display:
                return # Window closed

            self.chat_display.config(state='normal')
            
            if system:
                self.chat_display.insert(tk.END, f"{message}\n", "system")
            else:
                self.chat_display.insert(tk.END, f"{username}: ", "username")
                self.chat_display.insert(tk.END, f"{message}\n", "message")
            
            self.chat_display.config(state='disabled')
            self.chat_display.see(tk.END)
        except tk.TclError:
            # This can happen if the window is destroyed
            pass
    
    def send_chat_message(self):
        """Sends a chat message to the server."""
        message = self.chat_entry.get().strip()
        if message and self.socket:
            try:
                message_json = {"type": "CHAT_MESSAGE", "payload": message}
                self.socket.sendall(json.dumps(message_json).encode('utf-8'))
                self.chat_entry.delete(0, tk.END)
            except Exception as e:
                self.append_chat_message("System", f"Error sending message: {e}", system=True)

    def listen_for_data(self):
        """Listens for data (chat, file commands, video) from the server in a thread."""
        buffer = ""
        while self.socket:
            try:
                data_chunk = self.socket.recv(1024)
                if not data_chunk:
                    # Server closed connection
                    break
                
                # We buffer data to handle multiple JSONs in one chunk
                buffer += data_chunk.decode('utf-8')
                
                # Process all complete JSON objects in the buffer
                while '}' in buffer:
                    try:
                        end_index = buffer.find('}') + 1
                        json_str = buffer[:end_index]
                        message = json.loads(json_str)
                        buffer = buffer[end_index:] # Keep the rest of the buffer
                        
                        # --- Process the JSON message ---
                        msg_type = message.get("type")
                        
                        if msg_type == "NEW_CHAT":
                            username = message.get("username", "Server")
                            payload = message.get("payload", "")
                            # Schedule GUI update on main thread
                            self.root.after(0, self.append_chat_message, username, payload)
                        
                        elif msg_type == "FILE_LIST_UPDATE":
                            self.server_file_list = message.get("file_list", [])
                            self.root.after(0, self.update_file_list)
                        
                        elif msg_type == "UPLOAD_READY":
                            self.upload_port = message.get("port")
                            self.upload_port_event.set() # Unblock the upload thread
                        
                        elif msg_type == "DOWNLOAD_READY":
                            self.download_port = message.get("port")
                            self.download_filesize = message.get("filesize")
                            self.download_port_event.set() # Unblock the download thread
                        
                        elif msg_type == "UPLOAD_ERROR" or msg_type == "DOWNLOAD_ERROR":
                            error_msg = message.get("error", "Unknown error")
                            filename = message.get("filename", "")
                            # --- FIX: Use lambda for system message ---
                            self.root.after(0, lambda: self.append_chat_message("System", 
                                            f"Error with file '{filename}': {error_msg}", system=True))
                            # Reset relevant buttons
                            if msg_type == "UPLOAD_ERROR":
                                self.root.after(0, lambda: self.upload_button.config(state="disabled", text="Upload", bg="#f0f0f0", fg="black"))
                            else:
                                btn = self.download_buttons.get(filename)
                                if btn:
                                    self.root.after(0, lambda: btn.config(text="Download", state="normal", bg="#f0f0f0", relief="raised"))

                    except json.JSONDecodeError:
                        # Not a JSON message, or incomplete JSON.
                        # If buffer is huge and no JSON, it's probably video data
                        if len(buffer) > 4096:
                            # Likely video stream. Clear buffer.
                            # In a real app, this would go to a video decoder
                            buffer = "" 
                        break # Wait for more data
                
            except (ConnectionResetError, ConnectionAbortedError):
                break
            except Exception as e:
                print(f"Error in listen thread: {e}")
                print(f"Buffer was: {buffer[:200]}") # Log what broke it
                break
        
        # If loop breaks, connection is lost
        if self.root.winfo_exists():
            self.root.after(0, self.append_chat_message, "System", "Disconnected from server.", system=True)
            if self.chat_entry:
                try:
                    self.chat_entry.config(state='disabled')
                except tk.TclError:
                    pass # Window already closed

    def handle_exit_click(self):
        """Called by the Exit button or window 'X'."""
        if self.is_remembered:
            self.show_exit_prompt()
        else:
            self.on_main_close() # Just exit normally

    def show_exit_prompt(self):
        """Shows a popup asking remembered users if they want to be forgotten."""
        if self.exit_prompt_window and self.exit_prompt_window.winfo_exists():
            self.exit_prompt_window.lift()
            return
            
        self.exit_prompt_window = Toplevel(self.root)
        self.exit_prompt_window.title("Exit")
        self.exit_prompt_window.geometry("350x120")
        
        # Center the prompt
        self.exit_prompt_window.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() // 2) - 175
        y = self.root.winfo_y() + (self.root.winfo_height() // 2) - 60
        self.exit_prompt_window.geometry(f"+{x}+{y}")
        
        self.exit_prompt_window.resizable(False, False)
        self.exit_prompt_window.grab_set() # Modal behavior
        self.exit_prompt_window.transient(self.root)

        Label(self.exit_prompt_window, text="You are a remembered user. How do you want to exit?", pady=10, wraplength=330).pack()
        
        button_frame = Frame(self.exit_prompt_window)
        button_frame.pack(pady=10)

        exit_btn = Button(button_frame, text="Exit", command=self.on_main_close, width=15)
        exit_btn.pack(side=tk.LEFT, padx=10)

        forget_btn = Button(button_frame, text="Exit and Forget Me", command=self.exit_and_forget, width=15)
        forget_btn.pack(side=tk.RIGHT, padx=10)

    def exit_and_forget(self):
        """Sends the FORGET_ME message to the server and then closes."""
        try:
            if self.socket:
                forget_message = {"type": "FORGET_ME"}
                self.socket.sendall(json.dumps(forget_message).encode('utf-8'))
        except Exception as e:
            print(f"Error sending FORGET_ME message: {e}") # Log to console
        finally:
            self.on_main_close() # Close connection and window regardless
 
    def on_main_close(self):
        """Handles closing the main application window."""
        temp_socket = self.socket
        self.socket = None # This will stop the listen_thread
        
        if temp_socket:
            try:
                temp_socket.close()
            except Exception as e:
                print(f"Error closing socket: {e}")
        
        self.root.destroy()
    
    def show_already_connected_error(self):
        """Shows a final error window when a connection already exists."""
        # 1. Destroy any lingering login/connecting windows
        if self.connecting_window:
            try:
                self.connecting_window.destroy()
            except tk.TclError: pass
            self.connecting_window = None
        
        if self.login_window:
            try:
                self.login_window.destroy()
            except tk.TclError: pass
            self.login_window = None
            
        # 2. Create the new error window
        error_window = Toplevel(self.root)
        error_window.title("Connection Failed")
        error_window.geometry("350x120")
        
        # Center it
        error_window.update_idletasks()
        x = self.root.winfo_screenwidth() // 2 - 175
        y = self.root.winfo_screenheight() // 2 - 60
        error_window.geometry(f"+{x}+{y}")
        
        error_window.resizable(False, False)
        
        Label(error_window, 
                 text="A connection from this device is already active.", 
                 wraplength=330, pady=10).pack(pady=10)
        
        exit_btn = Button(error_window, text="Exit", command=self.root.destroy, width=10)
        exit_btn.pack(pady=10)
        
        # Ensure closing the window exits the app
        error_window.protocol("WM_DELETE_WINDOW", self.root.destroy)
        error_window.grab_set() # Make it modal


if __name__ == "__main__":
    try:
        root = tk.Tk()
        app = ChatClient(root)
        root.mainloop()
    except KeyboardInterrupt:
        sys.exit(0)