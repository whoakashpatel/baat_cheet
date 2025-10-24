import tkinter as tk
from tkinter import (
    scrolledtext, simpledialog, messagebox, Checkbutton, 
    Frame, Label, Entry, Button, Toplevel, PanedWindow,
    StringVar, BooleanVar, Canvas
)
from tkinter import filedialog
from getmac import get_mac_address
import socket
import threading
import json
import sys
import time
from pathlib import Path

# --- Constants ---
SERVER_HOST = '10.83.175.161' # Change to server's IP if not local
SERVER_PORT = 12345
DOWNLOAD_DIR = 'downloads' # Directory to save downloaded files

class ChatClient:
    def __init__(self, root):
        self.root = root
        self.root.title("Video Chat Client")
        self.root.geometry("800x600")
        self.root.withdraw() # Hide main window until connected

        # --- State ---
        self.mac_address = get_mac_address() or "00:00:00:00:00:00"
        self.username = "Guest"
        self.is_remembered = False
        self.is_connected = False
        self.local_file_path = None # Stores path of file to be uploaded
        
        # --- Sockets ---
        self.socket = None # Main control socket
        self.buffer = ""   # Buffer for incoming JSON data

        # --- GUI Elements ---
        self.connecting_window = None
        self.login_window = None
        self.main_window = None
        self.chat_display = None
        self.chat_entry = None
        self.upload_button = None
        self.add_file_label = None
        self.file_list_frame = None
        self.file_list_canvas = None

        # --- Data & Threading ---
        self.server_file_list = []
        self.download_buttons = {} # {filename: button_widget}
        
        # Events to coordinate file transfer threads
        self.upload_port_event = threading.Event()
        self.upload_port_result = None
        
        self.download_port_event = threading.Event()
        self.download_port_result = {} # {filename: (port, filesize)}

        # Setup local download directory
        self.download_path = Path(DOWNLOAD_DIR)
        self.download_path.mkdir(parents=True, exist_ok=True)

        # --- Start Connection ---
        self.show_connecting_window()
        threading.Thread(target=self.try_auto_login, daemon=True).start()

    # --- 1. LOGIN & HANDSHAKE ---

    def show_connecting_window(self):
        """Shows a simple 'Connecting...' modal window."""
        self.connecting_window = Toplevel(self.root)
        self.connecting_window.title("Connecting")
        self.connecting_window.geometry("250x100")
        self.connecting_window.resizable(False, False)
        
        # Center it
        self.connecting_window.update_idletasks()
        x = self.root.winfo_screenwidth() // 2 - 125
        y = self.root.winfo_screenheight() // 2 - 50
        self.connecting_window.geometry(f"+{x}+{y}")
        
        Label(self.connecting_window, text="Connecting to server...", pady=20).pack()
        self.connecting_window.grab_set()
        self.connecting_window.protocol("WM_DELETE_WINDOW", self.root.destroy)

    def try_auto_login(self):
        """Attempts to log in automatically using just the MAC address."""
        try:
            temp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            temp_socket.connect((SERVER_HOST, SERVER_PORT))
            
            # Send AUTO_LOGIN request
            handshake_data = {
                "type": "AUTO_LOGIN",
                "mac": self.mac_address
            }
            temp_socket.sendall(json.dumps(handshake_data).encode('utf-8'))
            
            # Wait for response
            response_raw = temp_socket.recv(4096).decode('utf-8') # Increase buffer for history
            if not response_raw:
                raise ConnectionError("Server closed connection.")
                
            response_data = json.loads(response_raw)

            # 3. Process response
            if response_data.get("status") == "OK":
                self.username = response_data["username"]
                self.is_remembered = response_data.get("remembered", False)
                self.is_connected = True
                
                # Load initial data
                initial_chat_history = response_data.get("chat_history", [])
                self.server_file_list = response_data.get("file_list", [])
                
                self.socket = temp_socket # Keep this socket
                self.root.after(0, lambda: self.show_main_window(initial_chat_history))
            
            elif response_data.get("status") == "REQUIRE_USERNAME":
                # Server doesn't know us, show manual login
                self.root.after(0, self.show_login_window)
                temp_socket.close() # Close this connection, manual login will make a new one

            elif response_data.get("status") == "ALREADY_CONNECTED":
                # Server says we're already logged in. Show the special error.
                self.root.after(0, self.show_already_connected_error)
                temp_socket.close() # Close this new, redundant socket

            else:
                raise ConnectionError(f"Received invalid response: {response_data.get('status')}")

        except Exception as e:
            # Server is down or other error
            if self.connecting_window:
                try:
                    self.connecting_window.destroy()
                except tk.TclError: pass
            
            print(f"Auto-login failed: {e}")
            messagebox.showerror("Connection Failed", 
                                 f"Could not connect to server at {SERVER_HOST}:{SERVER_PORT}.\nError: {e}")
            self.root.destroy()
        
        finally:
            if self.connecting_window:
                try:
                    # Must be done from main thread
                    self.root.after(0, self.connecting_window.destroy)
                except tk.TclError:
                    pass
                self.connecting_window = None

    def show_login_window(self):
        """Shows the manual login window for new users."""
        self.login_window = Toplevel(self.root)
        self.login_window.title("Login")
        self.login_window.geometry("350x200")
        
        # Center it
        self.login_window.update_idletasks()
        x = self.root.winfo_screenwidth() // 2 - 175
        y = self.root.winfo_screenheight() // 2 - 100
        self.login_window.geometry(f"+{x}+{y}")
        
        self.login_window.resizable(False, False)
        
        Label(self.login_window, text="Please choose a username:").pack(pady=10)
        
        username_var = StringVar()
        Entry(self.login_window, textvariable=username_var, width=30).pack(pady=5, padx=15)
        
        remember_var = BooleanVar()
        Checkbutton(self.login_window, text="Remember me", variable=remember_var).pack(pady=5)
        
        connect_btn = Button(self.login_window, text="Connect", 
                             command=lambda: self.try_manual_login(username_var.get(), remember_var.get()))
        connect_btn.pack(pady=10)
        
        self.login_window.protocol("WM_DELETE_WINDOW", self.root.destroy)
        self.login_window.grab_set()
        
        # Bind enter key
        self.login_window.bind("<Return>", lambda e: connect_btn.invoke())

    def try_manual_login(self, requested_username, remember_me):
        """Attempts to log in with a user-chosen username."""
        if not requested_username:
            messagebox.showwarning("Login Failed", "Username cannot be empty.", parent=self.login_window)
            return
            
        try:
            # 1. Establish new connection
            if self.socket:
                self.socket.close()
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((SERVER_HOST, SERVER_PORT))

            # 2. Send MANUAL_LOGIN request
            handshake_data = {
                "type": "MANUAL_LOGIN",
                "mac": self.mac_address,
                "requested_username": requested_username,
                "remember_me": remember_me
            }
            self.socket.sendall(json.dumps(handshake_data).encode('utf-8'))
            
            # 3. Wait for response
            response_raw = self.socket.recv(4096).decode('utf-8') # Increase buffer
            if not response_raw:
                raise ConnectionError("Server closed connection.")
            
            response_data = json.loads(response_raw)
            
            # 4. Process response
            if response_data.get("status") == "OK":
                self.username = response_data["username"]
                self.is_remembered = response_data.get("remembered", False)
                self.is_connected = True
                
                # Load initial data
                initial_chat_history = response_data.get("chat_history", [])
                self.server_file_list = response_data.get("file_list", [])
                
                self.login_window.destroy()
                self.login_window = None
                self.root.after(0, lambda: self.show_main_window(initial_chat_history))
            
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
                                     "That username is already taken. Please try another.",
                                     parent=self.login_window)
                self.socket.close() # Close connection, user must retry
            
            else:
                raise ConnectionError(f"Login failed: {response_data.get('status')}")

        except Exception as e:
            print(f"Manual-login failed: {e}")
            messagebox.showerror("Connection Failed", 
                                 f"Could not connect to server.\nError: {e}",
                                 parent=self.login_window or self.root)

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

    # --- 2. MAIN APPLICATION GUI ---

    def show_main_window(self, chat_history):
        """Creates and displays the main application window."""
        self.root.deiconify() # Show the root window
        self.root.title(f"Video Chat Client - Logged in as: {self.username}")
        
        self.main_window = Frame(self.root)
        self.main_window.pack(fill=tk.BOTH, expand=True)
        
        # --- Top Bar ---
        top_bar = Frame(self.main_window, bg="#333", relief=tk.RAISED, borderwidth=1)
        top_bar.pack(fill=tk.X, side=tk.TOP)
        
        Label(top_bar, text=f"Welcome, {self.username}", fg="white", bg="#333", font=("Arial", 10, "bold")).pack(side=tk.LEFT, padx=10, pady=5)
        Button(top_bar, text="Exit", bg="#e63946", fg="white", command=self.handle_exit_click, font=("Arial", 9, "bold")).pack(side=tk.RIGHT, padx=10, pady=5)

        # --- Main Paned Window ---
        main_pane = PanedWindow(self.main_window, orient=tk.HORIZONTAL, sashrelief=tk.RAISED, sashwidth=4, bg="#f0f0f0")
        main_pane.pack(fill=tk.BOTH, expand=True)
        
        # --- Left Side (Video) ---
        video_frame = Frame(main_pane, bg="#eee", relief=tk.SUNKEN, borderwidth=1)
        Label(video_frame, text="Video Area (Coming Soon)", bg="#eee").pack(padx=20, pady=20)
        main_pane.add(video_frame, width=500, minsize=300)

        # --- Right Side (Files & Chat) ---
        right_pane = PanedWindow(main_pane, orient=tk.VERTICAL, sashrelief=tk.RAISED, sashwidth=4, bg="#f0f0f0")
        main_pane.add(right_pane, width=300, minsize=250)
        
        # --- Files Area (Top Right) ---
        files_frame = Frame(right_pane, bg="white", relief=tk.SUNKEN, borderwidth=1)
        
        Label(files_frame, text="Shared Files", font=("Arial", 12, "bold"), bg="white").pack(pady=(5,0))
        
        # --- File Upload Button Bar ---
        file_upload_frame = Frame(files_frame, bg="white")
        file_upload_frame.pack(fill=tk.X, side=tk.BOTTOM, pady=5, padx=5)

        add_file_btn = Button(file_upload_frame, text="Add File", command=self.add_file, font=("Arial", 9))
        add_file_btn.pack(side=tk.LEFT)
        
        self.upload_button = Button(file_upload_frame, text="Upload", state=tk.DISABLED, 
                                    command=self.start_file_upload, font=("Arial", 9, "bold"))
        self.upload_button.pack(side=tk.LEFT, padx=5)
        
        self.add_file_label = Label(file_upload_frame, text="No file selected.", font=("Arial", 8, "italic"), bg="white")
        self.add_file_label.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # --- File List (Scrollable) ---
        file_canvas_frame = Frame(files_frame, bg="white")
        file_canvas_frame.pack(fill=tk.BOTH, expand=True, side=tk.TOP, padx=(5,0), pady=5)
        
        self.file_list_canvas = Canvas(file_canvas_frame, bg="white", highlightthickness=0)
        file_scrollbar = tk.Scrollbar(file_canvas_frame, orient=tk.VERTICAL, command=self.file_list_canvas.yview)
        
        # This is the frame *inside* the canvas
        self.file_list_frame = Frame(self.file_list_canvas, bg="white") 
        
        self.file_list_canvas.configure(yscrollcommand=file_scrollbar.set)
        
        file_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.file_list_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.file_list_canvas.create_window((0,0), window=self.file_list_frame, anchor="nw")
        
        self.file_list_frame.bind("<Configure>", lambda e: self.file_list_canvas.configure(scrollregion=self.file_list_canvas.bbox("all")))
        self.file_list_canvas.bind("<Configure>", self.on_file_canvas_configure)
        
        right_pane.add(files_frame, height=250, minsize=150)

        # --- Chat Area (Bottom Right) ---
        chat_frame = Frame(right_pane, bg="white", relief=tk.SUNKEN, borderwidth=1)
        
        Label(chat_frame, text="Chat", font=("Arial", 12, "bold"), bg="white").pack(pady=(5,0))

        # --- Chat Input Button Bar ---
        chat_input_frame = Frame(chat_frame, bg="white")
        chat_input_frame.pack(fill=tk.X, side=tk.BOTTOM, pady=5, padx=5)

        self.chat_entry = Entry(chat_input_frame, font=("Arial", 9))
        self.chat_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        send_btn = Button(chat_input_frame, text="Send", command=self.send_chat_message, font=("Arial", 9, "bold"))
        send_btn.pack(side=tk.RIGHT, padx=5)
        
        self.chat_entry.bind("<Return>", lambda e: self.send_chat_message())

        # --- Chat Display (Scrollable) ---
        chat_display_frame = Frame(chat_frame)
        chat_display_frame.pack(fill=tk.BOTH, expand=True, side=tk.TOP)
        
        self.chat_display = scrolledtext.ScrolledText(chat_display_frame, state='disabled', wrap=tk.WORD, font=("Arial", 9))
        self.chat_display.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Configure text tags for colors
        self.chat_display.tag_config('username', foreground="#003399", font=("Arial", 9, "bold"))
        self.chat_display.tag_config('message', foreground="black")
        self.chat_display.tag_config('system', foreground="#777777", font=("Arial", 9, "italic"))
        
        right_pane.add(chat_frame, height=350, minsize=150)

        # --- Finalize ---
        # Populate initial data
        for (username, message) in chat_history:
            self.append_chat_message(username, message, system=(username == "System"))
        
        self.update_file_list()
        
        # Start listener thread
        threading.Thread(target=self.listen_for_data, daemon=True).start()
        
        # Bind exit
        self.root.protocol("WM_DELETE_WINDOW", self.handle_exit_click)

    def on_file_canvas_configure(self, event):
        """Updates the width of the inner frame to match the canvas width."""
        canvas_width = event.width
        self.file_list_canvas.itemconfig(self.file_list_canvas.create_window((0, 0), window=self.file_list_frame, anchor="nw"), width=canvas_width)

    # --- 3. CHAT & DATA LISTENER ---

    def append_chat_message(self, username, message, system=False):
        """Thread-safe way to add a message to the chat display."""
        try:
            if not self.chat_display: return
            
            self.chat_display.config(state='normal')
            if system:
                self.chat_display.insert(tk.END, f"{message}\n", 'system')
            else:
                self.chat_display.insert(tk.END, f"{username}: ", 'username')
                self.chat_display.insert(tk.END, f"{message}\n", 'message')
            
            self.chat_display.config(state='disabled')
            self.chat_display.see(tk.END) # Auto-scroll
        except tk.TclError:
            pass # Window closing

    def send_chat_message(self):
        """Sends a chat message to the server."""
        message = self.chat_entry.get()
        if message and self.is_connected:
            self.send_json_message({
                "type": "CHAT_MESSAGE",
                "payload": message
            })
            self.chat_entry.delete(0, tk.END)

    def listen_for_data(self):
        """Continuously listens for JSON messages from the server."""
        while self.is_connected and self.socket:
            try:
                data_chunk = self.socket.recv(1024)
                if not data_chunk:
                    raise ConnectionError("Server disconnected.")
                
                self.buffer += data_chunk.decode('utf-8')
                
                # Process all complete JSON objects in the buffer
                while '}' in self.buffer:
                    try:
                        end_index = self.buffer.find('}') + 1
                        json_str = self.buffer[:end_index]
                        message = json.loads(json_str)
                        self.buffer = self.buffer[end_index:]
                        
                        # --- Route message based on type ---
                        self.root.after(0, self.handle_server_message, message)
                        
                    except json.JSONDecodeError:
                        # Incomplete JSON, wait for more data
                        break
                        
            except (ConnectionResetError, ConnectionError, OSError) as e:
                if self.is_connected: # Only show error if we didn't initiate exit
                    print(f"Connection lost: {e}")
                    self.root.after(0, lambda: messagebox.showerror("Connection Lost", "Lost connection to the server."))
                    self.root.after(0, self.root.destroy)
                break
            except Exception as e:
                print(f"Error in listener: {e}")
                self.buffer = "" # Clear buffer to prevent loops
                
        print("Listener thread stopping.")

    def handle_server_message(self, message):
        """Handles a single parsed JSON message from the server."""
        msg_type = message.get("type")
        
        if msg_type == "NEW_CHAT":
            self.append_chat_message(message.get("username"), 
                                     message.get("payload"), 
                                     system=(message.get("username") == "System"))
        
        elif msg_type == "FILE_LIST_UPDATE":
            self.server_file_list = message.get("file_list", [])
            self.update_file_list()
        
        # --- File Upload Responses ---
        elif msg_type == "UPLOAD_READY":
            self.upload_port_result = message.get("port")
            self.upload_port_event.set() # Wake up the upload thread
        
        elif msg_type == "UPLOAD_ERROR":
            filename = message.get("filename", "unknown file")
            error = message.get("error", "Unknown error")
            messagebox.showerror("Upload Failed", f"Server error uploading {filename}: {error}")
            self.upload_port_result = None
            self.upload_port_event.set() # Wake up thread to exit
        
        # --- File Download Responses ---
        elif msg_type == "DOWNLOAD_READY":
            filename = message.get("filename")
            port = message.get("port")
            filesize = message.get("filesize")
            if filename and port and filesize is not None:
                self.download_port_result[filename] = (port, filesize)
                self.download_port_event.set() # Wake up the download thread
        
        elif msg_type == "DOWNLOAD_ERROR":
            filename = message.get("filename", "unknown file")
            error = message.get("error", "Unknown error")
            messagebox.showerror("Download Failed", f"Server error downloading {filename}: {error}")
            # Reset button
            if filename in self.download_buttons:
                self.download_buttons[filename].config(text="Download", state=tk.NORMAL, bg="#f0f0f0")


    # --- 4. FILE TRANSFER ---

    def format_filesize(self, size_bytes):
        """Converts bytes to a human-readable string."""
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < (1024 * 1024):
            return f"{size_bytes / 1024:.1f} KB"
        elif size_bytes < (1024 * 1024 * 1024):
            return f"{size_bytes / (1024*1024):.1f} MB"
        else:
            return f"{size_bytes / (1024*1024*1024):.1f} GB"

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
                
                dl_btn = Button(file_row, text="Download", 
                                  command=lambda f=filename: self.start_file_download(f), 
                                  font=("Arial", 8), borderwidth=1, relief="raised", padx=2, bg="#f0f0f0")
                dl_btn.pack(side=tk.RIGHT, padx=5, anchor='n') # Pack button first, anchor to top
                
                info_text = f"{filename} ({self.format_filesize(filesize)})"
                info_label = Label(file_row, text=info_text, anchor="w", bg="white", justify=tk.LEFT, font=("Arial", 9))
                info_label.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
                
                # Function to update wraplength
                def update_wrap(event, label=info_label, button=dl_btn):
                    # We need the width of the row, which is event.width
                    # Subtract button's required width and some padding
                    button_width = button.winfo_reqwidth() 
                    wrap_width = event.width - button_width - 20 # 20 for paddings
                    
                    if wrap_width > 20:
                        label.config(wraplength=wrap_width)

                # Bind to the row's configure event
                file_row.bind("<Configure>", update_wrap)
                
                self.download_buttons[filename] = dl_btn
        
        except tk.TclError:
            pass # Window closing

    def add_file(self):
        """Opens a dialog to select a file for uploading."""
        filepath = filedialog.askopenfilename(title="Select a file to upload")
        if filepath:
            self.local_file_path = Path(filepath)
            filename = self.local_file_path.name
            
            # Truncate long filenames for display
            display_name = (filename[:30] + '...') if len(filename) > 30 else filename
            self.add_file_label.config(text=display_name, font=("Arial", 8, "normal"))
            self.upload_button.config(state=tk.NORMAL, bg="#2a9d8f", fg="white")
        else:
            self.local_file_path = None
            self.add_file_label.config(text="No file selected.", font=("Arial", 8, "italic"))
            self.upload_button.config(state=tk.DISABLED, bg="#f0f0f0", fg="black")

    def start_file_upload(self):
        """Initiates the file upload process."""
        if not self.local_file_path or not self.local_file_path.is_file():
            messagebox.showwarning("Upload Error", "No file selected or file not found.")
            return

        self.upload_button.config(state=tk.DISABLED, text="Uploading...", bg="#0077b6", fg="white")
        
        # Start the upload in a separate thread
        threading.Thread(target=self.upload_file_thread, daemon=True).start()

    def upload_file_thread(self):
        """Handles the upload logic in a non-blocking thread."""
        filepath = self.local_file_path
        filename = filepath.name
        filesize = filepath.stat().st_size
        
        try:
            # 1. Clear previous event and send request
            self.upload_port_event.clear()
            self.upload_port_result = None
            
            self.send_json_message({
                "type": "REQUEST_UPLOAD",
                "filename": filename,
                "filesize": filesize
            })
            
            # 2. Wait for server to respond with a port
            if not self.upload_port_event.wait(timeout=10): # 10-second timeout
                raise TimeoutError("Server did not respond to upload request.")
            
            port = self.upload_port_result
            if not port:
                raise ConnectionError("Server denied upload request.")
                
            # 3. Connect to the new data port
            data_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            data_socket.connect((SERVER_HOST, port))
            
            # 4. Send the file
            bytes_sent = 0
            with open(filepath, 'rb') as f:
                while bytes_sent < filesize:
                    chunk = f.read(4096)
                    if not chunk:
                        break # Should not happen
                    data_socket.sendall(chunk)
                    bytes_sent += len(chunk)
            
            print(f"File {filename} sent successfully.")
            # Add chat message on success
            self.root.after(0, lambda: self.append_chat_message("System", f"Uploaded '{filename}' successfully.", system=True))

        except Exception as e:
            print(f"File upload error: {e}")
            self.root.after(0, lambda: messagebox.showerror("Upload Error", f"Failed to upload {filename}: {e}"))
        
        finally:
            # 5. Cleanup
            if 'data_socket' in locals():
                data_socket.close()
            
            # Reset GUI elements on the main thread
            def reset_upload_gui():
                self.local_file_path = None
                self.add_file_label.config(text="No file selected.", font=("Arial", 8, "italic"))
                self.upload_button.config(state=tk.DISABLED, text="Upload", bg="#f0f0f0", fg="black")

            self.root.after(0, reset_upload_gui)

    def start_file_download(self, filename):
        """Initiates the file download process."""
        if filename not in self.download_buttons:
            return
            
        # 1. Update button state
        btn = self.download_buttons[filename]
        btn.config(state=tk.DISABLED, text="Downloading...", bg="#0077b6", fg="white")
        
        # 2. Start download in a thread
        threading.Thread(target=self.download_file_thread, args=(filename, btn), daemon=True).start()

    def download_file_thread(self, filename, button_widget):
        """Handles the download logic in a non-blocking thread."""
        local_filepath = self.download_path / filename
        
        try:
            # 1. Clear previous event and send request
            self.download_port_event.clear()
            self.download_port_result.pop(filename, None)
            
            self.send_json_message({
                "type": "REQUEST_DOWNLOAD",
                "filename": filename
            })
            
            # 2. Wait for server to respond with port and filesize
            if not self.download_port_event.wait(timeout=10):
                raise TimeoutError("Server did not respond to download request.")
            
            result = self.download_port_result.pop(filename, None)
            if not result:
                raise ConnectionError("Server denied download request.")
                
            port, expected_size = result
            
            # 3. Connect to the new data port
            data_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            data_socket.connect((SERVER_HOST, port))
            
            # 4. Receive the file
            bytes_received = 0
            with open(local_filepath, 'wb') as f:
                while bytes_received < expected_size:
                    chunk_size = min(4096, expected_size - bytes_received)
                    chunk = data_socket.recv(chunk_size)
                    if not chunk:
                        break # Connection broken
                    f.write(chunk)
                    bytes_received += len(chunk)

            if bytes_received != expected_size:
                raise ConnectionError(f"Incomplete download: Received {bytes_received}/{expected_size} bytes.")
            
            print(f"File {filename} downloaded successfully.")
            # Add chat message on success
            self.root.after(0, lambda: self.append_chat_message("System", f"Downloaded '{filename}' successfully.", system=True))

        except Exception as e:
            print(f"File download error: {e}")
            if local_filepath.exists():
                try:
                    local_filepath.unlink() # Delete partial file
                except OSError:
                    pass
            # Use lambda to fix TypeError
            self.root.after(0, lambda: self.append_chat_message("System", f"Error downloading {filename}: {e}", system=True))
        
        finally:
            # 5. Cleanup
            if 'data_socket' in locals():
                data_socket.close()
            
            # Reset button state on main thread
            def reset_button():
                if button_widget.winfo_exists():
                    button_widget.config(text="Download", state=tk.NORMAL, bg="#f0f0f0", fg="black")
            
            self.root.after(0, reset_button)

    # --- 5. EXIT & CLEANUP ---

    def handle_exit_click(self):
        """Handles the 'Exit' button click, showing a prompt if needed."""
        if self.is_remembered:
            self.show_exit_prompt()
        else:
            self.on_main_close() # Just exit

    def show_exit_prompt(self):
        """Shows a custom dialog for 'remembered' users."""
        prompt = Toplevel(self.root)
        prompt.title("Exit")
        prompt.geometry("350x150")
        
        # Center it
        prompt.update_idletasks()
        x = self.root.winfo_screenwidth() // 2 - 175
        y = self.root.winfo_screenheight() // 2 - 75
        prompt.geometry(f"+{x}+{y}")
        
        prompt.resizable(False, False)
        
        Label(prompt, text="You are a 'remembered' user.", font=("Arial", 10), pady=10).pack()
        Label(prompt, text="How do you want to exit?", pady=5).pack()
        
        btn_frame = Frame(prompt)
        btn_frame.pack(pady=15)
        
        def on_simple_exit():
            prompt.destroy()
            self.on_main_close()

        def on_forget_exit():
            prompt.destroy()
            self.exit_and_forget()

        Button(btn_frame, text="Exit", width=15, command=on_simple_exit).pack(side=tk.LEFT, padx=10)
        Button(btn_frame, text="Exit and Forget Me", width=15, command=on_forget_exit).pack(side=tk.LEFT, padx=10)
        
        prompt.protocol("WM_DELETE_WINDOW", on_simple_exit)
        prompt.grab_set()

    def exit_and_forget(self):
        """Sends the FORGET_ME message and then closes."""
        self.send_json_message({"type": "FORGET_ME"})
        self.on_main_close()

    def on_main_close(self):
        """Shuts down the client application cleanly."""
        self.is_connected = False
        if self.socket:
            try:
                self.socket.shutdown(socket.SHUT_RDWR)
                self.socket.close()
            except OSError:
                pass # Socket already closed
        self.root.destroy()
        sys.exit(0)
    
    def send_json_message(self, data):
        """Utility to send a JSON message, handling errors."""
        if self.is_connected and self.socket:
            try:
                self.socket.sendall(json.dumps(data).encode('utf-8'))
            except (ConnectionResetError, BrokenPipeError, OSError) as e:
                print(f"Failed to send message: {e}")
                # Don't destroy root here, let the listener thread handle it
                self.is_connected = False

if __name__ == "__main__":
    try:
        root = tk.Tk()
        app = ChatClient(root)
        root.mainloop()
    except KeyboardInterrupt:
        print("Client shutting down.")
        sys.exit(0)