# 10.83.175.161

import tkinter as tk
from tkinter import scrolledtext, messagebox, Frame, Label, Button
import socket
import threading
import json
import time
import sys
import os
from pathlib import Path

# --- Constants ---
HOST = '10.83.175.161' # Listen on all interfaces
PORT = 12345
USER_DATA_FILE = 'remembered_users.json' # File to store user:mac mappings
MAX_HISTORY = 50 # Max chat history to store
UPLOAD_DIR = 'uploaded' # Directory to store uploaded files

class ChatServer:
    def __init__(self, root):
        self.root = root
        self.root.title("Video Chat Server")
        self.root.geometry("600x500")

        # --- Server State ---
        self.server_socket = None
        self.is_running = False
        self.active_connections = {} # {conn: (username, mac)}
        self.active_conn_lock = threading.Lock()
        
        # --- User Data ---
        self.remembered_users = {} # {username: mac}
        self.user_data_lock = threading.Lock()
        self.load_user_data()

        # --- Chat History ---
        self.chat_history = [] # List of (username, message)
        self.chat_lock = threading.Lock()
        
        # --- File Data ---
        self.upload_path = Path(UPLOAD_DIR)
        self.server_file_list = [] # List of (filename, filesize)
        self.file_list_lock = threading.Lock()
        self.setup_upload_dir()
        self.scan_upload_directory()

        # --- GUI Setup ---
        self.setup_gui()

    def setup_gui(self):
        """Initializes the Tkinter GUI components."""
        # --- Control Frame ---
        control_frame = Frame(self.root, pady=5)
        control_frame.pack(fill=tk.X)

        self.start_button = Button(control_frame, text="Start Server", command=self.start_server_thread, width=15)
        self.start_button.pack(pady=5)

        # --- Paned Window for Lists ---
        main_pane = tk.PanedWindow(self.root, orient=tk.HORIZONTAL, sashrelief=tk.RAISED, sashwidth=4, bg="#f0f0f0")
        main_pane.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # --- Active Connections List ---
        conn_frame = Frame(main_pane, bg="white", relief=tk.SUNKEN, borderwidth=1)
        Label(conn_frame, text="Active Connections (0)", font=("Arial", 12, "bold"), bg="white").pack(pady=5)
        
        conn_list_frame = Frame(conn_frame, bg="white")
        conn_list_frame.pack(fill=tk.BOTH, expand=True)
        
        conn_scrollbar = tk.Scrollbar(conn_list_frame, orient=tk.VERTICAL)
        self.connections_list = tk.Listbox(conn_list_frame, yscrollcommand=conn_scrollbar.set, bg="white")
        conn_scrollbar.config(command=self.connections_list.yview)
        
        conn_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.connections_list.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(5,0), pady=5)
        
        main_pane.add(conn_frame, width=250)
        
        self.conn_label = conn_frame.winfo_children()[0] # Get the label to update count

        # --- Server Logs ---
        log_frame = Frame(main_pane, bg="white", relief=tk.SUNKEN, borderwidth=1)
        Label(log_frame, text="Server Logs", font=("Arial", 12, "bold"), bg="white").pack(pady=5)
        
        self.log_area = scrolledtext.ScrolledText(log_frame, state='disabled', wrap=tk.WORD, font=("Arial", 9))
        self.log_area.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        main_pane.add(log_frame, width=350)
        
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def setup_upload_dir(self):
        """Creates the upload directory if it doesn't exist."""
        try:
            self.upload_path.mkdir(parents=True, exist_ok=True)
            self.log_message(f"Upload directory '{self.upload_path}' is ready.")
        except OSError as e:
            self.log_message(f"Error creating upload directory: {e}", error=True)

    def scan_upload_directory(self):
        """Scans the upload directory to build the initial file list."""
        with self.file_list_lock:
            self.server_file_list.clear()
            if not self.upload_path.is_dir():
                return
            for f in self.upload_path.iterdir():
                if f.is_file():
                    try:
                        filesize = f.stat().st_size
                        self.server_file_list.append((f.name, filesize))
                    except OSError:
                        pass # Skip files we can't access
        self.log_message(f"Scanned {len(self.server_file_list)} existing files.")

    def log_message(self, message, error=False):
        """Appends a message to the server's log area in a thread-safe way."""
        try:
            if not self.root.winfo_exists():
                return
            
            def append_log():
                self.log_area.config(state='normal')
                timestamp = time.strftime("[%Y-%m-%d %H:%M:%S] ")
                tag = "error" if error else "info"
                self.log_area.tag_config("error", foreground="red")
                self.log_area.tag_config("info", foreground="black")
                self.log_area.insert(tk.END, timestamp + message + "\n", tag)
                self.log_area.config(state='disabled')
                self.log_area.see(tk.END)
            
            self.root.after(0, append_log)
        except Exception:
            pass # Suppress errors if GUI is closing

    def update_connections_list(self):
        """Updates the GUI list of active connections in a thread-safe way."""
        try:
            if not self.root.winfo_exists():
                return

            def update_gui():
                self.connections_list.delete(0, tk.END)
                with self.active_conn_lock:
                    count = len(self.active_connections)
                    self.conn_label.config(text=f"Active Connections ({count})")
                    for conn, (username, mac) in self.active_connections.items():
                        addr = conn.getpeername()
                        self.connections_list.insert(tk.END, f"{username} ({addr[0]})")
                
            self.root.after(0, update_gui)
        except Exception:
            pass # Suppress errors if GUI is closing

    def load_user_data(self):
        """Loads the username:mac mapping from the JSON file."""
        with self.user_data_lock:
            if not os.path.exists(USER_DATA_FILE):
                self.remembered_users = {}
                return
            try:
                with open(USER_DATA_FILE, 'r') as f:
                    self.remembered_users = json.load(f)
            except (json.JSONDecodeError, IOError) as e:
                self.log_message(f"Error loading user data: {e}", error=True)
                self.remembered_users = {}

    def start_server_thread(self):
        """Starts the main server logic in a separate thread."""
        self.start_button.config(text="Stop Server", command=self.stop_server, bg="#e63946", fg="white")
        self.is_running = True
        threading.Thread(target=self.run_server, daemon=True).start()

    def stop_server(self):
        """Signals the server to stop, closes sockets, and resets the GUI."""
        if not self.is_running:
            return
            
        self.is_running = False
        
        # Close all active client connections
        with self.active_conn_lock:
            self.log_message(f"Closing {len(self.active_connections)} client connections...")
            for conn in list(self.active_connections.keys()):
                try:
                    conn.close()
                except Exception:
                    pass # Socket already closed
            self.active_connections.clear()
            
        self.update_connections_list()

        # Unblock the server_socket.accept() call by connecting to it
        try:
            dummy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            dummy_socket.connect((HOST if HOST != '0.0.0.0' else '127.0.0.1', PORT))
            dummy_socket.close()
        except ConnectionRefusedError:
            pass # Server was already down
        except Exception as e:
            self.log_message(f"Error during server shutdown: {e}", error=True)

        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception as e:
                self.log_message(f"Error closing server socket: {e}", error=True)
                
        self.server_socket = None
        self.log_message("Server stopped.")
        
        # Reset the button
        self.start_button.config(text="Start Server", command=self.start_server_thread, bg="#f0f0f0", fg="black")


    def run_server(self):
        """The main server loop that accepts new connections."""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((HOST, PORT))
            self.server_socket.listen(5)
            self.log_message(f"Server started on {HOST}:{PORT}")
        except Exception as e:
            self.log_message(f"Error starting server: {e}", error=True)
            self.root.after(0, self.stop_server) # Reset GUI
            return

        while self.is_running:
            try:
                conn, addr = self.server_socket.accept()
                if not self.is_running:
                    break
                
                self.log_message(f"New connection from {addr[0]}")
                # Start a new thread for each client
                threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True).start()
            except Exception as e:
                if self.is_running:
                    self.log_message(f"Error accepting connections: {e}", error=True)
                break # Exit loop if socket is closed

    def handle_client(self, conn, addr):
        """Handles the initial handshake and (later) the communication for a single client."""
        client_mac = None
        username_to_use = None
        is_remembered_user = False
        
        try:
            # 1. Receive initial handshake message
            data = conn.recv(1024).decode('utf-8')
            if not data:
                self.log_message(f"Connection from {addr[0]} dropped before handshake.")
                conn.close()
                return

            client_data = json.loads(data)
            client_mac = client_data['mac']
            
            # --- Duplicate MAC Check ---
            is_duplicate = False
            with self.active_conn_lock:
                for _, mac_in_use in self.active_connections.values():
                    if mac_in_use == client_mac:
                        is_duplicate = True
                        break
            
            if is_duplicate:
                self.log_message(f"Refused: Duplicate connection attempt from MAC {client_mac} at {addr[0]}.")
                response_data = {"status": "ALREADY_CONNECTED"}
                try:
                    conn.sendall(json.dumps(response_data).encode('utf-8'))
                except Exception as e:
                    self.log_message(f"Error sending ALREADY_CONNECTED to {addr[0]}: {e}", error=True)
                finally:
                    conn.close()
                    return # Stop handling this client
            
            handshake_type = client_data.get('type', 'MANUAL_LOGIN')
            
            self.log_message(f"Handshake from {addr[0]} (MAC={client_mac}, Type={handshake_type})")
            
            response_status = "ERROR"

            # Check if MAC is remembered (using the in-memory dictionary)
            found_user_for_mac = None
            with self.user_data_lock: # Need to lock for reading, in case it's being written
                for user, mac in self.remembered_users.items():
                    if mac == client_mac:
                        found_user_for_mac = user
                        break

            if handshake_type == "AUTO_LOGIN":
                if found_user_for_mac:
                    username_to_use = found_user_for_mac
                    response_status = "OK"
                    is_remembered_user = True
                    self.log_message(f"Auto-login successful for '{username_to_use}'.")
                else:
                    response_status = "REQUIRE_USERNAME"
                    self.log_message(f"Unknown MAC {client_mac}. Requesting manual login.")
            
            elif handshake_type == "MANUAL_LOGIN":
                req_username = client_data['requested_username']
                remember_me = client_data['remember_me']
                
                # Check if this MAC is already known by another name
                if found_user_for_mac:
                    username_to_use = found_user_for_mac # Force using the remembered name
                    response_status = "OK"
                    is_remembered_user = True
                    self.log_message(f"Manual login for recognized user '{username_to_use}'.")
                
                else:
                    # Not a recognized MAC. Check if username is available.
                    # Check against active AND remembered users
                    username_is_active = False
                    with self.active_conn_lock:
                        for (username, mac) in self.active_connections.values():
                            if username == req_username:
                                username_is_active = True
                                break
                    
                    if (req_username in self.remembered_users) or username_is_active:
                        response_status = "USERNAME_TAKEN"
                        reason = "remembered" if (req_username in self.remembered_users) else "active"
                        self.log_message(f"Username '{req_username}' is already {reason}. Login refused.")
                    
                    else:
                        # Username is free!
                        username_to_use = req_username
                        response_status = "OK"
                        is_remembered_user = remember_me
                        self.log_message(f"New user '{username_to_use}' registered for this session.")
                        
                        if remember_me:
                            self.log_message(f"Saving user '{username_to_use}' to remembered list.")
                            with self.user_data_lock:
                                self.remembered_users[username_to_use] = client_mac
                                # Write the modified dictionary back to the file *inside* the lock
                                try:
                                    with open(USER_DATA_FILE, 'w') as f:
                                        json.dump(self.remembered_users, f, indent=4)
                                except IOError as e:
                                    self.log_message(f"Error saving user data: {e}", error=True)
 
            # 3. Send response back to client
            response_data = {
                "status": response_status, 
                "username": username_to_use, 
                "remembered": is_remembered_user
            }
            
            if response_status == "OK":
                # Add chat history and file list to successful login
                with self.chat_lock:
                    response_data["chat_history"] = self.chat_history
                with self.file_list_lock:
                    response_data["file_list"] = self.server_file_list
            
            conn.sendall(json.dumps(response_data).encode('utf-8'))

            # 4. If not OK, close connection
            if response_status != "OK":
                self.log_message(f"Login failed for {addr[0]}. Closing connection.")
                conn.close()
                return

            # 5. If OK, add to active list and listen for messages
            with self.active_conn_lock:
                self.active_connections[conn] = (username_to_use, client_mac)
            
            self.update_connections_list()
            self.broadcast("System", f"{username_to_use} has joined the chat.")

            # --- Main Client Loop ---
            buffer = ""
            while self.is_running:
                data_chunk = conn.recv(1024)
                if not data_chunk:
                    break # Client disconnected
                
                buffer += data_chunk.decode('utf-8')
                
                while '}' in buffer:
                    try:
                        end_index = buffer.find('}') + 1
                        json_str = buffer[:end_index]
                        message = json.loads(json_str)
                        buffer = buffer[end_index:] # Keep the rest
                        
                        msg_type = message.get("type")
                        
                        if msg_type == "CHAT_MESSAGE":
                            payload = message.get("payload", "")
                            self.broadcast(username_to_use, payload)
                        
                        elif msg_type == "FORGET_ME":
                            self.log_message(f"User '{username_to_use}' requested to be forgotten.")
                            self.forget_user(client_mac)
                        
                        elif msg_type == "REQUEST_UPLOAD":
                            filename = message.get("filename")
                            filesize = message.get("filesize")
                            self.handle_file_upload(conn, username_to_use, filename, filesize)
                            
                        elif msg_type == "REQUEST_DOWNLOAD":
                            filename = message.get("filename")
                            self.handle_file_download(conn, username_to_use, filename)

                    except json.JSONDecodeError:
                        # Incomplete JSON, break and wait for more data
                        break
                    except Exception as e:
                        self.log_message(f"Error processing message from {username_to_use}: {e}", error=True)
                        buffer = "" # Clear buffer to prevent loops
            
        except (ConnectionResetError, ConnectionAbortedError):
            self.log_message(f"Client {username_to_use or addr[0]} disconnected unexpectedly.")
        except json.JSONDecodeError:
            self.log_message(f"Received invalid handshake from {addr[0]}.")
        except Exception as e:
            self.log_message(f"Error in handle_client ({username_to_use or addr[0]}): {e}", error=True)
        
        finally:
            # --- Cleanup ---
            if conn in self.active_connections:
                with self.active_conn_lock:
                    # Need to check again as stop_server might have cleared it
                    if conn in self.active_connections:
                        del self.active_connections[conn]
                
                self.update_connections_list()
                if username_to_use:
                    self.broadcast("System", f"{username_to_use} has left the chat.")
            
            conn.close()

    def handle_file_upload(self, client_conn, username, filename, filesize):
        """Sets up a temporary socket to receive a file upload."""
        if not filename or filesize is None:
            self.send_json_message(client_conn, {"type": "UPLOAD_ERROR", "filename": filename, "error": "Invalid file info"})
            return
            
        # Sanitize filename
        filename = Path(filename).name
        filepath = self.upload_path / filename
        
        try:
            # 1. Create a new temporary data socket
            data_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            data_socket.bind((HOST, 0)) # Bind to port 0 to get an OS-assigned port
            data_port = data_socket.getsockname()[1]
            data_socket.listen(1)
            
            self.log_message(f"Waiting for upload of '{filename}' from {username} on port {data_port}...")
            
            # 2. Tell the client which port to connect to
            self.send_json_message(client_conn, {"type": "UPLOAD_READY", "port": data_port})
            
            # 3. Start a thread to handle the data transfer
            threading.Thread(
                target=self.receive_file_thread, 
                args=(data_socket, filepath, filesize, username, filename), 
                daemon=True
            ).start()
            
        except Exception as e:
            self.log_message(f"Error setting up upload for {filename}: {e}", error=True)
            self.send_json_message(client_conn, {"type": "UPLOAD_ERROR", "filename": filename, "error": str(e)})
            
    def receive_file_thread(self, data_socket, filepath, expected_size, username, filename):
        """Receives file data on a dedicated socket."""
        conn = None
        try:
            conn, addr = data_socket.accept()
            bytes_received = 0
            
            with open(filepath, 'wb') as f:
                while bytes_received < expected_size:
                    chunk_size = min(4096, expected_size - bytes_received)
                    chunk = conn.recv(chunk_size)
                    if not chunk:
                        break # Connection broken
                    f.write(chunk)
                    bytes_received += len(chunk)
            
            if bytes_received == expected_size:
                self.log_message(f"Successfully received '{filename}' ({expected_size} B) from {username}.")
                # Update the main file list
                with self.file_list_lock:
                    # Remove old entry if it exists (overwrite)
                    self.server_file_list = [f for f in self.server_file_list if f[0] != filename]
                    self.server_file_list.append((filename, expected_size))
                
                # Broadcast the file list update to ALL clients
                self.broadcast_file_list()
                
                # --- NEW: Broadcast chat message about upload ---
                self.broadcast("System", f"{username} uploaded '{filename}'.")
            else:
                raise ConnectionError(f"Incomplete upload: Received {bytes_received}/{expected_size} bytes.")
                
        except Exception as e:
            self.log_message(f"Error receiving file '{filename}': {e}", error=True)
            # Send error on the *control* socket (client_conn) - but we don't have it here.
            # Client will time out; we can also broadcast an error.
            if filepath.exists():
                try:
                    filepath.unlink() # Delete partial file
                except OSError:
                    pass
        finally:
            if conn:
                conn.close()
            data_socket.close()

    def handle_file_download(self, client_conn, username, filename):
        """Sets up a temporary socket to send a file."""
        if not filename:
            self.send_json_message(client_conn, {"type": "DOWNLOAD_ERROR", "filename": filename, "error": "Invalid filename"})
            return
            
        # Sanitize filename
        filename = Path(filename).name
        filepath = self.upload_path / filename
        
        if not filepath.is_file():
            self.log_message(f"{username} requested missing file '{filename}'.")
            self.send_json_message(client_conn, {"type": "DOWNLOAD_ERROR", "filename": filename, "error": "File not found"})
            return
            
        try:
            filesize = filepath.stat().st_size
            
            # 1. Create a new temporary data socket
            data_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            data_socket.bind((HOST, 0)) # OS-assigned port
            data_port = data_socket.getsockname()[1]
            data_socket.listen(1)
            
            self.log_message(f"Preparing to send '{filename}' to {username} on port {data_port}...")
            
            # 2. Tell the client which port to connect to
            self.send_json_message(client_conn, {"type": "DOWNLOAD_READY", "port": data_port, "filesize": filesize})
            
            # 3. Start a thread to handle the data transfer
            threading.Thread(
                target=self.send_file_thread, 
                args=(data_socket, filepath, filesize, username), 
                daemon=True
            ).start()
            
        except Exception as e:
            self.log_message(f"Error setting up download for {filename}: {e}", error=True)
            self.send_json_message(client_conn, {"type": "DOWNLOAD_ERROR", "filename": filename, "error": str(e)})

    def send_file_thread(self, data_socket, filepath, filesize, username):
        """Sends file data on a dedicated socket."""
        conn = None
        try:
            conn, addr = data_socket.accept()
            bytes_sent = 0
            
            with open(filepath, 'rb') as f:
                while bytes_sent < filesize:
                    chunk = f.read(4096)
                    if not chunk:
                        break # Should not happen if filesize is correct
                    conn.sendall(chunk)
                    bytes_sent += len(chunk)
            
            self.log_message(f"Successfully sent '{filepath.name}' to {username}.")
            
        except Exception as e:
            self.log_message(f"Error sending file '{filepath.name}' to {username}: {e}", error=True)
        finally:
            if conn:
                conn.close()
            data_socket.close()

    def broadcast(self, username, message):
        """Sends a chat message to all connected clients."""
        with self.chat_lock:
            # Add to history
            self.chat_history.append((username, message))
            if len(self.chat_history) > MAX_HISTORY:
                self.chat_history.pop(0) # Keep history trimmed
            
            # Prep message
            message_json = json.dumps({
                "type": "NEW_CHAT",
                "username": username,
                "payload": message
            })
            
            self.log_message(f"Chat: {username}: {message}")
            
            # Send to all
            with self.active_conn_lock:
                # Iterate over a copy of the keys, as one might disconnect
                for conn in list(self.active_connections.keys()):
                    self.send_json_message(conn, message_json, is_json_string=True)

    def broadcast_file_list(self):
        """Sends the updated file list to all connected clients."""
        with self.file_list_lock:
            file_list_data = self.server_file_list
            
        message_json = json.dumps({
            "type": "FILE_LIST_UPDATE",
            "file_list": file_list_data
        })
        
        with self.active_conn_lock:
            for conn in list(self.active_connections.keys()):
                self.send_json_message(conn, message_json, is_json_string=True)

    def send_json_message(self, conn, message_data, is_json_string=False):
        """Utility to send a JSON message, handling errors."""
        try:
            if is_json_string:
                conn.sendall(message_data.encode('utf-8'))
            else:
                conn.sendall(json.dumps(message_data).encode('utf-8'))
        except (ConnectionResetError, BrokenPipeError):
            pass # Client disconnected, will be cleaned up by handle_client
        except Exception as e:
            self.log_message(f"Error sending message: {e}", error=True)

    def forget_user(self, mac_to_forget):
        """Finds a user by MAC and removes them from the remembered list."""
        with self.user_data_lock:
            user_to_forget = None
            # Find user in the in-memory dictionary
            for user, mac in self.remembered_users.items():
                if mac == mac_to_forget:
                    user_to_forget = user
                    break
            
            if user_to_forget:
                try:
                    # Remove from the in-memory dictionary
                    del self.remembered_users[user_to_forget]
                    self.log_message(f"User '{user_to_forget}' (MAC: {mac_to_forget}) removed from remembered list.")
                    
                    # Now, write the modified dictionary back to the file
                    try:
                        with open(USER_DATA_FILE, 'w') as f:
                            json.dump(self.remembered_users, f, indent=4)
                    except IOError as e:
                        self.log_message(f"Error saving user data: {e}", error=True)
                    
                except KeyError:
                    self.log_message(f"Warning: Race condition? User '{user_to_forget}' not found during delete.")
            else:
                self.log_message(f"Warning: FORGET_ME request for unknown MAC {mac_to_forget}.")

    def on_closing(self):
        """Called when the main GUI window is closed."""
        if messagebox.askokcancel("Quit", "Do you want to stop the server and quit?"):
            self.stop_server()
            self.root.destroy()
            sys.exit(0) # Force exit if threads are hanging

if __name__ == "__main__":
    try:
        root = tk.Tk()
        app = ChatServer(root)
        root.mainloop()
    except KeyboardInterrupt:
        print("Server shutting down.")
        sys.exit(0)