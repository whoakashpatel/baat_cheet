# 10.83.175.161

import tkinter as tk
from tkinter import scrolledtext, messagebox, simpledialog
import socket
import threading
import json
import time
import sys
import os
from pathlib import Path

# --- Constants ---
HOST = '10.83.175.161'  # Listen on all available interfaces
PORT = 12345
USER_DATA_FILE = 'remembered_users.json'
MAX_HISTORY = 100 # Max chat messages to store
UPLOAD_DIR = 'uploaded' # Directory to store uploaded files


class ChatServer:
    def __init__(self, root):
        self.root = root
        self.root.title("Chat Server")
        self.root.geometry("600x500")
        
        self.running = True
        self.server_socket = None

        # --- User Data ---
        self.user_data_lock = threading.Lock()
        self.remembered_users = self.load_user_data()
        
        # {conn: (username, mac)}
        self.active_connections = {}
        self.active_conn_lock = threading.Lock()

        # --- Chat History ---
        self.chat_history = [] # List of (username, message) tuples
        self.chat_lock = threading.Lock()

        # --- File Data ---
        self.upload_dir_path = Path(UPLOAD_DIR)
        self.server_file_list = [] # List of (filename, filesize_bytes)
        self.file_lock = threading.Lock() # Lock for both file list and directory access
        self.setup_upload_dir()
        self.scan_upload_directory()

        # --- GUI ---
        self.setup_gui()
        
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def setup_gui(self):
        main_pane = tk.PanedWindow(self.root, orient=tk.HORIZONTAL, sashrelief=tk.RAISED, sashwidth=4, bg="#f0f0f0")
        main_pane.pack(fill=tk.BOTH, expand=True)

        # --- Left Pane (Connections) ---
        conn_frame = tk.Frame(main_pane, relief=tk.RIDGE, borderwidth=1)
        tk.Label(conn_frame, text="Active Connections", font=("Arial", 12, "bold")).pack(pady=5)
        self.conn_listbox = tk.Listbox(conn_frame, font=("Arial", 9))
        self.conn_listbox.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        main_pane.add(conn_frame, width=200)

        # --- Right Pane (Logs) ---
        log_frame = tk.Frame(main_pane, relief=tk.RIDGE, borderwidth=1)
        tk.Label(log_frame, text="Server Logs", font=("Arial", 12, "bold")).pack(pady=5)
        self.log_text = scrolledtext.ScrolledText(log_frame, state='disabled', wrap=tk.WORD, font=("Arial", 9))
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        main_pane.add(log_frame, width=400)
        
        # --- Add Start/Stop Button ---
        self.start_button = tk.Button(self.root, text="Start Server", font=("Arial", 12, "bold"), 
                                     bg="#4CAF50", fg="white", command=self.start_server_thread)
        self.start_button.pack(pady=10, side=tk.BOTTOM)

    def log_message(self, message):
        """Appends a message to the server's log GUI in a thread-safe way."""
        def append_log():
            try:
                self.log_text.config(state='normal')
                self.log_text.insert(tk.END, f"[{time.strftime('%H:%M:%S')}] {message}\n")
                self.log_text.config(state='disabled')
                self.log_text.see(tk.END)
            except tk.TclError:
                pass # Window might be closing
        
        # Schedule GUI updates on the main thread
        self.root.after(0, append_log)

    def update_active_user_list(self):
        """Updates the active user listbox GUI in a thread-safe way."""
        def update_list():
            try:
                self.conn_listbox.delete(0, tk.END)
                with self.active_conn_lock:
                    for username, mac in self.active_connections.values():
                        self.conn_listbox.insert(tk.END, f"{username} ({mac})")
            except tk.TclError:
                pass # Window might be closing
        
        self.root.after(0, update_list)

    def load_user_data(self):
        """Loads the username-MAC mapping from the JSON file."""
        with self.user_data_lock:
            try:
                if not os.path.exists(USER_DATA_FILE):
                    return {}
                with open(USER_DATA_FILE, 'r') as f:
                    data = json.load(f)
                    return data
            except (IOError, json.JSONDecodeError):
                # If file doesn't exist or is empty/corrupt, start fresh
                return {}

    def setup_upload_dir(self):
        """Creates the upload directory if it doesn't exist."""
        try:
            self.upload_dir_path.mkdir(parents=True, exist_ok=True)
            self.log_message(f"Upload directory '{UPLOAD_DIR}' is ready.")
        except OSError as e:
            self.log_message(f"FATAL: Could not create upload directory '{UPLOAD_DIR}': {e}")
            messagebox.showerror("Server Error", f"Could not create upload directory: {e}\nExiting.")
            self.on_closing()

    def scan_upload_directory(self):
        """Scans the upload directory and populates the file list."""
        with self.file_lock:
            self.server_file_list.clear()
            for f in self.upload_dir_path.iterdir():
                if f.is_file():
                    try:
                        filesize = f.stat().st_size
                        self.server_file_list.append((f.name, filesize))
                    except OSError as e:
                        self.log_message(f"Error scanning file {f.name}: {e}")
        self.log_message(f"Found {len(self.server_file_list)} files in upload directory.")

    def start_server_thread(self):
        """Starts the main server socket loop in a separate thread."""
        self.start_button.config(text="Stop Server", command=self.stop_server, bg="#e63946", fg="white")
        server_thread = threading.Thread(target=self.run_server, daemon=True)
        server_thread.start()

    def run_server(self):
        """Main server loop to accept new connections."""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((HOST, PORT))
            self.server_socket.listen(5)
            self.log_message(f"Server started on {HOST}:{PORT}")
        except Exception as e:
            self.log_message(f"Error starting server: {e}")
            return

        while self.running:
            try:
                conn, addr = self.server_socket.accept()
                if not self.running:
                    break
                self.log_message(f"New connection from {addr[0]}")
                client_thread = threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True)
                client_thread.start()
            except OSError:
                break # Socket was closed
            except Exception as e:
                if self.running:
                    self.log_message(f"Accept loop error: {e}")

    def handle_client(self, conn, addr):
        """Handles the initial handshake and (later) the communication for a single client."""
        username_to_use = None
        client_mac = None
        try:
            # 1. Initial Handshake (Get MAC and Type)
            data_raw = conn.recv(1024).decode('utf-8')
            if not data_raw:
                self.log_message(f"Connection from {addr[0]} dropped before handshake.")
                return
            
            client_data = json.loads(data_raw)
            client_mac = client_data['mac']
            
            # --- NEW DUPLICATE MAC CHECK ---
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
                    self.log_message(f"Error sending ALREADY_CONNECTED to {addr[0]}: {e}")
                finally:
                    conn.close()
                    return # Stop handling this client
            # --- END NEW DUPLICATE MAC CHECK ---

            handshake_type = client_data.get('type', 'MANUAL_LOGIN') # Default to old behavior if type not specified
            
            self.log_message(f"Handshake from {addr[0]} (MAC={client_mac}, Type={handshake_type})")
            
            response_status = "ERROR"
            remembered_status = False

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
                    remembered_status = True
                    self.log_message(f"Auto-login successful for '{username_to_use}'.")
                else:
                    response_status = "REQUIRE_USERNAME"
                    self.log_message(f"Unknown MAC {client_mac}. Requesting manual login.")
            
            elif handshake_type == "MANUAL_LOGIN":
                req_username = client_data['requested_username']
                remember_me = client_data['remember_me']
                
                # --- NEW DUPLICATE USERNAME CHECK (Checks active AND remembered) ---
                username_is_active = False
                with self.active_conn_lock:
                    for (username, mac) in self.active_connections.values():
                        if username == req_username:
                            username_is_active = True
                            break
                # --- END NEW DUPLICATE USERNAME CHECK ---
                
                if found_user_for_mac and found_user_for_mac == req_username:
                    username_to_use = found_user_for_mac
                    response_status = "OK"
                    remembered_status = True
                    self.log_message(f"Manual login for recognized user '{username_to_use}'.")
                
                elif (req_username in self.remembered_users) or username_is_active: # <-- MODIFIED THIS LINE
                    # Username is taken (by a *different* MAC) either in remembered list or active list
                    response_status = "USERNAME_TAKEN"
                    if username_is_active:
                         self.log_message(f"Refused: MAC {client_mac} requested username '{req_username}', which is *currently active*.")
                    else:
                        self.log_message(f"Refused: MAC {client_mac} requested username '{req_username}', which is *remembered*.")
                
                else:
                    # New user, or existing user with a new username (not allowed by current logic, but OK)
                    username_to_use = req_username
                    response_status = "OK"
                    remembered_status = remember_me
                    
                    if remember_me:
                        self.log_message(f"Saving user '{username_to_use}' to remembered list.")
                        with self.user_data_lock:
                            # If this MAC was already known by another name, remove old entry
                            if found_user_for_mac:
                                try:
                                    del self.remembered_users[found_user_for_mac]
                                except KeyError:
                                    self.log_message(f"Warning: Could not remove old user entry '{found_user_for_mac}'")
                            self.remembered_users[username_to_use] = client_mac
                            
                            # Now, write the modified dictionary back to the file *inside* the lock
                            try:
                                with open(USER_DATA_FILE, 'w') as f:
                                    json.dump(self.remembered_users, f, indent=4)
                            except IOError as e:
                                self.log_message(f"Error saving user data: {e}")
 
            # 3. Send response back to client
            response_data = {
                "status": response_status, 
                "username": username_to_use,
                "remembered": remembered_status # Add this flag
            }
            
            # Add chat history and file list to the response if login was OK
            if response_status == "OK":
                with self.chat_lock:
                    response_data["chat_history"] = self.chat_history
                with self.file_lock:
                    response_data["file_list"] = self.server_file_list
            
            conn.sendall(json.dumps(response_data).encode('utf-8'))

            # 4. If successful, add to active list and proceed
            if response_status == "OK":
                with self.active_conn_lock:
                    self.active_connections[conn] = (username_to_use, client_mac)
                
                self.update_active_user_list()
                self.log_message(f"User '{username_to_use}' successfully connected.")
                
                # Broadcast join message
                join_msg = {
                    "type": "NEW_CHAT",
                    "username": "System",
                    "payload": f"'{username_to_use}' has joined the chat."
                }
                self.broadcast(json.dumps(join_msg))

                # --- Main data loop ---
                while self.running:
                    try:
                        # We use a longer recv buffer for file chunks, but
                        # JSON messages will be small and processed one by one
                        data = conn.recv(1024)
                        if not data:
                            # Client disconnected gracefully
                            break
                        
                        # Check for JSON control messages
                        try:
                            message = json.loads(data.decode('utf-8'))
                            msg_type = message.get("type")

                            if msg_type == "FORGET_ME":
                                self.log_message(f"Received FORGET_ME request from '{username_to_use}'.")
                                self.forget_user(client_mac)
                            
                            elif msg_type == "CHAT_MESSAGE":
                                payload = message.get("payload")
                                if payload:
                                    self.log_message(f"Chat from '{username_to_use}': {payload}")
                                    
                                    # Add to history (with lock)
                                    with self.chat_lock:
                                        self.chat_history.append((username_to_use, payload))
                                        # Trim history if it's too long
                                        if len(self.chat_history) > MAX_HISTORY:
                                            self.chat_history = self.chat_history[-MAX_HISTORY:]
                                    
                                    # Broadcast to all clients
                                    broadcast_msg = {
                                        "type": "NEW_CHAT",
                                        "username": username_to_use,
                                        "payload": payload
                                    }
                                    self.broadcast(json.dumps(broadcast_msg))
                            
                            elif msg_type == "REQUEST_UPLOAD":
                                filename = message.get("filename")
                                filesize = message.get("filesize")
                                if filename and filesize:
                                    self.log_message(f"Got upload request for {filename} ({filesize} bytes) from {username_to_use}")
                                    self.prepare_file_reception(conn, filename, filesize, username_to_use)

                            elif msg_type == "REQUEST_DOWNLOAD":
                                filename = message.get("filename")
                                if filename:
                                    self.log_message(f"Got download request for {filename} from {username_to_use}")
                                    self.prepare_file_send(conn, filename, username_to_use)

                        except json.JSONDecodeError:
                            # This is expected when video data starts flowing
                            # For now, just ignore it.
                            pass
                        except Exception as e:
                            self.log_message(f"Error processing JSON from {username_to_use}: {e}")
                            
                    except (ConnectionResetError, ConnectionAbortedError):
                        # Client disconnected abruptly
                        break
                    except Exception as e:
                        self.log_message(f"Error in client loop for {username_to_use}: {e}")
                        break
                
                # --- After loop (client disconnected) ---
                if username_to_use:
                    self.log_message(f"User '{username_to_use}' disconnected.")
                    # Broadcast leave message
                    leave_msg = {
                        "type": "NEW_CHAT",
                        "username": "System",
                        "payload": f"'{username_to_use}' has left the chat."
                    }
                    self.broadcast(json.dumps(leave_msg))
            
        except json.JSONDecodeError:
            self.log_message(f"Invalid JSON handshake from {addr[0]}")
        except Exception as e:
            if self.running:
                self.log_message(f"Error in handle_client for {addr[0]}: {e}")
        
        finally:
            with self.active_conn_lock:
                if conn in self.active_connections:
                    del self.active_connections[conn]
            
            self.update_active_user_list()
            conn.close()

    def open_ephemeral_port(self):
        """Opens a new socket on a random free port (ephemeral port)."""
        try:
            temp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            temp_socket.bind((HOST, 0)) # 0 means OS picks a free port
            temp_socket.listen(1)
            port = temp_socket.getsockname()[1]
            return temp_socket, port
        except Exception as e:
            self.log_message(f"Error opening ephemeral port: {e}")
            return None, None

    def prepare_file_reception(self, control_conn, filename, filesize, username):
        """Opens a new port and starts a thread to receive a file."""
        temp_socket, port = self.open_ephemeral_port()
        if not temp_socket:
            # Send error back on control connection
            try:
                err_msg = {"type": "UPLOAD_ERROR", "filename": filename, "error": "Server failed to open data port."}
                control_conn.sendall(json.dumps(err_msg).encode('utf-8'))
            except Exception as e:
                self.log_message(f"Error sending UPLOAD_ERROR to {username}: {e}")
            return

        self.log_message(f"Telling {username} to upload {filename} to port {port}")
        
        # Start the receiver thread
        threading.Thread(
            target=self.receive_file_thread, 
            args=(temp_socket, filename, filesize, username), 
            daemon=True
        ).start()
        
        # Send the OK and port number on the *control* connection
        try:
            ok_msg = {"type": "UPLOAD_READY", "filename": filename, "port": port}
            control_conn.sendall(json.dumps(ok_msg).encode('utf-8'))
        except Exception as e:
            self.log_message(f"Error sending UPLOAD_READY to {username}: {e}")
            temp_socket.close() # Clean up

    def receive_file_thread(self, server_socket, filename, filesize, username):
        """Thread function to accept one connection and receive a file."""
        try:
            server_socket.settimeout(60.0) # 60 second timeout to connect
            data_conn, addr = server_socket.accept()
            self.log_message(f"Data connection for {filename} opened from {addr}")
            
            safe_filename = Path(filename).name # Sanitize filename
            filepath = self.upload_dir_path / safe_filename
            
            bytes_received = 0
            with open(filepath, 'wb') as f:
                while bytes_received < filesize:
                    chunk_size = min(4096, filesize - bytes_received)
                    chunk = data_conn.recv(chunk_size)
                    if not chunk:
                        break
                    f.write(chunk)
                    bytes_received += len(chunk)
            
            data_conn.close()
            
            if bytes_received == filesize:
                self.log_message(f"Successfully received {filename} from {username}.")
                # Update and broadcast the new file list
                with self.file_lock:
                    self.server_file_list.append((safe_filename, filesize))
                
                broadcast_msg = {
                    "type": "FILE_LIST_UPDATE",
                    "file_list": self.server_file_list
                }
                self.broadcast(json.dumps(broadcast_msg))
            else:
                self.log_message(f"File transfer for {filename} incomplete. Received {bytes_received}/{filesize}")
                try:
                    filepath.unlink() # Delete partial file
                except OSError as e:
                    self.log_message(f"Error deleting partial file {filename}: {e}")

        except socket.timeout:
            self.log_message(f"File upload timed out for {filename} from {username}.")
        except Exception as e:
            self.log_message(f"Error in receive_file_thread ({filename}): {e}")
        finally:
            server_socket.close()

    def prepare_file_send(self, control_conn, filename, username):
        """Checks if file exists, opens a port, and starts a thread to send it."""
        safe_filename = Path(filename).name
        filepath = self.upload_dir_path / safe_filename
        
        if not filepath.is_file():
            self.log_message(f"User {username} requested non-existent file: {filename}")
            try:
                err_msg = {"type": "DOWNLOAD_ERROR", "filename": filename, "error": "File not found on server."}
                control_conn.sendall(json.dumps(err_msg).encode('utf-8'))
            except Exception as e:
                self.log_message(f"Error sending DOWNLOAD_ERROR to {username}: {e}")
            return
            
        filesize = filepath.stat().st_size
        
        temp_socket, port = self.open_ephemeral_port()
        if not temp_socket:
            try:
                err_msg = {"type": "DOWNLOAD_ERROR", "filename": filename, "error": "Server failed to open data port."}
                control_conn.sendall(json.dumps(err_msg).encode('utf-8'))
            except Exception as e:
                self.log_message(f"Error sending DOWNLOAD_ERROR to {username}: {e}")
            return

        self.log_message(f"Telling {username} to download {filename} from port {port}")

        # Start the sender thread
        threading.Thread(
            target=self.send_file_thread,
            args=(temp_socket, filepath, filesize, username),
            daemon=True
        ).start()

        # Send the OK, port, and size on the *control* connection
        try:
            ok_msg = {"type": "DOWNLOAD_READY", "filename": filename, "filesize": filesize, "port": port}
            control_conn.sendall(json.dumps(ok_msg).encode('utf-8'))
        except Exception as e:
            self.log_message(f"Error sending DOWNLOAD_READY to {username}: {e}")
            temp_socket.close()

    def send_file_thread(self, server_socket, filepath, filesize, username):
        """Thread function to accept one connection and send a file."""
        try:
            server_socket.settimeout(60.0) # 60 second timeout
            data_conn, addr = server_socket.accept()
            self.log_message(f"Data connection for sending {filepath.name} opened to {addr}")

            with open(filepath, 'rb') as f:
                bytes_sent = 0
                while bytes_sent < filesize:
                    chunk = f.read(4096)
                    if not chunk:
                        break # Should not happen if filesize is correct
                    data_conn.sendall(chunk)
                    bytes_sent += len(chunk)
            
            self.log_message(f"Successfully sent {filepath.name} to {username}.")

        except socket.timeout:
            self.log_message(f"File download timed out for {filepath.name} to {username}.")
        except (ConnectionError, BrokenPipeError):
            self.log_message(f"Client {username} disconnected during file transfer of {filepath.name}")
        except Exception as e:
            self.log_message(f"Error in send_file_thread ({filepath.name}): {e}")
        finally:
            data_conn.close()
            server_socket.close()

    def broadcast(self, message_json_string):
        """Broadcasts a JSON string message to all active clients."""
        with self.active_conn_lock:
            # Create a list of connections to iterate over
            # This avoids holding the lock while sending, which can be slow
            all_conns = list(self.active_connections.keys())
        
        for conn in all_conns:
            try:
                conn.sendall(message_json_string.encode('utf-8'))
            except (OSError, ConnectionResetError, BrokenPipeError) as e:
                # Client might have disconnected, server will clean it up on recv() fail
                self.log_message(f"Error broadcasting to a client: {e}. (Will be cleaned up shortly)")

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
                        self.log_message(f"Error saving user data: {e}")
                    
                except KeyError:
                    self.log_message(f"Warning: Race condition? User '{user_to_forget}' not found during delete.")
            else:
                self.log_message(f"Warning: FORGET_ME request for unknown MAC {mac_to_forget}.")

    def stop_server(self, ask=True):
        """Shuts down the server sockets and connections."""
        if ask and not messagebox.askokcancel("Quit", "Do you want to shut down the server?"):
            return False # User cancelled

        self.running = True # Set to True to allow dummy socket connection, then false
        
        # Stop the server socket
        if self.server_socket:
            try:
                # Create a dummy connection to unblock the accept() call
                dummy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                # Use 127.0.0.1 for the dummy socket
                dummy_socket.connect(('127.0.0.1', PORT)) 
                dummy_socket.close()
            except ConnectionRefusedError:
                pass # Server might already be down
            finally:
                self.server_socket.close()
                self.server_socket = None
        
        self.running = False # Now set to false to stop client loops

        # Close all active connections
        with self.active_conn_lock:
            all_conns = list(self.active_connections.keys())
            for conn in all_conns:
                try:
                    conn.close()
                except Exception:
                    pass # Ignore errors
            self.active_connections.clear()
        
        self.update_active_user_list()
        
        self.log_message("Server has been shut down.")
        # Reset the button
        if self.start_button:
            self.start_button.config(text="Start Server", command=self.start_server_thread, bg="#4CAF50", fg="white")
        
        return True # Shutdown was successful

    def on_closing(self):
        """Handles the server shutting down."""
        if self.stop_server(ask=True): # Call the new stop function
            self.root.destroy()


if __name__ == "__main__":
    try:
        main_root = tk.Tk()
        app = ChatServer(main_root)
        main_root.mainloop()

    except KeyboardInterrupt:
        sys.exit(0)