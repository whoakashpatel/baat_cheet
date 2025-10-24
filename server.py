# 10.83.175.161

import tkinter as tk
from tkinter import scrolledtext, messagebox
import socket
import threading
import json
import time

# --- Constants ---
HOST = '10.83.175.161'  # Listen on all available interfaces
PORT = 12345
USER_DATA_FILE = 'remembered_users.json'
MAX_HISTORY = 100 # Max chat messages to store


class ChatServer:
    def __init__(self, root):
        self.root = root
        self.root.title("Video Chat Server")
        self.root.geometry("600x400")

        # --- Data ---
        self.user_data_lock = threading.Lock()
        self.remembered_users = self.load_user_data()
        
        # {conn: (username, mac)}
        self.active_connections = {}
        self.active_conn_lock = threading.Lock()

        # --- Chat History ---
        self.chat_history = [] # List of (username, message) tuples
        self.chat_lock = threading.Lock()

        # --- GUI ---
        self.setup_gui()

        # --- Networking ---
        self.server_socket = None
        self.running = True
        self.start_server_thread()

        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def setup_gui(self):
        # Main frames
        main_frame = tk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        main_frame.grid_columnconfigure(0, weight=1)
        main_frame.grid_columnconfigure(1, weight=3)
        main_frame.grid_rowconfigure(1, weight=1)

        # --- Active Connections ---
        tk.Label(main_frame, text="Active Connections", font=("Arial", 12, "bold")).grid(row=0, column=0, sticky="w")
        
        conn_frame = tk.Frame(main_frame, borderwidth=1, relief="solid")
        conn_frame.grid(row=1, column=0, sticky="nsew", padx=(0, 5))
        
        conn_scrollbar = tk.Scrollbar(conn_frame)
        conn_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.conn_listbox = tk.Listbox(conn_frame, yscrollcommand=conn_scrollbar.set, selectmode=tk.SINGLE)
        self.conn_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        conn_scrollbar.config(command=self.conn_listbox.yview)

        # --- Server Logs ---
        tk.Label(main_frame, text="Server Logs", font=("Arial", 12, "bold")).grid(row=0, column=1, sticky="w")
        
        log_frame = tk.Frame(main_frame, borderwidth=1, relief="solid")
        log_frame.grid(row=1, column=1, sticky="nsew", padx=(5, 0))
        
        self.log_text = scrolledtext.ScrolledText(log_frame, state='disabled', wrap=tk.WORD, font=("Arial", 9))
        self.log_text.pack(fill=tk.BOTH, expand=True)

    def log_message(self, message):
        """Thread-safe logging to the GUI."""
        def append_log():
            self.log_text.config(state='normal')
            self.log_text.insert(tk.END, f"[{time.strftime('%H:%M:%S')}] {message}\n")
            self.log_text.config(state='disabled')
            self.log_text.see(tk.END)
        
        # Schedule GUI updates on the main thread
        self.root.after(0, append_log)

    def update_active_user_list(self):
        """Thread-safe update of the active user list GUI."""
        def update_list():
            self.conn_listbox.delete(0, tk.END)
            with self.active_conn_lock:
                # Display as "username (mac_addr)"
                for conn, (username, mac) in self.active_connections.items():
                    self.conn_listbox.insert(tk.END, f"{username} ({mac})")
        
        self.root.after(0, update_list)

    def load_user_data(self):
        """Loads the username-MAC mapping from the JSON file."""
        with self.user_data_lock:
            try:
                with open(USER_DATA_FILE, 'r') as f:
                    return json.load(f)
            except (FileNotFoundError, json.JSONDecodeError):
                # If file doesn't exist or is empty/corrupt, start fresh
                return {}

    def save_user_data(self):
        """Saves the current username-MAC mapping to the JSON file."""
        with self.user_data_lock:
            try:
                with open(USER_DATA_FILE, 'w') as f:
                    json.dump(self.remembered_users, f, indent=4)
            except IOError as e:
                self.log_message(f"Error saving user data: {e}")

    def start_server_thread(self):
        """Starts the main server loop in a separate thread to not block the GUI."""
        server_thread = threading.Thread(target=self.run_server, daemon=True)
        server_thread.start()

    def run_server(self):
        """Binds, listens, and accepts new client connections."""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.bind((HOST, PORT))
            self.server_socket.listen()
            self.log_message(f"Server started on {HOST}:{PORT}")
        except Exception as e:
            self.log_message(f"Server startup failed: {e}")
            messagebox.showerror("Server Error", f"Server startup failed: {e}")
            self.on_closing()
            return

        while self.running:
            try:
                conn, addr = self.server_socket.accept()
                if not self.running:
                    conn.close()
                    break
                
                self.log_message(f"New connection from {addr[0]}:{addr[1]}")
                # Start a new thread to handle this client's handshake and comms
                handler_thread = threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True)
                handler_thread.start()
            except OSError:
                # This likely happens when self.server_socket.close() is called
                if self.running:
                    self.log_message("Error accepting connection.")
            except Exception as e:
                if self.running:
                    self.log_message(f"Accept loop error: {e}")

    def handle_client(self, conn, addr):
        """Handles the initial handshake and (later) the communication for a single client."""
        try:
            # 1. Receive initial handshake data from client
            # Protocol: JSON string {"mac": "...", "type": "AUTO_LOGIN" | "MANUAL_LOGIN", ...}
            data = conn.recv(1024).decode('utf-8')
            if not data:
                self.log_message(f"Client {addr[0]} disconnected before handshake.")
                conn.close()
                return

            client_data = json.loads(data)
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
            
            # self.remembered_users = self.load_user_data() # <-- REMOVE THIS. It's racy and causes deadlocks.
            # We will rely on the self.remembered_users loaded in __init__ as the single source of truth.
            
            username_to_use = None
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
                    # MAC is known, log them in automatically
                    username_to_use = found_user_for_mac
                    response_status = "OK"
                    self.log_message(f"Recognized MAC {client_mac}. Auto-logging in as '{username_to_use}'.")
                else:
                    # MAC is not known, tell client to ask for username
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
                    # This happens if user exists, but somehow got to manual login.
                    # This is fine, just log them in.
                    username_to_use = found_user_for_mac
                    response_status = "OK"
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
                    # New MAC and new username, registration is successful
                    username_to_use = req_username
                    response_status = "OK"
                    self.log_message(f"New user '{username_to_use}' with MAC {client_mac}.")
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
                                
                        # self.save_user_data() # <-- REMOVE THIS. This caused the deadlock.
 
            # 3. Send response back to client
            # Protocol: JSON string {"status": "...", "username": "...", "remembered": bool}
            remembered_status = False
            if response_status == "OK":
                if handshake_type == "AUTO_LOGIN":
                    remembered_status = True
                elif handshake_type == "MANUAL_LOGIN":
                    remembered_status = client_data['remember_me']
            
            response_data = {
                "status": response_status, 
                "username": username_to_use,
                "remembered": remembered_status # Add this flag
            }
            
            # Add chat history to the response if login was OK
            if response_status == "OK":
                with self.chat_lock:
                    response_data["chat_history"] = self.chat_history
            
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

                # --- This is where the video/audio streaming loop will go ---
                # For now, just keep the connection alive until they disconnect
                try:
                    while self.running:
                        # Keep-alive or data processing loop
                        # A simple recv() will block and detect disconnects
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

                        except json.JSONDecodeError:
                            # This is expected when video data starts flowing
                            # For now, we'll just ignore non-JSON data
                            pass 
                        
                except (ConnectionResetError, ConnectionAbortedError):
                    pass # Client disconnected abruptly
                finally:
                    self.log_message(f"User '{username_to_use}' disconnected.")
                    # Broadcast leave message
                    leave_msg = {
                        "type": "NEW_CHAT",
                        "username": "System",
                        "payload": f"'{username_to_use}' has left the chat."
                    }
                    self.broadcast(json.dumps(leave_msg))
            
        except json.JSONDecodeError:
            self.log_message(f"Invalid JSON from {addr[0]}. Dropping.")
        except ConnectionResetError:
            self.log_message(f"Connection reset by {addr[0]} during handshake.")
        except Exception as e:
            self.log_message(f"Error handling client {addr[0]}: {e}")
        
        # 7. Cleanup
        with self.active_conn_lock:
            if conn in self.active_connections:
                del self.active_connections[conn]
        
        self.update_active_user_list()
        conn.close()

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
            # self.remembered_users = self.load_user_data() # <-- REMOVE THIS.
            
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
                    
                    # self.save_user_data() # <-- REMOVE THIS. This caused the deadlock.
                except KeyError:
                    self.log_message(f"Warning: Race condition? User '{user_to_forget}' not found during delete.")
            else:
                self.log_message(f"Warning: FORGET_ME request for unknown MAC {mac_to_forget}.")

    def on_closing(self):
        """Handle the GUI window being closed."""
        if messagebox.askokcancel("Quit", "Do you want to shut down the server?"):
            self.log_message("Server is shutting down...")
            self.running = False
            
            # Close all active connections
            with self.active_conn_lock:
                for conn in self.active_connections:
                    conn.close()
            
            # Stop accepting new ones by closing the server socket
            # We create a dummy connection to unblock the .accept() call
            try:
                dummy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                dummy_socket.connect((HOST if HOST != '0.0.0.0' else '127.0.0.1', PORT))
                dummy_socket.close()
            except ConnectionRefusedError:
                pass # Server socket might already be closed
            finally:
                if self.server_socket:
                    self.server_socket.close()
            
            self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = ChatServer(root)
    root.mainloop()