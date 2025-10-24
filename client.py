import tkinter as tk
from tkinter import messagebox, scrolledtext, simpledialog
from getmac import get_mac_address
import socket
import threading
import json
import time
import sys

# --- Constants ---
SERVER_HOST = '10.83.175.161'  # Change to server's IP if not running locally
SERVER_PORT = 12345


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

        # Get MAC address
        self.mac_address = get_mac_address()
        if not self.mac_address:
            messagebox.showerror("Fatal Error", "Could not determine MAC address. Exiting.")
            self.root.destroy()
            return
        
        # Start the connection process
        self.show_connecting_window()
        threading.Thread(target=self.try_auto_login, daemon=True).start()

    def show_connecting_window(self):
        """Shows a small 'Connecting...' popup."""
        self.connecting_window = tk.Toplevel(self.root)
        self.connecting_window.title("Connecting")
        self.connecting_window.geometry("250x80")
        
        # Center the prompt
        self.connecting_window.update_idletasks()
        x = self.root.winfo_screenwidth() // 2 - 125
        y = self.root.winfo_screenheight() // 2 - 40
        self.connecting_window.geometry(f"+{x}+{y}")

        self.connecting_window.resizable(False, False)
        self.connecting_window.grab_set()
        
        tk.Label(self.connecting_window, text="Attempting to connect...", pady=10).pack(pady=10)
        
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
                self.chat_history = response_data.get("chat_history", []) # Get history
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
            self.root.after(0, lambda: messagebox.showerror("Connection Failed", f"Could not connect to server: {e}\n\nIs the server running?"))
            # If auto-login fails, maybe fall back to manual login?
            # For now, just show manual login if server is reachable
            if "REQUIRE_USERNAME" not in str(e):
                self.root.after(0, self.root.destroy) # Exit if connection failed
            if self.connecting_window:
                self.root.after(0, self.connecting_window.destroy)

    def show_login_window(self):
        """Shows the manual login window."""
        # Close connecting window if it's open
        if self.connecting_window:
            try:
                self.connecting_window.destroy()
            except tk.TclError:
                pass
            self.connecting_window = None

        self.login_window = tk.Toplevel(self.root)
        self.login_window.title("Login")
        
        # Center the prompt
        self.login_window.update_idletasks()
        x = self.root.winfo_screenwidth() // 2 - 150
        y = self.root.winfo_screenheight() // 2 - 100
        self.login_window.geometry(f"300x200+{x}+{y}")
        self.login_window.resizable(False, False)
        
        tk.Label(self.login_window, text=f"Welcome! Please choose a username.", pady=5).pack(pady=(10,5))
        
        tk.Label(self.login_window, text="Username:").pack()
        username_entry = tk.Entry(self.login_window, width=30)
        username_entry.pack(pady=5, padx=20)
        
        remember_var = tk.BooleanVar()
        remember_check = tk.Checkbutton(self.login_window, text="Remember me", variable=remember_var)
        remember_check.pack(pady=5)
        
        self.connect_button = tk.Button(self.login_window, text="Connect", 
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
                self.chat_history = response_data.get("chat_history", []) # Get history
                # Schedule GUI update on the main thread
                # We need to destroy the login window and show the main one
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

    def show_main_window(self):
        """Shows the main application window (video + chat)."""
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
        top_frame = tk.Frame(self.root, bg="#f0f0f0")
        top_frame.pack(fill=tk.X, side=tk.TOP)

        tk.Label(top_frame, text=f"Welcome, {self.username}!", font=("Arial", 14), bg="#f0f0f0").pack(side=tk.LEFT, padx=10, pady=5)
        
        exit_button = tk.Button(top_frame, text="Exit", bg="#e63946", fg="white", font=("Arial", 10, "bold"), command=self.handle_exit_click, borderwidth=0, padx=10, pady=2)
        exit_button.pack(side=tk.RIGHT, padx=10, pady=5)
        
        # --- Main content area (PanedWindow) ---
        main_pane = tk.PanedWindow(self.root, orient=tk.HORIZONTAL, sashrelief=tk.RAISED, sashwidth=4, bg="#f0f0f0")
        main_pane.pack(fill=tk.BOTH, expand=True)

        # --- Left Pane (for video) ---
        video_frame = tk.Frame(main_pane, bg="#333333")
        tk.Label(video_frame, 
                 text="Video feeds will go here",
                 font=("Arial", 12), bg="#333333", fg="white").pack(expand=True)
        main_pane.add(video_frame, width=550) # Give it a default width

        # --- Right Pane (for chat) ---
        chat_frame = tk.Frame(main_pane, bg="white")
        
        # Chat display
        chat_display_frame = tk.Frame(chat_frame, bg="white")
        chat_display_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=(5,0))
        
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

        # Chat input
        chat_input_frame = tk.Frame(chat_frame, bg="white")
        chat_input_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.chat_entry = tk.Entry(chat_input_frame, font=("Arial", 10), borderwidth=1, relief="solid")
        self.chat_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=3)
        
        send_button = tk.Button(chat_input_frame, text="Send", command=self.send_chat_message, borderwidth=1, relief="raised", padx=5)
        send_button.pack(side=tk.RIGHT, padx=(5,0))
        
        # Bind <Return> key to send message
        self.chat_entry.bind("<Return>", lambda event: self.send_chat_message())

        main_pane.add(chat_frame, width=250) # Give chat a default width

        # --- Populate chat history ---
        for username, message in self.chat_history:
            self.append_chat_message(username, message)
        self.append_chat_message("System", "You have joined the chat.", system=True)
        
        # Start listening for new messages
        self.listen_thread = threading.Thread(target=self.listen_for_data, daemon=True)
        self.listen_thread.start()
        
        self.root.protocol("WM_DELETE_WINDOW", self.handle_exit_click)

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
        """Listens for data (chat, video commands) from the server in a thread."""
        while self.socket:
            try:
                data = self.socket.recv(1024)
                if not data:
                    # Server closed connection
                    break
                
                # We assume control messages are JSON.
                # Video data will be raw and fail the JSON load.
                try:
                    message = json.loads(data.decode('utf-8'))
                    msg_type = message.get("type")
                    
                    if msg_type == "NEW_CHAT":
                        username = message.get("username", "Server")
                        payload = message.get("payload", "")
                        # Schedule GUI update on main thread
                        self.root.after(0, self.append_chat_message, username, payload)
                    
                    # ... other control message types (like "USER_JOINED", "USER_LEFT") could go here ...
                
                except json.JSONDecodeError:
                    # Not a JSON message, probably video data.
                    # We'll ignore it for now.
                    pass
                
            except (ConnectionResetError, ConnectionAbortedError):
                break
            except Exception as e:
                print(f"Error in listen thread: {e}")
                break
        
        # If loop breaks, connection is lost
        if self.root.winfo_exists():
            self.root.after(0, self.append_chat_message, "System", "Disconnected from server.", system=True)
            # Maybe show a reconnect button or just disable chat
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
            
        self.exit_prompt_window = tk.Toplevel(self.root)
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

        tk.Label(self.exit_prompt_window, text="You are a remembered user. How do you want to exit?", pady=10, wraplength=330).pack()
        
        button_frame = tk.Frame(self.exit_prompt_window)
        button_frame.pack(pady=10)

        exit_btn = tk.Button(button_frame, text="Exit", command=self.on_main_close, width=15)
        exit_btn.pack(side=tk.LEFT, padx=10)

        forget_btn = tk.Button(button_frame, text="Exit and Forget Me", command=self.exit_and_forget, width=15)
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
        error_window = tk.Toplevel(self.root)
        error_window.title("Connection Failed")
        error_window.geometry("350x120")
        
        # Center it
        error_window.update_idletasks()
        x = self.root.winfo_screenwidth() // 2 - 175
        y = self.root.winfo_screenheight() // 2 - 60
        error_window.geometry(f"+{x}+{y}")
        
        error_window.resizable(False, False)
        
        tk.Label(error_window, 
                 text="A connection from this device is already active.", 
                 wraplength=330, pady=10).pack(pady=10)
        
        exit_btn = tk.Button(error_window, text="Exit", command=self.root.destroy, width=10)
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

