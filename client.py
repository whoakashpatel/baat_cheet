import tkinter as tk
from tkinter import messagebox
import socket
import json
import threading
from getmac import get_mac_address

# --- Constants ---
# !! Change this to the server's IP address !!
SERVER_HOST = '10.83.175.161' 
SERVER_PORT = 12345

class ChatClient:
    def __init__(self, root):
        self.root = root
        self.root.withdraw()  # Hide the main root window initially
        self.username = None
        self.socket = None
        self.login_window = None # Will hold login window
        self.connecting_window = None # Will hold connecting popup
        self.is_remembered = False # Flag to track if user is in server's list
        self.exit_prompt_window = None # Will hold the exit prompt
        
        # Get MAC address
        self.mac_address = get_mac_address()
        if not self.mac_address:
            messagebox.showerror("Network Error", "Could not get MAC address. Exiting.")
            self.root.destroy()
            return
            
        # self.show_login_window() # We no longer show this first
        self.start_auto_login()

    def show_connecting_window(self):
        """Shows a simple 'Connecting...' popup."""
        self.connecting_window = tk.Toplevel(self.root)
        self.connecting_window.title("Connecting")
        self.connecting_window.geometry("250x100")
        self.connecting_window.resizable(False, False)
        
        # Center the window
        self.connecting_window.update_idletasks()
        x = self.root.winfo_screenwidth() // 2 - 125
        y = self.root.winfo_screenheight() // 2 - 50
        self.connecting_window.geometry(f"+{x}+{y}")
        
        tk.Label(self.connecting_window, text="Connecting to server...", pady=20).pack()
        
        # Handle user closing this window
        self.connecting_window.protocol("WM_DELETE_WINDOW", self.on_login_close)

    def start_auto_login(self):
        """Shows 'Connecting...' and starts the auto-login thread."""
        self.show_connecting_window()
        threading.Thread(target=self.try_auto_login, daemon=True).start()

    def try_auto_login(self):
        """Tries to log in using just the MAC address."""
        try:
            temp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            temp_socket.connect((SERVER_HOST, SERVER_PORT))

            # 1. Send initial auto-login handshake
            handshake_data = {
                "mac": self.mac_address,
                "type": "AUTO_LOGIN"
            }
            temp_socket.sendall(json.dumps(handshake_data).encode('utf-8'))

            # 2. Wait for server response
            response_raw = temp_socket.recv(1024).decode('utf-8')
            if not response_raw:
                raise ConnectionError("Server closed connection.")
            
            response_data = json.loads(response_raw)

            # 3. Process response
            if response_data.get("status") == "OK":
                # Auto-login successful!
                self.username = response_data.get("username")
                self.is_remembered = response_data.get("remembered", True)
                self.socket = temp_socket # Keep this socket
                self.root.after(0, self.show_main_window)
            
            elif response_data.get("status") == "REQUIRE_USERNAME":
                # Server doesn't know us, need to show login window
                self.root.after(0, self.show_login_window)
                temp_socket.close() # Close this connection, manual login will make a new one

            elif response_data.get("status") == "ALREADY_CONNECTED":
                # Server says we're already logged in. Show the special error.
                self.root.after(0, self.show_already_connected_error)
                temp_socket.close() # Close this new, redundant socket

            else:
                raise ConnectionError(f"Received invalid response: {response_data.get('status')}")

        except Exception as e:
            # Any error in auto-login, we fall back to manual login
            self.root.after(0, self.show_login_window)
            if 'temp_socket' in locals():
                temp_socket.close()
        finally:
            # Hide the 'Connecting...' window
            if self.connecting_window:
                self.root.after(0, self.connecting_window.destroy)

    def show_login_window(self):
        """Creates the initial login pop-up window."""
        # Ensure 'Connecting' window is gone if it's still somehow open
        if self.connecting_window:
            try:
                self.connecting_window.destroy()
            except tk.TclError:
                pass # Window might already be destroyed
            self.connecting_window = None
            
        if self.login_window and self.login_window.winfo_exists(): # Already open?
            self.login_window.lift()
            return 
            
        self.login_window = tk.Toplevel(self.root)
        self.login_window.title("Login")
        self.login_window.geometry("300x150")
        self.login_window.resizable(False, False)
        
        # Center the login window
        self.login_window.update_idletasks()
        x = self.root.winfo_screenwidth() // 2 - 150
        y = self.root.winfo_screenheight() // 2 - 75
        self.login_window.geometry(f"+{x}+{y}")
        
        main_frame = tk.Frame(self.login_window, padx=10, pady=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        tk.Label(main_frame, text="Enter Username:").pack(pady=5)
        
        self.username_entry = tk.Entry(main_frame, width=30)
        self.username_entry.pack(pady=5, padx=10)
        
        self.remember_me_var = tk.BooleanVar()
        self.remember_me_check = tk.Checkbutton(main_frame, text="Remember me", variable=self.remember_me_var)
        self.remember_me_check.pack(pady=5)
        
        self.connect_button = tk.Button(main_frame, text="Connect", command=self.attempt_manual_login)
        self.connect_button.pack(pady=10)
        
        self.login_window.protocol("WM_DELETE_WINDOW", self.on_login_close)

    def on_login_close(self):
        """Handle closing the login window."""
        self.root.destroy() # Close the entire application

    def attempt_manual_login(self):
        """Called when the 'Connect' button is pressed."""
        username = self.username_entry.get().strip()
        if not username:
            messagebox.showwarning("Input Error", "Username cannot be empty.", parent=self.login_window)
            return
            
        remember = self.remember_me_var.get()
        
        # Disable button to prevent multiple clicks
        self.connect_button.config(text="Connecting...", state="disabled")

        # Start connection attempt in a new thread to not freeze the login GUI
        threading.Thread(target=self.try_manual_login, args=(username, remember), daemon=True).start()

    def try_manual_login(self, username, remember):
        """Handles the socket connection and handshake for manual login."""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((SERVER_HOST, SERVER_PORT))

            # 1. Send manual login handshake data
            handshake_data = {
                "mac": self.mac_address,
                "type": "MANUAL_LOGIN",
                "requested_username": username,
                "remember_me": remember
            }
            self.socket.sendall(json.dumps(handshake_data).encode('utf-8'))

            # 2. Wait for server response
            response_raw = self.socket.recv(1024).decode('utf-8')
            if not response_raw:
                raise ConnectionError("Server closed connection unexpectedly.")
            
            response_data = json.loads(response_raw)

            # 3. Process response
            if response_data.get("status") == "OK":
                self.username = response_data.get("username")
                self.is_remembered = response_data.get("remembered", False)
                # Schedule GUI update on the main thread
                # We need to destroy the login window and show the main one
                self.root.after(0, self.login_window.destroy)
                self.login_window = None
                self.root.after(0, self.show_main_window)
            
            elif response_data.get("status") == "ALREADY_CONNECTED":
                # Server says we're already logged in. Show the special error.
                # We need to destroy the login window and show the error instead.
                self.root.after(0, self.login_window.destroy)
                self.login_window = None
                self.root.after(0, self.show_already_connected_error)
                if self.socket:
                    self.socket.close()
                    self.socket = None

            elif response_data.get("status") == "USERNAME_TAKEN":
                messagebox.showerror("Login Failed", 
                                     f"The username '{username}' is already taken. Please try another.",
                                     parent=self.login_window)
                # Re-enable button
                self.root.after(0, lambda: self.connect_button.config(text="Connect", state="normal"))
                self.socket.close()
                self.socket = None # Clear the socket

            else:
                raise ConnectionError(f"Received invalid response from server: {response_data.get('status')}")

        except ConnectionRefusedError:
            messagebox.showerror("Connection Failed", 
                                 "Could not connect to the server. Is it running?",
                                 parent=self.login_window)
            self.root.after(0, lambda: self.connect_button.config(text="Connect", state="normal"))
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}", parent=self.login_window)
            self.root.after(0, lambda: self.connect_button.config(text="Connect", state="normal"))
            if self.socket:
                self.socket.close()
                self.socket = None # Clear the socket

    def show_main_window(self):
        """Destroys the login window and shows the main application window."""
        # Ensure login/connecting windows are gone
        if self.login_window:
            try:
                self.login_window.destroy()
            except tk.TclError:
                pass
            self.login_window = None
        if self.connecting_window:
            try:
                self.connecting_window.destroy()
            except tk.TclError:
                pass
            self.connecting_window = None
        
        self.root.deiconify() # Un-hide the main window
        self.root.title(f"Video Chat - {self.username} (MAC: {self.mac_address})")
        self.root.geometry("800x600")

        # --- Top bar for controls ---
        top_frame = tk.Frame(self.root, bg="#f0f0f0")
        top_frame.pack(fill=tk.X, side=tk.TOP)

        tk.Label(top_frame, text=f"Welcome, {self.username}!", font=("Arial", 14), bg="#f0f0f0").pack(side=tk.LEFT, padx=10, pady=5)
        
        exit_button = tk.Button(top_frame, text="Exit", bg="#e63946", fg="white", font=("Arial", 10, "bold"), command=self.handle_exit_click, borderwidth=0, padx=10, pady=2)
        exit_button.pack(side=tk.RIGHT, padx=10, pady=5)

        # --- Main content area ---
        main_content_frame = tk.Frame(self.root)
        main_content_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        tk.Label(main_content_frame, 
                 text="Connection established.\nVideo streaming will be implemented here.",
                 font=("Arial", 12)).pack(pady=40)

        # Start a thread to listen for server messages (e.g., video data)
        # self.listen_thread = threading.Thread(target=self.listen_for_data, daemon=True)
        # self.listen_thread.start()
        
        self.root.protocol("WM_DELETE_WINDOW", self.handle_exit_click) # Changed from on_main_close

    def listen_for_data(self):
        """(Future use) Listens for incoming data from the server."""
        while True:
            try:
                data = self.socket.recv(4096) # Buffer size will need to be much larger for video
                if not data:
                    break
                # Process video/audio data here
            except Exception:
                break # Socket closed
        
        if self.socket:
            self.socket.close()
        messagebox.showinfo("Disconnected", "You have been disconnected from the server.")
        self.root.destroy()

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

        tk.Label(self.exit_prompt_window, text="You are a remembered user. How do you want to exit?", pady=10).pack()
        
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
        if self.socket:
            self.socket.close()
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
    root = tk.Tk()
    app = ChatClient(root)
    root.mainloop()



