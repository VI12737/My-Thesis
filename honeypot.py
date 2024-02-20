import paramiko
import os
import socket
import threading
import datetime
import time
import argparse
import traceback
from flask import Flask, request, render_template, redirect, url_for, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address


LOG_FILE = "server_log.txt"


Web_Log_File = "web_log.txt"
LOG_COMMAND = "Command_log.txt"
SSH_BANNER = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3"
FAKE_CREDENTIALS = {"Thesis": "fake_pass"}
MAX_LOGIN_ATTEMPTS = 3
BLOCK_TIME_SECONDS = 60
BLOCKED_IPS = set()
BLOCKED_IPS_LOCK = threading.Lock()

DELAY_AFTER_INVALID_LOGIN = 5
COOLDOWN_PERIOD = BLOCK_TIME_SECONDS

REQUEST_WINDOW_SECONDS = 60
REQUEST_COUNT_LIMIT = 5
request_timestamps = {}

def log(message):
    timestamp = datetime.datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
    log_message = f"{timestamp} {message}\n"
    with open(LOG_FILE, "a", encoding="utf-8") as log_file:
        log_file.write(log_message)

def log_web(message):
    timestamp = datetime.datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
    log_message = f"{timestamp} {message}\n"
    with open(Web_Log_File, "a", encoding="utf-8") as log_file:
        log_file.write(log_message)

def com_log(message):
    timestamp = datetime.datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
    log_message = f"{timestamp} {message}\n"
    with open(LOG_COMMAND, "a", encoding="utf-8") as com_log_file:
        com_log_file.write(log_message)

#----------------------------------------------------------------------------------------------------------------#

app = Flask(__name__, template_folder='templates', static_folder='static',static_url_path='/static')
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "5 per minute"])
app.secret_key = '7^@+XQ*hv^$2WaF4'

class FakeWebHoneypot:
    def __init__(self):
        self.app = app

    def log_request(self, data):
        log_web(data)

    def start(self, port,host = '0.0.0.0'):
        self.app.run(host=host , port=port, threaded=True)
    

fake_web_honeypot = FakeWebHoneypot()

@app.route('/')
@limiter.limit("5 per minute")
def index():
    name = request.args.get('name', default=session.get('username')) 
    fake_web_honeypot.log_request(f"HTTP Request - {request.remote_addr} - {request.method} - {request.user_agent}")
    return render_template('index2.html', name=name)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Simulate authentication (replace this with your actual authentication logic)
        if username == 'fakeuser' and password == 'fakepass':
            fake_web_honeypot.log_request(f"Successful Login - {request.remote_addr} - Username: {username}")
            session['username'] = username  # Store the username in the session
            return redirect(url_for('index', name=username))
        else:
            fake_web_honeypot.log_request(f"Failed Login Attempt - {request.remote_addr} - Username: {username}, Password: {password}")

    fake_web_honeypot.log_request(f"Login Page Request - {request.remote_addr}")
    return render_template('login.html')

@app.route('/congrats')
def finalscreen():
    return render_template('code.html')

def start_moderate_web_honeypot(port,host = '0.0.0.0'):
    fake_web_honeypot.start(port,host)


#----------------------------------------------------------------------------------------------------------------#
class FakeSSHServer(paramiko.ServerInterface):
    def __init__(self):
        self.event = threading.Event()
        self.transport = None
        self.login_attempt_count = 0
        self.last_login_attempt_time = 0
        self.lock = threading.Lock()

    def check_auth_password(self, username, password):
        current_time = time.time()

        # Check if the IP is blocked
        client_ip = self.get_client_ip()
        if client_ip is not None and client_ip in BLOCKED_IPS:
            log(f"Blocked login attempt from {client_ip}")
            return paramiko.AUTH_FAILED

        with self.lock:
            if current_time < self.last_login_attempt_time:
                # In cooldown period, reject login
                return paramiko.AUTH_FAILED

            if username in FAKE_CREDENTIALS and password == FAKE_CREDENTIALS[username]:
                self.login_attempt_count = 0  # Reset login attempt count upon successful login
                return paramiko.AUTH_SUCCESSFUL
            else:
                log(f"Invalid login attempt: {username} / {password}")
                # Add delay after each unsuccessful login attempt
                time.sleep(DELAY_AFTER_INVALID_LOGIN)
                self.handle_invalid_login(client_ip)
                return paramiko.AUTH_FAILED

    def handle_invalid_login(self, client_ip):
            self.login_attempt_count += 1
            print(client_ip+" >attempt:"+str(self.login_attempt_count))

            # Check if login attempts exceed the limit
            max_login_attempts = MAX_LOGIN_ATTEMPTS
            if self.login_attempt_count >= max_login_attempts:
                log(f"Exceeded maximum login attempts for {client_ip}")
                BLOCKED_IPS.add(client_ip)
                log(f"Blocked IP: {client_ip}")

                # ใช้ Timer จาก threading เพื่อทำงานหลังจากผ่านไปเวลาที่กำหนด
                timer = threading.Timer(BLOCK_TIME_SECONDS + COOLDOWN_PERIOD, self.unblock_ip, args=(client_ip,))
                timer.start()
                
                with self.lock:
                    self.last_login_attempt_time = time.time() + COOLDOWN_PERIOD  # Set cooldown period
            else:
                log(f"Invalid login attempt from {client_ip}. Remaining attempts: {max_login_attempts - self.login_attempt_count}")

    def get_client_ip(self):
        if self.transport is not None:
            return self.transport.getpeername()[0]
        else:
            return None

    def unblock_ip(self, ip):
        print("Unblocking IP...")
        if ip in BLOCKED_IPS:
            BLOCKED_IPS.remove(ip)
            log(f"Unblocked IP: {ip}")
        else:
            log(f"IP {ip} not found in blocked list.")

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True
    
    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

def handle_cmd(cmd, channel,current_directory):
    # Response for fake
    response = ""
    if current_directory is None:
        current_directory = "C:\\Users\\Project"

    if cmd.startswith("dir"):
        # Windows dir command equivalent
        response = " Volume in drive C has no label.\r\n Volume Serial Number is XXXX-XXXX\r\n\r\n Directory of " + current_directory + "\r\n\r\n"
        response += "File1.txt         "
        response += "File2.txt         "
        response += "\r\n"

    elif cmd.startswith("echo"):
        # Windows echo command equivalent
        response = cmd[len("echo"):].strip()

    elif cmd.startswith("cd"):
        command_parts = cmd.split(maxsplit=1)
        # Extract the command and argument
        new_directory = command_parts[1] if len(command_parts) > 1 else ""
        current_directory = update_directory(current_directory, new_directory)

    elif cmd.startswith("type"):
        # Windows type command equivalent
        response = ""

    elif cmd == "help":
        # Windows help command equivalent
        response = "For more information on a specific command, type HELP command-name\r\n"
        response += "CD           Displays the name of or changes the current directory.\r\n"
        response += "DIR          Displays a list of files and subdirectories in a directory.\r\n"
        response += "ECHO         Displays messages, or turns command-echoing on or off.\r\n"
        response += "TYPE         Displays the contents of a text file.\r\n"
    else:
        response = f"'{cmd}' is not recognized as an internal or external command,\r\noperable program or batch file."


    channel.send(response + "\r\n")
    return current_directory

def update_directory(current_directory, new_directory):
    # Handle relative path changes
    if new_directory.startswith(".."):
        current_directory = os.path.dirname(current_directory)
        new_directory = new_directory[2:].lstrip(os.path.sep)
    elif not new_directory.startswith(os.path.sep):
        new_directory = os.path.join(current_directory, new_directory)

    # Normalize the path and update the current directory
    current_directory = os.path.normpath(new_directory)
    return current_directory

def read_txt_file(folder,filename,channel):
    try:
        filepath = f'{folder}/{filename}'
        with open(filepath, 'r') as text_file:
            channel.send("\r\n")
            for line in text_file:
                channel.send(line + "\r\n")
                time.sleep(0.1)  # Optional: Add a delay between lines
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found in folder '{folder}'.")
    except Exception as e:
        print(f"Error: {e}")

def handle_connection(client_sock, client_addr):
    """Handle a new ssh connection"""
    log("Connection success from: " + client_addr[0])
    print('SSH Got connection!')

    client_ip = client_sock.getpeername()[0]

    if client_ip in BLOCKED_IPS:
        log(f"Blocked connection attempt from {client_ip}")
        client_sock.close()
        return

    try:
        transport = paramiko.Transport(client_sock)
        server_key = paramiko.RSAKey(filename='key/key')

        transport.add_server_key(server_key)

        # Set up the SSH server
        transport.local_version = SSH_BANNER
        ssh_server = FakeSSHServer()
        ssh_server.transport = transport 

        try:
            transport.start_server(server=ssh_server)
        except paramiko.SSHException as e:
            log(f'*** SSH negotiation failed: {e}')
            raise Exception("SSH negotiation failed")

        # Wait for a channel to be requested
        channel = transport.accept(20)
        if channel is None:
            log("No Channel")
            raise Exception("No channel")

        ssh_server.event.wait(10)
        if not ssh_server.event.is_set():
            log('*** Client never asked for a shell.')
            raise Exception("No shell request")

        try:
            welcome_message = "Microsoft Windows [Version 10.0.19045.3803] \r\n(c) Microsoft Corporation. All rights reserved."

            channel.send(welcome_message + "\r\n")
            run = True

            # Initialize current_directory for each thread
            current_directory = "C:\\Users\\Project"  # Set default value here

            while run:
                exten = "" if current_directory is None else str(current_directory)
                channel.send(f"Test@DESKTOP-LPQ8Q0D {exten}>")

                command = ''
                while not command.endswith("\r"):
                    ch = channel.recv(1)
                    if ch == b'\r':
                        break
                    if ch == b'\xe0':
                        channel.recv(1)
                    elif ch == b'\x7f':
                        command = command[:-1]
                        channel.send("\r" + " " * 50 + f"\rTest@DESKTOP-LPQ8Q0D {exten}>" + command)
                    else:
                        decodech = ch.decode()
                        command = command + decodech
                        channel.send(decodech)

                channel.send("\r\n")
                command = command.rstrip()
                log(client_addr[0] + ":" + command)
                print(command)
                if command == "exit":
                    run = False
                else:
                    current_directory = handle_cmd(command, channel, current_directory)

        except Exception as e:
            log(f'!!! Exception: {e.__class__.__name__}: {e}')
            traceback.print_exc()
            try:
                transport.close()
            except Exception:
                pass

        channel.close()

    except Exception as e:
        log(f'!!! Exception: {e.__class__.__name__}: {e}')
        traceback.print_exc()
        try:
            transport.close()
        except Exception:
            pass

def main_ssh(port, bind):
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((bind, port))
    threads = []
    print("Wait for connection")
    try:
        while True:
            server_sock.listen(100)
            client_sock, client_addr = server_sock.accept()
            log(f"Connection from {client_addr[0]}:{client_addr[1]}")
            t = threading.Thread(target=handle_connection, args=(client_sock, client_addr))
            t.start()
            threads.append(t)
    except KeyboardInterrupt:
        log("Server terminated by user.")

def main(port, web_port, bind):
    # Start the moderate web honeypot
    web_thread = threading.Thread(target=start_moderate_web_honeypot, args=(web_port,bind))
    web_thread.start()

    # Start the SSH server
    ssh_thread = threading.Thread(target=main_ssh, args=(port, bind))
    ssh_thread.start()

    # Wait for both threads to finish
    ssh_thread.join()
    web_thread.join()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", "-p", help="The port to bind to ssh server", default=22, type=int, action="store")
    parser.add_argument("--web-port", "-wp", help="The port to bind to the HTTP server", default=8080, type=int, action="store")
    parser.add_argument("--bind", "-b", help="The address to bind to server", default="", type=str, action="store")
    args = parser.parse_args()

    # Start the combined SSH and moderate web honeypots
    main(args.port, args.web_port, args.bind)