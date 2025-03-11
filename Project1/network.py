import sys
import socket
import threading
import atexit
from shared import *

listener_socket = 0 # Initialize listener_socket here so that it's globally scoped

def crash_handler(*args):
    print("(SERVER) Server closing, closing listener socket")
    try:
        listener_socket.close()
        for client in connections.values():
            client.close()
    except:
        print("(SERVER) ... Failed to close sockets! netstat -ntp might show the socket in the CLOSE-WAIT state")
        return
    print("(SERVER) Socket closed successfully")

def handle_client(client_socket):
    # On connection established, first message sent will be the client's name
    # Respond with an OK just to proceed/synchronize
    client_name = client_socket.recv(1024).decode('utf-8')
    client_socket.send("OK".encode('utf-8'))

    client = Connection(client_socket, client_name)
    if not client: return # If client constructor returned None, the client couldn't be created; end this thread

    print(f"(SERVER) Client thread spawned for new client {client.name}")

    # Enter main loop
    # When the client closes the socket, it will send an empty message
    # So, our while loop is structured to terminate when it receives an empty message
    msg = client.recv()
    while msg:
        # First (or only) token of message is the command
        cmd = msg.split(' ')[0]

        response = 'OK'
        # Dispatch logic depending on what command was received
        # (Note: no fallthrough in Python match-case statements, so no breaks)
        match cmd:
            case 'LIST_CLIENTS':
                #response = 'LIST_CLIENTS PLACEHOLDER'
                #returning the names to the client
                response = ",".join(connections.keys())
            case 'GET_CLIENT_ADDR': 
                # There should be an argument provided
                try: 
                    arg = msg.split(' ')[1]
                    if arg in connections:
                        response = str(connections[arg].socket.getpeername())
                    else:
                        response = 'ERROR'
                except: response = 'ERROR'
        client.send(response)
        
        print(f"(SERVER) Received msg '{msg}' from Client {client.name}; responded '{response}'")
        msg = client.recv()

    # Out of the while loop -- empty message was received, so client must have closed the connection
    # Close the socket on our end
    print(f"(SERVER) Client {client.name} has closed connection: closing on our end too")
    client.close()
    return

if __name__ == '__main__':
    # Register emergency-termination function (to close sockets in case of crash)
    atexit.register(crash_handler)

    # Create and initialize the listener socket
    # The role of this socket is just to listen for incoming connections
    # When a new connection request is received, it creates a new thread
    #   to handle the new client
    server_ip = socket.gethostbyname(socket.gethostname())
    listener_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener_socket.bind(("0.0.0.0", SERVER_PORT)) # 0.0.0.0 is to listen for any connections
    listener_socket.listen(10)

    print(f"(SERVER) Network started on {server_ip}:{SERVER_PORT}")

    # Start listening on the listener socket
    # Whenever a new connection is established,
    #   start a new thread running handle_client
    #   for the new client
    while True:
        try:
            client_socket, client_address = listener_socket.accept()
            print(f"client details: {client_socket},{client_address}")
            threading.Thread(target=handle_client, args=(client_socket,)).start()

        except Exception as e:
            print("(SERVER) Error accepting new client, terminating!")
            print(e)
            exit()
