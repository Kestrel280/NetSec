import socket

SERVER_PORT = 10179
RSA_KEY_SIZE = 2048

# Dictionary of all connected clients, as key-value pairs of connection_name:Connection_obj
connections = {}

def sanitize_name(name):
    return name.strip().replace(',', '')

class Connection:
    def __init__(self, socket, name, ip, port):
        # Sanitize name -- no beginning/ending whitespace, and no commas
        name = sanitize_name(name)

        # Check if there's any connection which already have this name
        # If so, reject this new connection
        if name in connections:
            socket.close()
            raise NameError("Connection already exists")
        else:
            # TODO generate/exchance secret key?
            self.socket = socket
            self.name = name
            self.ip = ip
            self.port = port
            connections[name] = self

    # Sends a message
    # Returns True if successfully sent
    # Returns False if message could not be sent (recipient has closed connection)
    def send(self, msg : str):
        # TODO add encryption
        try:
            self.socket.send(msg.encode('utf-8'))
            return True
        except BrokenPipeError: # Recipient closed connection
            return False

    # Blocks until a message is received
    # Returns the message
    # If the message is empty, indicates that the recipient has closed the connection
    def recv(self):
        # TODO add decryption
        try:
            msg = self.socket.recv(1024).decode('utf-8')
        
        # Seems to be a Python GIL/threading issue???
        # Sometimes when client closes connection, instead of recv just returning an empty message,
        #   it throws this exception
        # Solution... well, just return what recv SHOULD have returned
        except ConnectionResetError:
            print(" ... unexpected ConnectionResetError")
            msg = ''
        except Exception as e:
            print(f"Unhandled exception in recv: {e}")
            msg = ''
        finally:
            return msg
        
    def close(self):
        try: 
            self.socket.shutdown(socket.SHUT_RDWR)
            self.socket.close()
        except OSError: # Socket was already closed
            pass
        except Exception as e: 
            print(f"Error closing Connection {self.name}")
            print(e)
        try: del connections[self.name]
        except KeyError: pass
