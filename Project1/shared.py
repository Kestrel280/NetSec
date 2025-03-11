SERVER_PORT = 10179

# Dictionary of all connected clients, as key-value pairs of connection_name:Connection_obj
connections = {}

class Connection:
    def __init__(self, socket, name):
        # Sanitize name -- no beginning/ending whitespace, and no commas
        name = name.strip().replace(',', '')

        # Check if there's any connection which already have this name
        # If so, reject this new connection
        if name in connections:
            print(f" --- Rejecting connection from {name} -- there's already another connection with that name connected! ---")
            socket.close()
            return None
        else:
            # TODO generate/exchance secret key?
            self.socket = socket
            self.name = name
            connections[name] = self

    def send(self, msg : str):
        # TODO add encryption
        self.socket.send(msg.encode('utf-8'))

    # Blocks
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
        finally:
            return msg
        
    def close(self):
        try: self.socket.close()
        except: pass
        try: del connections[self.name]
        except KeyError: pass
