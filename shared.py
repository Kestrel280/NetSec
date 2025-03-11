SERVER_PORT = 10179

# Dictionary of all connected clients, as key-value pairs of client_name:Client_obj
connected_clients = {}

class Client:
    def __init__(self, socket, name):
        # Sanitize name -- no beginning/ending whitespace, and no commas
        name = name.strip().replace(',', '')

        # Check if there's any clients which already have this name
        # If so, reject this new client
        if name in connected_clients:
            print(f" --- Rejecting connection from client {name} -- there's already another client with that name connected! ---")
            socket.close()
            return None
        else:
            # TODO generate/exchance secret key?
            self.socket = socket
            self.name = name
            connected_clients[name] = self

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
        del connected_clients[self.name]
