import socket
from Crypto.Hash import SHA3_512

SERVER_PORT = 10179
RSA_KEY_SIZE = 2048

# Dictionary of all connected clients, as key-value pairs of connection_name:Connection_obj
connections = {}

def sanitize_name(name):
    return name.strip().replace(',', '')

class Connection:
    def __init__(self, socket, name, ip, port, pub_key, 
                 pub_crypter, priv_crypter,     # Assymetric encryption/decryption objects
                 sym_encrypter, sym_decrypter): # Symmetric encryption/decryption objects
        # Sanitize name -- no beginning/ending whitespace, and no commas
        name = sanitize_name(name)

        # Check if there's any connection which already have this name
        # If so, reject this new connection
        if name in connections:
            socket.close()
            raise NameError("Connection already exists")
        else:
            self.socket = socket
            self.name = name
            self.ip = ip
            self.port = port
            self.pub_key = pub_key
            self.pub_crypter = pub_crypter
            self.priv_crypter = priv_crypter
            self.sym_encrypter = sym_encrypter
            self.sym_decrypter = sym_decrypter

            # Register this connection to the global connections object
            connections[name] = self

    # Encrypts a message and sends it
    #   Returns True if successfully sent
    #   Returns False if message could not be sent (recipient has closed connection)
    def send(self, plaintext, encutf8 = True):
        # Generate the ciphertext and tag
        if (plaintext == ''): msg = ''
        else:
            # Encryption
            plaintext = plaintext.encode('utf-8') if encutf8 else plaintext
            ciphertext, tag = self.sym_encrypter.encrypt_and_digest(plaintext)
            auth = self.priv_crypter.encrypt(SHA3_512.new(plaintext).digest())

            msg = bytearray()
            msg += "{},{},{}.".format(len(ciphertext), len(tag), len(auth)).encode('utf-8')
            msg.extend(ciphertext)
            msg.extend(tag)
            msg.extend(auth)

        try:
            self.socket.send(msg)
            return True
        except BrokenPipeError: # Recipient closed connection
            return False

    # (Blocking) Receives and decrypts an encrypted message
    #   If the message is empty, indicates that the recipient has closed the connection
    def recv(self):
        try:
            msg = self.socket.recv(1024)
            if (msg == ''): return msg

            print(f"msg received: {msg}")

            header = msg.split(b'.')[0].decode('utf-8')
            payload = b''.join(msg.split(b'.')[1:])

            # Decryption
            ciphertext_len  = int(header.split(',')[0])
            tag_len         = int(header.split(',')[1])
            auth_len        = int(header.split(',')[2])
            
            print(f"ciphertext_len: {ciphertext_len}")
            print(f"tag_len: {tag_len}")
            print(f"auth_len: {auth_len}")

            ciphertext      = payload[:ciphertext_len]
            tag             = payload[ciphertext_len : ciphertext_len + tag_len]
            auth            = payload[ciphertext_len + tag_len :]

            print(f"ciphertext: {ciphertext}")
            print(f"tag: {tag}")
            print(f"auth: {auth}")

            plaintext = self.sym_decrypter.decrypt_and_verify(ciphertext, tag).decode('utf-8')
            # TODO decrypt auth, check against hash of msh
        
        # Sometimes when client closes connection, instead of recv just returning an empty message,
        #   it throws this exception. Solution... well, just return what recv SHOULD have returned (empty message)
        except ConnectionResetError:
            print(" ... unexpected ConnectionResetError")
            plaintext = ''
        except Exception as e:
            print(f"Unhandled exception in recv: {e}")
            plaintext = ''
        finally:
            return plaintext
        
    # Closes the connection
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
