import socket
from Crypto.Hash import SHA3_512
from Crypto.Cipher import PKCS1_OAEP, AES

SERVER_PORT = 10179
RSA_KEY_SIZE = 2048

# Dictionary of all connected clients, as key-value pairs of connection_name:Connection_obj
connections = {}

def sanitize_name(name):
    return name.strip().replace(',', '')

class Connection:
    def __init__(self, socket, name, ip, port, pub_key, pub_crypter, priv_crypter, sym_key):
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
            self.sym_key = sym_key

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
            encrypter = AES.new(self.sym_key, AES.MODE_GCM)
            ciphertext, tag = encrypter.encrypt_and_digest(plaintext)
            auth = self.priv_crypter.encrypt(SHA3_512.new(plaintext).digest())
            nonce = encrypter.nonce
            header = "{},{},{},{}.".format(len(ciphertext), len(tag), len(auth), len(nonce)).encode('utf-8')

            # print(f"sent ciphertext_len: {len(ciphertext)}")
            # print(f"sent tag_len: {len(tag)}")
            # print(f"sent auth_len: {len(auth)}")
            # print(f"sent nonce_len: {len(nonce)}")
            # print(f"sent ciphertext: {ciphertext}")
            # print(f"sent tag: {tag}")
            # print(f"sent auth: {auth}")
            # print(f"sent nonce: {nonce}")

            msg = bytearray()
            msg += header
            msg.extend(ciphertext)
            msg.extend(tag)
            msg.extend(auth)
            msg.extend(nonce)

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

            # print(f"msg received: {msg}")

            header = msg.split(b'.')[0].decode('utf-8')
            payload = b'.'.join(msg.split(b'.')[1:])

            # Decryption
            ciphertext_len  = int(header.split(',')[0])
            tag_len         = int(header.split(',')[1])
            auth_len        = int(header.split(',')[2])
            nonce_len       = int(header.split(',')[3])
            
            # print(f"rcvd ciphertext_len: {ciphertext_len}")
            # print(f"rcvd tag_len: {tag_len}")
            # print(f"rcvd auth_len: {auth_len}")
            # print(f"rcvd nonce_len: {nonce_len}")

            ciphertext      = payload[:ciphertext_len]
            tag             = payload[ciphertext_len : ciphertext_len + tag_len]
            auth            = payload[ciphertext_len + tag_len : ciphertext_len + tag_len + auth_len]
            nonce           = payload[ciphertext_len + tag_len + auth_len :]

            # print(f"rcvd ciphertext: {ciphertext}")
            # print(f"rcvd tag: {tag}")
            # print(f"rcvd auth: {auth}")
            # print(f"rcvd nonce: {nonce}")

            decrypter = AES.new(self.sym_key, AES.MODE_GCM, nonce)
            plaintext = decrypter.decrypt_and_verify(ciphertext, tag).decode('utf-8')
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
