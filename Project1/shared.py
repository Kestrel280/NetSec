import socket
from Crypto.Hash import SHA3_512
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Signature import pkcs1_15
from threading import Semaphore

SERVER_PORT = 10179
RSA_KEY_SIZE = 2048

# Dictionary of all connected clients, as key-value pairs of connection_name:Connection_obj
connections = {}

def sanitize_name(name):
    return name.strip().replace(',', '')

class Connection:
    # These will be set as class attributes when the user generates an RSA key
    my_priv_key = 0
    my_pub_key = 0

    def __init__(self, socket, name, ip, port, connection_pub_key, sym_key, use_sendrecv_sync = False):
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
            self.connection_pub_key = connection_pub_key
            self.sym_key = sym_key

            # If use_sendrecv_sync is True, use a Semamphore so that..
            #   only one thread can communicate with the Connection at a time
            #   (.send() will set a lock, .recv() will release the lock)
            self.lock = Semaphore(value = 1)
            self.use_sendrecv_sync = use_sendrecv_sync

            # Register this connection to the global connections object
            connections[name] = self

    # Encrypts a message and sends it
    #   Returns True if successfully sent
    #   Returns False if message could not be sent (recipient has closed connection)
    def send(self, plaintext, encutf8 = True, expect_response = True):
        # Generate the ciphertext and tag
        if (plaintext == ''): msg = ''
        else:
            # Encryption
            plaintext = plaintext.encode('utf-8') if encutf8 else plaintext
            encrypter = AES.new(self.sym_key, AES.MODE_GCM)
            ciphertext, tag = encrypter.encrypt_and_digest(plaintext)
            auth = pkcs1_15.new(self.my_priv_key).sign(SHA3_512.new(plaintext))
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
            if self.use_sendrecv_sync:
                self.lock.acquire()

            # Send the encrypted message
            self.socket.send(msg)
            
            return True
        except BrokenPipeError: # Recipient closed connection
            return False

    # (Blocking) Receives and decrypts an encrypted message
    #   If the message is empty, indicates that the recipient has closed the connection
    def recv(self, signal_lock = True):
        plaintext = '' # If we error out before plaintext can be set, just shut down
        try:
            msg = self.socket.recv(1024)
            if self.use_sendrecv_sync:
                self.lock.release()
            if (msg == b''): return ''

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

            pkcs1_15.new(self.connection_pub_key).verify(SHA3_512.new(plaintext.encode('utf-8')), auth)
        
        # Sometimes when client closes connection, instead of recv just returning an empty message,
        #   it throws this exception. Solution... well, just return what recv SHOULD have returned (empty message)
        except ConnectionResetError:
            print(" ... unexpected ConnectionResetError")
            plaintext = ''
        except Exception as e:
            print(f"Unhandled exception in recv: {e}")
            plaintext = ''
        except (ValueError, TypeError):
            print("Authentication failure! Closing connection")
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
