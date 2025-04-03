import argparse
import os
import socket
import threading
from Crypto.Cipher import AES

from utils import * # sha3(), gcd(), fme(), mmi(), is_prime()

# Defined constants
LISTEN_PORT = 10176
NONCE_SIZE_BYTES = 16
NBUF_SIZE = 4096        # Buffer size in bytes for socket.recv() calls; DH sends 4096-bit numbers using base16 repr = 1024 chars, so should be at least 2x that

#RFC 3526: 4096-bit mod-p group
DH_G = 2
DH_P = int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF", 16)

# Global variables
# sjt = None      # Secret join token
sjt = "abc123"
wid = 1         # id to assign to next connected worker

# Arguments
parser = argparse.ArgumentParser()
parser.add_argument("--bootstrap", action='store_true', help="Start a new cluster as the manager", required=False)
parser.add_argument("--join", nargs=1, help="Join a cluster", type=str, required=False, metavar="{Manager IP}")
parser.add_argument("--token", nargs=1, help="Secret token required to --join a cluster", type=str, required=False, metavar="{Secret Join Token}")
parser.add_argument("--list-agents", nargs=1, help="List all worker agents on a cluster", type=str, required=False, metavar="{Manager IP}")
parser.add_argument("--deploy-service", nargs=1, help="Deploy a service to a cluster", type=str, required=False, metavar="{Manager IP}")
parser.add_argument("--path", nargs=1, help="Path to service to deploy with --deploy_service", type=str, required=False, metavar="{Path to Python file}")

###
### MISC Helper functions
###

#

###
### MANAGER Helper functions
###

def handle_new_connection(sock, addr):
    """
    (Thread function)
    Communicates with a newly connected entity to determine what they want.
    Dispatches to appropriate handler.
    """
    print(f"M: in handle_new_connection with sock={sock}, addr={addr}")

    imsg = sock.recv(NBUF_SIZE).decode('utf-8')

    print(f"M: received imsg = '{imsg}'")
    cmd = imsg.split(' ')[0]
    try:
        match cmd:
            case 'register':
                # --- Worker-Manager Connection Protocol --- 
                # Worker has sent step 1: check it's a unique nonce, and that they signed using the SJT
                Na, isig = imsg.split(' ')[1:3]
                # TODO add this nonce to used nonce list
                # TODO check if this nonce has already been used
                tsig = sha3(f"{cmd} {Na}{sjt}")
                assert tsig == isig

                # Step 2: Generate a nonce and DH parameter, and send to worker
                Nm = os.urandom(NONCE_SIZE_BYTES).hex()
                # TODO add this nonce to used nonce list
                x = random.randint(2**1024, 2**4095) # Generate my Diffie-Hellman parameter
                gxmodp = fme(DH_G, x, DH_P)

                omsg = f"{wid} {Nm} {gxmodp:x}" # [id, Nm (hex), g^x mod p (hex)]
                osig = sha3(f"{omsg}{sjt}")
                sock.send(f"{omsg} {osig}".encode('utf-8'))

            case 'list_agents':
                # TODO do Cluster Services Connection Protocol
                # TODO return list of workers
                pass
            case 'deploy_services':
                # TODO do Cluster Services Connection Protocol
                # TODO deploy service
                pass
    except AssertionError:
        print("worker provided invalid signature, terminating their connection request")
        sock.close()

    return

def listen(listen_sock):
    """
    (Thread function)
    Endless loop of listening for connections and spawning a handle_connection() thread.
    Should be dispatched by start_connection_listener().
    """

    print(f"in listen() with listen_sock={listen_sock}")

    while True:
        try:
            sock, addr = listen_sock.accept()
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            thread = threading.Thread(target = handle_new_connection, args = (sock, addr))
            thread.start()
        except TimeoutError:
            pass

    listen_sock.close()
    print("listen() closing listen socket")

    return

def start_connection_listener():
    """
    Helper for become_manager().
    Creates a listener socket and spawns a thread running listen().
    Returns a reference to the listen() thread.
    """

    print(f"in start_connection_listener()")

    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_sock.settimeout(3)
    listen_sock.bind(("0.0.0.0", LISTEN_PORT))
    listen_sock.listen(10)
    listener_thread = threading.Thread(target = listen, args = (listen_sock,))
    listener_thread.start()

    return listener_thread

###
### WORKER Helper functions
###

#

###
### Major functions (called from script's top level)
###

def become_manager():
    """
    Starts a new cluster as its manager.

    1. If we don't yet have a sjt (e.g. we are the bootstrapper), generate one
    2. Start a socket listening on port LISTEN_PORT in its own thread
    3. Whenever a new connection is received, start a new thread to handle communications with the worker/user

    Args:
        cjst (str): Optional -- Secret Join Token to use for cluster; if not provided, one will be generated and printed

    Returns:
        Nothing (for now)
    """

    print(f"in become_manager()")

    if (sjt is None):
        # TODO generate sjt
        pass

    start_connection_listener()
    print("Manager started listening for new connections")

    return

def connect_to_manager(mip):
    """
    Attempt to join a cluster as a worker.

    1. Connect to the cluster using the "Worker-Manager Connection Protocol"
    2. Enter message loop with manager

    Args:
        mip (str): IP of cluster manager

    Returns:
        Nothing (for now)
    """

    print(f"W: in connect_to_manager() with mip={mip}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)    
    sock.settimeout(3)
    sock.connect((mip, LISTEN_PORT))

    print(f"W: worker connected to manager at ip {mip}")
    # --- Worker-Manager Connection Protocol ---
    try:
        # Step 1: generate a nonce and send a connection request to manager, signed using SJT
        Na = os.urandom(NONCE_SIZE_BYTES).hex()
        # TODO add this nonce to used nonce list
        omsg = f"register {Na}"
        osig = sha3(f"{omsg}{sjt}")
        sock.send(f"{omsg} {osig}".encode('utf-8'))

        # Manager sends back step 2
        imsg = sock.recv(NBUF_SIZE).decode('utf-8')
        print(f"W: received imsg = '{imsg}'")
        wid, Nm, gxmodp, isig = imsg.split(' ')
        # TODO add this nonce to used nonce list
        tsig = sha3(f"{wid} {Nm} {gxmodp}{sjt}")
        assert tsig == isig
    except AssertionError:
        print("W: manager provided invalid signature, terminating connection request")
        sock.close()

    return

def deploy_service(mip, service_path):
    """
    Deploys a service to a cluster.

    1. Load the Python file at service_path into a byte buffer
    2. Connect to the cluster using "Cluster Services Connection Protocol"
    3. Send a "deploy_service {number of bytes}" message to manager
    4. Await "ok" message
    5. Send byte buffer
    6. Await "ok" message
    7. Disconnect from cluster

    Args:
        mip (str): IP of cluster manager
        service_path(str): Path to service to deploy (Python file)

    Returns:
        Nothing (for now)
    """

    print(f"in deploy_service() with mip={mip}, service_path={service_path}")

    return

def list_agents(mip):
    """
    Lists all worker agents on a cluster.

    1. Connect to the cluster using "Cluster Services Connection Protocol"
    2. Send a "list_agents" message to manager
    3. Await and print response
    4. Disconnect from cluster

    Args:
        mip (str): IP of cluster manager

    Returns:
        Nothing (for now)

    """

    print(f"in list_agents with mip={mip}")

    return

if __name__ == '__main__':
    # Interpret arguments and dispatch to appropriate handler
    args = parser.parse_args()
    print(args)
    if args.bootstrap:
        become_manager()
    elif ((args.join is not None) and (args.token is not None)):
        # sjt = args.token[0] TODO uncomment when we're actually setting an sjt
        connect_to_manager(args.join[0])
    elif ((args.deploy_service is not None) and (args.path is not None)):
        deploy_service(args.deploy_service[0], args.path[0])
    elif (args.list_agents is not None):
        list_agents(args.list_agents[0])
    else:
        raise ValueError("Invalid arguments! Use 'python3 agent.py -h' to for help")

