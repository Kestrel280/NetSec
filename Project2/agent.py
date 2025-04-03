import argparse
import os
import socket
import threading
from Crypto.Hash import SHA3_512
from Crypto.Cipher import AES

# Defined constants
LISTEN_PORT = 10176
NONCE_SIZE_BYTES = 16
NBUF_SIZE = 1024

# Global variables
# sjt = None      # Secret join token
sjt = "abc123"

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

def sha3(m, enc=True):
    # Calculates SHA3-512 of m and returns hex digest
    return SHA3_512.new(m.encode('utf-8') if enc else m).hexdigest()

###
### MANAGER Helper functions
###

def handle_new_connection(sock, addr):
    """
    (Thread function)
    Communicates with a newly connected entity to determine what they want.
    Dispatches to appropriate handler.
    """
    print(f"in handle_new_connection with sock={sock}, addr={addr}")

    imsg = sock.recv(NBUF_SIZE).decode('utf-8')

    print(f"mgr received imsg = '{imsg}'")

    cmd = imsg.split(' ')[0]
    try:
        match cmd:
            case 'register':
                # Worker-Manager Connection Protocol, step 1 validation
                Na, sig = imsg.split(' ')[1:3]
                tsig = sha3(f"{cmd} {Na}{sjt}")
                assert tsig == sig
                # Step 2
                Nm = os.urandom(NONCE_SIZE_BYTES).hex()
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
        sock.send("invalid_signature".encode('utf-8'))
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

    print(f"in connect_to_manager() with mip={mip}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)    
    sock.settimeout(3)
    sock.connect((mip, LISTEN_PORT))

    print(f"worker connected to manager at ip {mip}")

    # Worker-Manager Connection Protocol (worker's side)
    Na = os.urandom(NONCE_SIZE_BYTES).hex()
    omsg = f"register {Na}"
    print(f"worker calculating sha3 of '{omsg}{sjt}'")
    sig = sha3(f"{omsg}{sjt}")
    print(f"omsg: {omsg}")
    print(f"sig: {sig}")
    sock.send(f"{omsg} {sig}".encode('utf-8'))

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

