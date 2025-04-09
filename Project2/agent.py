import argparse
import numpy as np
import os
import socket
import threading
import time

from utils import * # sha3(), gcd(), fme(), mmi(), is_prime()

# Defined constants
PRINT_DEBUG         = True
PRINT_MSGS          = False
PRINT_REGISTRATION  = True
PRINT_REG_LISTS     = False  # When a new node/nonce is registered, print the full list
LISTEN_PORT = 10179
NONCE_SIZE_BYTES = 16
HEARTBEAT_INTERVAL = 5
fmt_mgr = "mgr    "

#RFC 3526: 4096-bit mod-p group
DH_G = 2
DH_P = int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF", 16)

# Global variables
# sjt = None              # Secret join token
sjt = "abc123"
wid = 1                 # running id counter for newly connected workers
used_nonces = set()     # Set of used nonces
network_nodes = {}      # List of Nodes on the cluster, connected or not
mgr = None              # For manager, this is None; for all other connections, this will be a Node object for the mgr

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

def broadcast_msg(msg):
    for node in network_nodes.values():
        try:
            node.secure_send(msg)
        except Exception: continue # If something fails, we don't want to handle it here -- there's a thread dedicated to the connection that should handle it

def register_nonce(n):
    if n in used_nonces:
        raise KeyError("tried to register a used nonce")
    else:
        used_nonces.add(n)
def register_node(n):
    if n in network_nodes:
        raise KeyError("tried to register a node whose id is already taken")
    else:
        network_nodes[n.nid] = n

def deregister_node(nid):
    if nid in network_nodes:
        del network_nodes[nid]

def heartbeat_loop(node):
    # thread function
    try:
        node.secure_send("heartbeat")
    except OSError: # connection to node closed -- shut down
        return
    time.sleep(HEARTBEAT_INTERVAL)
    heartbeat_loop(node)

###
### MANAGER Helper functions
###

def handle_worker(sock, addr, init_msg):
    # First, WMCP; then, enter message loop

    # --- Worker-Manager Connection Protocol --- 

    # create unique id for this worker
    global wid
    twid = wid
    wid += 1

    # Keep a list of things to do if we need to terminate connection
    _cleanup = [lambda: sock.close()] # On cleanup, will need to close socket

    try:
        # -- Step 1: Worker has sent a nonce: check it's a unique nonce, and that they signed using the SJT
        cmd, Na, isig = init_msg.split(' ')
        register_nonce(Na)
        broadcast_msg(f"nonce_used {Na}")
        tsig = sha3(f"{cmd} {Na}{sjt}")
        assert tsig == isig

        # -- Step 2: Generate a nonce and DH parameter, and send to worker
        
        Nm = os.urandom(NONCE_SIZE_BYTES).hex()     # Generate my nonce
        broadcast_msg(f"nonce_used {Nm}")
        if PRINT_DEBUG: print(f"{fmt_mgr} generated nonce Nm = {Nm[:10]}... for wid {twid:5}")
        register_nonce(Nm)
        x = random.randint(2**1024, 2**4095)        # Generate my Diffie-Hellman parameter
        gxmodp = fme(DH_G, x, DH_P)
        omsg = f"{twid} {Nm} {gxmodp:x}" # [id, Nm (hex), g^x mod p (hex)]
        osig = sha3(f"{omsg}{sjt}")
        sock.send(f"{omsg} {osig}".encode('utf-8'))

        node = Node(twid, addr[0])
        broadcast_msg(f"worker_connected {twid} {addr[0]}")
        _cleanup.append(lambda: broadcast_msg(f"worker_disconnected {twid}")) # On cleanup, will need to broadcast disconnected msg
        register_node(node)
        _cleanup.append(lambda: deregister_node(twid)) # On cleanup, need to deregister this node

        # Step 3: Worker sends their DH half
        imsg = sock.recv(NBUF_SIZE).decode('utf-8')
        gymodp, isig = imsg.split(' ')
        tsig = sha3(f"{gymodp}{sjt}")
        assert tsig == isig

        # Step 4: Generate key, send NONCE_USED and WORKER_CONNECTED msgs for all connected workers
        Kp = fme(int(gymodp, 16), x, DH_P)
        K = sha3(f"{Kp} {Na} {Nm}")[:32]
        if PRINT_DEBUG: print(f"{fmt_mgr} established secret key K = {K[:10]}... for {twid}")

        node.connect(sock, K.encode('utf-8'), threading.get_ident())

        # Send all used nonces except Na and Nm, since worker already registered those
        for _nonce in (used_nonces ^ {Na, Nm}):
            node.secure_send(f"nonce_used {_nonce}")
        for _node in network_nodes.values():
            node.secure_send(f"worker_connected {_node.nid} {_node.ip}")

        # Start sending heartbeats
        hbthread = threading.Thread(target = heartbeat_loop, args = (node,))
        hbthread.start()

        # --- Message Loop ---
        imsg = node.secure_recv()
        while imsg != '':
            if PRINT_MSGS: print(f"{fmt_mgr} received msg '{imsg}' from worker {twid}")
            tokens = imsg.split(' ')
            while tokens:
                cmd = tokens.pop(0)
                match cmd:
                    case 'heartbeat':
                        node.time_last_heartbeat = time.time()
                    case 'job_finished': 
                        node.busy = False
                    # TODO case for shutdown
            imsg = node.secure_recv()
    except Exception as e:
        print(f"{fmt_mgr} with worker {node.nid:5} encountered exception {e}")
    finally:
        print(f"{fmt_mgr} closing connection to worker {node.nid:5}")
        for fn in _cleanup:
            try: fn()
            except Exception as e: print(f"{fmt_mgr} encountered exception during cleanup of worker {twid}: {e}")

def handle_new_connection(sock, addr):
    """
    (Thread function)
    Communicates with a newly connected entity to determine what they want.
    Dispatches to appropriate handler.
    """
    imsg = sock.recv(NBUF_SIZE).decode('utf-8')

    if PRINT_MSGS: print(f"{fmt_mgr} connection listener received initial message '{imsg}'")
    cmd = imsg.split(' ')[0]
    try:
        match cmd:
            case 'register':
                handle_worker(sock, addr, imsg)
            case 'list_agents':
                # TODO do Cluster Services Connection Protocol
                # TODO return list of workers
                pass
            case 'deploy_services':
                # TODO do Cluster Services Connection Protocol
                # TODO deploy service
                pass
    except AssertionError: # Assertion while checking signature during DH key exchange for proof of SJT
        print("worker provided invalid signature, terminating their connection request")
        sock.close()
    except KeyError as e:
        print(f"failed to register a connection: {e}")
        sock.close()

    return

def listen(listen_sock):
    """
    (Thread function)
    Endless loop of listening for connections and spawning a handle_connection() thread.
    Should be dispatched by start_connection_listener().
    """
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
    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_sock.settimeout(HEARTBEAT_INTERVAL * 3.5)
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
    if (sjt is None):
        # TODO generate sjt
        pass

    start_connection_listener()
    if PRINT_DEBUG: print(f"{fmt_mgr} started connection listener")

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
    twid = -1
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)    
    sock.settimeout(HEARTBEAT_INTERVAL * 3.5)

    # Keep a list of things to do if we need to terminate connection
    _cleanup = []

    # --- Worker-Manager Connection Protocol ---
    try:
        sock.connect((mip, LISTEN_PORT))
        _cleanup.append(lambda: sock.close()) # On cleanup, will need to close socket

        # Step 1: generate a nonce and send a connection request to manager, signed using SJT
        Na = os.urandom(NONCE_SIZE_BYTES).hex()
        if PRINT_DEBUG: print(f"w {twid:5} generated nonce Na = {Na[:10]}...")
        register_nonce(Na)
        omsg = f"register {Na}"
        osig = sha3(f"{omsg}{sjt}")
        sock.send(f"{omsg} {osig}".encode('utf-8'))

        # Manager sends back step 2
        imsg = sock.recv(NBUF_SIZE).decode('utf-8')
        twid, Nm, gxmodp, isig = imsg.split(' ')
        register_nonce(Nm)
        tsig = sha3(f"{twid} {Nm} {gxmodp}{sjt}")
        assert tsig == isig

        # Step 3: send mgr my DH half
        y = random.randint(2**1024, 2**4095) # Generate my Diffie-Hellman parameter
        gymodp = fme(DH_G, y, DH_P)
        omsg = f"{gymodp:x}"
        osig = sha3(f"{omsg}{sjt}")
        sock.send(f"{omsg} {osig}".encode('utf-8'))

        # Step 4: Generate key, send status
        Kp = fme(int(gxmodp, 16), y, DH_P)
        K = sha3(f"{Kp} {Na} {Nm}")[:32].encode('utf-8')
        if PRINT_DEBUG: print(f"w {twid:5} generated nonce Na = {Na[:10]}...")

        mgr = Node(0, mip)
        mgr.connect(sock, K, threading.get_ident())

        # Start sending heartbeats
        hbthread = threading.Thread(target = heartbeat_loop, args = (mgr,))
        hbthread.start()

        # --- Message Loop ---
        imsg = mgr.secure_recv()
        while imsg != '':
            if PRINT_MSGS: print(f"w {twid:5} received msg '{imsg}'")
            tokens = imsg.split(' ')
            while tokens:
                cmd = tokens.pop(0)
                match cmd:
                    case 'heartbeat':
                        mgr.time_last_heartbeat = time.time()
                    case 'worker_connected':
                        _wid = tokens.pop(0)
                        _ip = tokens.pop(0)
                        new_node = Node(_wid, _ip)
                        if ((_wid != twid) and (_wid not in network_nodes)):
                            register_node(new_node)
                            if PRINT_REGISTRATION: print(f"w {twid:5} got instruction to register new node {_wid} @ {_ip}")
                            if PRINT_REG_LISTS: print(f"w {twid:5} network_nodes: {network_nodes}")
                    case 'worker_disconnected':
                        _node_id = tokens.pop(0)
                        deregister_node(_node_id)
                        if PRINT_REGISTRATION: print(f"w {twid:5} got instruction to deregister node {_wid}")
                        if PRINT_REG_LISTS: print(f"w {twid:5} network_nodes: {network_nodes}")
                    case 'nonce_used':
                        _nonce = tokens.pop(0)
                        register_nonce(_nonce)
                        if PRINT_REGISTRATION: print(f"w {twid:5} got instruction to register nonce {_nonce[:10]}...")
                        if PRINT_REG_LISTS: print(f"w {twid:5} used_nonces: {used_nonces}")
                    # TODO case for shutdown
                    # TODO case for do_job

            imsg = mgr.secure_recv()

    except AssertionError:
        print("w {twid:5} provided invalid signature, terminating connection")
    except Exception as e:
        print(f"w {twid:5} encountered exception {e}")
    finally:
        print(f"w {twid:5} closing connection to manager")
        for fn in _cleanup:
            try: fn()
            except Exception as e: print(f"w {twid} encountered exception during cleanup: {e}")
        # TODO heartbeat protocol case (2)

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

