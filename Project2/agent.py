import argparse
import socket
import threading

# Defined constants
LISTEN_PORT = 10179

# Global variables
sjt = None      # Secret join token

# Arguments
parser = argparse.ArgumentParser()
parser.add_argument("--bootstrap", action='store_true', help="Start a new cluster as the manager", required=False)
parser.add_argument("--join", nargs=1, help="Join a cluster", type=str, required=False, metavar="{Manager IP}")
parser.add_argument("--token", nargs=1, help="Secret token required to --join a cluster", type=str, required=False, metavar="{Secret Join Token}")
parser.add_argument("--list-agents", nargs=1, help="List all worker agents on a cluster", type=str, required=False, metavar="{Manager IP}")
parser.add_argument("--deploy-service", nargs=1, help="Deploy a service to a cluster", type=str, required=False, metavar="{Manager IP}")
parser.add_argument("--path", nargs=1, help="Path to service to deploy with --deploy_service", type=str, required=False, metavar="{Path to Python file}")

###
### MANAGER Helper functions
###

def handle_new_connection(socket, addr):
    """
    (Thread function)
    Communicates with a newly connected entity to determine what they want.
    Dispatches to appropriate handler.
    """

    print(f"in handle_new_connection with socket={socket}, addr={addr}")
    return

def listen(listen_socket):
    """
    (Thread function)
    Endless loop of listening for connections and spawning a handle_connection() thread.
    Should be dispatched by start_connection_listener().
    """

    print(f"in listen() with listen_socket={listen_socket}")

    while True:
        try:
            socket, addr = listen_socket.accept()
            socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            thread = threading.Thread(target = handle_new_conection, args = (socket, addr))
            thread.start()
        except TimeoutError:
            pass

    listen_socket.close()
    print("listen() closing listen socket")

    return

def start_connection_listener():
    """
    Helper for become_manager().
    Creates a listener socket and spawns a thread running listen().
    Returns a reference to the listen() thread.
    """

    print(f"in start_connection_listener()")

    listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_socket.settimeout(3)
    listen_socket.bind(("0.0.0.0", LISTEN_PORT))
    listen_socket.listen(10)
    listener_thread = threading.Thread(target = listen, args = (listen_socket,))
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

if __name__ == '__main__':
    # Interpret arguments and dispatch to appropriate handler
    args = parser.parse_args()
    print(args)
    if args.bootstrap:
        become_manager()
    elif ((args.join is not None) and (args.token is not None)):
        sjt = args.token
        connect_to_manager(args.join)
    elif ((args.deploy_service is not None) and (args.path is not None)):
        deploy_service(args.deploy_service, args.path)
    elif (args.list_agents is not None):
        list_agents(args.list_agents)
    else:
        raise ValueError("Invalid arguments! Use 'python3 agent.py -h' to for help")

