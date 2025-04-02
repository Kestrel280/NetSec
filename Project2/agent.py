import argparse

# Arguments
parser = argparse.ArgumentParser()
parser.add_argument("--bootstrap", action='store_true', help="Start a new cluster as the manager", required=False)
parser.add_argument("--join", nargs=1, help="Join a cluster", type=str, required=False, metavar="{Manager IP}")
parser.add_argument("--token", nargs=1, help="Secret token required to --join a cluster", type=str, required=False, metavar="{Secret Join Token}")
parser.add_argument("--list-agents", nargs=1, help="List all worker agents on a cluster", type=str, required=False, metavar="{Manager IP}")
parser.add_argument("--deploy-service", nargs=1, help="Deploy a service to a cluster", type=str, required=False, metavar="{Manager IP}")
parser.add_argument("--path", nargs=1, help="Path to service to deploy with --deploy_service", type=str, required=False, metavar="{Path to Python file}")

def become_manager(csjt=None):
    """
    Starts a new cluster as its manager.

    1. If no csjt was provided, generate a Secret Join Token
    2. Start a socket listening on port LISTEN_PORT in its own thread
    3. Whenever a new connection is received, start a new thread to handle communications with the worker/user

    Args:
        cjst (str): Optional -- Secret Join Token to use for cluster; if not provided, one will be generated and printed

    Returns:
        Nothing (for now)
    """
    print(f"in become_manager() with csjt={csjt}")

def connect_to_manager(mip, csjt):
    """
    Attempt to join a cluster as a worker.

    1. Connect to the cluster using the "Worker-Manager Connection Protocol"
    2. Enter message loop with manager

    Args:
        mip (str): IP of cluster manager
        csjt (str): Secret Join Token provided by cluster bootstrapper

    Returns:
        Nothing (for now)
    """

    print(f"in connect_to_manager() with mip={mip}, csjt={csjt}")

def deploy_service(mip, service_path):
    """
    Deploys a service to a cluster.

    1. Load the Python file at service_path into a byte buffer
    2. Connect to the cluster using "Cluster Services Connection Protocol"
    3. Send a "deploy_service {number of bytes}" message to manager
    4. Await "go_ahead" message
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
        connect_to_manager(args.join, args.token)
    elif ((args.deploy_service is not None) and (args.path is not None)):
        deploy_service(args.deploy_service, args.path)
    elif (args.list_agents is not None):
        list_agents(args.list_agents)
    else:
        raise ValueError("Invalid arguments! Use 'python3 agent.py -h' to for help")

