import argparse

# Arguments
parser = argparse.ArgumentParser()
parser.add_argument("--bootstrap", action='store_true', help="Start a new cluster as the manager", required=False)
parser.add_argument("--join", nargs=1, help="Join a cluster", type=str, required=False, metavar="{Manager IP}")
parser.add_argument("--token", nargs=1, help="Secret token required to --join a cluster", type=str, required=False, metavar="{Secret Join Token}")
parser.add_argument("--list-agents", nargs=1, help="List all worker agents on a cluster", type=str, required=False, metavar="{Manager IP}")
parser.add_argument("--deploy-service", action='store_true', help="Flag to deploy service specified by --path", required=False)
parser.add_argument("--path", nargs=1, help="Path to service to deploy with --deploy_service", type=str, required=False, metavar="{Path to Python file}")

if __name__ == '__main__':
    args = parser.parse_args()
    print(args)
