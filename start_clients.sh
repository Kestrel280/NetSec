if [[ "$#" -ne 2 ]]; then
	echo "Usage: start_clients.sh [server_ip] [num_clients]"
	exit
fi

server_ip=$1
num_clients=$2

for i in $(seq 1 $num_clients);
do
	python3 client.py --network $server_ip --name Client$i &
done

echo "Clients started"
