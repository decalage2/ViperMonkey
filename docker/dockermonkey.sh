#!/bin/bash

if [[ $1 == "-h" || $# -eq 0 ]]; then
   echo "Usage: dockermonkey.sh FILE [JSON_FILE] [-i ENTRY]"
   echo "FILE is the VBA/VBScript file to analyze."
   echo "If JSON_FILE is given JSON analysis results will be saved in JSON_FILE."
   echo "If '-i ENTRY' is given emulation will start with VBA/VBScript function ENTRY."
   exit
fi
   
if [ "$(uname)" == "Darwin" ]; then
        echo "[*] User running on a Mac"
        if [ "$(docker-machine status)" == "Stopped" ]; then
                echo "[*] 'docker-machine' is Stopped. Starting it and instantiating the environment."
                docker-machine start
                docker-machine env
                eval $(docker-machine env)
        fi
fi

echo "[*] Running 'docker ps' to see if script has required privileges to run..."
docker ps

if [ $? -ne 0 ]; then
	echo "[!] 'docker ps' failed to run - you may not have the privileges to run docker. Try using sudo."
	exit
fi

if [[ $(docker ps -f status=running -f ancestor=haroldogden/vipermonkey -l | tail -n +2) ]]; then
        echo "[+] Other ViperMonkey containers are running!"
fi

echo "[*] Pulling and starting container..."
docker pull haroldogden/vipermonkey:latest
docker_id=$(docker run --rm -d -t haroldogden/vipermonkey:latest)

echo "[*] Attempting to copy file $1 into container ID $docker_id"

file_basename=$(basename "$1")

echo "[*] Starting openoffice listener for file content conversions..."

docker exec $docker_id sh -c '/usr/lib/libreoffice/program/soffice.bin --headless --invisible --nocrashreport --nodefault --nofirststartwizard --nologo --norestore --accept="socket,host=127.0.0.1,port=2002,tcpNoDelay=1;urp;StarOffice.ComponentContext" &'

echo "[*] Checking for ViperMonkey and dependency updates..."

docker exec $docker_id sh -c "cd /opt;for d in *; do cd \$d; git pull > /dev/null 2>&1; cd /opt; done"

echo "[*] Disabling network connection for container ID $docker_id"
docker network disconnect bridge $docker_id

docker cp "$1" "$docker_id:/root/$file_basename"

# Figure out arguments.
entry=""
json=""
json_file=""

# Entry point with no JSON file?
if [[ $# -ge 3 && $2 == "-i" ]]; then
    entry="-i $3"
elif [ $# -eq 2 ]; then
    # Just JSON file.
    json="-o /root/report.json"
    json_file=$2
fi

# JSON file with entry point?
if [[ $# -ge 4 && $3 == "-i" ]]; then
    entry="-i $4"
    json="-o /root/report.json"
    json_file=$2
fi

# Run ViperMonkey in the docker container.
docker exec $docker_id sh -c "/opt/ViperMonkey/vipermonkey/vmonkey.py -s --ioc --jit '/root/$file_basename' $json $entry"

# Copy out the JSON analysis report if needed.
if [ "$json_file" != "" ]; then
    docker cp "$docker_id:/root/report.json" "$json_file"
fi

# Zip up dropped files if there are any.
docker exec $docker_id sh -c "touch /root/test.zip ; [ -d \"/root/${file_basename}_artifacts/\" ] && zip -r --password=infected - /root/${file_basename}_artifacts/ > /root/test.zip"
docker cp "$docker_id:/root/test.zip" test.zip
if [ ! -s test.zip ]; then rm test.zip; else mv test.zip ${file_basename}_artifacts.zip; echo "[*] Dropped files are in ${file_basename}_artifacts.zip"; fi

echo "[*] Done - Killing docker container $docker_id"
docker stop $docker_id > /dev/null
