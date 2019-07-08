#!/bin/bash
PORT=$1
VOLUME=NODERED_SPACE
sudo docker run -it -p 8088:8088 --name exentriq-advanced-analytics exentriq/exentriq-advanced-analytics
