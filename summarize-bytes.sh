#!/bin/bash
bytes_value=$(cat measurements.csv | awk -F ',' '{print $2}' | awk '{s+=$1} END {print s}')
tib_value=$(echo "scale=2; $bytes_value / (1024 * 1024 * 1024 * 1024)" | bc)
echo "So far: $bytes_value bytes ($tib_value TiB)"

