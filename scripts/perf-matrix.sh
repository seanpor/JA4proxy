#!/usr/bin/env bash
set -euo pipefail
OUT_MD=docs/reports/PERFORMANCE_MATRIX.md
OUT_JSON=docs/reports/PERFORMANCE_MATRIX.json
BIN=./bin/ja4p
mkdir -p docs/reports
printf "1\nja4perf\n0\n" | $BIN init
make start-poc
sleep 15
echo "{" > $OUT_JSON
run_scenario() {
    local gr=$2 br=$3 dur=$4 dial=$5
    $BIN management dial set $dial --url http://localhost:8090 --token bench-token-123 --confirm > /dev/null 2>&1 || true
    $BIN test benchmark --host 127.0.0.1:8081 --good-rate $gr --bad-rate $br --duration $dur --workers 64 --output json > tmp_res.json
    cat tmp_res.json
}
echo "  \"A\": " >> $OUT_JSON
run_scenario "A" 2000 0 20 0 >> $OUT_JSON
echo "," >> $OUT_JSON
echo "  \"B\": " >> $OUT_JSON
run_scenario "B" 1000 0 20 100 >> $OUT_JSON
echo "}" >> $OUT_JSON
make stop
