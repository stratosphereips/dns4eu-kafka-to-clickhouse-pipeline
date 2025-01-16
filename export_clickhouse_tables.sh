#!/bin/bash

# Set variables
CONTAINER_NAME="clickhouse"
BASE_OUTPUT_DIR="analysis/data"
TABLES=("dns_data_domain_stats_V" "dns_data_client_stats_V")

# ClickHouse authentication
CLICKHOUSE_USER=""
CLICKHOUSE_PASSWORD=""

# Get the current timestamp in the format YYYYMMDD_HHMMSS
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# Create a directory named with the current timestamp inside the analysis directory
OUTPUT_DIR="${BASE_OUTPUT_DIR}/${TIMESTAMP}"
mkdir -p "${OUTPUT_DIR}"

# Run the update query to set the 'is_benign' flag for matching domains
echo "Updating 'is_benign' flag in dns_data_domain_timestamps..."
docker compose exec ${CONTAINER_NAME} bash -c \
  "clickhouse-client --user=${CLICKHOUSE_USER} --password=${CLICKHOUSE_PASSWORD} --query=\"ALTER TABLE default.dns_data_domain_timestamps UPDATE is_benign = 1 WHERE domain IN (SELECT domain FROM default.benign_domains);\""

# Loop through each table and export it
for TABLE_NAME in "${TABLES[@]}"; do
  TMP_FILE="/tmp/${TABLE_NAME}_${TIMESTAMP}.csv"
  LOCAL_FILE="${OUTPUT_DIR}/${TABLE_NAME}_${TIMESTAMP}.csv"

  echo "Exporting table: ${TABLE_NAME}..."

  # Run ClickHouse query and export to a temporary file inside the container
  docker compose exec ${CONTAINER_NAME} bash -c \
    "clickhouse-client --user=${CLICKHOUSE_USER} --password=${CLICKHOUSE_PASSWORD} --query=\"SELECT * FROM default.${TABLE_NAME} FORMAT CSVWithNames\" > ${TMP_FILE}"

  # Copy the CSV file from the container to the local system
  docker compose cp "${CONTAINER_NAME}:${TMP_FILE}" "${LOCAL_FILE}"

  # Remove the temporary file from the container
  docker compose exec ${CONTAINER_NAME} bash -c "rm ${TMP_FILE}"

  echo "Table ${TABLE_NAME} exported successfully to ${LOCAL_FILE}"
done

echo "All tables have been exported"
