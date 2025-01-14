import os
import json
import logging
import signal
import sys
from datetime import datetime
from kafka import KafkaConsumer
from clickhouse_driver import Client
from tenacity import retry, stop_after_attempt, wait_fixed

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Kafka and ClickHouse configurations from environment variables
kafka_broker = os.getenv('KAFKA_BROKER', '')
topic = os.getenv('KAFKA_TOPIC', '')
consumer_group = os.getenv('KAFKA_CONSUMER_GROUP', '')

clickhouse_host = os.getenv('CLICKHOUSE_HOST')
clickhouse_port = int(os.getenv('CLICKHOUSE_PORT'))
clickhouse_user = os.getenv('CLICKHOUSE_USER')
clickhouse_password = os.getenv('CLICKHOUSE_PASSWORD')
batch_size = int(os.getenv('BATCH_SIZE'))
max_dns_data_size = int(os.getenv('MAX_DNS_DATA_SIZE'))

# Set the RAM limit to 24 GB (24 * 1024 * 1024 * 1024 bytes)
RAM_LIMIT = 24 * 1024 * 1024 * 1024

# Initialize ClickHouse client
clickhouse_client = Client(
    host=clickhouse_host,
    port=clickhouse_port,
    user=clickhouse_user,
    password=clickhouse_password
)

# SSL paths for mTLS
ssl_cafile = 'ca.crt'
ssl_certfile = 'tls.crt'
ssl_keyfile = 'tls.key'

# Kafka consumer
consumer = KafkaConsumer(
    topic,
    bootstrap_servers=kafka_broker,
    security_protocol="SSL",
    ssl_cafile=ssl_cafile,
    ssl_certfile=ssl_certfile,
    ssl_keyfile=ssl_keyfile,
    auto_offset_reset='earliest',
    enable_auto_commit=False,
    group_id=consumer_group,
)

logger.info(f"Started consuming messages from Kafka topic: {topic}")

# Graceful shutdown handler
def signal_handler(signal, frame):
    logger.info("Graceful shutdown initiated...")
    consumer.close()
    clickhouse_client.disconnect()
    sys.exit(0)

signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)

# Function to set the RAM limit for the session
def set_ram_limit():
    # Set the maximum memory usage to 24 GB
    clickhouse_client.execute(f"SET max_memory_usage = {RAM_LIMIT}")
    logger.info(f"RAM limit set to 24 GB.")

# Function to check the size of the dns_data table
def check_table_size():
    result = clickhouse_client.execute("""
        SELECT sum(bytes) FROM system.parts
        WHERE database = 'default' AND table = 'dns_data'
    """)
    size_in_gb = result[0][0] / (1024 ** 3)  # Convert bytes to gigabytes
    if size_in_gb >= max_dns_data_size:
        logger.info(f'Size of dns_data table is over {max_dns_data_size} Gb')
        return True
    return False

# Function to update benign domains flag
def update_benign_domains():
    update_query = '''
        ALTER TABLE default.dns_data_domain_timestamps
        UPDATE is_benign = 1
        WHERE domain IN (SELECT domain FROM default.benign_domains);
    '''
    clickhouse_client.execute(update_query)
    logger.info("Updated is_benign flag for domains in the benign_domains table.")

# Function to transfer and merge data into dns_data_domain_timestamps
def transfer_and_merge_domain_data():

    truncate_tmp_query = 'TRUNCATE TABLE dns_data_domain_timestamps_tmp;'

    insert_query = '''
        INSERT INTO dns_data_domain_timestamps_tmp (domain, timestamps, answer_ips)
        SELECT
            domain,
            arrayFlatten(groupArray(timestamps)),
            arrayDistinct(arrayFlatten(groupArray(answer_ips)))
        FROM (
            SELECT domain, timestamps, answer_ips FROM dns_data_domain_timestamps
            UNION ALL
            SELECT 
                domain_l2 AS domain, 
                groupArray(timestamp) AS timestamps,
                groupUniqArray(answer_ip) AS answer_ips
            FROM dns_data_tmp
            GROUP BY domain_l2
        )
        GROUP BY domain;
    '''

    truncate_query = 'TRUNCATE TABLE dns_data_domain_timestamps;'

    move_from_tmp_query = '''
        INSERT INTO dns_data_domain_timestamps
        SELECT * FROM dns_data_domain_timestamps_tmp;
    '''


    # Ensure the temporary table is clean
    clickhouse_client.execute(truncate_tmp_query)

    # Insert data into the temporary table
    clickhouse_client.execute(insert_query)
    
    # Move data back to the original table
    clickhouse_client.execute(truncate_query)
    clickhouse_client.execute(move_from_tmp_query)

    logger.info("Data transferred and merged into dns_data_domain_timestamps successfully.")


# Function to transfer and merge client request data into dns_data_client_requests
def transfer_and_merge_client_data():

    truncate_tmp_query = 'TRUNCATE TABLE dns_data_client_requests_tmp;'

    insert_query = '''
        INSERT INTO dns_data_client_requests_tmp (client_ip, domains, timestamps)
        SELECT
            client_ip,
            arrayFlatten(groupArray(domains)),
            arrayFlatten(groupArray(timestamps))
        FROM (
            SELECT client_ip, domains, timestamps FROM dns_data_client_requests
            UNION ALL
            SELECT 
                client_ip, 
                groupArray(domain_l2) AS domains, 
                groupArray(timestamp) AS timestamps
            FROM dns_data_tmp
            GROUP BY client_ip
        )
        GROUP BY client_ip;
    '''
    
    truncate_query = 'TRUNCATE TABLE dns_data_client_requests;'

    move_from_tmp_query = '''
        INSERT INTO dns_data_client_requests
        SELECT * FROM dns_data_client_requests_tmp;
    '''
    

    # Ensure the temporary table is clean
    clickhouse_client.execute(truncate_tmp_query)

    # Insert data into the temporary table
    clickhouse_client.execute(insert_query)
    
    # Move data back to the original table
    clickhouse_client.execute(truncate_query)
    clickhouse_client.execute(move_from_tmp_query)
    
    logger.info("Client request data transferred and merged into dns_data_client_requests successfully.")


# Function to clean the dns_data table
def clean_dns_data():
    clickhouse_client.execute("TRUNCATE TABLE dns_data")
    logger.info("dns_data table cleaned successfully.")


# Function to process and insert messages into ClickHouse
@retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
def process_messages(messages):

    insert_to_prod_query = '''
    INSERT INTO dns_data (answer, answer_ip, asn_number, asn_org, client_ip,
                        domain_l1, domain_l2, domain_rest, geoip_longitude, geoip_latitude, 
                        geoip_country_code2, query, query_type,
                        region_name, resolver_id, timestamp, ttl)
    VALUES
    '''

    truncate_tmp_query = 'TRUNCATE TABLE dns_data_tmp;'

    insert_to_tmp_query = '''
    INSERT INTO dns_data_tmp (answer, answer_ip, asn_number, asn_org, client_ip,
                        domain_l1, domain_l2, domain_rest, geoip_longitude, geoip_latitude, 
                        geoip_country_code2, query, query_type,
                        region_name, resolver_id, timestamp, ttl)
    VALUES
    '''

    data_batch = []
    for message in messages:
        try:
            if isinstance(message.value, bytes):
                data = json.loads(message.value.decode('utf-8'))
            else:
                logger.error(f"Unexpected message format: {message.value}")
                continue
            
            # Split geoip_coordinates into latitude and longitude
            geoip_coordinates = data.get('geoip_coordinates', '')
            geoip_longitude, geoip_latitude = '', ''
            if geoip_coordinates:
                lon_str, lat_str = map(str.strip, geoip_coordinates.split(','))
                geoip_longitude = lon_str
                geoip_latitude = lat_str

            timestamp_dt = datetime.fromisoformat(data['timestamp'].replace("Z", "+00:00"))
            
            values = (
                str(data.get('answer', '')),
                str(data.get('answer_ip', '')),
                str(data.get('asn_number', '')),
                f'"{data.get("asn_org", "")}"',
                str(data.get('client_ip', '')),
                str(data.get('domain_l1', '')),
                str(data.get('domain_l2', '')),
                str(data.get('domain_rest', '')),
                geoip_longitude,
                geoip_latitude,
                str(data.get('geoip_country_code2', '')),
                str(data.get('query', '')),
                str(data.get('query_type', '')),
                str(data.get('region_name', '')),
                str(data.get('resolver_id', '')),
                timestamp_dt,
                str(data.get('ttl', ''))
            )

            if len(values) == 17:
                data_batch.append(values)
            else:
                logger.error(f"Incorrect number of values: expected 17, got {len(values)}")

        except json.JSONDecodeError as e:
            logger.error(f"Failed to decode message: {message.value}. Error: {e}")
    
    if data_batch:
        clickhouse_client.execute(insert_to_prod_query, data_batch)
        clickhouse_client.execute(truncate_tmp_query)
        clickhouse_client.execute(insert_to_tmp_query, data_batch)
        logger.info(f"Inserted {len(data_batch)} messages into ClickHouse")


set_ram_limit()

# Consume messages and process
message_batch = []
try:
    for message in consumer:
        if check_table_size():
            clean_dns_data()
            

        message_batch.append(message)
        
        if len(message_batch) >= batch_size:
            process_messages(message_batch)
            transfer_and_merge_domain_data()
            # transfer_and_merge_client_data()
            update_benign_domains()
            consumer.commit()
            message_batch = []

except Exception as e:
    logger.error(f"Error consuming messages: {e}")

finally:
    if message_batch:
        process_messages(message_batch)
        consumer.commit()
    consumer.close()
    clickhouse_client.disconnect()
    logger.info("Kafka consumer shut down.")
