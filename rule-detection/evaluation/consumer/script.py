import os, json
from kafka import KafkaConsumer
from kafka.errors import NoBrokersAvailable

def get_json_messages(bootstrap_servers, topic, group_id='python-json-consumer'):
    try:
        consumer = KafkaConsumer(
            topic,
            bootstrap_servers=bootstrap_servers,
            auto_offset_reset='earliest',
            enable_auto_commit=False,
            group_id=group_id,
            value_deserializer=lambda x: json.loads(x.decode('utf-8'))
        )
        
        print(f"Connected to Kafka. Consuming JSON messages from topic: {topic}")
        print("Press Ctrl+C to stop...\n")

        result_list = []
        
        try:
            for message in consumer:
                try:
                    json_data = message.value
                    print(f"Received JSON message [Partition: {message.partition}, Offset: {message.offset}]:")
                    result_list.append(json_data)
                except json.JSONDecodeError as e:
                    print(f"Failed to decode JSON: {str(e)}")
                    print(f"Raw message: {message.value}")
                
        except KeyboardInterrupt:
            print("\nConsumer stopped by user")
            
        finally:
            consumer.close()
        
        with open("flink_portscan.json", "w") as file:
            file.write(json.dumps(result_list, indent=2))
        
            
    except NoBrokersAvailable:
        print("Error: Could not connect to Kafka brokers")
    except Exception as e:
        print(f"An error occurred: {str(e)}")

# Usage
bootstrap_servers = 'localhost:19092'  # Change to your Kafka broker address. If you use docker-compose-ksql.yml, you don't need to change it.
topic_name = 'PORT_SCAN'        # Change to your topic name (can be PORT_SCAN or DOS)
get_json_messages(bootstrap_servers, topic_name, os.urandom(16).hex())