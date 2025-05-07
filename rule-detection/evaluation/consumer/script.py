import os, json
from kafka import KafkaConsumer
from kafka.errors import NoBrokersAvailable

def get_json_messages(bootstrap_servers, topic, group_id='python-json-consumer'):
    try:
        # Create consumer with JSON deserializer
        consumer = KafkaConsumer(
            topic,
            bootstrap_servers=bootstrap_servers,
            auto_offset_reset='earliest',  # Start from beginning
            enable_auto_commit=False,      # Manual offset control
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
                    # print(json.dumps(json_data, indent=2))  # Pretty print JSON
                    
                    # Access specific fields
                    # Example: if your JSON has a 'user_id' field
                    # user_id = json_data.get('user_id')
                    # print(f"User ID: {user_id}")
                    
                except json.JSONDecodeError as e:
                    print(f"Failed to decode JSON: {str(e)}")
                    print(f"Raw message: {message.value}")
                
        except KeyboardInterrupt:
            print("\nConsumer stopped by user")
            
        finally:
            consumer.close()
        
        with open("slowhttptest_result.json", "w") as file:
            file.write(json.dumps(result_list, indent=2))
        
            
    except NoBrokersAvailable:
        print("Error: Could not connect to Kafka brokers")
    except Exception as e:
        print(f"An error occurred: {str(e)}")

# Usage
bootstrap_servers = 'localhost:19092'  # Change to your Kafka broker address
topic_name = 'DOS'        # Change to your topic name
get_json_messages(bootstrap_servers, topic_name, os.urandom(16).hex())