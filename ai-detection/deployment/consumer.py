import os
import json
from typing import Any, Dict
from kafka import KafkaConsumer, KafkaProducer

from predictions.port_scan import PortScanPredictor

class ModelPipeline:
    def __init__(
        self,
        bootstrap_servers: list[str],
        input_topic: str,
        output_topic: str,
        group_id: str,
    ):
        self.input_topic = input_topic
        self.output_topic = output_topic
        
        # TODO: I think when shutting down in the middle of processing, message will still be claimed as "Commited"
        self.consumer = KafkaConsumer(
            input_topic,
            bootstrap_servers=bootstrap_servers,
            group_id=group_id,
            value_deserializer=lambda x: json.loads(x.decode('utf-8')),
            auto_offset_reset='earliest'
        )
        
        self.producer = KafkaProducer(
            bootstrap_servers=bootstrap_servers,
            value_serializer=lambda x: json.dumps(x).encode('utf-8')
        )
        
        self.model = PortScanPredictor()
    
    def process_message(self, messages: list[Dict[str, Any]]) -> list[Dict[str, Any]]:
        try:
            predictions = self.model.predict(messages)
            return [{"prediction": pred} for pred in predictions]
        except Exception as e:
            return [{'error': str(e), 'original_message': msg} for msg in messages]
    
    def run(self):
        try:
            while True:
                records = self.consumer.poll(timeout_ms=100)

                for _, batch in records.items():
                    messages = [message.value for message in batch]
                    results = self.process_message(messages)
                    for result in results:
                        self.producer.send(self.output_topic, value=result)
                    self.producer.flush()                    
                    
        except Exception as e:
            print(e)
            pass
        finally:
            self.consumer.close()
            self.producer.close()

if __name__ == "__main__":
    pipeline = ModelPipeline(
        bootstrap_servers=[os.getenv("BOOTSTRAP_SERVER", "localhost:19092")],
        input_topic=os.getenv("INPUT_TOPIC", "network-flows"),
        output_topic=os.getenv("OUTPUT_TOPIC", "PORT_SCAN"),
        group_id=os.getenv("GROUP", os.urandom(16).hex()),
    )
    
    pipeline.run()
