import os
import json
from typing import Any, Dict
from dateutil import parser
from kafka import KafkaConsumer, KafkaProducer

from predictions.port_scan import PortScanPredictor
from predictions.dos import DoSPredictor

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

        if self.output_topic == "PORT_SCAN":
            print("Port Scan Chosen")
            self.model = PortScanPredictor()
        else:
            print("DoS Chosen")
            self.output_topic = "DOS"
            self.model = DoSPredictor()

        self.detected = 0
    
    def process_message(self, messages: list[Dict[str, Any]]) -> list[Dict[str, Any]]:
        try:
            predictions = self.model.predict(messages)

            results: list[Dict[str,Any]] = []
            for features, pred in zip(messages, predictions):
                start_time = parser.parse(features["timestamp"])
                start_time = int(start_time.timestamp() * 1_000_000)
                end_time = start_time + features["flowDuration"]
                
                sniff_time = int(features["sniffStartTime"])
                sniff_time_max = int(features["sniffStartTimeMax"])
                sniff_time_avg = float(features["sniffStartTimeAvg"])
                preprocess_end_time = int(features["preprocessEndTime"])
                first_arrival_time = int(features["firstArrivalTime"])

                count_packets = int(features["totalFwdPackets"]) + int(features["totalBwdPackets"])

                if pred:
                    self.detected += 1

                result = {
                    "TIMESTAMP_START": start_time,
                    "TIMESTAMP_END": end_time,
                    "STATUS": "DETECTED" if pred else "NOT DETECTED",
                    "COUNT_PACKETS": count_packets,
                    "SNIFF_TIMESTAMP_START": sniff_time,
                    "SNIFF_TIMESTAMP_START_MAX": sniff_time_max,
                    "SNIFF_TIMESTAMP_START_AVG": sniff_time_avg,
                    "PREPROCESS_END_TIME": preprocess_end_time,
                    "PREPROCESS_START_TIME": first_arrival_time,
                    # "METADATA": features,
                }

                if self.output_topic == "PORT_SCAN":
                    result["IP_SRC"] = features["srcIp"]
                else:
                    result["IP_DST"] = features["srcIp"]
                results.append(result)
            return results
        
        except Exception as e:
            print(e)
            return []
    
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
            print(f"DETECTED INTRUSIONS: {self.detected}")
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
