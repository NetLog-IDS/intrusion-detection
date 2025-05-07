import os
import json
import csv
import time
from kafka import KafkaConsumer

field_mappings = {
    # Flow Identifiers
    "fid": "Flow ID",
    "srcIp": "Src IP",
    "srcPort": "Src Port",
    "dstIp": "Dst IP",
    "dstPort": "Dst Port",
    "protocol": "Protocol",
    "timestamp": "Timestamp",
    
    # Basic Flow Statistics
    "flowDuration": "Flow Duration",
    "totalFwdPackets": "Total Fwd Packet",
    "totalBwdPackets": "Total Bwd packets",
    "totalFwdLength": "Total Length of Fwd Packet",
    "totalBwdLength": "Total Length of Bwd Packet",
    
    # Packet Length
    "fwdPacketLengthMax": "Fwd Packet Length Max",
    "fwdPacketLengthMin": "Fwd Packet Length Min",
    "fwdPacketLengthMean": "Fwd Packet Length Mean",
    "fwdPacketLengthStd": "Fwd Packet Length Std",
    "bwdPacketLengthMax": "Bwd Packet Length Max",
    "bwdPacketLengthMin": "Bwd Packet Length Min",
    "bwdPacketLengthMean": "Bwd Packet Length Mean",
    "bwdPacketLengthStd": "Bwd Packet Length Std",
    
    # Flow Rate
    "flowBytesPerSec": "Flow Bytes/s",
    "flowPacketsPerSec": "Flow Packets/s",
    
    # IAT Statistics
    "flowIatMean": "Flow IAT Mean",
    "flowIatStd": "Flow IAT Std",
    "flowIatMax": "Flow IAT Max",
    "flowIatMin": "Flow IAT Min",
    "fwdIatTotal": "Fwd IAT Total",
    "fwdIatMean": "Fwd IAT Mean",
    "fwdIatStd": "Fwd IAT Std",
    "fwdIatMax": "Fwd IAT Max",
    "fwdIatMin": "Fwd IAT Min",
    "bwdIatTotal": "Bwd IAT Total",
    "bwdIatMean": "Bwd IAT Mean",
    "bwdIatStd": "Bwd IAT Std",
    "bwdIatMax": "Bwd IAT Max",
    "bwdIatMin": "Bwd IAT Min",
    
    # PSH, URG, RST Flags
    "fwdPshFlags": "Fwd PSH Flags",
    "bwdPshFlags": "Bwd PSH Flags",
    "fwdUrgFlags": "Fwd URG Flags",
    "bwdUrgFlags": "Bwd URG Flags",
    "fwdRstFlags": "Fwd RST Flags",
    "bwdRstFlags": "Bwd RST Flags",
    
    # Header Lengths
    "fwdHeaderLength": "Fwd Header Length",
    "bwdHeaderLength": "Bwd Header Length",
    
    # Packet Rate
    "fwdPacketsPerSec": "Fwd Packets/s",
    "bwdPacketsPerSec": "Bwd Packets/s",
    
    # Total Packet Length
    "packetLengthMin": "Packet Length Min",
    "packetLengthMax": "Packet Length Max",
    "packetLengthMean": "Packet Length Mean",
    "packetLengthStd": "Packet Length Std",
    "packetLengthVar": "Packet Length Variance",
    
    # TCP Flag Counts
    "finCount": "FIN Flag Count",
    "synCount": "SYN Flag Count",
    "rstCount": "RST Flag Count",
    "pshCount": "PSH Flag Count",
    "ackCount": "ACK Flag Count",
    "urgCount": "URG Flag Count",
    "cwrCount": "CWR Flag Count",
    "eceCount": "ECE Flag Count",
    
    # Misc
    "downUpRatio": "Down/Up Ratio",
    "avgPacketSize": "Average Packet Size",
    "fwdSegmentSizeAvg": "Fwd Segment Size Avg",
    "bwdSegmentSizeAvg": "Bwd Segment Size Avg",
    
    # Bulk
    "fwdBytesPerBulkAvg": "Fwd Bytes/Bulk Avg",
    "fwdPacketsPerBulkAvg": "Fwd Packet/Bulk Avg",
    "fwdBulkRateAvg": "Fwd Bulk Rate Avg",
    "bwdBytesPerBulkAvg": "Bwd Bytes/Bulk Avg",
    "bwdPacketsPerBulkAvg": "Bwd Packet/Bulk Avg",
    "bwdBulkRateAvg": "Bwd Bulk Rate Avg",
    
    # Subflow
    "subflowFwdPackets": "Subflow Fwd Packets",
    "subflowFwdBytes": "Subflow Fwd Bytes",
    "subflowBwdPackets": "Subflow Bwd Packets",
    "subflowBwdBytes": "Subflow Bwd Bytes",
    
    # Window Statistics
    "fwdInitWinBytes": "FWD Init Win Bytes",
    "bwdInitWinBytes": "Bwd Init Win Bytes",
    "fwdActDataPackets": "Fwd Act Data Pkts",
    "bwdActDataPackets": "Bwd Act Data Pkts",
    "fwdSegSizeMin": "Fwd Seg Size Min",
    "bwdSegSizeMin": "Bwd Seg Size Min",
    
    # Active/Idle Statistics
    "activeMean": "Active Mean",
    "activeStd": "Active Std",
    "activeMax": "Active Max",
    "activeMin": "Active Min",
    "idleMean": "Idle Mean",
    "idleStd": "Idle Std",
    "idleMax": "Idle Max",
    "idleMin": "Idle Min",
    
    # ICMP
    "icmpCode": "ICMP Code",
    "icmpType": "ICMP Type",
    
    # Retransmission
    "fwdTCPRetransCount": "Fwd TCP Retrans. Count",
    "bwdTCPRetransCount": "Bwd TCP Retrans. Count",
    "totalTCPRetransCount": "Total TCP Retrans. Count",
    
    # Cumulative
    "cummConnectionTime": "Total Connection Flow Time",
    
    # Classification
    "label": "Label"
}

class FlowDataConsumer:
    def __init__(self, bootstrap_servers='localhost:9092', topic='flow-data', 
                 group_id='flow-data-group', output_file='flow_data.csv'):
        self.consumer = KafkaConsumer(
            topic,
            bootstrap_servers=bootstrap_servers,
            group_id=group_id,
            auto_offset_reset='earliest',
            value_deserializer=lambda x: json.loads(x.decode('utf-8')),
            max_poll_records=10000,
        )
        self.output_file = output_file
        self.header_written = False
    
    def process_messages(self, max_messages=None, timeout_ms=100):
        """Process JSON messages from Kafka and write to CSV"""
        message_count = 0
        
        with open(self.output_file, 'w', newline='') as csvfile:
            csv_writer = None
            
            while max_messages is None or message_count < max_messages:
                records = self.consumer.poll(timeout_ms=timeout_ms)
                
                if not records:
                    print("No messages received, continuing...")
                    continue
                
                for _, messages in records.items():
                    for message in messages:
                        flow_data = message.value
                        
                        filtered_data = {}
                        for field, value in flow_data.items():
                            if field in field_mappings:
                                filtered_data[field_mappings[field]] = value
                        
                        if csv_writer is None:
                            headers = filtered_data.keys()
                            csv_writer = csv.DictWriter(csvfile, fieldnames=headers)
                            csv_writer.writeheader()
                        
                        csv_writer.writerow(filtered_data)
                        message_count += 1
                        
                        if max_messages is not None and message_count >= max_messages:
                            break
                
                print(f"Processed {message_count} messages")
                
                if max_messages is None:
                    time.sleep(1)
        
        print(f"Finished processing {message_count} messages. Output written to {self.output_file}")

def main():
    kafka_config = {
        'bootstrap_servers': 'localhost:19092',
        'topic': 'network-flows',
        'group_id': os.urandom(16).hex(),
        'output_file': 'flink_wedfri_2_train.csv'
    }
    
    consumer = FlowDataConsumer(**kafka_config)
    
    try:
        print(f"Starting Kafka consumer, listening on topic {kafka_config['topic']}...")
        print(f"Writing output to {kafka_config['output_file']}")
        consumer.process_messages()
    except KeyboardInterrupt:
        print("Consumer stopped by user")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()