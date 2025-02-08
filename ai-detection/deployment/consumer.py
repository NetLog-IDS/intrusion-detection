import os
from kafka import KafkaConsumer, KafkaProducer
import json
from typing import Any, Dict
import logging
import joblib

class ModelPipeline:
    LABEL_NAMES = ['Benign', 'Bot', 'BruteForce', 'DoS', 'Infiltration', 'PortScan', 'WebAttack']
    MODEL_TO_JSON_KEYS = {
        'Bwd Packet Length Min': 'bwdPacketLengthMin',
        'Bwd Packet Length Std': 'bwdPacketLengthStd',
        'Init_Win_bytes_forward': 'fwdInitWinBytes',
        'Average Packet Size': 'avgPacketSize',
        'Init_Win_bytes_backward': 'bwdInitWinBytes',
        'PSH Flag Count': 'pshCount',
        'Bwd Packets/s': 'bwdPacketsPerSec',
        'Fwd PSH Flags': 'fwdPshFlags',
        'Avg Bwd Segment Size': 'bwdSegmentSizeAvg',
        'Bwd Header Length': 'bwdHeaderLength',
        'Fwd Header Length': 'fwdHeaderLength',
        'Packet Length Mean': 'packetLengthMean',
        'Packet Length Std': 'packetLengthStd',
        'Packet Length Variance': 'packetLengthVar',
        'min_seg_size_forward': 'fwdSegSizeMin',
        'Bwd Packet Length Mean': 'bwdPacketLengthMean',
        'Fwd Header Length.1': 'fwdHeaderLength',
        'Flow Bytes/s': 'flowBytesPerSec',
        'Bwd Packet Length Max': 'bwdPacketLengthMax',
        'Max Packet Length': 'packetLengthMax',
        'Flow IAT Min': 'flowIatMin',
        'Total Length of Fwd Packets': 'totalFwdLength',
        'Fwd Packet Length Mean': 'fwdPacketLengthMean',
        'Total Length of Bwd Packets': 'totalBwdLength',
        'Fwd Packet Length Max': 'fwdPacketLengthMax',
        'Fwd IAT Min': 'fwdIatMin',
        'Avg Fwd Segment Size': 'fwdSegmentSizeAvg',
        'Total Fwd Packets': 'totalFwdPackets',
        'Subflow Bwd Bytes': 'subflowBwdBytes',
        'Subflow Fwd Bytes': 'subflowFwdBytes',
        'Flow IAT Max': 'flowIatMax',
        'Total Backward Packets': 'totalBwdPackets',
        'Fwd IAT Mean': 'fwdIatMean',
        'Bwd IAT Min': 'bwdIatMin',
        'act_data_pkt_fwd': 'fwdActDataPackets',
        'Fwd Packets/s': 'fwdPacketsPerSec',
        'URG Flag Count': 'urgCount',
        'Flow IAT Std': 'flowIatStd',
        'Min Packet Length': 'packetLengthMin',
    }

    def __init__(
        self,
        bootstrap_servers: list[str],
        input_topic: str,
        output_topic: str,
        model_path: str,
        group_id: str,
    ):
        self.input_topic = input_topic
        self.output_topic = output_topic
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
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
        
        try:
            self.model = joblib.load(model_path)
            self.logger.info("Model loaded successfully")
        except Exception as e:
            self.logger.error(f"Failed to load model: {str(e)}")
            raise
    
    def preprocess_message(self, message: Dict[str, Any]) -> list:
        try:
            selected_message = { k: message[v] for k, v in self.MODEL_TO_JSON_KEYS.items() }
            return [list(selected_message.values())]
        except Exception as e:
            self.logger.error(f"Error in preprocessing: {str(e)}")
            raise
    
    def postprocess_prediction(self, prediction: int) -> Dict[str, Any]:
        if not (0 <= prediction < len(self.LABEL_NAMES)):
            self.logger.error(f"Error in postprocess: invalid prediction result {prediction}")
        return { 'prediction': self.LABEL_NAMES[prediction] }
    
    def process_message(self, message: Dict[str, Any]) -> Dict[str, Any]:
        try:
            preprocessed_data = self.preprocess_message(message)
            prediction = self.model.predict(preprocessed_data).tolist()[0]
            result = self.postprocess_prediction(prediction)
            
            # result['flowUniqueId'] = message['flowUniqueId']
            result['fid'] = message['fid']
                
            return result
            
        except Exception as e:
            self.logger.error(f"Error processing message: {str(e)}")
            return {'error': str(e), 'original_message': message}
    
    def run(self):
        self.logger.info(f"Starting to consume messages from {self.input_topic}")
        
        try:
            for message in self.consumer:
                self.logger.info(f"Received message from partition {message.partition}")
                
                try:
                    result = self.process_message(message.value)
                    
                    self.producer.send(
                        self.output_topic,
                        value=result
                    )
                    self.producer.flush()
                    
                    self.logger.info(f"Processed and sent message to {self.output_topic}")
                    
                except Exception as e:
                    self.logger.error(f"Failed to process message: {str(e)}")
                    # TODO: send to dead letter queue
                    continue
                    
        except KeyboardInterrupt:
            self.logger.info("Shutting down pipeline")
        finally:
            self.consumer.close()
            self.producer.close()

if __name__ == "__main__":
    pipeline = ModelPipeline(
        bootstrap_servers=[os.getenv("BOOTSTRAP_SERVER", "localhost:19092")],
        input_topic=os.getenv("INPUT_TOPIC", "network-flows"),
        output_topic=os.getenv("OUTPUT_TOPIC", "intrusion"),
        group_id=os.getenv("GROUP", "model-2"),
        model_path="./models/lgbm.pkl"
    )
    
    pipeline.run()