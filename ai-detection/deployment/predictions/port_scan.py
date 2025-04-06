import joblib
import warnings
import numpy as np

from .predictor import Predictor

class PortScanPredictor(Predictor):
    SELECTED_FEATURES = ['Total Connection Flow Time', 'Fwd Seg Size Min', 'Bwd RST Flags', 'Fwd Packet Length Max', 'Flow Duration', 'Packet Length Mean', 'Flow IAT Max', 'Fwd Packet Length Mean', 'Average Packet Size', 'Bwd IAT Total', 'Total Length of Bwd Packet', 'Bwd Packets/s', 'Total Length of Fwd Packet', 'Fwd Packets/s', 'Fwd Act Data Pkts', 'Flow Bytes/s', 'Bwd Packet Length Max', 'Bwd Segment Size Avg', 'Flow IAT Min', 'Packet Length Max', 'Fwd Segment Size Avg']
    JSON_FIELD_TO_FEATURE = {
        "fid": "Flow ID",
        "srcIp": "Src IP",
        "srcPort": "Src Port",
        "dstIp": "Dst IP",
        "dstPort": "Dst Port",
        "protocol": "Protocol",
        "timestamp": "Timestamp",
        "flowDuration": "Flow Duration",
        "totalFwdPackets": "Total Fwd Packet",
        "totalBwdPackets": "Total Bwd packets",
        "totalFwdLength": "Total Length of Fwd Packet",
        "totalBwdLength": "Total Length of Bwd Packet",
        "fwdPacketLengthMax": "Fwd Packet Length Max",
        "fwdPacketLengthMin": "Fwd Packet Length Min",
        "fwdPacketLengthMean": "Fwd Packet Length Mean",
        "fwdPacketLengthStd": "Fwd Packet Length Std",
        "bwdPacketLengthMax": "Bwd Packet Length Max",
        "bwdPacketLengthMin": "Bwd Packet Length Min",
        "bwdPacketLengthMean": "Bwd Packet Length Mean",
        "bwdPacketLengthStd": "Bwd Packet Length Std",
        "flowBytesPerSec": "Flow Bytes/s",
        "flowPacketsPerSec": "Flow Packets/s",
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
        "fwdPshFlags": "Fwd PSH Flags",
        "bwdPshFlags": "Bwd PSH Flags",
        "fwdUrgFlags": "Fwd URG Flags",
        "bwdUrgFlags": "Bwd URG Flags",
        "fwdRstFlags": "Fwd RST Flags",
        "bwdRstFlags": "Bwd RST Flags",
        "fwdHeaderLength": "Fwd Header Length",
        "bwdHeaderLength": "Bwd Header Length",
        "fwdPacketsPerSec": "Fwd Packets/s",
        "bwdPacketsPerSec": "Bwd Packets/s",
        "packetLengthMin": "Packet Length Min",
        "packetLengthMax": "Packet Length Max",
        "packetLengthMean": "Packet Length Mean",
        "packetLengthStd": "Packet Length Std",
        "packetLengthVar": "Packet Length Variance",
        "finCount": "FIN Flag Count",
        "synCount": "SYN Flag Count",
        "rstCount": "RST Flag Count",
        "pshCount": "PSH Flag Count",
        "ackCount": "ACK Flag Count",
        "urgCount": "URG Flag Count",
        "cwrCount": "CWR Flag Count",
        "eceCount": "ECE Flag Count",
        "downUpRatio": "Down/Up Ratio",
        "avgPacketSize": "Average Packet Size",
        "fwdSegmentSizeAvg": "Fwd Segment Size Avg",
        "bwdSegmentSizeAvg": "Bwd Segment Size Avg",
        "fwdBytesPerBulkAvg": "Fwd Bytes/Bulk Avg",
        "fwdPacketsPerBulkAvg": "Fwd Packet/Bulk Avg",
        "fwdBulkRateAvg": "Fwd Bulk Rate Avg",
        "bwdBytesPerBulkAvg": "Bwd Bytes/Bulk Avg",
        "bwdPacketsPerBulkAvg": "Bwd Packet/Bulk Avg",
        "bwdBulkRateAvg": "Bwd Bulk Rate Avg",
        "subflowFwdPackets": "Subflow Fwd Packets",
        "subflowFwdBytes": "Subflow Fwd Bytes",
        "subflowBwdPackets": "Subflow Bwd Packets",
        "subflowBwdBytes": "Subflow Bwd Bytes",
        "fwdInitWinBytes": "FWD Init Win Bytes",
        "bwdInitWinBytes": "Bwd Init Win Bytes",
        "fwdActDataPackets": "Fwd Act Data Pkts",
        "bwdActDataPackets": "Bwd Act Data Pkts",
        "fwdSegSizeMin": "Fwd Seg Size Min",
        "bwdSegSizeMin": "Bwd Seg Size Min",
        "activeMean": "Active Mean",
        "activeStd": "Active Std",
        "activeMax": "Active Max",
        "activeMin": "Active Min",
        "idleMean": "Idle Mean",
        "idleStd": "Idle Std",
        "idleMax": "Idle Max",
        "idleMin": "Idle Min",
        "icmpCode": "ICMP Code",
        "icmpType": "ICMP Type",
        "fwdTCPRetransCount": "Fwd TCP Retrans. Count",
        "bwdTCPRetransCount": "Bwd TCP Retrans. Count",
        "totalTCPRetransCount": "Total TCP Retrans. Count",
        "cummConnectionTime": "Total Connection Flow Time",
        "label": "Label"
    }
    FEATURE_TO_JSON_FIELD = {v: k for k, v in JSON_FIELD_TO_FEATURE.items()}

    def __init__(self):
        self.JSON_FIELD_TO_SELECTED_FEATURES = {
            self.FEATURE_TO_JSON_FIELD[selected]: selected
            for selected in self.SELECTED_FEATURES
        }

        warnings.filterwarnings("ignore")

        try:
            self.stack = joblib.load("models/port_scan/stk3.pkl")
            self.xg = joblib.load("models/port_scan/xg.pkl")
            self.rf = joblib.load("models/port_scan/rf.pkl")
            self.lgbm = joblib.load("models/port_scan/lgbm.pkl")
        except Exception as e:
            print("Invalid Model")
            raise

    def predict(self, rows: list[dict]) -> list[bool]:
        prepared_rows = []
        for row in rows:
            prepared_row = {}
            for json_field, feature in self.JSON_FIELD_TO_SELECTED_FEATURES.items():
                prepared_row[feature] = row[json_field]
            prepared_rows.append(list(prepared_row.values()))
        
        xg_test=self.xg.predict(prepared_rows).reshape(-1, 1)
        xg_prob_test=self.xg.predict_proba(prepared_rows)

        rf_test=self.rf.predict(prepared_rows).reshape(-1, 1)
        rf_prob_test=self.rf.predict_proba(prepared_rows)

        lgbm_test=self.lgbm.predict(prepared_rows).reshape(-1, 1)
        lgbm_prob_test=self.lgbm.predict_proba(prepared_rows)

        top_3_test_predictions = [xg_test, rf_test, lgbm_test]
        top_3_test_proba = [xg_prob_test, rf_prob_test, lgbm_prob_test]

        x_test = np.concatenate(top_3_test_predictions + top_3_test_proba, axis=1)
        y_predict=self.stack.predict(x_test)

        return [(True if pred else False) for pred in y_predict]
