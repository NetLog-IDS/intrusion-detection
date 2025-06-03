import joblib
import warnings
import numpy as np

from .predictor import Predictor

class PortScanPredictor(Predictor):
    SELECTED_FEATURES = ['Bwd RST Flags', 'Flow Duration', 'RST Flag Count', 'Fwd Segment Size Avg', 'Packet Length Mean', 'Protocol', 'Fwd Seg Size Min', 'Average Packet Size', 'Total Length of Fwd Packet', 'Flow IAT Max', 'Flow Bytes/s', 'Bwd Packets/s', 'Fwd Packet Length Max', 'Down/Up Ratio', 'Packet Length Max', 'Fwd Header Length', 'Bwd Segment Size Avg', 'Bwd Packet Length Max', 'FWD Init Win Bytes', 'Fwd Packet Length Mean', 'Bwd Packet Length Mean', 'Fwd Act Data Pkts', 'Bwd Packet Length Std', 'Total Length of Bwd Packet', 'Bwd Act Data Pkts', 'Packet Length Std', 'Bwd Init Win Bytes']
    FEATURE_TO_JSON_FIELD = {v: k for k, v in Predictor.JSON_FIELD_TO_FEATURE.items()}

    def __init__(self):
        self.JSON_FIELD_TO_SELECTED_FEATURES = {
            self.FEATURE_TO_JSON_FIELD[selected]: selected
            for selected in self.SELECTED_FEATURES
        }

        warnings.filterwarnings("ignore")

        try:
            self.dt = joblib.load("models/port_scan/lgbm_tuned_single.pkl")
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
        
        y_predict = self.dt.predict(prepared_rows)

        return [(True if pred else False) for pred in y_predict]
