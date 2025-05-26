import joblib
import warnings
import numpy as np

from .predictor import Predictor

class DoSPredictor(Predictor):
    SELECTED_FEATURES = ['Fwd Seg Size Min', 'Bwd Packet Length Mean', 'FWD Init Win Bytes', 'Fwd IAT Max', 'Bwd RST Flags', 'Bwd Packet Length Max', 'FIN Flag Count', 'Fwd IAT Min', 'Protocol', 'Bwd Segment Size Avg', 'Flow IAT Mean', 'Fwd Packet Length Max', 'Down/Up Ratio', 'Flow IAT Min', 'RST Flag Count', 'Flow Duration', 'Subflow Fwd Packets', 'Flow IAT Max', 'Flow Packets/s', 'Active Min', 'Bwd IAT Min', 'Bwd Act Data Pkts', 'Bwd Init Win Bytes', 'Bwd IAT Max', 'SYN Flag Count', 'Idle Max', 'Fwd IAT Total', 'Total Length of Bwd Packet', 'Fwd IAT Mean', 'Fwd Packets/s', 'Average Packet Size', 'Bwd IAT Mean', 'Total Bwd packets', 'Bwd Packets/s', 'Bwd IAT Total', 'Packet Length Mean', 'Packet Length Max', 'Bwd PSH Flags', 'Flow IAT Std', 'Packet Length Std', 'Fwd Bulk Rate Avg', 'Fwd Segment Size Avg', 'Fwd Packet Length Min', 'Fwd IAT Std', 'Fwd Packet Length Std', 'Flow Bytes/s', 'Fwd Bytes/Bulk Avg', 'ACK Flag Count', 'Packet Length Variance']
    FEATURE_TO_JSON_FIELD = {v: k for k, v in Predictor.JSON_FIELD_TO_FEATURE.items()}

    def __init__(self):
        self.JSON_FIELD_TO_SELECTED_FEATURES = {
            self.FEATURE_TO_JSON_FIELD[selected]: selected
            for selected in self.SELECTED_FEATURES
        }

        warnings.filterwarnings("ignore")

        try:
            self.xg = joblib.load("models/dos/xg_tuned.pkl")
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

        y_predict = self.xg.predict(prepared_rows)

        return [(True if pred else False) for pred in y_predict]
