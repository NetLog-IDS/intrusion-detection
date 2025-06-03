import joblib
import warnings
import numpy as np

from .predictor import Predictor

class DoSPredictor(Predictor):
    SELECTED_FEATURES = ['Bwd IAT Mean', 'Bwd IAT Max', 'Flow Duration', 'Fwd IAT Max', 'Idle Max', 'Flow IAT Max', 'Fwd Seg Size Min', 'Fwd IAT Total', 'Flow IAT Std', 'Idle Mean', 'Flow IAT Mean', 'Bwd IAT Total', 'Bwd IAT Min', 'Protocol', 'Fwd Bulk Rate Avg', 'Bwd Packet Length Max', 'Fwd Packets/s', 'Fwd IAT Mean', 'Flow Packets/s', 'Fwd PSH Flags', 'FWD Init Win Bytes', 'Total Length of Bwd Packet', 'Bwd Packet Length Mean', 'Bwd RST Flags', 'Fwd Packet Length Min', 'PSH Flag Count', 'SYN Flag Count', 'Bwd Segment Size Avg', 'RST Flag Count', 'Bwd Act Data Pkts', 'FIN Flag Count', 'Packet Length Std']
    FEATURE_TO_JSON_FIELD = {v: k for k, v in Predictor.JSON_FIELD_TO_FEATURE.items()}

    def __init__(self):
        self.JSON_FIELD_TO_SELECTED_FEATURES = {
            self.FEATURE_TO_JSON_FIELD[selected]: selected
            for selected in self.SELECTED_FEATURES
        }

        warnings.filterwarnings("ignore")

        try:
            self.xg = joblib.load("models/dos/et_tuned_single.pkl")
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
