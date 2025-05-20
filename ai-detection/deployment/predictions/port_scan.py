import joblib
import warnings
import numpy as np

from .predictor import Predictor

class PortScanPredictor(Predictor):
    SELECTED_FEATURES = ['Bwd RST Flags', 'FWD Init Win Bytes', 'RST Flag Count', 'Flow Duration', 'Packet Length Max', 'Flow Packets/s', 'Protocol', 'Total Length of Fwd Packet', 'Flow IAT Max', 'Fwd Seg Size Min', 'Average Packet Size', 'Packet Length Mean', 'Fwd Packet Length Max', 'Bwd IAT Mean', 'Total Fwd Packet', 'Flow Bytes/s', 'Fwd Act Data Pkts', 'Bwd Packets/s', 'Bwd Packet Length Std', 'Fwd IAT Total', 'Flow IAT Mean', 'Flow IAT Min', 'Fwd Segment Size Avg', 'Fwd Header Length', 'Bwd Packet Length Mean', 'Packet Length Std', 'Fwd IAT Min', 'Packet Length Variance', 'Bwd IAT Max']
    FEATURE_TO_JSON_FIELD = {v: k for k, v in Predictor.JSON_FIELD_TO_FEATURE.items()}

    def __init__(self):
        self.JSON_FIELD_TO_SELECTED_FEATURES = {
            self.FEATURE_TO_JSON_FIELD[selected]: selected
            for selected in self.SELECTED_FEATURES
        }

        warnings.filterwarnings("ignore")

        try:
            self.stack = joblib.load("models/port_scan/stk3_tuned.pkl")
            self.et = joblib.load("models/port_scan/et_tuned.pkl")
            self.rf = joblib.load("models/port_scan/rf_tuned.pkl")
            self.lgbm = joblib.load("models/port_scan/lgbm_tuned.pkl")
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
        
        et_test=self.et.predict(prepared_rows).reshape(-1, 1)
        et_prob_test=self.et.predict_proba(prepared_rows)

        rf_test=self.rf.predict(prepared_rows).reshape(-1, 1)
        rf_prob_test=self.rf.predict_proba(prepared_rows)

        lgbm_test=self.lgbm.predict(prepared_rows).reshape(-1, 1)
        lgbm_prob_test=self.lgbm.predict_proba(prepared_rows)

        top_3_test_predictions = [et_test, rf_test, lgbm_test]
        top_3_test_proba = [et_prob_test, rf_prob_test, lgbm_prob_test]

        x_test = np.concatenate(top_3_test_predictions + top_3_test_proba, axis=1)
        y_predict=self.stack.predict(x_test)

        return [(True if pred else False) for pred in y_predict]
