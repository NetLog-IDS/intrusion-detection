import joblib
import warnings
import numpy as np

from .predictor import Predictor

class DoSPredictor(Predictor):
    SELECTED_FEATURES = ['Bwd Packet Length Std', 'Average Packet Size', 'Bwd Segment Size Avg', 'Packet Length Std', 'Bwd Packet Length Mean', 'FWD Init Win Bytes', 'Bwd Init Win Bytes', 'Packet Length Variance', 'Bwd Packet Length Max', 'Packet Length Max', 'Total Length of Bwd Packet', 'Packet Length Mean', 'Fwd Seg Size Min', 'Fwd RST Flags', 'Idle Min', 'Bwd PSH Flags', 'Fwd IAT Min', 'Flow IAT Min', 'Total Connection Flow Time', 'Idle Std', 'Fwd IAT Max', 'Bwd Bulk Rate Avg', 'FIN Flag Count', 'RST Flag Count', 'Total Bwd packets', 'Total Fwd Packet', 'Protocol', 'Fwd Packet Length Std', 'Down/Up Ratio', 'Bwd IAT Total', 'Active Min', 'Flow IAT Max', 'SYN Flag Count', 'Fwd Packet Length Max', 'Active Mean', 'Flow Duration', 'Fwd IAT Total', 'Idle Max', 'Bwd Packets/s', 'Bwd Act Data Pkts', 'Fwd PSH Flags', 'Bwd IAT Max', 'Idle Mean', 'Fwd Header Length', 'Bwd IAT Min']
    FEATURE_TO_JSON_FIELD = {v: k for k, v in Predictor.JSON_FIELD_TO_FEATURE.items()}

    def __init__(self):
        self.JSON_FIELD_TO_SELECTED_FEATURES = {
            self.FEATURE_TO_JSON_FIELD[selected]: selected
            for selected in self.SELECTED_FEATURES
        }

        warnings.filterwarnings("ignore")

        try:
            self.stack = joblib.load("models/dos/stk3.pkl")
            self.rf = joblib.load("models/dos/rf.pkl")
            self.et = joblib.load("models/dos/et.pkl")
            self.lgbm = joblib.load("models/dos/lgbm.pkl")
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

        rf_test=self.rf.predict(prepared_rows).reshape(-1, 1)
        rf_prob_test=self.rf.predict_proba(prepared_rows)

        et_test=self.et.predict(prepared_rows).reshape(-1, 1)
        et_prob_test=self.et.predict_proba(prepared_rows)

        lgbm_test=self.lgbm.predict(prepared_rows).reshape(-1, 1)
        lgbm_prob_test=self.lgbm.predict_proba(prepared_rows)

        top_3_test_predictions = [rf_test, et_test, lgbm_test]
        top_3_test_proba = [rf_prob_test, et_prob_test, lgbm_prob_test]

        x_test = np.concatenate(top_3_test_predictions + top_3_test_proba, axis=1)
        y_predict=self.stack.predict(x_test)

        # Note that in DoS model, 0 = DoS and 1 = Not DoS
        return [(False if pred else True) for pred in y_predict]
