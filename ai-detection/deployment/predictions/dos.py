import joblib
import warnings
import numpy as np

from .predictor import Predictor

class DoSPredictor(Predictor):
    SELECTED_FEATURES = ['Fwd IAT Min', 'Bwd IAT Mean', 'Fwd Seg Size Min', 'Flow Packets/s', 'Fwd Packets/s', 'Total Length of Bwd Packet', 'Bwd Act Data Pkts', 'Bwd IAT Min', 'Flow IAT Mean', 'FIN Flag Count', 'Bwd Init Win Bytes', 'Fwd Bulk Rate Avg', 'Active Min', 'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Bwd Packets/s', 'Bwd Header Length', 'Bwd Packet Length Mean', 'Subflow Bwd Bytes', 'Flow Duration', 'Flow IAT Min', 'Total Bwd packets', 'Fwd Segment Size Avg', 'FWD Init Win Bytes', 'Packet Length Mean', 'Down/Up Ratio', 'ACK Flag Count', 'Fwd IAT Total', 'SYN Flag Count', 'Bwd Packet Length Max', 'Subflow Fwd Packets', 'Fwd Bytes/Bulk Avg', 'Flow IAT Max', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd Header Length']
    FEATURE_TO_JSON_FIELD = {v: k for k, v in Predictor.JSON_FIELD_TO_FEATURE.items()}

    def __init__(self):
        self.JSON_FIELD_TO_SELECTED_FEATURES = {
            self.FEATURE_TO_JSON_FIELD[selected]: selected
            for selected in self.SELECTED_FEATURES
        }

        warnings.filterwarnings("ignore")

        try:
            self.stack = joblib.load("models/dos/stk3_tuned.pkl")
            self.rf = joblib.load("models/dos/rf_tuned.pkl")
            self.xg = joblib.load("models/dos/xg_tuned.pkl")
            self.lgbm = joblib.load("models/dos/lgbm_tuned.pkl")
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

        xg_test=self.xg.predict(prepared_rows).reshape(-1, 1)
        xg_prob_test=self.xg.predict_proba(prepared_rows)

        lgbm_test=self.lgbm.predict(prepared_rows).reshape(-1, 1)
        lgbm_prob_test=self.lgbm.predict_proba(prepared_rows)

        top_3_test_predictions = [rf_test, xg_test, lgbm_test]
        top_3_test_proba = [rf_prob_test, xg_prob_test, lgbm_prob_test]

        x_test = np.concatenate(top_3_test_predictions + top_3_test_proba, axis=1)
        y_predict=self.stack.predict(x_test)

        return [(True if pred else False) for pred in y_predict]
