import os
os.environ['OMP_NUM_THREADS'] = "1"

import pandas as pd
import numpy as np
import joblib
import time

DOS_MODEL_LOCATION = "../../ai-detection/notebooks/models_dos/postfs"

# Load Test Dataset
flink_test = pd.read_csv('./test_final_2.csv', parse_dates=['Timestamp'], index_col=0)

dt = joblib.load(f"{DOS_MODEL_LOCATION}/dt_tuned.pkl")
rf = joblib.load(f"{DOS_MODEL_LOCATION}/rf_tuned_single.pkl")
et = joblib.load(f"{DOS_MODEL_LOCATION}/et_tuned_single.pkl")
xg = joblib.load(f"{DOS_MODEL_LOCATION}/xg_tuned_single.pkl")
lgbm = joblib.load(f"{DOS_MODEL_LOCATION}/lgbm_tuned_single.pkl")
cat = joblib.load(f"{DOS_MODEL_LOCATION}/cat_tuned_single.pkl")
ocse = joblib.load(f"{DOS_MODEL_LOCATION}/ocse_tuned_single.pkl")

fs = ['Bwd IAT Mean', 'Bwd IAT Max', 'Flow Duration', 'Fwd IAT Max', 'Idle Max', 'Flow IAT Max', 'Fwd Seg Size Min', 'Fwd IAT Total', 'Flow IAT Std', 'Idle Mean', 'Flow IAT Mean', 'Bwd IAT Total', 'Bwd IAT Min', 'Protocol', 'Fwd Bulk Rate Avg', 'Bwd Packet Length Max', 'Fwd Packets/s', 'Fwd IAT Mean', 'Flow Packets/s', 'Fwd PSH Flags', 'FWD Init Win Bytes', 'Total Length of Bwd Packet', 'Bwd Packet Length Mean', 'Bwd RST Flags', 'Fwd Packet Length Min', 'PSH Flag Count', 'SYN Flag Count', 'Bwd Segment Size Avg', 'RST Flag Count', 'Bwd Act Data Pkts', 'FIN Flag Count', 'Packet Length Std']

top_3_models = ['rf', 'xg', 'et']

X_test_fs = flink_test[fs]

TRIES = 100

def prints(x):
    print(x)
    with open("output_dos.txt", "a") as file:
        file.write(str(x) + "\n")

# this is in milliseconds, not seconds
def calculate_inference_time_in_ms(foo, tries: int):
    times = []
    for _ in range(tries):
        start = time.time()
        foo()
        end = time.time()
        times.append(((end - start) / len(X_test_fs)) * 1000)
    prints(times)
    return np.average(times)

dos_inference_times: list[tuple] = []

# Decision Tree
dos_inference_times.append(("DT", calculate_inference_time_in_ms(lambda: dt.predict(X_test_fs), TRIES)))
prints(dos_inference_times[0])

# Random Forest
dos_inference_times.append(("RF", calculate_inference_time_in_ms(lambda: rf.predict(X_test_fs), TRIES)))
prints(dos_inference_times[1])

# # Extra Trees
dos_inference_times.append(("ET", calculate_inference_time_in_ms(lambda: et.predict(X_test_fs), TRIES)))
prints(dos_inference_times[2])

# # XGBoost
dos_inference_times.append(("XG", calculate_inference_time_in_ms(lambda: xg.predict(X_test_fs), TRIES)))
prints(dos_inference_times[3])

# # LightGBM
dos_inference_times.append(("LGBM", calculate_inference_time_in_ms(lambda: lgbm.predict(X_test_fs), TRIES)))
prints(dos_inference_times[4])

# # CatBoost
dos_inference_times.append(("Cat", calculate_inference_time_in_ms(lambda: cat.predict(X_test_fs, thread_count=1), TRIES)))
prints(dos_inference_times[5])

# # OCSE (Change based on training's top 3 models results)
def ocse_timer():
    model_1_test = xg.predict(X_test_fs).reshape(-1, 1)
    model_2_test = et.predict(X_test_fs).reshape(-1, 1)
    model_3_test = lgbm.predict(X_test_fs).reshape(-1, 1)

    model_1_prob_test = xg.predict_proba(X_test_fs)
    model_2_prob_test = et.predict_proba(X_test_fs)
    model_3_prob_test = lgbm.predict_proba(X_test_fs)

    x_test = np.concatenate([model_1_test, model_2_test, model_3_test] + [model_1_prob_test, model_2_prob_test, model_3_prob_test], axis=1)

    ocse.predict(x_test)

dos_inference_times.append(("OCSE", calculate_inference_time_in_ms(ocse_timer, TRIES)))
prints(dos_inference_times[6])

dos_times = sorted(dos_inference_times, key=lambda x: x[1])

prints([[a, format(b, '.5f')] for a, b in dos_times])
