import os
os.environ['OMP_NUM_THREADS'] = "1"

import pandas as pd
import numpy as np
import joblib
import time

PS_MODEL_LOCATION = "../../ai-detection/notebooks/models_ps/postfs"

# Load Test Dataset
flink_test = pd.read_csv('./test_final_2.csv', parse_dates=['Timestamp'], index_col=0)

dt = joblib.load(f"{PS_MODEL_LOCATION}/dt_tuned.pkl")
rf = joblib.load(f"{PS_MODEL_LOCATION}/rf_tuned_single.pkl")
et = joblib.load(f"{PS_MODEL_LOCATION}/et_tuned_single.pkl")
xg = joblib.load(f"{PS_MODEL_LOCATION}/xg_tuned_single.pkl")
lgbm = joblib.load(f"{PS_MODEL_LOCATION}/lgbm_tuned_single.pkl")
cat = joblib.load(f"{PS_MODEL_LOCATION}/cat_tuned_single.pkl")
stk3 = joblib.load(f"{PS_MODEL_LOCATION}/ocse_tuned_single.pkl")

fs = ['Bwd RST Flags', 'Flow Duration', 'RST Flag Count', 'Fwd Segment Size Avg', 'Packet Length Mean', 'Protocol', 'Fwd Seg Size Min', 'Average Packet Size', 'Total Length of Fwd Packet', 'Flow IAT Max', 'Flow Bytes/s', 'Bwd Packets/s', 'Fwd Packet Length Max', 'Down/Up Ratio', 'Packet Length Max', 'Fwd Header Length', 'Bwd Segment Size Avg', 'Bwd Packet Length Max', 'FWD Init Win Bytes', 'Fwd Packet Length Mean', 'Bwd Packet Length Mean', 'Fwd Act Data Pkts', 'Bwd Packet Length Std', 'Total Length of Bwd Packet', 'Bwd Act Data Pkts', 'Packet Length Std', 'Bwd Init Win Bytes']

top_3_models = ['et', 'lgbm', 'rf']

X_test_fs = flink_test[fs]

TRIES = 100

def prints(x):
    print(x)
    with open("output_ps.txt", "a") as file:
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

ps_inference_times: list[tuple] = []

# Decision Tree
ps_inference_times.append(("DT", calculate_inference_time_in_ms(lambda: dt.predict(X_test_fs), TRIES)))
prints(ps_inference_times[0])

# Random Forest
ps_inference_times.append(("RF", calculate_inference_time_in_ms(lambda: rf.predict(X_test_fs), TRIES)))
prints(ps_inference_times[1])

# Extra Trees
ps_inference_times.append(("ET", calculate_inference_time_in_ms(lambda: et.predict(X_test_fs), TRIES)))
prints(ps_inference_times[2])

# XGBoost
ps_inference_times.append(("XG", calculate_inference_time_in_ms(lambda: xg.predict(X_test_fs), TRIES)))
prints(ps_inference_times[3])

# LightGBM
ps_inference_times.append(("LGBM", calculate_inference_time_in_ms(lambda: lgbm.predict(X_test_fs), TRIES)))
prints(ps_inference_times[4])

# CatBoost
ps_inference_times.append(("Cat", calculate_inference_time_in_ms(lambda: cat.predict(X_test_fs, thread_count=1), TRIES)))
prints(ps_inference_times[5])

# OCSE (Change based on training's top 3 models results)
def ocse_timer():
    model_1_test = et.predict(X_test_fs).reshape(-1, 1)
    model_2_test = lgbm.predict(X_test_fs).reshape(-1, 1)
    model_3_test = rf.predict(X_test_fs).reshape(-1, 1)

    model_1_prob_test = et.predict_proba(X_test_fs)
    model_2_prob_test = lgbm.predict_proba(X_test_fs)
    model_3_prob_test = rf.predict_proba(X_test_fs)

    x_test = np.concatenate([model_1_test, model_2_test, model_3_test] + [model_1_prob_test, model_2_prob_test, model_3_prob_test], axis=1)

    stk3.predict(x_test)

ps_inference_times.append(("OCSE", calculate_inference_time_in_ms(ocse_timer, TRIES)))
prints(ps_inference_times[6])

ps_times = sorted(ps_inference_times, key=lambda x: x[1])

prints([[a, format(b, '.5f')] for a, b in ps_times])
