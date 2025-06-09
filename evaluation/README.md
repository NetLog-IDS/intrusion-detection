# Evaluation Scripts

- `evaluation_5.ipynb`: Notebook for evaluating ML and ksqlDB in predicting intrusions. You can ignore the inference time evaluation, it is only used if you want to evaluate on your local computer.
- `inference_time/evaluate_dos.py` and `inference_time/evaluate_ps.py`: Files for evaluation inference time in cloud. Send the whole `inference_time` folder to the VM before evaluating.

## Installing Environment for Inference Time Evaluation

- Send `inference_time` folder to the VM.
- Add test dataset in the form of CSV to the folder, then rename it as `test_final_2.csv`.
- Create new virtual environment using `python3 -m venv venv` and `source venv/bin/activate`.
- Install dependencies using `pip3 install -r requirements.txt`.
- Run the evaluation by using `python3 evaluate_dos.py` and `python3 evaluate_ps.py`.
- Look for `output_dos.txt` and `output_ps.txt` which includes the evaluated inference time.
