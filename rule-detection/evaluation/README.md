# Rule-Based Detection using ksqlDB

Queries and scripts for rule-based detection using ksqlDB. Below are the description for each file:

- `queries.sql`: ksqlDB queries for port scan and DoS Slowloris. Modified from [Zenika/ids-ksql](https://github.com/Zenika/ids-ksql.git) to integrate with the infrastructure and monitoring.
- `evaluation`:
  - `consumer/script.py`: Collects raw result from `PORT_SCAN` or `DOS` topic in Kafka and turn it into JSON.
  - `ksql_evaluation_dos.py` and `ksql_evaluation_ps.py`: Tags which packet are malicious in PCAP file. It will return malicious packet indexes (e.g. first packet in a PCAP has index 0). It uses the results of `consumer/script.py` and the PCAP file.

## Running `consumer/script.py`

- Change the `topic_name` to the intrusion topic
- Go to the `consumer` folder and run with `python3 script.py`.
