import json
from scapy.all import *
from datetime import datetime, timedelta

with open("./consumer/result_2_portscan.json") as file:
    results = json.loads(file.read())

# Deduplication
key_status = {}
cnt_duplicate = 0
for calc in results:
    key = (calc["IP_SRC"], calc['TIMESTAMP_START'], calc['TIMESTAMP_END'])

    new_value = calc['STATUS']
    if key in key_status:
        old_value = key_status[key]
        key_status[key] = new_value
        cnt_duplicate += 1
    key_status[key] = new_value

# Lookup Optimization
time_to_detected_ip: dict[tuple,set] = {}
for key, value in key_status.items():
    ip_src, time_start, time_end = key
    time_key = (time_start, time_end)
    if value == "DETECTED":
        if time_key not in time_to_detected_ip:
            time_to_detected_ip[time_key] = set()
        time_to_detected_ip[time_key].add(ip_src)

print(time_to_detected_ip)

# Check Packets
with PcapReader("/media/meervix/DATA/Projects/thesis/test.pcap") as pr:
    pcap_reader: PcapReader = pr

    detected_idxs: list[str] = []

    cnt_pcap = 0
    i = 0
    while True:
        if i % 100_000 == 0 and i > 0:
            print(i)

        try:
            packet = pcap_reader.read_packet()
        except:
            print(f"{i} packets have been iterated")
            break
            
        timestamp = int(packet.time * 1_000_000)

        dt = datetime.fromtimestamp(float(packet.time))
        previous_minute = dt.replace(second=0, microsecond=0)
        next_minute = previous_minute + timedelta(minutes=1)

        prev_min_micro = int(previous_minute.timestamp() * 1_000_000)
        next_min_micro = int(next_minute.timestamp() * 1_000_000)

        time_key = (prev_min_micro, next_min_micro)
        try:
            ip_src = packet[IP].src
            ip_src_check = time_key in time_to_detected_ip and ip_src in time_to_detected_ip[time_key]
            if ip_src_check:
                detected_idxs.append(str(i))
        except:
            pass

        i += 1

with open("detected_ksql_2_portscan.txt", "w") as file:
    file.write("\n".join(detected_idxs))
