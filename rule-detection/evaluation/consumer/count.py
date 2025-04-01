import json

with open("result.json") as file:
    results = json.loads(file.read())

key_to_cnt = {}

for calc in results:
    key = calc['IP_SRC'] + "-" + str(calc["TIMESTAMP_START"]) + "-" + str(calc["TIMESTAMP_END"])

    new_value = calc['COUNT_PACKETS']
    if key in key_to_cnt:
        old_value = key_to_cnt[key]
        key_to_cnt[key] = new_value
        print(f"DUPLICATE FOUND: {old_value} to {new_value}")
    key_to_cnt[key] = new_value

cnt = 0
for key, value in key_to_cnt.items():
    cnt += value
print(cnt)

# TODO: bikin script buat deduplicate sebelum dievaluasi