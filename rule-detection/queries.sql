SET 'auto.offset.reset'='earliest';

-- Init a Stream from the topic
CREATE STREAM NETWORK_TRAFFIC_SOURCE
(
	"TIMESTAMP" BIGINT,
	"layers" STRUCT<
		"frame" STRUCT<
			"time" VARCHAR,
			"number" INT,
			"length" INT,
			"protocols" VARCHAR
		>,
		"data_link" STRUCT<
			"src" VARCHAR,
			"dst" VARCHAR,
			"type" INT,
			"header_size" INT,
			"trailer_size" INT
		>,
		"network" STRUCT<
			"version" INT,
			"hdr_len" INT,
			"tos" INT,
			"len" INT,
			"id" INT,
			"flags" INT,
			"flags_rb" INT,
			"flags_df" INT,
			"flags_mf" INT,
			"frag_offset" INT,
			"ttl" INT,
			"proto" INT,
			"checksum" INT,
			"src" VARCHAR,
			"dst" VARCHAR
		>,
		"transport" STRUCT<
			"type" VARCHAR,
			"src_port" INT,
			"dst_port" INT,
			"seq" BIGINT,
			"ack" BIGINT,
			"dataofs" INT,
			"flags" INT,
			"window" INT,
			"checksum" INT,
			"header_length" INT,
			"payload_length" INT
		>
	>
) 
WITH (KAFKA_TOPIC='network-traffic', TIMESTAMP='TIMESTAMP', VALUE_FORMAT='JSON');

CREATE STREAM NETWORK_TRAFFIC_STREAM AS SELECT * FROM NETWORK_TRAFFIC_SOURCE;

-- Number of connection per ip per port
CREATE STREAM connections_ip_port
AS SELECT
	"layers"->"network"->"dst" as ip_dest, 
	"layers"->"transport"->"dst_port" as port_dest
FROM NETWORK_TRAFFIC_STREAM
WHERE
	"layers"->"network"->"dst" IS NOT NULL
	AND "layers"->"transport"->"dst_port" IS NOT NULL;

-- Detect Port Scan Attacks
CREATE TABLE port_scan
AS SELECT
	WINDOWSTART as window_start,
	ip_dest,
	CASE 
		WHEN COUNT(*) > 20 THEN 'DETECTED' 
	ELSE 'BENIGN' 
END AS status
FROM connections_ip_port
WINDOW TUMBLING (SIZE 60 SECONDS)
GROUP BY ip_dest;

-- Detect Slowloris attacks
-- CREATE TABLE potential_slowloris_attacks
-- AS SELECT
-- 	ip_dest, count(*) as count_connection_reset
-- FROM NETWORK_TRAFFIC_FLAT
-- WINDOW TUMBLING (SIZE 60 SECONDS)
-- WHERE tcp_flags_ack = '1' AND tcp_flags_reset = '1'
-- GROUP BY ip_dest
-- HAVING count(*) > 100;
