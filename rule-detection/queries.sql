SET 'auto.offset.reset'='earliest';

-- Init a Stream from the topic
CREATE STREAM NETWORK_TRAFFIC_SOURCE
(
	"TIMESTAMP" BIGINT,
	"sniff_time" BIGINT,
	"layers" STRUCT<
		"network" STRUCT<
			"version" VARCHAR,
			"src" VARCHAR,
			"dst" VARCHAR
		>,
		"transport" STRUCT<
			"type" VARCHAR,
			"src_port" VARCHAR,
			"dst_port" VARCHAR,
			"seq" VARCHAR,
			"ack" VARCHAR,
			"flags" VARCHAR,
			"window" VARCHAR,
			"header_length" VARCHAR,
			"payload_length" VARCHAR
		>
	>
) 
WITH (KAFKA_TOPIC='network-traffic', TIMESTAMP='TIMESTAMP', VALUE_FORMAT='JSON');

CREATE STREAM NETWORK_TRAFFIC_FLAT 
AS SELECT
	"TIMESTAMP",

	"sniff_time" as sniff_time,

	"layers"->"network"->"version" as network_version,
	"layers"->"network"->"src" as network_src,
	"layers"->"network"->"dst" as network_dst,

	"layers"->"transport"->"type" as transport_type,
	"layers"->"transport"->"src_port" as transport_src_port,
	"layers"->"transport"->"dst_port" as transport_dst_port,
	"layers"->"transport"->"seq" as transport_seq,
	"layers"->"transport"->"ack" as transport_ack,
	"layers"->"transport"->"flags" as transport_flags,
	"layers"->"transport"->"window" as transport_window,
	"layers"->"transport"->"header_length" as transport_header_length,
	"layers"->"transport"->"payload_length" as transport_payload_length
FROM NETWORK_TRAFFIC_SOURCE;

-- Port Scan
-- DROP TABLE IF EXISTS port_scan;
CREATE TABLE port_scan
AS SELECT
   network_src AS id,
   network_src + '' AS ip_src,
   WINDOWSTART as timestamp_start,
   WINDOWEND as timestamp_end,
   (CASE WHEN COUNT_DISTINCT(network_dst + transport_dst_port) > 1000 THEN 'DETECTED' ELSE 'NOT DETECTED' END) AS status,
   COUNT_DISTINCT(network_dst + transport_dst_port) AS count,
   COUNT(*) AS count_packets,
   MIN(sniff_time) AS sniff_timestamp_start
FROM NETWORK_TRAFFIC_FLAT
WINDOW TUMBLING (SIZE 60000 SECONDS)
GROUP BY network_src;

-- Original Here:
-- DROP TABLE IF EXISTS potential_port_scan_attacks;
-- CREATE TABLE potential_port_scan_attacks
-- AS SELECT
--    ip_source,
--    COUNT_DISTINCT(ip_dest + tcp_port_dest)
-- FROM NETWORK_TRAFFIC_FLAT
-- WINDOW TUMBLING (SIZE 60 SECONDS)
-- GROUP BY ip_source
-- HAVING COUNT_DISTINCT(ip_dest + tcp_port_dest) > 1000;

-- DoS (Slowloris)
-- DROP TABLE IF EXISTS dos;
CREATE TABLE dos
AS SELECT
	network_dst AS id,
	network_dst + '' AS ip_dst,
	WINDOWSTART as timestamp_start,
   	WINDOWEND as timestamp_end,
	(CASE WHEN count(*) > 100 THEN 'DETECTED' ELSE 'NOT DETECTED' END) AS status,
	COUNT(*) AS count_packets,
	MIN(sniff_time) AS sniff_timestamp_start
FROM NETWORK_TRAFFIC_FLAT
WINDOW TUMBLING (SIZE 60000 SECONDS)
WHERE (CAST(transport_flags AS INT) / 16) % 2 = 1 AND (CAST(transport_flags AS INT) / 4) % 2 = 1
GROUP BY network_dst;

-- Original Here:
-- DROP TABLE IF EXISTS potential_slowloris_attacks;
-- CREATE TABLE potential_slowloris_attacks
-- AS SELECT
-- 	ip_dest, 
-- 	count(*) as count_connection_reset
-- FROM NETWORK_TRAFFIC_FLAT
-- WINDOW TUMBLING (SIZE 60 SECONDS)
-- WHERE tcp_flags_ack = '1' AND tcp_flags_reset = '1'
-- GROUP BY ip_dest
-- HAVING count(*) > 100;
