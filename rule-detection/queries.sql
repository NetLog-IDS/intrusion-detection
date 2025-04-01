SET 'auto.offset.reset'='earliest';

-- Init a Stream from the topic
CREATE STREAM NETWORK_TRAFFIC_SOURCE
(
	"TIMESTAMP" BIGINT,
	"layers" STRUCT<
		-- "frame" STRUCT<
		-- 	"time" VARCHAR,
		-- 	"number" VARCHAR,
		-- 	"length" VARCHAR,
		-- 	"protocols" VARCHAR
		-- >,
		-- "data_link" STRUCT<
		-- 	"src" VARCHAR,
		-- 	"dst" VARCHAR,
		-- 	"type" VARCHAR,
		-- 	"header_size" VARCHAR,
		-- 	"trailer_size" VARCHAR
		-- >,
		"network" STRUCT<
			"version" VARCHAR,
			-- "hdr_len" VARCHAR,
			-- "tos" VARCHAR,
			-- "len" VARCHAR,
			-- "id" VARCHAR,
			-- "flags" VARCHAR,
			-- "flags_rb" VARCHAR,
			-- "flags_df" VARCHAR,
			-- "flags_mf" VARCHAR,
			-- "frag_offset" VARCHAR,
			-- "ttl" VARCHAR,
			-- "proto" VARCHAR,
			-- "checksum" VARCHAR,
			"src" VARCHAR,
			"dst" VARCHAR
		>,
		"transport" STRUCT<
			"type" VARCHAR,
			"src_port" VARCHAR,
			"dst_port" VARCHAR,
			-- "seq" VARCHAR,
			-- "ack" VARCHAR,
			-- "dataofs" VARCHAR,
			"flags" VARCHAR,
			"window" VARCHAR,
			-- "checksum" VARCHAR,
			"header_length" VARCHAR,
			"payload_length" VARCHAR
		>
	>
) 
WITH (KAFKA_TOPIC='network-traffic', TIMESTAMP='TIMESTAMP', VALUE_FORMAT='JSON');

-- CREATE STREAM NETWORK_TRAFFIC_STREAM AS SELECT * FROM NETWORK_TRAFFIC_SOURCE;

CREATE STREAM NETWORK_TRAFFIC_FLAT 
AS SELECT
	"TIMESTAMP",
	-- "layers"->"frame"->"protocols" as frame_protocols,
	-- "layers"->"frame"->"time" as frame_time,
	-- "layers"->"frame"->"number" as frame_number,
	-- "layers"->"frame"->"length" as frame_length,

	-- "layers"->"data_link"->"src" as data_link_src,
	-- "layers"->"data_link"->"dst" as data_link_dst,
	-- "layers"->"data_link"->"type" as data_link_type,
	-- "layers"->"data_link"->"header_size" as data_link_header_size,
	-- "layers"->"data_link"->"trailer_size" as data_link_trailer_size,

	"layers"->"network"->"version" as network_version,
	-- "layers"->"network"->"hdr_len" as network_hdr_len,
	-- "layers"->"network"->"tos" as network_tos,
	-- "layers"->"network"->"len" as network_len,
	-- "layers"->"network"->"id" as network_id,
	-- "layers"->"network"->"flags" as network_flags,
	-- "layers"->"network"->"flags_rb" as network_flags_rb,
	-- "layers"->"network"->"flags_df" as network_flags_df,
	-- "layers"->"network"->"flags_mf" as network_flags_mf,
	-- "layers"->"network"->"frag_offset" as network_frag_offset,
	-- "layers"->"network"->"ttl" as network_ttl,
	-- "layers"->"network"->"proto" as network_proto,
	-- "layers"->"network"->"checksum" as network_checksum,
	"layers"->"network"->"src" as network_src,
	"layers"->"network"->"dst" as network_dst,

	"layers"->"transport"->"type" as transport_type,
	"layers"->"transport"->"src_port" as transport_src_port,
	"layers"->"transport"->"dst_port" as transport_dst_port,
	-- "layers"->"transport"->"seq" as transport_seq,
	-- "layers"->"transport"->"ack" as transport_ack,
	-- "layers"->"transport"->"dataofs" as transport_dataofs,
	"layers"->"transport"->"flags" as transport_flags,
	"layers"->"transport"->"window" as transport_window,
	-- "layers"->"transport"->"checksum" as transport_checksum,
	"layers"->"transport"->"header_length" as transport_header_length,
	"layers"->"transport"->"payload_length" as transport_payload_length
FROM NETWORK_TRAFFIC_SOURCE;

-- Port Scan
DROP TABLE IF EXISTS port_scan;
CREATE TABLE port_scan
AS SELECT
   network_src AS id,
   network_src + '' AS ip_src,
   WINDOWSTART as timestamp_start,
   WINDOWEND as timestamp_end,
   (CASE WHEN COUNT_DISTINCT(network_dst + transport_dst_port) > 1000 THEN 'DETECTED' ELSE 'NOT DETECTED' END) AS status,
   COUNT_DISTINCT(network_dst + transport_dst_port) AS count,
   COUNT(*) AS count_packets
FROM NETWORK_TRAFFIC_FLAT
WINDOW TUMBLING (SIZE 60000 SECONDS)
GROUP BY network_src;

-- DROP TABLE IF EXISTS potential_port_scan_attacks_debug;
-- CREATE TABLE potential_port_scan_attacks_debug
-- AS SELECT
--    network_src AS id,
--    network_src + '' AS ip_src,
--    WINDOWSTART as timestamp_start,
--    WINDOWEND as timestamp_end,
--    (CASE WHEN COUNT_DISTINCT(network_dst + transport_dst_port) > 1000 THEN 'DETECTED' ELSE 'NOT DETECTED' END) AS status,
--    COUNT_DISTINCT(network_dst + transport_dst_port) AS distinct_ports
-- FROM NETWORK_TRAFFIC_FLAT
-- WINDOW TUMBLING (SIZE 60000 SECONDS)
-- GROUP BY network_src;

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
DROP TABLE IF EXISTS dos;
CREATE TABLE dos
AS SELECT
	network_dst AS id,
	network_dst + '' AS ip_dst,
	WINDOWSTART as timestamp_start,
   	WINDOWEND as timestamp_end,
	(CASE WHEN count(*) > 100 THEN 'DETECTED' ELSE 'NOT DETECTED' END) AS status
FROM NETWORK_TRAFFIC_FLAT
WINDOW TUMBLING (SIZE 60000 SECONDS)
WHERE (CAST('20' AS INT) / 16) % 2 = 1 AND (CAST('20' AS INT) / 4) % 2 = 1 -- TODO: wkwkwkwk jangan lupa ini yg '20'
GROUP BY network_dst;

-- DROP TABLE IF EXISTS potential_slowloris_attacks_debug;
-- CREATE TABLE potential_slowloris_attacks_debug
-- AS SELECT
-- 	network_dst AS id,
-- 	network_dst + '' AS ip_dst,
-- 	WINDOWSTART as timestamp_start,
--    	WINDOWEND as timestamp_end,
-- 	(CASE WHEN count(*) > 100 THEN 'DETECTED' ELSE 'NOT DETECTED' END) AS status,
-- 	count(*) as count_connection_reset
-- FROM NETWORK_TRAFFIC_FLAT
-- WINDOW TUMBLING (SIZE 60000 SECONDS)
-- WHERE (CAST('20' AS INT) / 16) % 2 = 1 AND (CAST('20' AS INT) / 4) % 2 = 1
-- GROUP BY network_dst;


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
