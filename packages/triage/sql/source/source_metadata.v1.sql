/* Metadata-only contract query. It reads no source-table rows. */
SELECT
    columns.table_schema AS database,
    columns.table_name AS "table",
    columns.column_name AS column_name,
    columns.data_type AS column_type,
    tables.table_type AS engine
FROM information_schema.columns AS columns
INNER JOIN information_schema.tables AS tables
    ON columns.table_schema = tables.table_schema AND columns.table_name = tables.table_name
WHERE columns.table_schema = 'flow'
  AND columns.table_name IN ('activity_1m', 'host_load_5m', 'dns_pairs', 'long_flows')
ORDER BY columns.table_schema, columns.table_name, columns.ordinal_position
