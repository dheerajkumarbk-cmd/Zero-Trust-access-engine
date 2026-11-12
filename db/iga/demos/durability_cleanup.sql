-- durability_cleanup.sql : removes the marker row.
SET search_path = iga, public;
DELETE FROM department WHERE name = 'DEMO_DURABILITY_MARKER';
SELECT count(*) AS marker_rows_left FROM department WHERE name = 'DEMO_DURABILITY_MARKER';
