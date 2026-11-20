-- OSV records are now cached in a compacted form (only the fields the
-- scanner uses). Drop large records cached in raw form; they are fetched
-- again, compacted, on the next scan. Ubuntu kernel CVE records reached
-- several MB each because they list every binary package.
DELETE FROM osv_records WHERE length(data) > 65536;
