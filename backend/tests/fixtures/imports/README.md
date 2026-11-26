# Import test fixtures (generated)

Every file here was **written by hand for VulnSight's tests**. None is
real scanner output, and none contains third-party scan data:
- `sample.nessus` follows the Tenable `.nessus` v2 format;
- `sample-openvas.xml` follows the Greenbone GMP report XML format.

Hosts, plugin ids 900001+ and NVT OIDs ending 9000xx are made up. CVE
ids are real public identifiers.

The hostile inputs (XXE, an entity bomb, malformed XML) are built inline
in `tests/test_import.py`, so no exploit file sits in the repo.
