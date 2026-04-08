# ual-timeliner

**ual-timeliner** (User Access Logging Timeliner) is a forensic tool for parsing Windows User Access Logging (UAL) databases. It extracts historical access data from Windows Server 2012+ servers to reconstruct user and host activity timelines from offline triage collections and forensic images.

Originally derived from [KStrike](https://github.com/brimorlabs/KStrike) by BriMor Labs.

## Features

- **Multi-Table Extraction**: Parses `CLIENTS`, `DNS`, and `ROLE_ACCESS` tables from UAL ESE databases.
- **Dirty Database Recovery**: Automatically patches ESE databases in Dirty Shutdown state for offline parsing.
- **Timestamp Correlation**: Merges `InsertDate`, `LastAccess`, `FirstSeen`, `LastSeen`, and historical `Day###` columns into a unified chronological view.
- **High Performance**: Built on [Polars](https://pola.rs/) for fast processing of large UAL datasets.
- **Standardized Output**: Export to CSV, Excel (XLSX), SQLite, Parquet, or K2T (Timesketch JSONL).
- **Deduplication**: Intelligently handles overlapping data between `Current.mdb` and historical GUID databases.
- **Role GUID Resolution**: Maps known Windows Server role GUIDs to human-readable names.

## Installation

Requires Python 3.9+.

```bash
# Clone the repository and install
pip install -e .

# The 'ual-timeliner' command is now available
ual-timeliner --help
```

### Dependencies

- `polars` — High-performance DataFrame library
- `libesedb-python` — For reading ESE (.mdb) databases
- `openpyxl` — For Excel output

## Usage

```bash
# Basic usage — prints CSV to stdout
ual-timeliner path/to/UAL_data/

# Export to Excel
ual-timeliner path/to/UAL_data/ -f xlsx -o timeline.xlsx

# Recursive search with full forensic output (all columns + Day### entries)
ual-timeliner path/to/UAL_data/ -r --full-output -f parquet -o timeline.parquet

# Split large output into multiple files (CSV and K2T only)
ual-timeliner path/to/UAL_data/ -f csv -o timeline.csv --split-rows 100000

# Single file input
ual-timeliner path/to/Current.mdb -o timeline.csv
```

### Sample Output (Default)

```text
timestamp (UTC)              | timestamp_desc | source_table | authenticated_user | ip_address     | host_name | user          | total_accesses | role_name                        | source_file
2021-06-05T18:47:19.633980   | FirstSeen      | ROLE_ACCESS  |                    |                |           |               |                | Print and Document Services      | Current.mdb
2021-06-12T23:47:14.167754   | FirstSeen      | ROLE_ACCESS  |                    |                |           |               |                | Active Directory Domain Services | Current.mdb
2021-06-12T23:47:21.232323   | InsertDate     | CLIENTS      | lab\dc-1$          | ::1            | dc-1      |               | 310            | Active Directory Domain Services | Current.mdb
2021-06-12T23:48:45.468902   | InsertDate     | CLIENTS      | lab\dc-1$          | fe80::e15c:... | dc-1      |               | 101            | Active Directory Domain Services | Current.mdb
2021-06-12T23:49:44.255548   | InsertDate     | CLIENTS      | lab\dc-1$          | 10.0.0.10      | dc-1      |               | 1              | File Server                      | Current.mdb
2021-06-13T14:26:58.359685   | InsertDate     | CLIENTS      | lab\administrator  | 10.0.0.10      |           | administrator | 1              | File Server                      | Current.mdb
2021-06-23T11:47:37.042000   | LastSeen       | DNS          |                    | 10.0.0.123     | Laptop-Bob|               |                |                                  | Current.mdb
```

### Sample Output (`--full-output`)

Full output adds `access_count`, `role_guid`, `tenant_id`, and `client_name` columns, and includes Day### historical access events:

```text
timestamp (UTC)              | timestamp_desc | source_table | authenticated_user | ip_address | host_name | user          | access_count | role_name   | role_guid                              | tenant_id
2021-06-12T00:00:00.000000   | Day163         | CLIENTS      | lab\administrator  | fe80::...  |           | administrator | 1            | File Server | {10A9226F-50EE-49D8-A393-9A501D47CE04} | {00000000-...}
2021-06-12T00:00:00.000000   | Day163         | CLIENTS      | lab\dc-2$          | 10.0.0.20  | dc-2      |               | 4            | File Server | {10A9226F-50EE-49D8-A393-9A501D47CE04} | {00000000-...}
```

### Output Formats

| Format | Flag | Description |
| :--- | :--- | :--- |
| CSV | `-f csv` | Comma-separated values (default). Prints to stdout if no `-o` specified. |
| Excel | `-f xlsx` | Streaming XLSX with auto-filter and 900K row sheet splitting. |
| SQLite | `-f sqlite` | SQLite database with a `timeline` table. |
| Parquet | `-f parquet` | Compressed columnar storage for large-scale analytics. |
| K2T | `-f k2t` | Timesketch-compatible JSONL with `message`, `datetime`, and `timestamp_desc` fields. |

### Timesketch Integration

When using `-f k2t`, a dedicated OpenSearch mapping file is provided at:
`resources/ual-timeliner-opensearch-mapping.json`

This ensures fields like `ip_address` (type: `ip`) and `datetime` (type: `date`) are correctly typed in OpenSearch for Timesketch ingestion.

## UAL Background

User Access Logging (UAL) is a built-in Windows Server feature that records client access to server roles. UAL databases are stored as ESE (Extensible Storage Engine) files at `%SystemRoot%\System32\LogFiles\SUM\`:

| File | Purpose |
| :--- | :--- |
| `Current.mdb` | Active database being written to |
| `{GUID}.mdb` | Yearly snapshots, rotated every 24 hours |
| `SystemIdentity.mdb` | Server identity info (skipped by this tool) |

Data is retained for up to 3 years and covers roles including File Server, AD DS, DHCP, DNS, IIS, RDS, WSUS, and more. Third-party software can also register with UAL.

For more information:

- [KStrike article on UAL forensics](https://dfir-kev.medium.com/kstrike-2aff53eaecce)
- [Microsoft: Get Started with User Access Logging](https://learn.microsoft.com/windows-server/administration/user-access-logging/get-started-with-user-access-logging)

### Sample Data

[Original KStrike sample UAL databases](https://github.com/brimorlabs/KStrike/tree/master/Sample_UAL)

## License

MIT License. See [LICENSE](LICENSE).

This project is derived from [KStrike](https://github.com/brimorlabs/KStrike) by Brian Moran (BriMor Labs). The original KStrike license is preserved in [LICENSE-KSTRIKE](LICENSE-KSTRIKE).
