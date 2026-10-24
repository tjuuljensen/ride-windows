# MiTeC SQLite Query synthetic acceptance fixtures

These fixtures contain synthetic rows only. Use them only on a disposable
Windows VM after staging the pinned `package.mitec-sqlite-query` candidate.
Never open personal, production, forensic, or other evidence databases.

`synthetic-acceptance.sql` creates a small schema with an index, an update
trigger, NULL and empty values, Unicode text, quoted punctuation, and short BLOB
sentinels. `synthetic-import.csv` contains three unrelated import rows with CSV
quoting and an empty field. Neither file contains or references user data.

## Acceptance procedure

1. Create a new database under a run-owned temporary directory in the VM. Open
   that database in MiTeC SQLite Query and run `synthetic-acceptance.sql` in its
   SQL Editor. Confirm the three seeded rows and schema objects appear.
2. Run a read-only SELECT, then update a synthetic label and verify both the
   edited value and the trigger row in `ride_acceptance_audit`. Confirm the
   successful statements appear in SQL History.
3. Use Table Editor to edit another synthetic row. Re-query it in SQL Editor and
   verify the change. Inspect the table structure, index, trigger and one BLOB
   sentinel without opening any outside file.
4. Import `synthetic-import.csv` into `ride_acceptance_import`; verify three rows,
   the quoted comma/text, and the empty string. Export the table or a SELECT result
   to a run-owned CSV and check the result in the same temporary directory.
5. Export a synthetic SELECT to SQL and XML using the publisher-described
   exporters. Inspect only these generated files. Do not import XML until the
   fixture format has been matched to the publisher's DataPacket 2.0 contract.
6. Close the database and the application. Restore the original database bytes
   from the run's saved copy, then compare SHA-256. Keep this database-file
   recovery result separate from RIDE's package saved-run restore evidence.

Record the application version, result of each step, output hashes, temporary
file cleanup, and exact database recovery. If the app prompts for network update,
license, account, or an external database connection, stop that subtest and record
the prompt; do not accept terms or connect to a service as part of this fixture.
This manual GUI procedure is a prepared test, not Windows acceptance. The package
still has no supported target until a disposable-VM run passes and its separately
recorded build-provenance and recovery gates are resolved.
