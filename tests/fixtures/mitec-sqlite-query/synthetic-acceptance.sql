PRAGMA foreign_keys = ON;

CREATE TABLE ride_acceptance_records (
  record_id INTEGER PRIMARY KEY,
  label TEXT NOT NULL,
  category TEXT NOT NULL,
  amount NUMERIC,
  notes TEXT,
  payload BLOB
);

CREATE INDEX ride_acceptance_records_category
  ON ride_acceptance_records(category);

CREATE TABLE ride_acceptance_audit (
  audit_id INTEGER PRIMARY KEY,
  record_id INTEGER NOT NULL,
  old_label TEXT NOT NULL,
  new_label TEXT NOT NULL
);

CREATE TRIGGER ride_acceptance_record_update
AFTER UPDATE OF label ON ride_acceptance_records
BEGIN
  INSERT INTO ride_acceptance_audit(record_id, old_label, new_label)
  VALUES (OLD.record_id, OLD.label, NEW.label);
END;

CREATE TABLE ride_acceptance_import (
  external_id INTEGER PRIMARY KEY,
  label TEXT NOT NULL,
  amount NUMERIC,
  notes TEXT
);

INSERT INTO ride_acceptance_records
  (record_id, label, category, amount, notes, payload)
VALUES
  (1, 'Alpha', 'basic', 12.5, NULL, X'005241'),
  (2, 'Comma, quote "value"', 'roundtrip', 0, '', X''),
  (3, 'Café / 東京', 'unicode', -7.25, 'Synthetic text only', X'FF00');
