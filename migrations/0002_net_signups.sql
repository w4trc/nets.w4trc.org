CREATE TABLE IF NOT EXISTS net_signups (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  net_date TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('primary', 'backup')),
  operator_name TEXT NOT NULL,
  operator_email TEXT NOT NULL,
  operator_callsign TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  UNIQUE(net_date, role)
);

CREATE INDEX IF NOT EXISTS idx_net_signups_date ON net_signups (net_date ASC);