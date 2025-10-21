CREATE TABLE IF NOT EXISTS nets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  net_date TEXT NOT NULL,
  net_control_callsign TEXT NOT NULL,
  net_control_name TEXT NOT NULL,
  check_ins_count INTEGER NOT NULL,
  check_ins_list TEXT NOT NULL,
  comments TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE INDEX IF NOT EXISTS idx_nets_date_desc ON nets (net_date DESC, id DESC);