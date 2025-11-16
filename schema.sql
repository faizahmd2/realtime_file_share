-- Files table
CREATE TABLE IF NOT EXISTS files (
    id TEXT PRIMARY KEY,
    unique_id TEXT NOT NULL,
    file_key TEXT NOT NULL,
    original_name TEXT NOT NULL,
    size INTEGER NOT NULL,
    content_type TEXT,
    expiry_minutes INTEGER NOT NULL,
    expire_at INTEGER NOT NULL,
    uploaded_at INTEGER NOT NULL,
    status TEXT DEFAULT 'completed',
    session_id TEXT
);

-- Upload sessions table
CREATE TABLE IF NOT EXISTS upload_sessions (
    session_id TEXT PRIMARY KEY,
    session_token TEXT NOT NULL,
    unique_id TEXT NOT NULL,
    file_key TEXT NOT NULL,
    file_name TEXT NOT NULL,
    file_size INTEGER NOT NULL,
    expiry_minutes INTEGER NOT NULL,
    client_fingerprint TEXT,
    status TEXT DEFAULT 'pending',
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    upload_started INTEGER DEFAULT 0,
    upload_completed INTEGER DEFAULT 0,
    completed_at INTEGER
);

-- Indexes for better performance
CREATE INDEX IF NOT EXISTS idx_files_unique_id ON files(unique_id);
CREATE INDEX IF NOT EXISTS idx_files_expire ON files(expire_at);
CREATE INDEX IF NOT EXISTS idx_files_uploaded ON files(uploaded_at);
CREATE INDEX IF NOT EXISTS idx_sessions_token ON upload_sessions(session_token);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON upload_sessions(expires_at);