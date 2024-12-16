-- ================ STORED KEYS ================

CREATE TABLE stored_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    team_id INTEGER REFERENCES teams(id),
    public_key CHAR(64) NOT NULL, -- hex
    secret_key TEXT NOT NULL, -- hex
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
);

CREATE TRIGGER stored_keys_update_trigger 
AFTER UPDATE ON stored_keys
BEGIN
    UPDATE stored_keys SET updated_at = DATETIME('now') 
    WHERE id = NEW.id;
END;


-- ================ AUTHORIZATIONS ================

CREATE TABLE authorizations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    stored_key_id INTEGER REFERENCES stored_keys(id),
    secret TEXT NOT NULL, -- secret connection uuid
    bunker_nsec TEXT NOT NULL,
    relays TEXT NOT NULL, -- array of relays
    policy TEXT NOT NULL, -- json
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
);

CREATE TRIGGER authorizations_update_trigger 
AFTER UPDATE ON authorizations
BEGIN
    UPDATE authorizations SET updated_at = DATETIME('now') 
    WHERE id = NEW.id;
END;


-- ================ USERS ================

CREATE TABLE users (
    public_key CHAR(64) PRIMARY KEY, -- hex
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
);

CREATE TRIGGER users_update_trigger 
AFTER UPDATE ON users
BEGIN
    UPDATE users SET updated_at = DATETIME('now') 
    WHERE public_key = NEW.public_key;
END;


-- ================ USER AUTHORIZATIONS ================

CREATE TABLE user_authorizations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_public_key CHAR(64) REFERENCES users(public_key),
    authorization_id INTEGER REFERENCES authorizations(id),
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
);

CREATE TRIGGER user_authorizations_update_trigger 
AFTER UPDATE ON user_authorizations
BEGIN
    UPDATE user_authorizations SET updated_at = DATETIME('now') 
    WHERE user_public_key = NEW.user_public_key AND authorization_id = NEW.authorization_id;
END;


-- ================ TEAMS ================

CREATE TABLE teams (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
);

CREATE TRIGGER teams_update_trigger 
AFTER UPDATE ON teams
BEGIN
    UPDATE teams SET updated_at = DATETIME('now') 
    WHERE id = NEW.id;
END;


-- ================ TEAM USERS ================

CREATE TABLE team_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    team_id INTEGER REFERENCES teams(id),
    user_public_key CHAR(64) REFERENCES users(public_key),
    role TEXT NOT NULL CHECK (role IN ('admin', 'member')),
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
);

CREATE TRIGGER team_users_update_trigger 
AFTER UPDATE ON team_users
BEGIN
    UPDATE team_users SET updated_at = DATETIME('now') 
    WHERE id = NEW.id;
END;


-- ================ INDEXES ================

CREATE INDEX stored_keys_public_key_idx ON stored_keys (public_key);
CREATE INDEX stored_keys_team_id_idx ON stored_keys (team_id);

CREATE INDEX authorizations_stored_key_id_idx ON authorizations (stored_key_id);
CREATE UNIQUE INDEX authorizations_secret_idx ON authorizations (secret);

CREATE INDEX user_authorizations_user_public_key_idx ON user_authorizations (user_public_key);
CREATE INDEX user_authorizations_authorization_id_idx ON user_authorizations (authorization_id);
CREATE UNIQUE INDEX user_authorizations_user_public_key_authorization_id_idx ON user_authorizations (user_public_key, authorization_id);

CREATE UNIQUE INDEX users_public_key_idx ON users (public_key);

CREATE INDEX teams_name_idx ON teams (name);

CREATE INDEX team_users_team_id_idx ON team_users (team_id);
CREATE INDEX team_users_user_public_key_idx ON team_users (user_public_key);
CREATE UNIQUE INDEX team_users_team_id_user_public_key_idx ON team_users (team_id, user_public_key);
