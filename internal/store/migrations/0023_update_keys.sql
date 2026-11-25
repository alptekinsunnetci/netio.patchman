-- Release signing keys (base64 Ed25519, JSON array) the agent requires agent
-- updates to be signed with; empty when it checks SHA-256 only.
ALTER TABLE hosts ADD COLUMN update_keys TEXT NOT NULL DEFAULT '[]';
