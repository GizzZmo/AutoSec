-- Create users table
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    "firstName" VARCHAR(50) NOT NULL,
    "lastName" VARCHAR(50) NOT NULL,
    role VARCHAR(20) DEFAULT 'viewer' NOT NULL CHECK (role IN ('admin', 'analyst', 'operator', 'viewer')),
    "isActive" BOOLEAN DEFAULT TRUE NOT NULL,
    "lastLogin" TIMESTAMP WITH TIME ZONE,
    "failedLoginAttempts" INTEGER DEFAULT 0 NOT NULL,
    "lockoutUntil" TIMESTAMP WITH TIME ZONE,
    "mfaEnabled" BOOLEAN DEFAULT FALSE NOT NULL,
    "mfaSecret" VARCHAR(255),
    "emailVerified" BOOLEAN DEFAULT FALSE NOT NULL,
    "emailVerificationToken" VARCHAR(255),
    "passwordResetToken" VARCHAR(255),
    "passwordResetExpires" TIMESTAMP WITH TIME ZONE,
    preferences JSON DEFAULT '{}',
    "createdAt" TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    "updatedAt" TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Add indexes for users table
CREATE INDEX IF NOT EXISTS idx_users_email ON users (email);
CREATE INDEX IF NOT EXISTS idx_users_username ON users (username);
CREATE INDEX IF NOT EXISTS idx_users_role ON users (role);
CREATE INDEX IF NOT EXISTS idx_users_is_active ON users ("isActive");
CREATE INDEX IF NOT EXISTS idx_users_lockout_until ON users ("lockoutUntil") WHERE "lockoutUntil" IS NOT NULL;

-- Create blocklist_rules table
CREATE TABLE IF NOT EXISTS blocklist_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    type VARCHAR(50) NOT NULL, -- e.g., 'IP_SINGLE', 'IP_RANGE', 'COUNTRY', 'ORGANIZATION'
    value VARCHAR(255) NOT NULL UNIQUE, -- The IP, CIDR, country code, or organization name/ASN
    description TEXT,
    is_permanent BOOLEAN DEFAULT FALSE NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT TRUE NOT NULL,
    source VARCHAR(100) DEFAULT 'manual' NOT NULL, -- e.g., 'manual', 'threat_feed', 'behavioral_analysis'
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
    "createdAt" TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    "updatedAt" TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Add indexes for blocklist_rules table
CREATE INDEX IF NOT EXISTS idx_blocklist_rules_type ON blocklist_rules (type);
CREATE INDEX IF NOT EXISTS idx_blocklist_rules_value ON blocklist_rules (value);
CREATE INDEX IF NOT EXISTS idx_blocklist_rules_is_active ON blocklist_rules (is_active);
CREATE INDEX IF NOT EXISTS idx_blocklist_rules_expires_at ON blocklist_rules (expires_at) WHERE expires_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_blocklist_rules_created_by ON blocklist_rules (created_by);

-- Create audit_logs table for tracking changes
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    table_name VARCHAR(50) NOT NULL,
    record_id UUID NOT NULL,
    action VARCHAR(20) NOT NULL CHECK (action IN ('INSERT', 'UPDATE', 'DELETE')),
    old_values JSON,
    new_values JSON,
    changed_by UUID REFERENCES users(id) ON DELETE SET NULL,
    ip_address INET,
    user_agent TEXT,
    "createdAt" TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Add indexes for audit_logs table
CREATE INDEX IF NOT EXISTS idx_audit_logs_table_name ON audit_logs (table_name);
CREATE INDEX IF NOT EXISTS idx_audit_logs_record_id ON audit_logs (record_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs (action);
CREATE INDEX IF NOT EXISTS idx_audit_logs_changed_by ON audit_logs (changed_by);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs ("createdAt");

-- Function to update "updatedAt" automatically
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW."updatedAt" = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Triggers for updatedAt
DROP TRIGGER IF EXISTS update_users_updated_at ON users;
CREATE TRIGGER update_users_updated_at
BEFORE UPDATE ON users
FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_blocklist_rules_updated_at ON blocklist_rules;
CREATE TRIGGER update_blocklist_rules_updated_at
BEFORE UPDATE ON blocklist_rules
FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column();

-- Function for audit logging
CREATE OR REPLACE FUNCTION audit_trigger_function()
RETURNS TRIGGER AS $$
DECLARE
    audit_action TEXT;
    old_values JSON;
    new_values JSON;
BEGIN
    -- Determine action
    IF TG_OP = 'INSERT' THEN
        audit_action = 'INSERT';
        old_values = NULL;
        new_values = row_to_json(NEW);
    ELSIF TG_OP = 'UPDATE' THEN
        audit_action = 'UPDATE';
        old_values = row_to_json(OLD);
        new_values = row_to_json(NEW);
    ELSIF TG_OP = 'DELETE' THEN
        audit_action = 'DELETE';
        old_values = row_to_json(OLD);
        new_values = NULL;
    END IF;

    -- Insert audit record
    INSERT INTO audit_logs (table_name, record_id, action, old_values, new_values, "createdAt")
    VALUES (
        TG_TABLE_NAME,
        COALESCE(NEW.id, OLD.id),
        audit_action,
        old_values,
        new_values,
        NOW()
    );

    -- Return appropriate value
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    ELSE
        RETURN NEW;
    END IF;
END;
$$ LANGUAGE plpgsql;

-- Create audit triggers for important tables
DROP TRIGGER IF EXISTS audit_users_trigger ON users;
CREATE TRIGGER audit_users_trigger
AFTER INSERT OR UPDATE OR DELETE ON users
FOR EACH ROW
EXECUTE FUNCTION audit_trigger_function();

DROP TRIGGER IF EXISTS audit_blocklist_rules_trigger ON blocklist_rules;
CREATE TRIGGER audit_blocklist_rules_trigger
AFTER INSERT OR UPDATE OR DELETE ON blocklist_rules
FOR EACH ROW
EXECUTE FUNCTION audit_trigger_function();

-- Insert default admin user (password: 'Admin123!' - change in production!)
INSERT INTO users (username, email, password, "firstName", "lastName", role, "isActive", "emailVerified") VALUES
('admin', 'admin@autosec.local', '$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/CXL9lhBGTDBzJCgKu', 'System', 'Administrator', 'admin', TRUE, TRUE)
ON CONFLICT (username) DO NOTHING;

-- Insert sample blocklist rules
INSERT INTO blocklist_rules (type, value, description, is_permanent, is_active, source) VALUES
('IP_SINGLE', '192.0.2.1', 'Known attacker IP from threat feed', TRUE, TRUE, 'threat_feed'),
('IP_RANGE', '10.0.0.0/8', 'Internal network range (example, usually not blocked)', TRUE, FALSE, 'manual'),
('COUNTRY', 'CN', 'Blocking traffic from China due to high risk', TRUE, TRUE, 'manual'),
('COUNTRY', 'RU', 'Blocking traffic from Russia', TRUE, TRUE, 'manual'),
('IP_SINGLE', '203.0.113.45', 'Temporary block for suspicious activity', FALSE, TRUE, 'manual')
ON CONFLICT (value) DO NOTHING;