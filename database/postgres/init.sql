-- Create the blocklist_rules table
CREATE TABLE IF NOT EXISTS blocklist_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    type VARCHAR(50) NOT NULL, -- e.g., 'IP_SINGLE', 'IP_RANGE', 'COUNTRY', 'ORGANIZATION'
    value VARCHAR(255) NOT NULL UNIQUE, -- The IP, CIDR, country code, or organization name/ASN
    description TEXT,
    is_permanent BOOLEAN DEFAULT FALSE NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT TRUE NOT NULL,
    source VARCHAR(100) DEFAULT 'manual' NOT NULL, -- e.g., 'manual', 'threat_feed', 'behavioral_analysis'
    "createdAt" TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    "updatedAt" TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Add indexes for faster lookups
CREATE INDEX IF NOT EXISTS idx_blocklist_rules_type ON blocklist_rules (type);
CREATE INDEX IF NOT EXISTS idx_blocklist_rules_value ON blocklist_rules (value);
CREATE INDEX IF NOT EXISTS idx_blocklist_rules_is_active ON blocklist_rules (is_active);
CREATE INDEX IF NOT EXISTS idx_blocklist_rules_expires_at ON blocklist_rules (expires_at) WHERE expires_at IS NOT NULL;

-- Optional: Function to update "updatedAt" automatically
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW."updatedAt" = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Optional: Trigger to call the function before update
DROP TRIGGER IF EXISTS update_blocklist_rules_updated_at ON blocklist_rules;
CREATE TRIGGER update_blocklist_rules_updated_at
BEFORE UPDATE ON blocklist_rules
FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column();

-- Insert some sample data (optional)
INSERT INTO blocklist_rules (type, value, description, is_permanent, is_active, source) VALUES
('IP_SINGLE', '192.0.2.1', 'Known attacker IP from threat feed', TRUE, TRUE, 'threat_feed'),
('IP_RANGE', '10.0.0.0/8', 'Internal network range (example, usually not blocked)', TRUE, FALSE, 'manual'),
('COUNTRY', 'CN', 'Blocking traffic from China due to high risk', TRUE, TRUE, 'manual'),
('COUNTRY', 'RU', 'Blocking traffic from Russia', TRUE, TRUE, 'manual'),
('IP_SINGLE', '203.0.113.45', 'Temporary block for suspicious activity', FALSE, TRUE, 'manual');