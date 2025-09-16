import React from 'react';

function Dashboard() {
  return (
    <div>
      <h2>System Overview</h2>
      <p>Welcome to the AutoSec CyberSec Operations Console.</p>
      <p>This dashboard provides a high-level overview of your network security posture.</p>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '20px', marginTop: '30px' }}>
        <div style={{ border: '1px solid #00ffff', padding: '20px', borderRadius: '5px', backgroundColor: '#1a1a2e' }}>
          <h3>Active Blocklist Rules</h3>
          <p style={{ fontSize: '2em', color: '#00ff00' }}>150</p>
          <p>Currently active rules protecting your perimeter.</p>
        </div>
        <div style={{ border: '1px solid #00ffff', padding: '20px', borderRadius: '5px', backgroundColor: '#1a1a2e' }}>
          <h3>Logs Ingested (24h)</h3>
          <p style={{ fontSize: '2em', color: '#00ffff' }}>1,234,567</p>
          <p>Total telemetry events processed in the last 24 hours.</p>
        </div>
        <div style={{ border: '1px solid #00ffff', padding: '20px', borderRadius: '5px', backgroundColor: '#1a1a2e' }}>
          <h3>Critical Alerts (7d)</h3>
          <p style={{ fontSize: '2em', color: '#ff0000' }}>5</p>
          <p>High-severity incidents requiring immediate attention.</p>
        </div>
        <div style={{ border: '1px solid #00ffff', padding: '20px', borderRadius: '5px', backgroundColor: '#1a1a2e' }}>
          <h3>Blocked Attempts (24h)</h3>
          <p style={{ fontSize: '2em', color: '#ffcc00' }}>87,654</p>
          <p>Connections denied by AutoSec blocklist rules.</p>
        </div>
      </div>

      <h3 style={{ marginTop: '40px' }}>Recent Activity Feed</h3>
      <ul style={{ listStyle: 'none', padding: 0 }}>
        <li style={{ borderBottom: '1px dashed #00ffff', padding: '10px 0' }}>
          <span style={{ color: '#00ff00' }}>[2025-07-23 16:05]</span> New IP_SINGLE rule added: 1.2.3.4 (Manual)
        </li>
        <li style={{ borderBottom: '1px dashed #00ffff', padding: '10px 0' }}>
          <span style={{ color: '#00ffff' }}>[2025-07-23 15:50]</span> Log ingestion spike detected (120% above baseline)
        </li>
        <li style={{ borderBottom: '1px dashed #00ffff', padding: '10px 0' }}>
          <span style={{ color: '#ff0000' }}>[2025-07-23 15:30]</span> Critical: Brute-force attempt detected from 203.0.113.10
        </li>
        <li style={{ borderBottom: '1px dashed #00ffff', padding: '10px 0' }}>
          <span style={{ color: '#00ff00' }}>[2025-07-23 15:00]</span> Country block for 'KP' updated (Threat Feed)
        </li>
      </ul>
    </div>
  );
}

export default Dashboard;