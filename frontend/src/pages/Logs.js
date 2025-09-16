import React, { useState, useEffect, useCallback } from 'react';
import api from '../services/api';

function Logs() {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [filters, setFilters] = useState({
    level: '',
    source: '',
    event_type: '',
    ip_address: '',
    search: '',
    page: 1,
    limit: 20,
  });
  const [pagination, setPagination] = useState({
    currentPage: 1,
    totalPages: 1,
    totalLogs: 0,
  });

  const fetchLogs = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const queryParams = new URLSearchParams(filters).toString();
      const response = await api.get(`/logs?${queryParams}`);
      setLogs(response.data.data);
      setPagination({
        currentPage: response.data.currentPage,
        totalPages: response.data.totalPages,
        totalLogs: response.data.totalLogs,
      });
    } catch (err) {
      console.error('Error fetching logs:', err);
      setError('Failed to fetch logs. Please try again.');
    } finally {
      setLoading(false);
    }
  }, [filters]);

  useEffect(() => {
    fetchLogs();
  }, [fetchLogs]); // Now properly includes fetchLogs dependency

  const handleFilterChange = (e) => {
    const { name, value } = e.target;
    setFilters(prev => ({ ...prev, [name]: value, page: 1 })); // Reset to page 1 on filter change
  };

  const handleSearchSubmit = (e) => {
    e.preventDefault();
    fetchLogs(); // Trigger fetch with current filters
  };

  const handlePageChange = (newPage) => {
    setFilters(prev => ({ ...prev, page: newPage }));
  };

  return (
    <div>
      <h2>Telemetry Logs</h2>

      {error && <p style={{ color: 'red' }}>{error}</p>}

      <form onSubmit={handleSearchSubmit} style={{ marginBottom: '20px', border: '1px solid #00ffff', padding: '15px', borderRadius: '5px', backgroundColor: '#1a1a2e' }}>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '15px' }}>
          <div className="form-group">
            <label htmlFor="level">Level:</label>
            <select id="level" name="level" value={filters.level} onChange={handleFilterChange}>
              <option value="">All</option>
              <option value="info">Info</option>
              <option value="warn">Warn</option>
              <option value="error">Error</option>
              <option value="debug">Debug</option>
              <option value="critical">Critical</option>
            </select>
          </div>
          <div className="form-group">
            <label htmlFor="source">Source:</label>
            <input type="text" id="source" name="source" value={filters.source} onChange={handleFilterChange} placeholder="e.g., firewall, application" />
          </div>
          <div className="form-group">
            <label htmlFor="event_type">Event Type:</label>
            <input type="text" id="event_type" name="event_type" value={filters.event_type} onChange={handleFilterChange} placeholder="e.g., login_failure, connection_attempt" />
          </div>
          <div className="form-group">
            <label htmlFor="ip_address">IP Address:</label>
            <input type="text" id="ip_address" name="ip_address" value={filters.ip_address} onChange={handleFilterChange} placeholder="e.g., 192.168.1.1" />
          </div>
          <div className="form-group" style={{ gridColumn: 'span 2' }}>
            <label htmlFor="search">Search (Message/Metadata):</label>
            <input type="text" id="search" name="search" value={filters.search} onChange={handleFilterChange} placeholder="Search keywords..." />
          </div>
        </div>
        <button type="submit" style={{ marginTop: '15px' }}>Apply Filters</button>
      </form>

      {loading ? (
        <p>Loading logs...</p>
      ) : logs.length === 0 ? (
        <p>No logs found matching your criteria.</p>
      ) : (
        <>
          <table>
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Level</th>
                <th>Source</th>
                <th>Event Type</th>
                <th>Message</th>
                <th>IP Address</th>
                <th>Country</th>
                <th>Organization</th>
                <th>User/Device</th>
              </tr>
            </thead>
            <tbody>
              {logs.map(log => (
                <tr key={log._id}>
                  <td>{new Date(log.timestamp).toLocaleString()}</td>
                  <td>{log.level}</td>
                  <td>{log.source}</td>
                  <td>{log.event_type}</td>
                  <td>{log.message}</td>
                  <td>{log.ip_address || 'N/A'}</td>
                  <td>{log.country || 'N/A'}</td>
                  <td>{log.organization || 'N/A'}</td>
                  <td>{log.user_id || log.device_id || 'N/A'}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <div className="pagination">
            <button onClick={() => handlePageChange(pagination.currentPage - 1)} disabled={pagination.currentPage <= 1}>
              Previous
            </button>
            <span>Page {pagination.currentPage} of {pagination.totalPages} ({pagination.totalLogs} total logs)</span>
            <button onClick={() => handlePageChange(pagination.currentPage + 1)} disabled={pagination.currentPage >= pagination.totalPages}>
              Next
            </button>
          </div>
        </>
      )}
    </div>
  );
}

export default Logs;