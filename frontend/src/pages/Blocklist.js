import React, { useState, useEffect } from 'react';
import api from '../services/api';

const RULE_TYPES = {
  IP_SINGLE: 'IP_SINGLE',
  IP_RANGE: 'IP_RANGE',
  COUNTRY: 'COUNTRY',
  ORGANIZATION: 'ORGANIZATION',
};

function Blocklist() {
  const [rules, setRules] = useState([]);
  const [newRule, setNewRule] = useState({
    type: RULE_TYPES.IP_SINGLE,
    value: '',
    description: '',
    is_permanent: true,
    expires_at: '',
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [successMessage, setSuccessMessage] = useState(null);

  useEffect(() => {
    fetchRules();
  }, []);

  const fetchRules = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await api.get('/rules');
      setRules(response.data);
    } catch (err) {
      console.error('Error fetching rules:', err);
      setError('Failed to fetch rules. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleChange = (e) => {
    const { name, value, type, checked } = e.target;
    setNewRule(prev => ({
      ...prev,
      [name]: type === 'checkbox' ? checked : value,
    }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);
    setSuccessMessage(null);

    try {
      const ruleToCreate = { ...newRule };
      if (ruleToCreate.is_permanent) {
        delete ruleToCreate.expires_at;
      } else if (ruleToCreate.expires_at) {
        // Ensure expires_at is a valid ISO string for backend
        ruleToCreate.expires_at = new Date(ruleToCreate.expires_at).toISOString();
      } else {
        setError('Temporary rules require an expiry date.');
        return;
      }

      const response = await api.post('/rules', ruleToCreate);
      setRules(prev => [response.data, ...prev]);
      setNewRule({
        type: RULE_TYPES.IP_SINGLE,
        value: '',
        description: '',
        is_permanent: true,
        expires_at: '',
      });
      setSuccessMessage('Rule added successfully!');
      setTimeout(() => setSuccessMessage(null), 3000);
    } catch (err) {
      console.error('Error adding rule:', err);
      setError(err.response?.data?.message || 'Failed to add rule. Please check your input.');
    }
  };

  const handleDelete = async (id) => {
    if (!window.confirm('Are you sure you want to delete this rule?')) {
      return;
    }
    setError(null);
    setSuccessMessage(null);
    try {
      await api.delete(`/rules/${id}`);
      setRules(prev => prev.filter(rule => rule.id !== id));
      setSuccessMessage('Rule deleted successfully!');
      setTimeout(() => setSuccessMessage(null), 3000);
    } catch (err) {
      console.error('Error deleting rule:', err);
      setError(err.response?.data?.message || 'Failed to delete rule.');
    }
  };

  const getStatus = (rule) => {
    if (!rule.is_active) return <span className="status-inactive">Inactive</span>;
    if (!rule.is_permanent && new Date(rule.expires_at) <= new Date()) {
      return <span className="status-expired">Expired</span>;
    }
    return <span className="status-active">Active</span>;
  };

  return (
    <div>
      <h2>Dynamic IP Blocklist</h2>

      {error && <p style={{ color: 'red' }}>{error}</p>}
      {successMessage && <p style={{ color: 'lime' }}>{successMessage}</p>}

      <h3>Add New Rule</h3>
      <form onSubmit={handleSubmit}>
        <div className="form-group">
          <label htmlFor="type">Rule Type:</label>
          <select id="type" name="type" value={newRule.type} onChange={handleChange} required>
            {Object.values(RULE_TYPES).map(type => (
              <option key={type} value={type}>{type.replace('_', ' ')}</option>
            ))}
          </select>
        </div>
        <div className="form-group">
          <label htmlFor="value">Value (IP, CIDR, Country Code, Organization):</label>
          <input
            type="text"
            id="value"
            name="value"
            value={newRule.value}
            onChange={handleChange}
            placeholder={
              newRule.type === RULE_TYPES.IP_SINGLE ? 'e.g., 192.168.1.1' :
              newRule.type === RULE_TYPES.IP_RANGE ? 'e.g., 192.168.1.0/24' :
              newRule.type === RULE_TYPES.COUNTRY ? 'e.g., US, CN, RU' :
              'e.g., Google, AS15169'
            }
            required
          />
        </div>
        <div className="form-group">
          <label htmlFor="description">Description (Optional):</label>
          <textarea
            id="description"
            name="description"
            value={newRule.description}
            onChange={handleChange}
            rows="3"
          ></textarea>
        </div>
        <div className="form-group">
          <label>
            <input
              type="checkbox"
              name="is_permanent"
              checked={newRule.is_permanent}
              onChange={handleChange}
            />
            Permanent Rule
          </label>
        </div>
        {!newRule.is_permanent && (
          <div className="form-group">
            <label htmlFor="expires_at">Expires At:</label>
            <input
              type="datetime-local"
              id="expires_at"
              name="expires_at"
              value={newRule.expires_at}
              onChange={handleChange}
              required={!newRule.is_permanent}
            />
          </div>
        )}
        <button type="submit">Add Rule</button>
      </form>

      <h3 style={{ marginTop: '40px' }}>Existing Rules</h3>
      {loading ? (
        <p>Loading rules...</p>
      ) : rules.length === 0 ? (
        <p>No rules found. Add a new rule above.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Type</th>
              <th>Value</th>
              <th>Description</th>
              <th>Source</th>
              <th>Status</th>
              <th>Expires At</th>
              <th>Created At</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {rules.map(rule => (
              <tr key={rule.id}>
                <td>{rule.type.replace('_', ' ')}</td>
                <td>{rule.value}</td>
                <td>{rule.description}</td>
                <td>{rule.source}</td>
                <td>{getStatus(rule)}</td>
                <td>{rule.is_permanent ? 'N/A' : new Date(rule.expires_at).toLocaleString()}</td>
                <td>{new Date(rule.createdAt).toLocaleString()}</td>
                <td>
                  <button onClick={() => handleDelete(rule.id)} style={{ backgroundColor: '#ff0000', color: '#fff' }}>Delete</button>
                  {/* Add an Edit button/modal here for full functionality */}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

export default Blocklist;