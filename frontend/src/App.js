import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import Header from './components/Header';
import Sidebar from './components/Sidebar';
import Dashboard from './pages/Dashboard';
import Blocklist from './pages/Blocklist';
import Logs from './pages/Logs';
import './index.css'; // Import the main CSS file

function App() {
  return (
    <Router>
      <Header />
      <div className="app-container">
        <Sidebar />
        <div className="main-content">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/blocklist" element={<Blocklist />} />
            <Route path="/logs" element={<Logs />} />
            {/* Add more routes for other features */}
          </Routes>
        </div>
      </div>
    </Router>
  );
}

export default App;