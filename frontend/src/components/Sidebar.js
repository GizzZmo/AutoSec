import React from 'react';
import { NavLink } from 'react-router-dom';

function Sidebar() {
  return (
    <aside className="sidebar">
      <nav>
        <ul>
          <li>
            <NavLink to="/" end>
              Dashboard
            </NavLink>
          </li>
          <li>
            <NavLink to="/blocklist">
              Dynamic Blocklist
            </NavLink>
          </li>
          <li>
            <NavLink to="/logs">
              Telemetry Logs
            </NavLink>
          </li>
          {/* Add more navigation links here */}
          <li>
            <NavLink to="/attack-surface" disabled>
              Attack Surface (WIP)
            </NavLink>
          </li>
          <li>
            <NavLink to="/behavioral-analysis" disabled>
              Behavioral Analysis (WIP)
            </NavLink>
          </li>
          <li>
            <NavLink to="/segmentation" disabled>
              Network Segmentation (WIP)
            </NavLink>
          </li>
          <li>
            <NavLink to="/incident-response" disabled>
              Incident Response (WIP)
            </NavLink>
          </li>
        </ul>
      </nav>
    </aside>
  );
}

export default Sidebar;