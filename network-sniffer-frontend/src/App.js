import React, { useEffect, useState } from 'react';
import './App.css';

function App() {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);

  const fetchLogs = async () => {
    try {
      const res = await fetch('http://localhost:5000/logs');
      const data = await res.json();
      setLogs(data);
      setLoading(false);
    } catch (err) {
      console.error('Error fetching logs:', err);
      setLoading(false);
    }
  };

  const startSniffer = async () => {
    try {
      const res = await fetch('http://localhost:5000/start-sniffer');
      const data = await res.json();
      alert(data.status);
    } catch (err) {
      alert('Failed to start sniffer.');
    }
  };

  useEffect(() => {
    fetchLogs();
  }, []);

  return (
    <div className="app">
      <header>
        <h1>Network Threat Detection Dashboard</h1>
        <div className="controls">
          <button onClick={startSniffer}>Start Sniffer</button>
          <button onClick={fetchLogs}>Refresh Logs</button>
        </div>
      </header>

      <main>
        {loading ? (
          <p>Loading logs...</p>
        ) : logs.length === 0 ? (
          <p>No threats detected.</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>ID</th>
                <th>Timestamp</th>
                <th>Source IP</th>
                <th>Destination IP</th>
                <th>Reason</th>
                <th>Country</th>
                <th>City</th>
              </tr>
            </thead>
            <tbody>
              {logs.map((log, index) => (
                <tr key={index}>
                  {log.map((item, i) => (
                    <td key={i}>{item}</td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </main>
    </div>
  );
}

export default App;