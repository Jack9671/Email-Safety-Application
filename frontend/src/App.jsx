import React, { useState, useEffect } from "react";
import { BrowserRouter as Router, Routes, Route, NavLink } from "react-router-dom";
import axios from "axios";

import InboxPage from "./pages/InboxPage";
import SpamPage from "./pages/SpamPage";
import MalwarePage from "./pages/MalwarePage";

const API_BASE_URL = "http://localhost:8000";

function App() {
  const [apiStatus, setApiStatus] = useState({ online: false, checking: true });
  const [spamResult, setSpamResult] = useState(null);
  const [malwareResult, setMalwareResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    checkApiStatus();
  }, []);

  const checkApiStatus = async () => {
    try {
      const res = await axios.get(`${API_BASE_URL}/health`, { timeout: 3000 });
      setApiStatus({
        online: res.data.xgboost_model_loaded || res.data.bert_model_loaded,
        checking: false,
        hasSpamDetection: res.data.bert_model_loaded,
        hasMalwareDetection: res.data.xgboost_model_loaded,
      });
    } catch {
      setApiStatus({ online: false, checking: false });
    }
  };

  const handleSpamCheck = async (text) => {
    setLoading(true);
    setError(null);
    setSpamResult(null);
    try {
      const res = await axios.post(`${API_BASE_URL}/scan/spam`, { email_text: text });
      setSpamResult(res.data);
    } catch (err) {
      setError(err.response?.data?.detail || "Error scanning spam");
    } finally {
      setLoading(false);
    }
  };

  const handlePEFileUpload = async (file) => {
    setLoading(true);
    setError(null);
    setMalwareResult(null);

    const formData = new FormData();
    formData.append("file", file);

    try {
      const res = await axios.post(`${API_BASE_URL}/scan/pe`, formData);
      setMalwareResult(res.data);
    } catch (err) {
      setError(err.response?.data?.detail || "Error scanning PE file");
    } finally {
      setLoading(false);
    }
  };

  return (
    <Router>
      <div className="app-container">
        <header className="header">
          <h1>Email Security System</h1>
          <p>AI-Powered Spam Detection & Malware Scanner</p>
        </header>

        <div className="tabs">
          <NavLink to="/" className="tab">📬 Inbox</NavLink>
          <NavLink to="/spam" className="tab">📧 Spam Detection</NavLink>
          <NavLink to="/malware" className="tab">🦠 Malware Scanner</NavLink>
        </div>

        <div className="card">
          <Routes>
            <Route path="/" element={<InboxPage apiStatus={apiStatus} />} />
            <Route
              path="/spam"
              element={
                <SpamPage
                  apiStatus={apiStatus}
                  loading={loading}
                  error={error}
                  spamResult={spamResult}
                  onCheck={handleSpamCheck}
                />
              }
            />
            <Route
              path="/malware"
              element={
                <MalwarePage
                  apiStatus={apiStatus}
                  loading={loading}
                  error={error}
                  malwareResult={malwareResult}
                  onUpload={handlePEFileUpload}
                />
              }
            />
          </Routes>
        </div>

        <footer className="footer">
          <p>
            Email Security System © 2025 | 
            <a href="http://localhost:8000/docs" target="_blank" rel="noopener noreferrer">
              API Documentation
            </a>
          </p>
        </footer>
      </div>
    </Router>
  );
}

export default App;
