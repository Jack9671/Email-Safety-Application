import React, { useState, useEffect } from "react";
import { BrowserRouter as Router, Routes, Route, NavLink } from "react-router-dom";
import axios from "axios";

// Pages
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
      <div className="page">
        {/* Sidebar */}
        <aside className="sidebar">
          <div className="sidebar__brand">
            <h1 className="brand__title">SecureMail</h1>
            <p className="brand__subtitle">Spam & Malware</p>
          </div>

          <div className="sidebar__nav">
            <NavLink to="/" className={({ isActive }) => "nav-item" + (isActive ? " nav-item--active" : "")}>
              📬 Inbox
            </NavLink>
            <NavLink to="/spam" className={({ isActive }) => "nav-item" + (isActive ? " nav-item--active" : "")}>
              📧 Spam Detection
            </NavLink>
            <NavLink to="/malware" className={({ isActive }) => "nav-item" + (isActive ? " nav-item--active" : "")}>
              🦠 Malware Scanner
            </NavLink>
          </div>

          <div className="sidebar__note">
            <p className="note__title">Next steps</p>
            <p className="note__desc">Wire actions to FastAPI endpoints (scan, classify, release…)</p>
          </div>
        </aside>

        {/* Main content */}
        <main className="content">
          <div className="container">
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
              <Route path="*" element={<p>Page not found</p>} />
            </Routes>
          </div>
        </main>
      </div>
    </Router>
  );
}

export default App;
