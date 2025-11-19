import React, { useState, useEffect } from 'react';
import axios from 'axios';
import ModelInfo from './components/ModelInfo';
import PEFileUpload from './components/PEFileUpload';
import PredictionResult from './components/PredictionResult';
import SpamChecker from './components/SpamChecker';
import SpamResult from './components/SpamResult';
import EmailInbox from './components/EmailInbox';

const API_BASE_URL = 'http://localhost:8000';

function App() {
  const [activeTab, setActiveTab] = useState('inbox');
  const [apiStatus, setApiStatus] = useState({ online: false, checking: true });
  const [modelInfo, setModelInfo] = useState(null);
  const [spamResult, setSpamResult] = useState(null);
  const [malwareResult, setMalwareResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    checkApiStatus();
    fetchModelInfo();
  }, []);

  const checkApiStatus = async () => {
    try {
      const response = await axios.get(`${API_BASE_URL}/health`, { timeout: 3000 });
      setApiStatus({ 
        online: response.data.xgboost_model_loaded || response.data.bert_model_loaded, 
        checking: false,
        hasSpamDetection: response.data.bert_model_loaded,
        hasMalwareDetection: response.data.xgboost_model_loaded
      });
    } catch (err) {
      setApiStatus({ online: false, checking: false });
    }
  };

  const fetchModelInfo = async () => {
    try {
      const response = await axios.get(`${API_BASE_URL}/model/info`);
      setModelInfo(response.data);
    } catch (err) {
      console.error('Failed to fetch model info:', err);
    }
  };

  const handleSpamCheck = async (emailText) => {
    setLoading(true);
    setError(null);
    setSpamResult(null);

    try {
      const response = await axios.post(`${API_BASE_URL}/scan/spam`, {
        email_text: emailText
      });
      console.log('Spam check result:', response.data);
      setSpamResult(response.data);
    } catch (err) {
      console.error('Spam check error:', err);
      setError(err.response?.data?.detail || err.message || 'Failed to check spam. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handlePEFileUpload = async (file) => {
    setLoading(true);
    setError(null);
    setMalwareResult(null);

    console.log('Uploading file:', file.name, 'Size:', file.size);

    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await axios.post(`${API_BASE_URL}/scan/pe`, formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });
      console.log('Scan result:', response.data);
      setMalwareResult(response.data);
    } catch (err) {
      console.error('Upload error:', err);
      console.error('Error response:', err.response);
      setError(err.response?.data?.detail || err.message || 'Failed to scan PE file. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="app-container">
      <header className="header">
        <h1>Email Security System</h1>
        <p>AI-Powered Spam Detection & Malware Scanner</p>
      </header>

      <div className="main-content">
        <div>
          <div className="tabs">
            <button
              className={`tab ${activeTab === 'inbox' ? 'active' : ''}`}
              onClick={() => {
                setActiveTab('inbox');
                setError(null);
              }}
            >
              <span>📬</span>
              Email Inbox
            </button>
            <button
              className={`tab ${activeTab === 'spam' ? 'active' : ''}`}
              onClick={() => {
                setActiveTab('spam');
                setError(null);
              }}
              disabled={!apiStatus.hasSpamDetection}
            >
              <span>📧</span>
              Spam Detection
            </button>
            <button
              className={`tab ${activeTab === 'malware' ? 'active' : ''}`}
              onClick={() => {
                setActiveTab('malware');
                setError(null);
              }}
              disabled={!apiStatus.hasMalwareDetection}
            >
              <span>🦠</span>
              Malware Scanner
            </button>
          </div>

          <div className="card">
            {activeTab === 'inbox' ? (
              <>
                <EmailInbox apiStatus={apiStatus} />
              </>
            ) : activeTab === 'spam' ? (
              <>
                <h2>
                  <span className="icon">📧</span>
                  Check Email for Spam
                </h2>
                <p className="card-description">
                  Analyze email text using advanced BERT neural network to detect spam and phishing attempts
                </p>

                {error && (
                  <div className="alert alert-error">
                    <span>⚠️</span>
                    <span>{error}</span>
                  </div>
                )}

                <SpamChecker 
                  onCheck={handleSpamCheck}
                  loading={loading}
                  apiStatus={apiStatus}
                />
              </>
            ) : (
              <>
                <h2>
                  <span className="icon">🔍</span>
                  Scan PE File for Malware
                </h2>
                <p className="card-description">
                  Upload Windows executable files (.exe, .dll, .sys) to detect malware using machine learning
                </p>

                {error && (
                  <div className="alert alert-error">
                    <span>⚠️</span>
                    <span>{error}</span>
                  </div>
                )}

                <PEFileUpload 
                  onUpload={handlePEFileUpload} 
                  loading={loading}
                  apiStatus={apiStatus}
                />
              </>
            )}
          </div>

          {activeTab === 'spam' && spamResult && (
            <SpamResult result={spamResult} />
          )}

          {activeTab === 'malware' && malwareResult && (
            <PredictionResult prediction={malwareResult} />
          )}
        </div>
      </div>

      <footer className="footer">
        <p>
          Email Security System © 2025 | 
          <a href="http://localhost:8000/docs" target="_blank" rel="noopener noreferrer"> API Documentation</a>
        </p>
      </footer>
    </div>
  );
}

export default App;
