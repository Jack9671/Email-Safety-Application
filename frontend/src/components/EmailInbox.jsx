import React, { useState } from 'react';
import Plot from 'react-plotly.js';

function EmailInbox({ apiStatus }) {
  const [emailConfig, setEmailConfig] = useState({
    email_address: '',
    app_password: '',
    provider: 'gmail'
  });
  
  const [emails, setEmails] = useState([]);
  const [selectedEmail, setSelectedEmail] = useState(null);
  const [scanResult, setScanResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [fetching, setFetching] = useState(false);
  const [error, setError] = useState(null);
  const [showConfig, setShowConfig] = useState(true);

  const handleFetchEmails = async (e) => {
    e.preventDefault();
    setFetching(true);
    setError(null);
    setEmails([]);

    try {
      const response = await fetch('http://localhost:8000/email/fetch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(emailConfig)
      });

      const data = await response.json();

      if (data.success) {
        setEmails(data.emails);
        setShowConfig(false);
      } else {
        setError(data.message || 'Failed to fetch emails');
      }
    } catch (err) {
      setError(err.message || 'Failed to connect to API');
    } finally {
      setFetching(false);
    }
  };

  const handleScanEmail = async (emailId) => {
    setLoading(true);
    setError(null);
    setScanResult(null);

    try {
      const response = await fetch('http://localhost:8000/email/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ...emailConfig,
          email_id: emailId
        })
      });

      const data = await response.json();
      
      if (data.success) {
        setScanResult(data);
        setSelectedEmail(emailId);
      } else {
        setError('Failed to scan email');
      }
    } catch (err) {
      setError(err.message || 'Failed to scan email');
    } finally {
      setLoading(false);
    }
  };

  const getThreatBadge = (email) => {
    // This is a placeholder - actual threat detection happens on scan
    if (email.attachment_count > 0) {
      return <span className="badge badge-warning">⚠️ Has Attachments</span>;
    }
    return null;
  };

  return (
    <div className="email-inbox">
      {showConfig && (
        <div className="card">
          <h2>
            <span className="icon">📬</span>
            Connect to Your Email
          </h2>
          
          <div className="alert alert-info">
            <span>ℹ️</span>
            <div>
              <strong>Important:</strong> You need an App Password (not your regular password)
              <ul style={{ marginTop: '10px', paddingLeft: '20px' }}>
                <li><strong>Gmail:</strong> <a href="https://myaccount.google.com/apppasswords" target="_blank" rel="noopener noreferrer">Generate App Password</a></li>
                <li><strong>Outlook:</strong> <a href="https://account.live.com/proofs/AppPassword" target="_blank" rel="noopener noreferrer">Generate App Password</a></li>
              </ul>
            </div>
          </div>

          <form onSubmit={handleFetchEmails}>
            <div className="form-group">
              <label>Email Provider</label>
              <select
                value={emailConfig.provider}
                onChange={(e) => setEmailConfig({...emailConfig, provider: e.target.value})}
                disabled={fetching}
              >
                <option value="gmail">Gmail</option>
                <option value="outlook">Outlook/Hotmail</option>
                <option value="yahoo">Yahoo</option>
              </select>
            </div>

            <div className="form-group">
              <label>Email Address</label>
              <input
                type="email"
                value={emailConfig.email_address}
                onChange={(e) => setEmailConfig({...emailConfig, email_address: e.target.value})}
                placeholder="your.email@gmail.com"
                required
                disabled={fetching}
              />
            </div>

            <div className="form-group">
              <label>App Password</label>
              <input
                type="password"
                value={emailConfig.app_password}
                onChange={(e) => setEmailConfig({...emailConfig, app_password: e.target.value})}
                placeholder="App-specific password"
                required
                disabled={fetching}
              />
            </div>

            {error && (
              <div className="alert alert-error">
                <span>⚠️</span>
                <span>{error}</span>
              </div>
            )}

            <button
              type="submit"
              className="submit-button"
              disabled={fetching || !apiStatus.online}
            >
              {fetching ? (
                <>
                  <span className="spinner"></span>
                  Connecting...
                </>
              ) : (
                <>
                  <span>📬</span>
                  Fetch Emails
                </>
              )}
            </button>
          </form>
        </div>
      )}

      {!showConfig && emails.length > 0 && (
        <div className="email-list-container">
          <div className="email-list-header">
            <h2>
              <span className="icon">📧</span>
              Inbox ({emails.length} emails)
            </h2>
            <button
              className="btn btn-secondary"
              onClick={() => {
                setShowConfig(true);
                setEmails([]);
                setScanResult(null);
              }}
            >
              🔄 Change Account
            </button>
          </div>

          <div className="email-grid">
            <div className="email-list">
              {emails.map((email) => (
                <div
                  key={email.id}
                  className={`email-item ${selectedEmail === email.id ? 'selected' : ''}`}
                  onClick={() => handleScanEmail(email.id)}
                >
                  <div className="email-item-header">
                    <div className="email-from">{email.from}</div>
                    <div className="email-date">{new Date(email.date).toLocaleDateString()}</div>
                  </div>
                  <div className="email-subject">{email.subject || '(No Subject)'}</div>
                  <div className="email-preview">{email.body_preview}</div>
                  {email.has_attachments && (
                    <div className="email-attachments">
                      📎 {email.attachment_count} attachment{email.attachment_count > 1 ? 's' : ''}
                      {email.attachment_names && email.attachment_names.length > 0 && (
                        <span className="attachment-list">
                          : {email.attachment_names.join(', ')}
                        </span>
                      )}
                    </div>
                  )}
                  {getThreatBadge(email)}
                </div>
              ))}
            </div>

            <div className="email-detail">
              {loading && (
                <div className="loading-state">
                  <div className="spinner-large"></div>
                  <p>Scanning email for threats...</p>
                </div>
              )}

              {!loading && !scanResult && (
                <div className="empty-state">
                  <span className="icon-large">📧</span>
                  <p>Select an email to scan for spam and malware</p>
                </div>
              )}

              {!loading && scanResult && (
                <div className="scan-result-detail">
                  <h3>Scan Results</h3>
                  
                  <div className="email-info">
                    <div><strong>From:</strong> {scanResult.email.from}</div>
                    <div><strong>Subject:</strong> {scanResult.email.subject}</div>
                    <div><strong>Date:</strong> {scanResult.email.date}</div>
                  </div>

                  {scanResult.spam_scan && (
                    <>
                      <div className={`threat-card ${scanResult.spam_scan.is_spam ? 'danger' : 'safe'}`}>
                        <h4>
                          {scanResult.spam_scan.is_spam ? '🚨 Spam Detected' : '✅ Not Spam'}
                        </h4>
                        <div className="threat-details">
                          <div>Label: <strong>{scanResult.spam_scan.label}</strong></div>
                          <div>Confidence: <strong>{(scanResult.spam_scan.confidence * 100).toFixed(1)}%</strong></div>
                          <div className="probability-bars-small">
                            <div>Ham: {(scanResult.spam_scan.probabilities.ham * 100).toFixed(1)}%</div>
                            <div>Spam: {(scanResult.spam_scan.probabilities.spam * 100).toFixed(1)}%</div>
                          </div>
                        </div>
                      </div>
                      
                      {/* Pie Chart for Spam/Ham Confidence */}
                      <div className="chart-container">
                        <h4 style={{fontSize: '1rem', marginBottom: '12px', color: '#333'}}>Confidence Distribution</h4>
                        <Plot
                          data={[
                            {
                              values: [
                                scanResult.spam_scan.probabilities.ham * 100,
                                scanResult.spam_scan.probabilities.spam * 100
                              ],
                              labels: ['Ham (Safe)', 'Spam'],
                              type: 'pie',
                              hole: 0.4,
                              marker: {
                                colors: ['#51cf66', '#ff6b6b']
                              },
                              textinfo: 'label+percent',
                              textposition: 'auto',
                              hovertemplate: '<b>%{label}</b><br>Confidence: %{value:.1f}%<extra></extra>'
                            }
                          ]}
                          layout={{
                            width: 350,
                            height: 300,
                            margin: { t: 20, b: 20, l: 20, r: 20 },
                            showlegend: true,
                            legend: {
                              orientation: 'h',
                              x: 0.5,
                              xanchor: 'center',
                              y: -0.1
                            },
                            paper_bgcolor: 'transparent',
                            plot_bgcolor: 'transparent',
                            font: {
                              family: 'Inter, sans-serif',
                              size: 12
                            }
                          }}
                          config={{
                            displayModeBar: false,
                            responsive: true
                          }}
                        />
                      </div>
                    </>
                  )}

                  {scanResult.malware_scans && scanResult.malware_scans.length > 0 && (
                    <div>
                      <h4>Attachment Scans ({scanResult.pe_files_scanned} PE files)</h4>
                      {scanResult.malware_scans.map((scan, idx) => (
                        <div key={idx} className={`threat-card ${scan.is_malware ? 'danger' : 'safe'}`}>
                          <h5>
                            {scan.is_malware ? '🦠 Malware Detected' : '✅ Clean'}
                          </h5>
                          <div className="threat-details">
                            <div>File: <strong>{scan.filename}</strong></div>
                            <div>Type: <strong>{scan.predicted_class}</strong></div>
                            <div>Confidence: <strong>{(scan.confidence * 100).toFixed(1)}%</strong></div>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}

                  {scanResult.threats_detected && (
                    <div className="alert alert-danger">
                      <span>⚠️</span>
                      <strong>Threats Detected!</strong> This email contains malicious content. Do not interact with it.
                    </div>
                  )}

                  {!scanResult.threats_detected && (
                    <div className="alert alert-success">
                      <span>✅</span>
                      <strong>Email appears safe.</strong> No threats detected.
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default EmailInbox;
