import React from 'react';

function SpamResult({ result }) {
  if (!result) return null;

  const { is_spam, label, confidence, probabilities } = result;

  return (
    <div className="card result-card">
      <h2>
        <span className="icon">📊</span>
        Analysis Result
      </h2>

      <div className={`detection-status ${is_spam ? 'spam' : 'safe'}`}>
        <div className="status-icon">
          {is_spam ? '⚠️' : '✅'}
        </div>
        <div className="status-content">
          <h3>{label}</h3>
          <p>
            {is_spam 
              ? 'This email appears to be spam or malicious content'
              : 'This email appears to be legitimate'
            }
          </p>
        </div>
      </div>

      <div className="metric-group">
        <div className="metric-item">
          <div className="metric-label">Classification</div>
          <div className={`metric-value ${is_spam ? 'spam' : 'ham'}`}>
            {label}
          </div>
        </div>
        <div className="metric-item">
          <div className="metric-label">Confidence</div>
          <div className="metric-value">
            {(confidence * 100).toFixed(2)}%
          </div>
        </div>
      </div>

      <div className="confidence-bar-container">
        <div className="confidence-label">Confidence Level</div>
        <div className="confidence-bar">
          <div
            className={`confidence-fill ${is_spam ? 'spam' : 'safe'}`}
            style={{ width: `${confidence * 100}%` }}
          >
            {(confidence * 100).toFixed(1)}%
          </div>
        </div>
      </div>

      <div className="probabilities-section">
        <h4>Detailed Probabilities</h4>
        <div className="probability-bars">
          <div className="probability-item">
            <div className="probability-header">
              <span className="probability-label">
                <span className="dot safe"></span>
                Ham (Legitimate)
              </span>
              <span className="probability-value">
                {(probabilities.ham * 100).toFixed(2)}%
              </span>
            </div>
            <div className="probability-bar">
              <div
                className="probability-fill safe"
                style={{ width: `${probabilities.ham * 100}%` }}
              ></div>
            </div>
          </div>

          <div className="probability-item">
            <div className="probability-header">
              <span className="probability-label">
                <span className="dot spam"></span>
                Spam (Suspicious)
              </span>
              <span className="probability-value">
                {(probabilities.spam * 100).toFixed(2)}%
              </span>
            </div>
            <div className="probability-bar">
              <div
                className="probability-fill spam"
                style={{ width: `${probabilities.spam * 100}%` }}
              ></div>
            </div>
          </div>
        </div>
      </div>

      <div className={`recommendation ${is_spam ? 'danger' : 'success'}`}>
        <h4>
          <span className="icon">💡</span>
          Recommendation
        </h4>
        {is_spam ? (
          <ul>
            <li>❌ Do not click any links in this email</li>
            <li>❌ Do not download any attachments</li>
            <li>❌ Do not reply with personal information</li>
            <li>🗑️ Delete this email immediately</li>
            <li>🚫 Mark as spam in your email client</li>
          </ul>
        ) : (
          <ul>
            <li>✅ This email appears safe to read</li>
            <li>✅ Links are likely legitimate</li>
            <li>⚠️ Still verify sender identity if unexpected</li>
            <li>⚠️ Be cautious with sensitive information</li>
          </ul>
        )}
      </div>
    </div>
  );
}

export default SpamResult;
