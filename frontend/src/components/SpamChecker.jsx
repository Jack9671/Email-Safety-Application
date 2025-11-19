import React, { useState } from 'react';

function SpamChecker({ onCheck, loading, apiStatus }) {
  const [emailText, setEmailText] = useState('');

  const handleSubmit = (e) => {
    e.preventDefault();
    if (emailText.trim()) {
      onCheck(emailText);
    }
  };

  const sampleEmails = [
    {
      label: 'Legitimate Email',
      text: 'Hi John, Are we still meeting for lunch tomorrow at 12pm? Let me know if you can make it. Thanks!'
    },
    {
      label: 'Potential Spam',
      text: 'CONGRATULATIONS! You have WON $1,000,000! Click here NOW to claim your prize before it expires! Limited time offer!!!'
    },
    {
      label: 'Business Email',
      text: 'Dear customer, your package has been shipped and will arrive in 2-3 business days. Track your order using tracking code XYZ123.'
    }
  ];

  const loadSample = (text) => {
    setEmailText(text);
  };

  return (
    <div className="spam-checker">
      <form onSubmit={handleSubmit}>
        <div className="form-group">
          <label htmlFor="emailText">
            <span className="icon">📧</span>
            Email Text to Analyze
          </label>
          <textarea
            id="emailText"
            value={emailText}
            onChange={(e) => setEmailText(e.target.value)}
            placeholder="Paste your email text here..."
            rows={8}
            disabled={loading || !apiStatus.online}
            required
          />
          <div className="char-count">
            {emailText.length} characters
          </div>
        </div>

        <div className="sample-emails">
          <p className="sample-label">Quick Test:</p>
          <div className="sample-buttons">
            {sampleEmails.map((sample, index) => (
              <button
                key={index}
                type="button"
                className="sample-button"
                onClick={() => loadSample(sample.text)}
                disabled={loading}
              >
                {sample.label}
              </button>
            ))}
          </div>
        </div>

        <button
          type="submit"
          className="submit-button"
          disabled={loading || !emailText.trim() || !apiStatus.online}
        >
          {loading ? (
            <>
              <span className="spinner"></span>
              Analyzing...
            </>
          ) : (
            <>
              <span>🔍</span>
              Check for Spam
            </>
          )}
        </button>

        {!apiStatus.online && (
          <div className="alert alert-warning">
            <span>⚠️</span>
            <span>API is offline. Please start the backend server.</span>
          </div>
        )}
      </form>
    </div>
  );
}

export default SpamChecker;
