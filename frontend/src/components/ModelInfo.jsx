import React from 'react';

function ModelInfo({ apiStatus, modelInfo, onRefresh }) {
  return (
    <div className="card">
      <h2>
        <span className="icon">📊</span>
        Model Information
      </h2>

      <div className={`status-badge ${apiStatus.online ? 'online' : 'offline'}`}>
        <span className="status-indicator"></span>
        {apiStatus.checking ? 'Checking...' : apiStatus.online ? 'API Online' : 'API Offline'}
      </div>

      {!apiStatus.online && !apiStatus.checking && (
        <div className="alert alert-error">
          <span>⚠️</span>
          <span>
            API server is not running. Please start it with: <code>uvicorn app:app --reload</code>
          </span>
        </div>
      )}

      {modelInfo && (
        <>
          {modelInfo.spam_detection && (
            <div className="model-section">
              <h3 style={{ marginTop: '20px', marginBottom: '15px', color: '#667eea' }}>
                📧 Spam Detection Model
              </h3>
              <div className="model-info">
                <div className="info-item">
                  <label>Model Type</label>
                  <div className="value">{modelInfo.spam_detection.model_type}</div>
                </div>
                <div className="info-item">
                  <label>Model Name</label>
                  <div className="value">{modelInfo.spam_detection.model_name}</div>
                </div>
                <div className="info-item">
                  <label>Vocabulary</label>
                  <div className="value">{modelInfo.spam_detection.vocab_size.toLocaleString()}</div>
                </div>
                <div className="info-item">
                  <label>Device</label>
                  <div className="value">{modelInfo.spam_detection.device}</div>
                </div>
              </div>
            </div>
          )}

          {modelInfo.malware_detection && (
            <div className="model-section">
              <h3 style={{ marginTop: '30px', marginBottom: '15px', color: '#764ba2' }}>
                🦠 Malware Detection Model
              </h3>
              <div className="model-info">
                <div className="info-item">
                  <label>Model Type</label>
                  <div className="value">{modelInfo.malware_detection.model_type}</div>
                </div>
                <div className="info-item">
                  <label>Features</label>
                  <div className="value">{modelInfo.malware_detection.n_features}</div>
                </div>
                <div className="info-item">
                  <label>Classes</label>
                  <div className="value">{modelInfo.malware_detection.n_classes}</div>
                </div>
                <div className="info-item">
                  <label>Class Names</label>
                  <div className="value" style={{ fontSize: '0.85rem' }}>
                    {modelInfo.malware_detection.class_names.join(', ')}
                  </div>
                </div>
              </div>

              <h4 style={{ marginTop: '20px', marginBottom: '10px', color: '#555', fontSize: '1rem' }}>
                Test Performance Metrics
              </h4>
              <div className="metrics-grid">
                <div className="metric-card">
                  <label>MCC</label>
                  <div className="value">{(modelInfo.malware_detection.test_metrics.mcc * 100).toFixed(1)}%</div>
                </div>
                <div className="metric-card">
                  <label>F1 Score</label>
                  <div className="value">{(modelInfo.malware_detection.test_metrics.f1 * 100).toFixed(1)}%</div>
                </div>
                <div className="metric-card">
                  <label>Precision</label>
                  <div className="value">{(modelInfo.malware_detection.test_metrics.precision * 100).toFixed(1)}%</div>
                </div>
                <div className="metric-card">
                  <label>Recall</label>
                  <div className="value">{(modelInfo.malware_detection.test_metrics.recall * 100).toFixed(1)}%</div>
                </div>
              </div>
            </div>
          )}
        </>
      )}

      <button 
        className="btn btn-secondary" 
        onClick={onRefresh}
        style={{ width: '100%', marginTop: '20px' }}
      >
        🔄 Refresh Status
      </button>
    </div>
  );
}

export default ModelInfo;
