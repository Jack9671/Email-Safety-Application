import React from 'react';

function PredictionResult({ prediction }) {
  if (!prediction) return null;

  // Handle PE file scan results
  const { 
    filename, 
    sha256, 
    is_malware, 
    predicted_class, 
    confidence, 
    probabilities,
    file_size 
  } = prediction;

  const sortedProbs = Object.entries(probabilities)
    .sort(([, a], [, b]) => b - a);

  const formatFileSize = (bytes) => {
    if (!bytes) return 'N/A';
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(2) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
  };

  const getMalwareIcon = () => {
    if (predicted_class === 'Benign') return '✅';
    return '⚠️';
  };

  const getMalwareColor = () => {
    if (predicted_class === 'Benign') return '#10b981';
    return '#ef4444';
  };

  return (
    <div className="results-card">
      <div className="prediction-result">
        <h3 style={{ marginBottom: '20px', textAlign: 'center' }}>
          {getMalwareIcon()} Scan Result
        </h3>
        
        {/* File Information */}
        <div className="file-info-section" style={{
          background: '#f9fafb',
          padding: '15px',
          borderRadius: '8px',
          marginBottom: '20px'
        }}>
          <h4 style={{ marginBottom: '10px', color: '#555' }}>File Information</h4>
          <div style={{ fontSize: '0.9rem', color: '#666' }}>
            <div style={{ marginBottom: '5px' }}>
              <strong>Filename:</strong> {filename}
            </div>
            <div style={{ marginBottom: '5px' }}>
              <strong>Size:</strong> {formatFileSize(file_size)}
            </div>
            <div style={{ 
              wordBreak: 'break-all', 
              fontSize: '0.85rem',
              marginTop: '8px',
              padding: '8px',
              background: 'white',
              borderRadius: '4px'
            }}>
              <strong>SHA256:</strong><br />
              <code style={{ color: '#667eea' }}>{sha256}</code>
            </div>
          </div>
        </div>

        {/* Detection Status */}
        <div className={`alert ${is_malware ? 'alert-danger' : 'alert-success'}`} style={{
          marginBottom: '20px',
          border: `2px solid ${getMalwareColor()}`,
          background: is_malware ? '#fef2f2' : '#f0fdf4'
        }}>
          <span style={{ fontSize: '1.2rem' }}>{getMalwareIcon()}</span>
          <div>
            <strong style={{ fontSize: '1.1rem' }}>
              {is_malware ? 'MALWARE DETECTED' : 'FILE IS SAFE'}
            </strong>
            <div style={{ marginTop: '5px', fontSize: '0.9rem' }}>
              Detected as: <strong style={{ color: getMalwareColor() }}>
                {predicted_class}
              </strong>
            </div>
          </div>
        </div>

        {/* Confidence Level */}
        <div style={{ marginBottom: '20px' }}>
          <label style={{
            display: 'block',
            marginBottom: '10px',
            fontSize: '1.1rem',
            fontWeight: '600',
            color: '#555'
          }}>
            Confidence Level
          </label>
          <div className="confidence-bar">
            <div
              className="confidence-fill"
              style={{ 
                width: `${confidence * 100}%`,
                background: `linear-gradient(90deg, ${getMalwareColor()}, ${getMalwareColor()}dd)`
              }}
            >
              {(confidence * 100).toFixed(2)}%
            </div>
          </div>
        </div>

        {/* All Malware Type Probabilities */}
        <div className="probabilities-list">
          <h4 style={{ marginBottom: '15px', color: '#555' }}>
            Malware Type Probabilities
          </h4>
          {sortedProbs.map(([className, prob]) => {
            const isBenign = className === 'Benign';
            const isDetected = className === predicted_class;
            
            return (
              <div key={className} className="probability-item">
                <span style={{ 
                  fontWeight: isDetected ? '700' : '600', 
                  minWidth: '150px',
                  color: isDetected ? getMalwareColor() : '#555'
                }}>
                  {isDetected && '→ '}{className}
                </span>
                <div className="probability-bar">
                  <div
                    className="probability-fill"
                    style={{ 
                      width: `${prob * 100}%`,
                      background: isBenign ? '#10b981' : 
                                isDetected ? getMalwareColor() : '#cbd5e1'
                    }}
                  />
                </div>
                <span style={{ 
                  minWidth: '60px', 
                  textAlign: 'right',
                  fontWeight: isDetected ? '700' : '400'
                }}>
                  {(prob * 100).toFixed(2)}%
                </span>
              </div>
            );
          })}
        </div>

        {/* Recommendation */}
        <div style={{
          marginTop: '20px',
          padding: '15px',
          background: is_malware ? '#fef2f2' : '#f0fdf4',
          borderLeft: `4px solid ${getMalwareColor()}`,
          borderRadius: '4px'
        }}>
          <strong style={{ color: getMalwareColor() }}>Recommendation:</strong>
          <p style={{ marginTop: '5px', fontSize: '0.9rem', lineHeight: '1.5' }}>
            {is_malware ? (
              <>
                This file has been identified as <strong>{predicted_class}</strong> malware. 
                Do not execute this file. Delete it immediately and run a full system scan if it was opened.
              </>
            ) : (
              <>
                This file appears to be safe. However, always exercise caution when running 
                executable files from unknown sources.
              </>
            )}
          </p>
        </div>
      </div>
    </div>
  );
}

export default PredictionResult;
