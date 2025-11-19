import React, { useState } from 'react';

function PredictionForm({ onPredict, loading, apiStatus }) {
  const [features, setFeatures] = useState({
    feature1: '0.5',
    feature2: '1.0',
    feature3: '0.3',
    feature4: '0.7',
  });

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFeatures(prev => ({
      ...prev,
      [name]: value
    }));
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    
    // Convert string values to numbers
    const numericFeatures = {};
    Object.keys(features).forEach(key => {
      numericFeatures[key] = parseFloat(features[key]) || 0;
    });

    onPredict(numericFeatures);
  };

  const handleRandomize = () => {
    const randomFeatures = {};
    Object.keys(features).forEach(key => {
      randomFeatures[key] = (Math.random() * 2 - 1).toFixed(3);
    });
    setFeatures(randomFeatures);
  };

  return (
    <form onSubmit={handleSubmit} className="prediction-form">
      <div className="alert alert-info">
        <span>ℹ️</span>
        <span>
          Enter feature values for prediction. The model uses 1000 features, but you can provide any subset.
          Missing features will be filled with 0.
        </span>
      </div>

      <div className="form-section">
        <h3>Sample Features (Enter any values)</h3>
        
        <div className="feature-input-grid">
          {Object.keys(features).map((key) => (
            <div key={key} className="input-group">
              <label htmlFor={key}>{key}</label>
              <input
                type="number"
                id={key}
                name={key}
                value={features[key]}
                onChange={handleInputChange}
                step="0.001"
                required
              />
            </div>
          ))}
        </div>

        <div style={{ display: 'flex', gap: '10px', marginTop: '15px' }}>
          <button
            type="button"
            className="btn btn-secondary"
            onClick={handleRandomize}
            style={{ flex: 1 }}
          >
            🎲 Randomize
          </button>
          <button
            type="button"
            className="btn btn-secondary"
            onClick={() => setFeatures({
              feature1: '0',
              feature2: '0',
              feature3: '0',
              feature4: '0',
            })}
            style={{ flex: 1 }}
          >
            🔄 Reset
          </button>
        </div>
      </div>

      <button
        type="submit"
        className="btn btn-primary"
        disabled={loading || !apiStatus.online}
      >
        {loading ? (
          <>
            <div className="spinner"></div>
            Predicting...
          </>
        ) : (
          <>
            <span>🚀</span>
            Predict Malware Type
          </>
        )}
      </button>

      {!apiStatus.online && (
        <div className="alert alert-error" style={{ marginTop: '15px' }}>
          <span>⚠️</span>
          <span>API is offline. Please start the server first.</span>
        </div>
      )}
    </form>
  );
}

export default PredictionForm;
