import React, { useState } from 'react';

function CSVUpload({ onUpload, loading, apiStatus }) {
  const [selectedFile, setSelectedFile] = useState(null);
  const [dragOver, setDragOver] = useState(false);

  const handleFileChange = (e) => {
    const file = e.target.files[0];
    if (file && file.type === 'text/csv') {
      setSelectedFile(file);
    } else {
      alert('Please select a valid CSV file');
    }
  };

  const handleDragOver = (e) => {
    e.preventDefault();
    setDragOver(true);
  };

  const handleDragLeave = () => {
    setDragOver(false);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setDragOver(false);
    
    const file = e.dataTransfer.files[0];
    if (file && file.type === 'text/csv') {
      setSelectedFile(file);
    } else {
      alert('Please drop a valid CSV file');
    }
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    if (selectedFile) {
      onUpload(selectedFile);
    }
  };

  const clearFile = () => {
    setSelectedFile(null);
  };

  return (
    <form onSubmit={handleSubmit} className="prediction-form">
      <div className="alert alert-info">
        <span>ℹ️</span>
        <span>
          Upload a CSV file containing feature columns. Results will include predictions for all rows.
        </span>
      </div>

      <div className="form-section">
        <h3>Upload CSV File</h3>
        
        <div
          className={`upload-area ${dragOver ? 'drag-over' : ''}`}
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
          onClick={() => document.getElementById('csv-input').click()}
        >
          <div className="upload-icon">📁</div>
          <p>Drag and drop your CSV file here</p>
          <p style={{ fontSize: '0.9rem', color: '#999' }}>or click to browse</p>
          <input
            id="csv-input"
            type="file"
            accept=".csv"
            onChange={handleFileChange}
            className="file-input"
          />
        </div>

        {selectedFile && (
          <div className="file-selected">
            <div>
              <strong>Selected file:</strong> {selectedFile.name}
              <div style={{ fontSize: '0.9rem', color: '#666' }}>
                Size: {(selectedFile.size / 1024).toFixed(2)} KB
              </div>
            </div>
            <button
              type="button"
              onClick={clearFile}
              className="btn btn-secondary"
              style={{ padding: '8px 16px' }}
            >
              ✕
            </button>
          </div>
        )}

        <div style={{ marginTop: '20px', padding: '15px', background: '#f8f9fa', borderRadius: '10px' }}>
          <strong>CSV Format Example:</strong>
          <pre style={{ marginTop: '10px', fontSize: '0.85rem', overflow: 'auto' }}>
{`SHA256,feature1,feature2,feature3,...
sample1,0.5,1.0,0.3,...
sample2,0.7,0.8,0.6,...`}
          </pre>
        </div>
      </div>

      <button
        type="submit"
        className="btn btn-primary"
        disabled={loading || !apiStatus.online || !selectedFile}
      >
        {loading ? (
          <>
            <div className="spinner"></div>
            Processing...
          </>
        ) : (
          <>
            <span>📊</span>
            Process CSV File
          </>
        )}
      </button>
    </form>
  );
}

export default CSVUpload;
