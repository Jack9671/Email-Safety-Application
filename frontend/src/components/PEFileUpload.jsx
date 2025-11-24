import React, { useState } from 'react';

function PEFileUpload({ onUpload, loading, apiStatus }) {
  const [selectedFile, setSelectedFile] = useState(null);
  const [isDragging, setIsDragging] = useState(false);

  const handleFileSelect = (event) => {
    const file = event.target.files[0];
    validateAndSetFile(file);
  };

  const validateAndSetFile = (file) => {
    if (!file) return;

    const validExtensions = ['.exe', '.dll', '.sys', '.scr'];
    const fileExtension = file.name.substring(file.name.lastIndexOf('.')).toLowerCase();

    if (!validExtensions.includes(fileExtension)) {
      alert(`Invalid file type. Please upload a PE file (${validExtensions.join(', ')})`);
      return;
    }

  //  if (file.size > 50 * 1024 * 1024) { // 50MB limit
  //    alert('File size must be less than 50MB');
  //    return;
  //  }

    setSelectedFile(file);
  };

  const handleDrop = (event) => {
    event.preventDefault();
    setIsDragging(false);
    
    const file = event.dataTransfer.files[0];
    validateAndSetFile(file);
  };

  const handleDragOver = (event) => {
    event.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = () => {
    setIsDragging(false);
  };

  const handleUpload = () => {
    if (selectedFile && !loading) {
      onUpload(selectedFile);
    }
  };

  const handleClear = () => {
    setSelectedFile(null);
  };

  const formatFileSize = (bytes) => {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(2) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
  };

  return (
    <div className="pe-file-upload">
      <div 
        className={`drop-zone ${isDragging ? 'dragging' : ''}`}
        onDrop={handleDrop}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
      >
        <div className="drop-zone-content">
          <span className="drop-zone-icon">📁</span>
          <p className="drop-zone-text">
            Drag and drop a PE file here, or click to select
          </p>
          <p className="drop-zone-subtext">
            Supported: .exe, .dll, .sys, .scr (Max 50MB)
          </p>
          <input
            type="file"
            id="pe-file-input"
            className="file-input"
            accept=".exe,.dll,.sys,.scr"
            onChange={handleFileSelect}
            disabled={loading || !apiStatus.online}
          />
          <label htmlFor="pe-file-input" className="btn btn-secondary">
            Browse Files
          </label>
        </div>
      </div>

      {selectedFile && (
        <div className="selected-file-info">
          <div className="file-details">
            <div className="file-icon">
              {selectedFile.name.endsWith('.exe') ? '⚙️' : 
               selectedFile.name.endsWith('.dll') ? '📦' : '📄'}
            </div>
            <div className="file-meta">
              <div className="file-name">{selectedFile.name}</div>
              <div className="file-size">{formatFileSize(selectedFile.size)}</div>
            </div>
            <button 
              className="btn-icon" 
              onClick={handleClear}
              disabled={loading}
              title="Remove file"
            >
              ❌
            </button>
          </div>

          <div className="upload-actions">
            <button
              className="btn btn-primary"
              onClick={handleUpload}
              disabled={loading || !apiStatus.online}
            >
              {loading ? (
                <>
                  <span className="spinner"></span>
                  Scanning...
                </>
              ) : (
                <>
                  <span>🔍</span>
                  Scan for Malware
                </>
              )}
            </button>
          </div>
        </div>
      )}

      {!apiStatus.online && (
        <div className="alert alert-warning" style={{ marginTop: '20px' }}>
          <span>⚠️</span>
          <span>API is offline. Please start the backend server.</span>
        </div>
      )}
    </div>
  );
}

export default PEFileUpload;
