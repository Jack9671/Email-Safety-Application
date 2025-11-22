# Email Security System - Complete Documentation

A comprehensive AI-powered email security system combining spam detection and malware analysis.

## 🎯 Project Overview

This system provides three integrated security features:

### 1. Email Inbox Scanner (Primary Feature)
Connect to your email account and scan messages:
- **IMAP Integration** - Gmail, Outlook, Yahoo support
- **Spam Detection** - BERT analysis with 99.19% accuracy
- **Malware Scanning** - XGBoost PE file analysis
- **Visual Analytics** - Plotly pie charts for confidence distribution
- **Batch Processing** - Scan multiple emails

### 2. PE Malware Classification
Multi-class classification of Windows PE files with **88.75% MCC accuracy**:
- **XGBoost** - Production model (Gradient boosted trees)
- **Random Forest** - Ensemble classifier
- **Logistic Regression** - Baseline model
- **Naive Bayes** - Probabilistic classifier

**Malware Types Detected:**
- Benign (Safe files)
- RedLineStealer
- Downloader
- RAT (Remote Access Trojan)
- BankingTrojan
- SnakeKeyLogger
- Spyware

### 3. Email Spam Detection
Binary classification with **99.19% accuracy**:
- **BERT (DistilBERT)** - Transformer-based NLP model
- **Vocabulary**: 30,522 tokens
- **Interactive Visualization** - Plotly pie charts
- **Real-time Analysis** - Instant spam/ham classification

---

## 📋 Requirements

### Core Dependencies
```
Python 3.12.3
FastAPI
Uvicorn
pefile>=2023.2.7
XGBoost
Scikit-learn
Pandas, NumPy
PyTorch (for BERT)
Transformers (Hugging Face)
Plotly.js, react-plotly.js (visualization)
```

See `requirements.txt` and `frontend/package.json` for complete lists.

---

## 🚀 Quick Start

### Installation

1. **Clone the repository:**
```bash
git clone https://github.com/quangthai843/COS30049.git
cd COS30049
```

2. **Install dependencies:**
```bash
pip install -r requirements.txt
```

3. **⚠️ IMPORTANT: Train the BERT Model First**

The BERT spam detection model is **not included** in the repository (268 MB file). You **must** train it before running the system:

```bash
# Option 1: Use Jupyter Notebook or VS Code
# Open email_spam_classification.ipynb and run all cells

# Option 2: Use the setup script
python setup_models.py
```

Training takes ~5-10 minutes on CPU, ~1-2 minutes on GPU. The model will be saved to `saved_models/bert_spam_detector/`.

4. **Verify pefile is installed:**
```bash
pip install pefile>=2023.2.7
```

### Running the System

⚠️ **Make sure you've trained the BERT model first (step 3 above)!**

#### Start API Server
```powershell
# Windows PowerShell
python app_email_scanner.py
```

The API will be available at: `http://localhost:8000`

#### Start Frontend
```powershell
cd frontend
npm install
npm run dev
```

Frontend available at: `http://localhost:3002`

### Using the Email Inbox

1. **Generate App Password**:
   - Gmail: https://myaccount.google.com/apppasswords
   - Outlook: https://account.live.com/proofs/AppPassword
   - See [EMAIL_INBOX_GUIDE.md](EMAIL_INBOX_GUIDE.md)

2. **Connect to Email**:
   - Select provider (Gmail/Outlook/Yahoo)
   - Enter email address
   - Enter app password (NOT regular password)
   - Click "Fetch Emails"

3. **Scan Emails**:
   - Click any email in the list
   - View spam detection results with pie chart
   - Check attachment malware scan results

---

## 📁 Project Structure

```
├── app_email_scanner.py      # FastAPI server (all endpoints)
├── email_fetcher.py          # IMAP email client (Gmail/Outlook/Yahoo)
├── pe_feature_extractor.py   # PE file feature extraction
├── load_bert_model_demo.py   # BERT model demo script
├── requirements.txt          # Python dependencies
├── EMAIL_INBOX_GUIDE.md      # Email setup guide
│
├── saved_models/
│   ├── xgboost/              # XGBoost malware classifier
│   └── bert_spam_detector/   # BERT spam detector
│
├── frontend/                  # React web interface
│   ├── src/
│   │   ├── App.jsx           # Main app (3 tabs)
│   │   └── components/
│   │       ├── EmailInbox.jsx    # Email client with charts
│   │       ├── SpamChecker.jsx   # Spam detection UI
│   │       ├── PEFileUpload.jsx  # Malware scanner
│   │       └── PredictionResult.jsx
│   └── package.json          # Includes plotly.js
│
├── Dataset/                   # Training datasets
│   ├── merged_data.csv       # PE malware features
│   └── raw_email_data.csv    # Email spam data
│
└── Notebooks/
    ├── XGBoost.ipynb
    ├── random_forest.ipynb
    └── email_spam_classification.ipynb
```

---

## 🔌 API Documentation

### Email Scanner API (`app_email_scanner.py`)

#### Base URL
```
http://localhost:8000
```

#### Endpoints

##### 1. Health Check
```http
GET /health
```

**Response:**
```json
{
  "status": "healthy",
  "xgboost_model_loaded": true,
  "bert_model_loaded": true,
  "pe_extractor_ready": true
}
```

##### 2. Model Information
```http
GET /model/info
```

**Response:**
```json
{
  "spam_detection": {
    "model": "DistilBERT",
    "accuracy": 0.9919,
    "vocab_size": 30522
  },
  "malware_detection": {
    "model_type": "XGBoost",
    "n_features": 1000,
    "n_classes": 7,
    "test_metrics": {...}
  }
}
```

##### 3. Spam Detection
```http
POST /scan/spam
Content-Type: application/json
```

**Body:**
```json
{
  "email_text": "Congratulations! You've won $1000000..."
}
```

**Response:**
```json
{
  "is_spam": true,
  "label": "spam",
  "confidence": 0.9758,
  "probabilities": {
    "ham": 0.0242,
    "spam": 0.9758
  }
}
```

##### 4. Fetch Emails
```http
POST /email/fetch
Content-Type: application/json
```

**Body:**
```json
{
  "email_address": "user@gmail.com",
  "app_password": "xxxx xxxx xxxx xxxx",
  "provider": "gmail"
}
```

**Response:**
```json
{
  "success": true,
  "emails": [
    {
      "id": "1",
      "from": "sender@example.com",
      "subject": "Meeting tomorrow",
      "date": "2025-11-19",
      "body_preview": "Hi, let's meet...",
      "has_attachments": false
    }
  ]
}
```

##### 5. Scan Email
```http
POST /email/scan
Content-Type: application/json
```

**Body:**
```json
{
  "email_address": "user@gmail.com",
  "app_password": "xxxx xxxx xxxx xxxx",
  "provider": "gmail",
  "email_id": "1"
}
```

**Response:**
```json
{
  "spam_scan": {
    "is_spam": false,
    "confidence": 0.9967,
    "probabilities": {"ham": 0.9967, "spam": 0.0033}
  },
  "malware_scans": [...],
  "threats_detected": false
}
```

##### 6. Scan PE File
```http
POST /scan/pe
Content-Type: multipart/form-data
```

**Parameters:**
- `file`: PE file (.exe, .dll, .sys, .scr) - Max 50MB

**Response:**
```json
{
  "filename": "suspicious.exe",
  "sha256": "abc123...",
  "is_malware": true,
  "predicted_class": "RedLineStealer",
  "confidence": 0.95,
  "probabilities": {
    "Benign": 0.02,
    "RedLineStealer": 0.95,
    "Downloader": 0.01,
    "RAT": 0.01,
    "BankingTrojan": 0.005,
    "SnakeKeyLogger": 0.005,
    "Spyware": 0.005
  },
  "file_size": 204800
}
```

**Example Usage:**

PowerShell:
```powershell
# Upload a PE file for scanning
$headers = @{"Content-Type"="multipart/form-data"}
$file = Get-Item "suspicious.exe"
$form = @{file=Get-Item -Path $file}
Invoke-RestMethod -Uri "http://localhost:8000/scan/pe" -Method Post -Form $form
```

cURL:
```bash
curl -X POST "http://localhost:8000/scan/pe" -F "file=@suspicious.exe"
```

Python:
```python
import requests

with open("suspicious.exe", "rb") as f:
    files = {"file": f}
    response = requests.post("http://localhost:8000/scan/pe", files=files)
    result = response.json()
    print(f"Malware: {result['is_malware']}")
    print(f"Type: {result['predicted_class']}")
    print(f"Confidence: {result['confidence']:.2%}")
```

---

## 🔬 PE Feature Extraction

The system extracts **1140+ features** from Windows PE files:

### Feature Categories

#### 1. DOS Header (18 features)
- `e_magic`, `e_cblp`, `e_cp`, `e_crlc`, `e_cparhdr`, `e_minalloc`, `e_maxalloc`, `e_ss`, `e_sp`, `e_csum`, `e_ip`, `e_cs`, `e_lfarlc`, `e_ovno`, `e_oemid`, `e_oeminfo`, `e_lfanew`

#### 2. FILE Header (7 features)
- `Machine`, `NumberOfSections`, `TimeDateStamp`, `PointerToSymbolTable`, `NumberOfSymbols`, `SizeOfOptionalHeader`, `Characteristics`

#### 3. OPTIONAL Header (25 features)
- `Magic`, `MajorLinkerVersion`, `MinorLinkerVersion`, `SizeOfCode`, `SizeOfInitializedData`, `SizeOfUninitializedData`, `AddressOfEntryPoint`, `BaseOfCode`, `ImageBase`, `SectionAlignment`, `FileAlignment`, OS versions, Image versions, Subsystem versions, `CheckSum`, `Subsystem`, `DllCharacteristics`, etc.

#### 4. Section Information (90 features)
For 10 sections (`.text`, `.data`, `.rdata`, `.bss`, `.idata`, `.edata`, `.rsrc`, `.reloc`, `.tls`, `.pdata`):
- `Misc_VirtualSize`, `VirtualAddress`, `SizeOfRawData`, `PointerToRawData`, `PointerToRelocations`, `PointerToLinenumbers`, `NumberOfRelocations`, `NumberOfLinenumbers`, `Characteristics`

#### 5. Imported DLLs (~359 binary features)
Binary flags (0/1) indicating whether common DLLs are imported:
- `kernel32.dll`, `user32.dll`, `advapi32.dll`, `ntdll.dll`, `msvcrt.dll`, etc.

#### 6. API Functions (~499 binary features)
Binary flags for commonly imported Windows API functions:
- `CreateFileA`, `WriteFile`, `VirtualAlloc`, `LoadLibraryA`, etc.

### Using the Feature Extractor

```python
from pe_feature_extractor import PEFeatureExtractor
from pathlib import Path
import joblib

# Initialize with model features
models_dir = Path('./saved_models/xgboost')
extractor = PEFeatureExtractor(
    model_features_path=models_dir / 'xgboost_top_features.joblib',
    expected_features=loaded_features  # List of 1000 features model expects
)

# Extract from single file
features = extractor.extract_features_from_file(Path("sample.exe"))
print(f"SHA256: {features['SHA256']}")
print(f"Features extracted: {len(features)}")

# Batch processing
pe_files = list(Path("samples/").glob("*.exe"))
df = extractor.extract_features_batch(pe_files)

# Prepare for model
df_ready = extractor.prepare_for_prediction(
    df, 
    scaler_header, 
    scaler_section,
    expected_features=loaded_features
)
```

---

## 🖥️ Frontend Interface

The React frontend provides an intuitive web interface for PE file scanning.

### Features
- **Minimalist ChatGPT-style Design** - Clean white interface with neutral colors
- **Three-tab Interface** - Email Inbox, Spam Checker, Malware Scanner
- **Interactive Visualizations** - Plotly pie charts for confidence distribution
- **Drag-and-drop Upload** - Easy file upload for malware scanning
- **Real-time Analysis** - Instant spam and malware detection
- **Detailed Results** - Confidence scores, probabilities, and threat indicators

### Running the Frontend

```bash
cd frontend
npm install
npm run dev
```

Access at: `http://localhost:3002`

### Components

- **EmailInbox.jsx** - Email client with IMAP integration and Plotly charts
- **SpamChecker.jsx** - Spam detection with text input
- **PEFileUpload.jsx** - PE file upload with drag-and-drop
- **PredictionResult.jsx** - Malware scan results with visual indicators
- **SpamResult.jsx** - Spam detection results display

---

## 📊 Model Performance

### XGBoost Malware Classifier

**Test Set Metrics:**
- **MCC (Matthews Correlation Coefficient)**: 0.8875
- **F1 Score (Macro)**: 0.9051
- **Precision (Macro)**: 0.9049
- **Recall (Macro)**: 0.9070

**Model Details:**
- Features: 1000 (selected from 1140+)
- Classes: 7 (Benign + 6 malware types)
- Algorithm: XGBoost with Bayesian Optimization
- Training: Optuna hyperparameter tuning

### Feature Importance
Top features include:
- Section characteristics (.text, .data, .rsrc)
- Import table information (DLLs and API functions)
- PE header metadata
- File size and structure metrics

---

## 🛠️ Development

### Adding New Models

1. Train your model and save in `saved_models/`
2. Update feature extraction if needed
3. Modify `app_email_scanner.py` to load new model
4. Update API response schema if necessary

### Extending Feature Extraction

Edit `pe_feature_extractor.py`:
```python
def extract_custom_features(self, pe):
    """Add your custom PE features"""
    features = {}
    # Your feature extraction logic
    return features
```

### API Testing

Interactive API documentation available at:
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

---

## 🔒 Security Considerations

### Important Notes

1. **Sandbox Execution**: Always scan PE files in an isolated environment
2. **File Size Limits**: Default max 50MB per file
3. **Supported Formats**: .exe, .dll, .sys, .scr only
4. **Model Limitations**: 
   - Model trained on specific malware families
   - New/unknown malware may not be accurately classified
   - Use as part of defense-in-depth strategy

### Recommendations

- Do NOT execute files identified as malware
- Use in combination with other security tools
- Regularly update model with new malware samples
- Implement rate limiting in production
- Use HTTPS in production deployments

---

## 📝 Training New Models

### XGBoost Training

See `XGBoost.ipynb` for complete training pipeline:

1. **Data Preparation**
   - Load PE features from `merged_data.csv`
   - Handle missing values
   - Split train/test sets

2. **Feature Selection**
   - Select top 1000 features using XGBoost importance
   - Save feature list for consistency

3. **Hyperparameter Optimization**
   - Use Optuna for Bayesian optimization
   - Optimize for MCC score
   - Cross-validation

4. **Model Training**
   - Train with best parameters
   - Save model, encoders, scalers, metadata

5. **Evaluation**
   - Test set performance
   - Confusion matrix
   - Per-class metrics

---

## 🐛 Troubleshooting

### Common Issues

**Issue**: "pefile not installed"
```bash
pip install pefile>=2023.2.7
```

**Issue**: "Model not loaded"
- Ensure model files exist in `saved_models/xgboost/`
- Check file paths are correct
- Verify all 6 model files are present

**Issue**: "Feature names mismatch"
- This is automatically handled by the system
- DLLs/APIs not in training data are ignored
- Missing features are filled with 0

**Issue**: "Port 8000 already in use"
```powershell
# Find and kill process
Get-Process | Where-Object {$_.ProcessName -eq "python"} | Stop-Process -Force
```

**Issue**: "Frontend can't connect to API"
- Verify API is running on port 8000
- Check `API_BASE_URL` in `frontend/src/App.jsx`
- Enable CORS if needed

---

## 📚 Dataset Information

### PE Malware Dataset
- **Source**: Compiled from multiple malware repositories
- **Size**: Training samples with 1140+ features each
- **Classes**: 7 (1 benign + 6 malware families)
- **Features**: PE headers, sections, imports, API calls

### Email Spam Dataset
- **File**: `raw_email_data.csv`
- **Columns**: Email text, spam/ham label
- **Used for**: BERT spam classifier training

---

## 🤝 Contributing

Contributions are welcome! Areas for improvement:
- Additional malware families
- Enhanced feature extraction
- Model optimization
- Frontend improvements
- Documentation updates

---

## 📄 License

This project is for educational and research purposes.

---

## 👥 Authors

- **Jack** - Initial development and model training

---

## 🔗 Resources

- [pefile Documentation](https://github.com/erocarrera/pefile)
- [XGBoost Documentation](https://xgboost.readthedocs.io/)
- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [React Documentation](https://react.dev/)

---

## 📞 Support

For issues and questions:
1. Check this documentation
2. Review API docs at `/docs`
3. Check terminal output for error messages
4. Open an issue on GitHub

---

## ⚡ Performance Tips

### API Server
- Use multiple workers in production: `uvicorn app_email_scanner:app --workers 4`
- Enable caching for model loading
- Implement request queuing for large files

### Frontend
- Use production build: `npm run build`
- Enable gzip compression
- Cache API responses when appropriate

---

## 🔄 Updates

**Latest Version: 2.0.0**

**Recent Changes:**
- Added PE file scanning capability
- Created React frontend for file upload
- Improved error handling
- Added malware family name mapping
- Enhanced feature extraction with pefile
- Fixed feature mismatch issues

---

**Last Updated**: November 18, 2025
