# Email Security System - AI-Powered Spam & Malware Detection

[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-latest-green.svg)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18.2.0-blue.svg)](https://reactjs.org/)
[![BERT](https://img.shields.io/badge/BERT-DistilBERT-yellow.svg)](https://huggingface.co/distilbert-base-uncased)
[![XGBoost](https://img.shields.io/badge/XGBoost-latest-orange.svg)](https://xgboost.readthedocs.io/)
[![Plotly](https://img.shields.io/badge/Plotly-latest-blue.svg)](https://plotly.com/javascript/)

Comprehensive email security system combining **BERT spam detection (99.19% accuracy)** and **XGBoost malware classification (88.75% MCC)**. Connect to your Gmail/Outlook/Yahoo inbox, scan emails for spam, and detect malware in attachments.

## 📁 Project Structure

```
├── backend/          # FastAPI server, ML models (ready to run)
├── frontend/         # React UI with Plotly visualizations
├── docs/            # Documentation and reports
└── README.md        # This file
```

**Note**: All trained models are included in the repository. The application is **ready to run immediately** after cloning - no model training required!

See [STRUCTURE.md](STRUCTURE.md) for detailed directory structure.

## 🎯 What It Does

### 📧 Email Spam Detection
- ✅ Scan email content with **BERT (99.19% accuracy)**
- 📊 Visual confidence analysis with interactive pie charts (Plotly)
- 📬 Connect to Gmail, Outlook, or Yahoo via IMAP
- 🔍 Fetch and scan emails directly from your inbox
- 📈 Real-time spam/ham probability distribution

### 🦠 Malware Detection
- ✅ Analyze Windows PE files (`.exe`, `.dll`, `.sys`, `.scr`)
- 🔍 Classify across 7 malware families (**88.75% MCC**)
- 📎 Scan email attachments automatically
- 📊 Confidence scores and probability breakdown
- 🔐 SHA256 hash calculation
- 📈 Extract 1140+ PE features

## 🚀 Quick Start

### Prerequisites

**Git LFS Required**: The BERT model (268 MB) is stored using Git LFS. Make sure you have Git LFS installed:

```bash
# Check if Git LFS is installed
git lfs version

# If not installed, download from: https://git-lfs.github.com/
# After installation, run:
git lfs install
```

**Clone with LFS**:
```bash
git clone https://github.com/quangthai843/COS30049.git
cd Spam-and-Malware-Detection-AI-model

# Ensure LFS files are pulled
git lfs pull
```

**All models are pre-trained and included!** Just install dependencies and run.

### 1. Start Backend API

```bash
cd backend
pip install -r requirements.txt
python app_email_scanner.py
```

You should see:
```
✓ Model and PE extractor loaded successfully!
✓ BERT spam detector loaded successfully!
INFO:     Uvicorn running on http://0.0.0.0:8000
```

API available at: http://localhost:8000
- Interactive API docs: http://localhost:8000/docs

### 2. Start Frontend
```bash
cd frontend
npm install
npm run dev
```
Web UI available at: http://localhost:3002

### 3. Use the System

#### Email Inbox Scanner
1. Navigate to **Email Inbox** tab
2. Enter email credentials (Gmail/Outlook/Yahoo)
3. Use **App Password** (not regular password) - [Setup Guide](EMAIL_INBOX_GUIDE.md)
4. Fetch emails from your inbox
5. Click any email to scan for spam and malware
6. View results with interactive pie chart visualization

#### Spam Detection
1. Navigate to **Spam Detection** tab
2. Type or paste email content
3. Click "Check for Spam"
4. View confidence scores

#### Malware Scanner
1. Navigate to **Malware Scanner** tab
2. Upload PE file or drag & drop
3. View malware classification results

## 📊 Performance

### Spam Detection (BERT)
- **Accuracy**: 99.19%
- **Model**: DistilBERT (distilbert-base-uncased)
- **Vocabulary**: 30,522 tokens
- **Device**: CPU optimized

### Malware Detection (XGBoost)
- **MCC**: 0.8875
- **F1**: 0.9051  
- **Precision**: 0.9049
- **Recall**: 0.9070
- **Features**: 1000 (from 1140+ extracted)
- **Classes**: 7 malware families

## 📁 Project Structure

```
├── app_email_scanner.py         # FastAPI server (all endpoints)
├── email_fetcher.py             # IMAP email fetching (Gmail/Outlook/Yahoo)
├── pe_feature_extractor.py      # PE feature extraction
├── load_bert_model_demo.py      # BERT model demo
├── EMAIL_INBOX_GUIDE.md         # Email setup guide
├── frontend/                    # React web interface
│   ├── src/
│   │   ├── App.jsx              # Main app with 3 tabs
│   │   ├── components/
│   │   │   ├── EmailInbox.jsx   # Email client with IMAP
│   │   │   ├── SpamChecker.jsx  # Spam detection UI
│   │   │   ├── PEFileUpload.jsx # Malware scanner UI
│   │   │   └── PredictionResult.jsx
│   │   └── index.css            # Minimalist styling
├── saved_models/
│   ├── bert_spam_detector/      # BERT model files
│   └── xgboost/                 # XGBoost model files
└── DOCUMENTATION.md             # Complete docs
```

## 🔌 API Endpoints

### Health Check
```http
GET /health
```

### Model Info
```http
GET /model/info
```
Returns info for both BERT (spam detection) and XGBoost (malware detection) models.

### Spam Detection
```http
POST /scan/spam
Content-Type: application/json
```
**Body**: `{"email_text": "Your email content here"}`

**Response**:
```json
{
  "is_spam": false,
  "label": "ham",
  "confidence": 0.9967,
  "probabilities": {"ham": 0.9967, "spam": 0.0033}
}
```

### Scan PE File
```http
POST /scan/pe
Content-Type: multipart/form-data
```

**Response**:
```json
{
  "filename": "suspicious.exe",
  "sha256": "abc123...",
  "is_malware": true,
  "predicted_class": "RedLineStealer",
  "confidence": 0.95,
  "probabilities": {...},
  "file_size": 204800
}
```

### Fetch Emails
```http
POST /email/fetch
Content-Type: application/json
```
**Body**: `{"email_address": "user@gmail.com", "app_password": "xxxx", "provider": "gmail"}`

### Scan Email
```http
POST /email/scan
Content-Type: application/json
```
Scans email body for spam (BERT) and attachments for malware (XGBoost).

## 🛠️ Installation

### Prerequisites
- Python 3.12.3
- Node.js 16+ (for frontend)
- 4GB+ RAM (for training BERT model)

```bash
# Clone repository
git clone https://github.com/quangthai843/COS30049.git
cd COS30049

# Install Python dependencies
pip install -r requirements.txt

# Train the BERT model (required - see Quick Start above)
# Open email_spam_classification.ipynb and run all cells

# Install frontend dependencies
cd frontend
npm install
```

**Note**: The trained BERT model is **not included** in the repository due to its 268 MB size. You must train it yourself using `email_spam_classification.ipynb`. Training takes ~5-10 minutes on CPU, ~1-2 minutes on GPU.

## 📖 Documentation

**Complete documentation**: [DOCUMENTATION.md](DOCUMENTATION.md)

Includes:
- API reference
- Feature extraction details  
- Model training guide
- Troubleshooting
- Security considerations

## 🔬 System Features

### Email Security Features
- **IMAP Integration**: Connect to Gmail, Outlook, Yahoo
- **App Password Authentication**: Secure 2FA-compatible login
- **Real-time Scanning**: Scan email body and attachments
- **Visual Analytics**: Interactive pie charts (Plotly) for confidence scores
- **Threat Detection**: Combined spam + malware analysis

### PE Features Extracted (Malware Detection)
1. **DOS Header** (18 features)
2. **FILE Header** (7 features)
3. **OPTIONAL Header** (25 features)
4. **Sections** (90 features: .text, .data, .rdata, etc.)
5. **Imported DLLs** (~359 binary features)
6. **API Functions** (~499 binary features)

**Total**: 1140+ features → 1000 selected for model

## 🛡️ Security Notes

⚠️ **Important**:
- Run in sandboxed environment
- Don't execute files marked as malware
- Use as part of defense-in-depth strategy
- Model trained on specific malware families
- New/unknown malware may not classify accurately

## 🧪 Development

### Train New Model
See `XGBoost.ipynb` for training pipeline

### Add Features
Edit `pe_feature_extractor.py`:
```python
def extract_custom_features(self, pe):
    # Your feature logic
    return features
```

### API Testing
- Interactive docs: http://localhost:8000/docs
- Alternative docs: http://localhost:8000/redoc

## 📝 Technologies

- **Backend**: FastAPI, Python 3.12, Uvicorn
- **Spam Detection**: BERT (DistilBERT), PyTorch, Transformers (Hugging Face)
- **Malware Detection**: XGBoost + Bayesian optimization (Optuna)
- **Email Fetching**: IMAP (imaplib), MIME parsing
- **PE Analysis**: pefile library
- **Frontend**: React 18, Vite, Plotly.js
- **Visualization**: Plotly.js (interactive pie charts)
- **Styling**: CSS3 (minimalist design)

## 🐛 Troubleshooting

**"pefile not installed"**
```bash
pip install pefile>=2023.2.7
```

**"Port 8000 in use"**
```bash
Get-Process python | Stop-Process -Force  # Windows
```

**"Email authentication failed"**
- Use **App Password**, not regular password
- Gmail: https://myaccount.google.com/apppasswords
- Outlook: https://account.live.com/proofs/AppPassword
- See [EMAIL_INBOX_GUIDE.md](EMAIL_INBOX_GUIDE.md)

**"BERT model not loading"**
```bash
pip install torch transformers
```

**"Plotly chart not showing"**
```bash
cd frontend
npm install plotly.js react-plotly.js
```

## 📚 Model Details

**XGBoost Classifier**:
- 1000 features (Bayesian-optimized selection)
- 7 classes (6 malware + 1 benign)
- Trained with Optuna hyperparameter tuning
- StandardScaler preprocessing on numeric features
- Binary features (DLLs/APIs) unscaled

**Malware Families**:
1. Benign
2. RedLineStealer (info stealer)
3. Downloader (malware loader)
4. RAT (Remote Access Trojan)
5. BankingTrojan (banking credential theft)
6. SnakeKeyLogger (keylogger)
7. Spyware (surveillance malware)

## 🤝 Contributing

Areas for improvement:
- Additional malware families
- Enhanced features
- Model optimization
- Frontend UX
- Documentation

## 📄 License

Educational and research use.

## 👤 Author

**Jack** - Machine learning model development and system architecture

## 🔗 Links

- [pefile](https://github.com/erocarrera/pefile)
- [XGBoost](https://xgboost.readthedocs.io/)
- [FastAPI](https://fastapi.tiangolo.com/)
- [React](https://react.dev/)

---

**Version**: 2.0.0 | **Last Updated**: November 18, 2025

For complete documentation, see [DOCUMENTATION.md](DOCUMENTATION.md)
