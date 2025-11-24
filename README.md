# Email Security System - AI-Powered Spam & Malware Detection

[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-latest-green.svg)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18.2.0-blue.svg)](https://reactjs.org/)
[![BERT](https://img.shields.io/badge/BERT-DistilBERT-yellow.svg)](https://huggingface.co/distilbert-base-uncased)
[![XGBoost](https://img.shields.io/badge/XGBoost-latest-orange.svg)](https://xgboost.readthedocs.io/)

A full-stack email security application combining:
1. **Email Spam Detection** - BERT transformer model with 99.19% accuracy
2. **PE Malware Classification** - XGBoost classifier detecting 7 malware families (88.75% MCC)
3. **Email Integration** - Connect to Gmail, Outlook, Yahoo via IMAP
4. **Interactive UI** - Real-time scanning with confidence visualizations

## 🎯 Project Overview

This full-stack application provides comprehensive email security through:
- **Frontend**: React + Vite with Plotly visualizations
- **Backend**: FastAPI with async request handling
- **ML Models**: BERT (spam) + XGBoost (malware), both pre-trained and included
- **Email Integration**: IMAP support for major email providers

## 📁 Project Structure

```
├── backend/                        # FastAPI server
│   ├── app_email_scanner.py       # Main API server
│   ├── email_fetcher.py           # IMAP email client
│   ├── pe_feature_extractor.py    # PE file feature extraction
│   ├── requirements.txt           # Python dependencies
│   └── saved_models/              # Pre-trained models
│       ├── bert_spam_detector/    # BERT model (268MB)
│       └── xgboost/               # XGBoost model (37MB)
│
├── frontend/                       # React application
│   ├── src/
│   │   ├── App.jsx                # Main app component
│   │   ├── components/            # UI components
│   │   └── pages/                 # Page views
│   ├── package.json               # Node dependencies
│   └── vite.config.js             # Vite configuration
│
└── docs/                          # Documentation
    ├── DOCUMENTATION.md           # Complete guide
    └── spam_detection_bert_report.txt  # Model metrics
```

**Note**: All trained models are included - no training required!

## ✨ Features

### 1. Email Spam Detection (BERT)
- **99.19% accuracy** using DistilBERT transformer
- Real-time text analysis with confidence scores
- Interactive probability charts (Plotly)
- Handles plain text and HTML emails

### 2. PE Malware Classification (XGBoost)
- Detects **7 malware families**: Benign, RedLineStealer, Downloader, RAT, BankingTrojan, SnakeKeyLogger, Spyware
- **88.75% MCC** (Matthews Correlation Coefficient)
- Extracts **1,000 features** from PE files
- Supports `.exe`, `.dll`, `.sys`, `.scr` files
- SHA256 hash calculation

### 3. Email Integration (IMAP)
- Connect to **Gmail, Outlook, Yahoo**
- Fetch emails directly from inbox
- Scan email body + attachments simultaneously
- App password authentication

### 4. Interactive Web UI
- Tab-based navigation (Inbox, Spam Checker, Malware Scanner)
- Real-time scanning with progress indicators
- Plotly charts for confidence visualization
- Responsive design with modern UI

## 🚀 Quick Start

### Prerequisites
- Python 3.12+
- Node.js 18+
- Git LFS (for BERT model - 268MB)

### Installation

1. **Clone and setup**:
```bash
git clone https://github.com/quangthai843/COS30049.git
cd Spam-and-Malware-Detection-AI-model
git lfs install
git lfs pull  # Download BERT model
```

2. **Start Backend**:
```bash
cd backend
pip install -r requirements.txt
python app_email_scanner.py
```
Backend runs at: http://localhost:8000 (API docs: http://localhost:8000/docs)

3. **Start Frontend** (new terminal):
```bash
cd frontend
npm install
npm run dev
```
Frontend runs at: http://localhost:3000

## 🔌 API Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/health` | GET | Health check |
| `/model/info` | GET | Model metadata |
| `/scan/spam` | POST | Scan email text for spam |
| `/scan/pe` | POST | Scan PE file for malware |
| `/email/fetch` | POST | Fetch emails via IMAP |
| `/email/scan` | POST | Scan email body + attachments |

Interactive API docs: http://localhost:8000/docs

## 📖 Usage

### Email Inbox
1. Enter email credentials (use app password, not regular password)
2. Select provider: Gmail, Outlook, or Yahoo
3. Fetch and scan emails directly

**App Password Setup**: 
- Gmail: https://myaccount.google.com/apppasswords
- Outlook: https://account.live.com/proofs/AppPassword

### Spam Detection
- Paste email text
- Click "Check for Spam"
- View confidence chart

### Malware Scanner
- Upload PE file (.exe, .dll, .sys, .scr)
- View classification results

## 🔬 Technical Details

### Models
- **BERT**: DistilBERT (99.19% accuracy, 268MB)
- **XGBoost**: 1,000 features, 7 malware families (88.75% MCC, 37MB)

### Stack
- **Backend**: FastAPI, PyTorch, XGBoost, pefile
- **Frontend**: React 18, Vite, Plotly.js
- **Email**: IMAP (Gmail, Outlook, Yahoo)

### Malware Families Detected
Benign, RedLineStealer, Downloader, RAT, BankingTrojan, SnakeKeyLogger, Spyware

## 🙏 Acknowledgments

Hugging Face • FastAPI • XGBoost • React • Plotly.js

---

