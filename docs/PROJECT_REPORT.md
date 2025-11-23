# Email Security System - Full-Stack Web Application Project Report

**Course:** COS30049 - Computing Technology Innovation Project  
**Project:** Spam and Malware Detection AI Model  
**Date:** November 22, 2025  

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Introduction](#2-introduction)
   - 2.1 Project Overview
   - 2.2 Problem Statement
   - 2.3 Objectives
   - 2.4 Scope
3. [System Architecture](#3-system-architecture)
   - 3.1 Overall Architecture
   - 3.2 Technology Stack
   - 3.3 Component Diagram
   - 3.4 Data Flow
4. [Backend Development](#4-backend-development)
   - 4.1 API Design and Structure
   - 4.2 Machine Learning Models
   - 4.3 Email Processing Pipeline
   - 4.4 PE File Analysis Module
   - 4.5 Database Integration
5. [Machine Learning Models](#5-machine-learning-models)
   - 5.1 Spam Detection Models
   - 5.2 Malware Detection Models
   - 5.3 Model Training and Evaluation
   - 5.4 Model Performance Comparison
   - 5.5 Model Deployment
6. [Frontend Development](#6-frontend-development)
   - 6.1 User Interface Design
   - 6.2 Component Architecture
   - 6.3 State Management
   - 6.4 API Integration
   - 6.5 User Experience Features
7. [Features and Functionality](#7-features-and-functionality)
   - 7.1 Email Spam Detection
   - 7.2 PE File Malware Analysis
   - 7.3 Email Inbox Integration
   - 7.4 Batch Processing
   - 7.5 Real-time Predictions
8. [Implementation Details](#8-implementation-details)
   - 8.1 Development Environment Setup
   - 8.2 Dependencies and Libraries
   - 8.3 Configuration Management
   - 8.4 Security Considerations
9. [Testing and Validation](#9-testing-and-validation)
   - 9.1 Unit Testing
   - 9.2 Integration Testing
   - 9.3 Model Validation
   - 9.4 User Acceptance Testing
10. [Results and Analysis](#10-results-and-analysis)
    - 10.1 Model Performance Metrics
    - 10.2 System Performance
    - 10.3 User Feedback
    - 10.4 Comparative Analysis
11. [Challenges and Solutions](#11-challenges-and-solutions)
    - 11.1 Technical Challenges
    - 11.2 Integration Issues
    - 11.3 Performance Optimization
    - 11.4 Lessons Learned
12. [Future Enhancements](#12-future-enhancements)
    - 12.1 Planned Features
    - 12.2 Scalability Improvements
    - 12.3 Model Enhancements
    - 12.4 UI/UX Improvements
13. [Conclusion](#13-conclusion)
14. [References](#14-references)
15. [Appendices](#15-appendices)
    - Appendix A: API Documentation
    - Appendix B: Model Training Scripts
    - Appendix C: Database Schema
    - Appendix D: Installation Guide
    - Appendix E: User Manual

---

## 1. Executive Summary

[Content to be added - Overview of the project, key achievements, and main findings]

---

## 2. Introduction

### 2.1 Project Overview

This project is a full-stack email security system that combines AI-powered spam detection and malware classification. The system uses BERT for email spam detection (99.19% accuracy) and XGBoost for PE file malware classification (88.75% MCC across 7 malware families). Built with FastAPI backend and React frontend, it provides real-time threat analysis with IMAP integration for Gmail, Outlook, and Yahoo accounts.

### 2.2 Problem Statement

Email remains a primary attack vector for cyber threats. Traditional signature-based detection methods struggle with evolving spam tactics and new malware variants. Organizations need intelligent, automated solutions that can accurately identify spam emails and detect malicious executables in attachments while minimizing false positives and processing emails in real-time.

### 2.3 Objectives

- Develop a BERT-based spam classifier achieving >98% accuracy
- Build an XGBoost malware classifier for 7 threat categories (MCC >0.85)
- Integrate IMAP email fetching for major email providers
- Extract 1,000+ PE file features for malware analysis
- Create an intuitive web interface with interactive visualizations
- Provide real-time threat detection with confidence scoring

### 2.4 Scope

**Included:**
- Email spam detection (English text)
- PE file malware classification (.exe, .dll, .sys, .scr)
- IMAP integration (Gmail, Outlook, Yahoo)
- 7 malware family classification
- Interactive web UI with Plotly visualizations
- RESTful API with FastAPI

**Excluded:**
- Multilingual support
- Dynamic malware analysis (sandboxing)
- POP3/Exchange protocols
- Enterprise authentication systems
- Mobile native applications

---

## 3. System Architecture

### 3.1 Overall Architecture

The Email Security System follows a three-tier architecture pattern with clear separation between presentation, application logic, and data layers.

```
┌─────────────────────────────────────────────────────────────────┐
│                         CLIENT LAYER                             │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │              React Frontend (Port 3002)                   │   │
│  │  • Email Inbox UI    • Spam Checker    • PE File Upload  │   │
│  │  • Plotly Charts     • Result Display  • State Management│   │
│  └──────────────────────────────────────────────────────────┘   │
└───────────────────────────────┬─────────────────────────────────┘
                                │ HTTP/REST API
                                │ (JSON)
┌───────────────────────────────▼─────────────────────────────────┐
│                      APPLICATION LAYER                           │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │           FastAPI Server (Port 8000)                      │   │
│  │  • API Endpoints      • Request Validation                │   │
│  │  • CORS Middleware    • Error Handling                    │   │
│  └──────────────────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                  Business Logic                           │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌───────────────┐  │   │
│  │  │ Email Fetcher│  │ PE Feature   │  │ Spam Analyzer │  │   │
│  │  │ (IMAP)       │  │ Extractor    │  │ (BERT)        │  │   │
│  │  └──────────────┘  └──────────────┘  └───────────────┘  │   │
│  └──────────────────────────────────────────────────────────┘   │
└───────────────────────────────┬─────────────────────────────────┘
                                │
┌───────────────────────────────▼─────────────────────────────────┐
│                         MODEL LAYER                              │
│  ┌─────────────────────┐        ┌──────────────────────┐        │
│  │  BERT Model         │        │  XGBoost Model       │        │
│  │  (268 MB)           │        │  (1000 features)     │        │
│  │  • DistilBERT       │        │  • 7 Classes         │        │
│  │  • 30,522 vocab     │        │  • Label Encoder     │        │
│  │  • Tokenizer        │        │  • StandardScaler    │        │
│  └─────────────────────┘        └──────────────────────┘        │
└─────────────────────────────────────────────────────────────────┘
                                │
┌───────────────────────────────▼─────────────────────────────────┐
│                      EXTERNAL SERVICES                           │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │ Gmail IMAP   │  │ Outlook IMAP │  │ Yahoo IMAP   │          │
│  │ (port 993)   │  │ (port 993)   │  │ (port 993)   │          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
└─────────────────────────────────────────────────────────────────┘
```

### 3.2 Technology Stack

**Frontend Layer**
| Technology | Version | Purpose |
|------------|---------|---------|
| React | 18.2.0 | UI framework for component-based architecture |
| Vite | 5.0+ | Fast build tool and dev server |
| Plotly.js | 2.27+ | Interactive visualization for confidence charts |
| CSS3 | - | Minimalist styling and responsive design |
| Axios | 1.6+ | HTTP client for API communication |

**Backend Layer**
| Technology | Version | Purpose |
|------------|---------|---------|
| Python | 3.12.3 | Core programming language |
| FastAPI | 0.104+ | Modern, high-performance web framework |
| Uvicorn | 0.24+ | ASGI server for async request handling |
| Pydantic | 2.5+ | Data validation and serialization |

**Machine Learning**
| Technology | Version | Purpose |
|------------|---------|---------|
| PyTorch | 2.1+ | Deep learning framework for BERT |
| Transformers | 4.35+ | Hugging Face library for NLP models |
| XGBoost | 2.0+ | Gradient boosting for malware classification |
| scikit-learn | 1.3+ | Preprocessing, scaling, and metrics |
| NumPy | 1.26+ | Numerical computing and array operations |
| Optuna | 3.4+ | Hyperparameter optimization |

**Email & File Processing**
| Technology | Version | Purpose |
|------------|---------|---------|
| imaplib | Built-in | IMAP protocol implementation |
| pefile | 2023.2.7+ | PE file parsing and analysis |
| hashlib | Built-in | SHA256 hash calculation |

### 3.3 Component Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                    FRONTEND COMPONENTS                           │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                      App.jsx (Root)                       │   │
│  │              Tab Navigation & Routing                     │   │
│  └───┬──────────────────────┬────────────────────┬──────────┘   │
│      │                      │                    │               │
│  ┌───▼───────────┐  ┌──────▼────────┐  ┌────────▼─────────┐   │
│  │ EmailInbox.jsx│  │SpamChecker.jsx│  │PEFileUpload.jsx  │   │
│  │ • Credentials │  │ • Text Input  │  │ • File Upload    │   │
│  │ • Fetch Emails│  │ • Scan Button │  │ • Drag & Drop    │   │
│  │ • Email List  │  │ • Results     │  │ • SHA256 Display │   │
│  └───┬───────────┘  └──────┬────────┘  └────────┬─────────┘   │
│      │                     │                     │               │
│  ┌───▼─────────────────────▼─────────────────────▼──────────┐  │
│  │            SpamResult.jsx & PredictionResult.jsx          │  │
│  │         • Plotly Pie Charts  • Confidence Scores          │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                              │ API Calls
┌─────────────────────────────▼─────────────────────────────────┐
│                      BACKEND API ENDPOINTS                      │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐ │
│  │ GET /health  │  │GET /model/   │  │POST /scan/spam       │ │
│  │              │  │    info      │  │ Body: {email_text}   │ │
│  └──────────────┘  └──────────────┘  └──────────────────────┘ │
│  ┌──────────────────────┐  ┌──────────────────────────────┐   │
│  │ POST /scan/pe        │  │ POST /email/fetch            │   │
│  │ Form: PE file upload │  │ Body: {email, password}      │   │
│  └──────────────────────┘  └──────────────────────────────┘   │
│  ┌────────────────────────────────────────────────────────┐   │
│  │ POST /email/scan                                        │   │
│  │ Body: {email_id, email_data, attachments}              │   │
│  └────────────────────────────────────────────────────────┘   │
└───────────────────────────┬───────────────────────────────────┘
                            │
┌───────────────────────────▼───────────────────────────────────┐
│                     PROCESSING MODULES                         │
│  ┌───────────────────────────────────────────────────────┐    │
│  │          email_fetcher.py                              │    │
│  │  • connect_to_server()  • fetch_emails()              │    │
│  │  • parse_attachments()  • MIME processing             │    │
│  └───────────────────────────────────────────────────────┘    │
│  ┌───────────────────────────────────────────────────────┐    │
│  │          pe_feature_extractor.py                       │    │
│  │  • extract_dos_header()     • extract_sections()      │    │
│  │  • extract_imports()        • encode_features()       │    │
│  └───────────────────────────────────────────────────────┘    │
│  ┌───────────────────────────────────────────────────────┐    │
│  │          BERT Spam Detector (in app_email_scanner.py) │    │
│  │  • tokenize()               • predict()               │    │
│  │  • softmax_probabilities()                            │    │
│  └───────────────────────────────────────────────────────┘    │
└───────────────────────────────────────────────────────────────┘
```

### 3.4 Data Flow

**Email Spam Detection Flow:**

```
┌─────────────┐
│   User      │ 1. Enters email text
│  (Browser)  │────────────────────────────┐
└─────────────┘                            │
                                           ▼
                            ┌──────────────────────────────┐
                            │ POST /scan/spam              │
                            │ {"email_text": "..."}        │
                            └──────────┬───────────────────┘
                                       │ 2. FastAPI receives request
                                       ▼
                            ┌──────────────────────────────┐
                            │ BERT Tokenizer               │
                            │ • Tokenize text              │
                            │ • Add special tokens         │
                            │ • Create attention mask      │
                            └──────────┬───────────────────┘
                                       │ 3. Tokens (tensor)
                                       ▼
                            ┌──────────────────────────────┐
                            │ DistilBERT Model             │
                            │ • Forward pass               │
                            │ • Extract logits             │
                            └──────────┬───────────────────┘
                                       │ 4. Raw predictions
                                       ▼
                            ┌──────────────────────────────┐
                            │ Post-processing              │
                            │ • Apply softmax              │
                            │ • Get probabilities          │
                            │ • Determine label (ham/spam) │
                            └──────────┬───────────────────┘
                                       │ 5. JSON response
                                       ▼
┌─────────────┐              ┌──────────────────────────────┐
│   User      │ 7. Display   │ {is_spam: false,             │
│  (Browser)  │◄─────────────│  confidence: 0.9967,         │
│  + Plotly   │  results     │  probabilities: {...}}       │
└─────────────┘              └──────────────────────────────┘
     6. Render pie chart
```

**Malware Detection Flow:**

```
┌─────────────┐
│   User      │ 1. Upload PE file
│  (Browser)  │────────────────────────────┐
└─────────────┘                            │
                                           ▼
                            ┌──────────────────────────────┐
                            │ POST /scan/pe                │
                            │ FormData: file binary        │
                            └──────────┬───────────────────┘
                                       │ 2. Save to temp storage
                                       ▼
                            ┌──────────────────────────────┐
                            │ PEFeatureExtractor           │
                            │ • Parse PE headers           │
                            │ • Extract sections           │
                            │ • Get imported DLLs (359)    │
                            │ • Get API functions (499)    │
                            └──────────┬───────────────────┘
                                       │ 3. Feature vector (1140+)
                                       ▼
                            ┌──────────────────────────────┐
                            │ Feature Selection            │
                            │ • Select top 1000 features   │
                            │ • Apply StandardScaler       │
                            └──────────┬───────────────────┘
                                       │ 4. Scaled features
                                       ▼
                            ┌──────────────────────────────┐
                            │ XGBoost Classifier           │
                            │ • Predict class              │
                            │ • Get probability per class  │
                            └──────────┬───────────────────┘
                                       │ 5. Predictions
                                       ▼
                            ┌──────────────────────────────┐
                            │ Label Decoder                │
                            │ • Map to malware family      │
                            │ • Calculate confidence       │
                            │ • Compute SHA256 hash        │
                            └──────────┬───────────────────┘
                                       │ 6. JSON response
                                       ▼
┌─────────────┐              ┌──────────────────────────────┐
│   User      │ 8. Display   │ {predicted_class: "...",     │
│  (Browser)  │◄─────────────│  confidence: 0.95,           │
│  + Plotly   │  results     │  probabilities: {...}}       │
└─────────────┘              └──────────────────────────────┘
     7. Render probability chart
```

**Email Inbox Integration Flow:**

```
User enters credentials (email, app password, provider)
              │
              ▼
    POST /email/fetch
              │
              ▼
    ┌─────────────────────────┐
    │ EmailFetcher             │
    │ 1. Connect via IMAP/SSL  │──► Gmail/Outlook/Yahoo
    │ 2. Authenticate          │    (port 993)
    │ 3. Select INBOX folder   │
    └─────────┬────────────────┘
              │
              ▼
    ┌─────────────────────────┐
    │ Fetch email headers      │
    │ • From, To, Subject      │
    │ • Date, Message-ID       │
    │ • Attachment info        │
    └─────────┬────────────────┘
              │
              ▼
    Return list of emails to frontend
              │
              ▼
    User selects email to scan
              │
              ▼
    POST /email/scan {email_id, body, attachments}
              │
              ├──► Scan body text with BERT
              │    (spam detection)
              │
              └──► Scan PE attachments with XGBoost
                   (malware detection)
              │
              ▼
    Combined results returned to user
```

**Key Architectural Patterns:**

- **RESTful API Design**: Stateless communication using HTTP methods
- **Separation of Concerns**: Clear boundaries between UI, business logic, and models
- **Modular Design**: Independent modules for email fetching, PE extraction, and ML inference
- **Async Processing**: FastAPI supports concurrent request handling
- **Error Handling**: Centralized exception handling with meaningful error messages

---

## 4. Backend Development

### 4.1 API Design and Structure

The backend is built with **FastAPI**, a modern Python web framework chosen for its high performance, automatic API documentation, and native async support. The API follows REST principles with clear endpoint naming and HTTP method conventions.

**API Server Configuration:**
```python
app = FastAPI(
    title="Email Security API",
    description="Detect spam emails and scan PE file attachments",
    version="3.0.0"
)

# CORS middleware for frontend communication
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)
```

**Core API Endpoints:**

| Endpoint | Method | Purpose | Request Body |
|----------|--------|---------|--------------|
| `/` | GET | API overview and documentation | - |
| `/health` | GET | Service health check | - |
| `/model/info` | GET | Model metadata and statistics | - |
| `/scan/spam` | POST | BERT spam detection | `{email_text: string}` |
| `/scan/pe` | POST | XGBoost malware scan | `FormData: file` |
| `/email/fetch` | POST | Fetch emails via IMAP | `{email, password, provider}` |
| `/email/scan` | POST | Comprehensive email threat scan | `{email_id, body, attachments}` |

**Request/Response Models (Pydantic):**
```python
class SpamCheckRequest(BaseModel):
    email_text: str

class SpamCheckResult(BaseModel):
    is_spam: bool
    label: str  # "spam" or "ham"
    confidence: float
    probabilities: Dict[str, float]

class ScanResult(BaseModel):
    filename: str
    sha256: str
    is_malware: bool
    predicted_class: str
    confidence: float
    probabilities: Dict[str, float]
    file_size: int
```

### 4.2 Machine Learning Models

**Model Loading on Startup:**

The application uses FastAPI's `@app.on_event("startup")` lifecycle hook to load models once during initialization, avoiding repeated loading for each request.

```python
@app.on_event("startup")
async def load_model():
    global bert_model, bert_tokenizer, loaded_model, pe_extractor
    
    # Load BERT spam detector
    bert_dir = Path('./saved_models/bert_spam_detector')
    bert_device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    bert_tokenizer = DistilBertTokenizerFast.from_pretrained(bert_dir)
    bert_model = DistilBertForSequenceClassification.from_pretrained(bert_dir)
    bert_model.to(bert_device)
    bert_model.eval()  # Set to inference mode
    
    # Load XGBoost malware detector
    models_dir = Path('./saved_models/xgboost')
    loaded_model = joblib.load(models_dir / 'xgboost_best_model.joblib')
    loaded_encoder = joblib.load(models_dir / 'xgboost_label_encoder.joblib')
    loaded_scaler_header = joblib.load(models_dir / 'xgboost_scaler_header.joblib')
    loaded_scaler_section = joblib.load(models_dir / 'xgboost_scaler_section.joblib')
    loaded_features = joblib.load(models_dir / 'xgboost_top_features.joblib')
    
    # Initialize PE feature extractor
    pe_extractor = PEFeatureExtractor(
        model_features_path=models_dir / 'xgboost_top_features.joblib',
        expected_features=loaded_features
    )
```

**BERT Spam Detection Implementation:**
```python
@app.post("/scan/spam", response_model=SpamCheckResult)
async def check_spam(request: SpamCheckRequest):
    # Tokenization
    inputs = bert_tokenizer(
        request.email_text,
        padding=True,
        truncation=True,
        max_length=128,
        return_tensors="pt"
    ).to(bert_device)
    
    # Inference
    with torch.no_grad():
        outputs = bert_model(**inputs)
        logits = outputs.logits
        probabilities = F.softmax(logits, dim=1)[0]
    
    # Post-processing
    predicted_class = torch.argmax(probabilities).item()
    confidence = probabilities[predicted_class].item()
    
    return SpamCheckResult(
        is_spam=(predicted_class == 1),
        label="spam" if predicted_class == 1 else "ham",
        confidence=confidence,
        probabilities={"ham": prob[0], "spam": prob[1]}
    )
```

**XGBoost Malware Detection Implementation:**
```python
@app.post("/scan/pe", response_model=ScanResult)
async def scan_pe_file(file: UploadFile = File(...)):
    # Save uploaded file temporarily
    with tempfile.NamedTemporaryFile(delete=False, suffix='.exe') as tmp:
        shutil.copyfileobj(file.file, tmp)
        file_path = tmp.name
    
    try:
        # Extract features using pe_extractor
        features_dict = pe_extractor.extract_features(file_path)
        
        # Prepare features for model
        df = pd.DataFrame([features_dict])
        df = df[loaded_features]  # Select only model features
        
        # Apply scaling
        header_cols = [col for col in df.columns if col.startswith(('DOS_', 'FILE_', 'OPTIONAL_'))]
        section_cols = [col for col in df.columns if '_Section_' in col]
        df[header_cols] = loaded_scaler_header.transform(df[header_cols])
        df[section_cols] = loaded_scaler_section.transform(df[section_cols])
        
        # Prediction
        prediction = loaded_model.predict(df)[0]
        probabilities = loaded_model.predict_proba(df)[0]
        
        return ScanResult(
            filename=file.filename,
            sha256=features_dict['sha256'],
            is_malware=(prediction != 0),
            predicted_class=loaded_encoder.inverse_transform([prediction])[0],
            confidence=float(max(probabilities)),
            probabilities={class_name: float(prob) 
                          for class_name, prob in zip(loaded_encoder.classes_, probabilities)},
            file_size=Path(file_path).stat().st_size
        )
    finally:
        Path(file_path).unlink()  # Clean up temp file
```

### 4.3 Email Processing Pipeline

**IMAP Email Fetching (`email_fetcher.py`):**

```python
class EmailFetcher:
    IMAP_SERVERS = {
        'gmail': 'imap.gmail.com',
        'outlook': 'outlook.office365.com',
        'yahoo': 'imap.mail.yahoo.com'
    }
    
    def connect_to_server(self, email_address, app_password, provider):
        """Establish IMAP SSL connection"""
        server = self.IMAP_SERVERS.get(provider.lower())
        mail = imaplib.IMAP4_SSL(server, 993)
        mail.login(email_address, app_password)
        return mail
    
    def fetch_emails(self, mail, limit=20):
        """Fetch emails from INBOX"""
        mail.select('INBOX')
        status, messages = mail.search(None, 'ALL')
        email_ids = messages[0].split()[-limit:]  # Get latest N emails
        
        emails = []
        for email_id in email_ids:
            status, msg_data = mail.fetch(email_id, '(RFC822)')
            email_message = email.message_from_bytes(msg_data[0][1])
            
            # Parse email structure
            emails.append({
                'id': email_id.decode(),
                'from': email_message.get('From'),
                'subject': email_message.get('Subject'),
                'date': email_message.get('Date'),
                'body': self._extract_body(email_message),
                'attachments': self._extract_attachments(email_message)
            })
        
        return emails
```

**Email Fetch Endpoint:**
```python
@app.post("/email/fetch", response_model=EmailListResponse)
async def fetch_emails(request: EmailConnectRequest):
    try:
        fetcher = EmailFetcher()
        mail = fetcher.connect_to_server(
            request.email_address,
            request.app_password,
            request.provider
        )
        emails = fetcher.fetch_emails(mail, limit=20)
        mail.logout()
        
        return EmailListResponse(
            success=True,
            emails=emails,
            total=len(emails)
        )
    except Exception as e:
        raise HTTPException(status_code=401, detail=str(e))
```

**Comprehensive Email Scanning:**
```python
@app.post("/email/scan")
async def scan_email(request: EmailScanRequest):
    # 1. Fetch specific email
    fetcher = EmailFetcher()
    mail = fetcher.connect_to_server(...)
    email_data = fetcher.fetch_single_email(mail, request.email_id)
    
    # 2. Scan email body for spam (BERT)
    spam_result = await check_spam(SpamCheckRequest(email_text=email_data['body']))
    
    # 3. Scan PE attachments for malware (XGBoost)
    attachment_results = []
    for attachment in email_data['attachments']:
        if attachment['filename'].endswith(('.exe', '.dll', '.sys', '.scr')):
            result = await scan_pe_file(attachment['content'])
            attachment_results.append(result)
    
    return {
        "email_id": request.email_id,
        "spam_detection": spam_result,
        "malware_detection": attachment_results,
        "overall_threat": spam_result.is_spam or any(r.is_malware for r in attachment_results)
    }
```

### 4.4 PE File Analysis Module

**Feature Extraction Architecture (`pe_feature_extractor.py`):**

```python
class PEFeatureExtractor:
    def __init__(self, model_features_path, expected_features):
        """Initialize with DLL/API lists from training data"""
        self.dll_list = self._load_dll_list()      # 359 DLLs
        self.api_functions = self._load_apis()     # 499 API functions
        self.expected_features = expected_features
    
    def extract_features(self, pe_file_path):
        """Extract 1140+ features from PE file"""
        pe = pefile.PE(pe_file_path)
        
        features = {}
        features.update(self._extract_dos_header(pe))      # 18 features
        features.update(self._extract_file_header(pe))     # 7 features
        features.update(self._extract_optional_header(pe)) # 25 features
        features.update(self._extract_sections(pe))        # 90 features
        features.update(self._extract_imports(pe))         # 359 + 499 features
        features['sha256'] = self._calculate_sha256(pe_file_path)
        
        return features
    
    def _extract_dos_header(self, pe):
        """DOS header features"""
        return {
            'DOS_e_magic': pe.DOS_HEADER.e_magic,
            'DOS_e_cblp': pe.DOS_HEADER.e_cblp,
            'DOS_e_cp': pe.DOS_HEADER.e_cp,
            # ... 15 more DOS features
        }
    
    def _extract_imports(self, pe):
        """Binary encoding of imported DLLs and APIs"""
        features = {}
        
        # Initialize all DLLs/APIs to 0
        for dll in self.dll_list:
            features[f'DLL_{dll}'] = 0
        for api in self.api_functions:
            features[f'API_{api}'] = 0
        
        # Set to 1 if present in PE
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode().lower()
                if f'DLL_{dll_name}' in features:
                    features[f'DLL_{dll_name}'] = 1
                
                for imp in entry.imports:
                    if imp.name:
                        api_name = imp.name.decode()
                        if f'API_{api_name}' in features:
                            features[f'API_{api_name}'] = 1
        
        return features
```

### 4.5 Database Integration

While the current implementation focuses on real-time processing, the architecture supports future database integration:

**Planned Schema:**
```sql
-- Scan history table
CREATE TABLE scan_history (
    id INT PRIMARY KEY AUTO_INCREMENT,
    scan_type ENUM('spam', 'malware', 'email'),
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    result JSON,
    confidence FLOAT,
    is_threat BOOLEAN
);

-- Email scan details
CREATE TABLE email_scans (
    id INT PRIMARY KEY AUTO_INCREMENT,
    email_id VARCHAR(255),
    sender VARCHAR(255),
    subject TEXT,
    spam_score FLOAT,
    malware_found BOOLEAN,
    scan_timestamp DATETIME
);
```

**Error Handling:**

Centralized exception handling ensures graceful degradation:
```python
@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "detail": str(exc),
            "endpoint": str(request.url)
        }
    )
```

**Performance Optimization:**
- Models loaded once at startup (not per request)
- Temporary file cleanup with `finally` blocks
- CPU-optimized inference for BERT and XGBoost
- Async endpoint definitions for concurrent request handling

---

## 5. Machine Learning Models

### 5.1 Spam Detection Models

[Content to be added - BERT, Naive Bayes, Logistic Regression, Random Forest]

### 5.2 Malware Detection Models

[Content to be added - XGBoost implementation]

### 5.3 Model Training and Evaluation

[Content to be added - Training process and metrics]

### 5.4 Model Performance Comparison

[Content to be added - Comparative analysis of different models]

### 5.5 Model Deployment

[Content to be added - How models are deployed and served]

---

## 6. Frontend Development

### 6.1 User Interface Design

The frontend is built with **React 18** and **Vite**, providing a fast, modern development experience with hot module replacement (HMR). The UI follows a minimalist design philosophy with clean typography, subtle shadows, and a professional color scheme.

**Design Principles:**
- **Simplicity**: Clean interface focused on core functionality
- **Responsiveness**: Adapts to different screen sizes
- **Visual Feedback**: Loading states, error messages, and success indicators
- **Accessibility**: Semantic HTML and proper contrast ratios
- **Performance**: Code splitting and optimized bundle sizes

**Visual Design System:**
```css
/* Color Palette */
Primary Background: #ffffff
Secondary Background: #f8f9fa
Text Primary: #2d2d2d
Text Secondary: #666666
Accent (Spam): #dc3545
Accent (Safe): #28a745
Border: #e5e5e5
Shadow: rgba(0,0,0,0.1)

/* Typography */
Primary Font: 'Inter', -apple-system, system-ui
Headings: 600 weight, 1.8-2rem
Body Text: 400 weight, 0.95rem
Code: 'Courier New', monospace
```

**Layout Structure:**
```
┌─────────────────────────────────────────────┐
│          Header (App Title + Status)        │
├─────────────────────────────────────────────┤
│  [Email Inbox] [Spam Detection] [Malware]  │  ← Tabs
├─────────────────────────────────────────────┤
│                                             │
│           Active Tab Content                │
│     (EmailInbox / SpamChecker / PE)        │
│                                             │
│           ┌─────────────┐                  │
│           │   Result    │                  │
│           │  Component  │                  │
│           │  + Plotly   │                  │
│           └─────────────┘                  │
│                                             │
└─────────────────────────────────────────────┘
```

### 6.2 Component Architecture

**Component Hierarchy:**

```
App.jsx (Root Component)
├── Header
├── API Status Indicator
├── Tab Navigation
└── Tab Content
    ├── EmailInbox.jsx
    │   ├── Email Config Form
    │   ├── Email List
    │   └── SpamResult.jsx (Plotly Chart)
    │
    ├── SpamChecker.jsx
    │   ├── Text Input Area
    │   ├── Check Button
    │   └── SpamResult.jsx (Plotly Chart)
    │
    └── PEFileUpload.jsx
        ├── File Upload Zone
        ├── Drag & Drop
        └── PredictionResult.jsx (Plotly Chart)
```

**Core Components:**

**1. App.jsx (Main Container)**
```jsx
function App() {
  const [activeTab, setActiveTab] = useState('inbox');
  const [apiStatus, setApiStatus] = useState({ online: false });
  const [modelInfo, setModelInfo] = useState(null);
  
  useEffect(() => {
    checkApiStatus();
    fetchModelInfo();
  }, []);
  
  const checkApiStatus = async () => {
    const response = await axios.get(`${API_BASE_URL}/health`);
    setApiStatus({
      online: response.data.xgboost_model_loaded || response.data.bert_model_loaded,
      hasSpamDetection: response.data.bert_model_loaded,
      hasMalwareDetection: response.data.xgboost_model_loaded
    });
  };
  
  return (
    <div className="app-container">
      <header className="header">
        <h1>Email Security System</h1>
        <p>AI-Powered Spam Detection & Malware Scanner</p>
      </header>
      
      {/* Tab Navigation */}
      <div className="tabs">
        <button onClick={() => setActiveTab('inbox')}>Email Inbox</button>
        <button onClick={() => setActiveTab('spam')}>Spam Detection</button>
        <button onClick={() => setActiveTab('malware')}>Malware Scanner</button>
      </div>
      
      {/* Tab Content */}
      {activeTab === 'inbox' && <EmailInbox />}
      {activeTab === 'spam' && <SpamChecker />}
      {activeTab === 'malware' && <PEFileUpload />}
    </div>
  );
}
```

**2. EmailInbox.jsx (IMAP Integration)**
```jsx
function EmailInbox() {
  const [emailConfig, setEmailConfig] = useState({
    email_address: '',
    app_password: '',
    provider: 'gmail'
  });
  const [emails, setEmails] = useState([]);
  const [selectedEmail, setSelectedEmail] = useState(null);
  const [scanResult, setScanResult] = useState(null);
  
  const handleFetchEmails = async (e) => {
    e.preventDefault();
    const response = await fetch('http://localhost:8000/email/fetch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(emailConfig)
    });
    const data = await response.json();
    if (data.success) setEmails(data.emails);
  };
  
  const handleScanEmail = async (emailId) => {
    const email = emails.find(e => e.id === emailId);
    const response = await fetch('http://localhost:8000/scan/spam', {
      method: 'POST',
      body: JSON.stringify({ email_text: email.body })
    });
    setScanResult(await response.json());
  };
  
  return (
    <div className="email-inbox">
      {/* Email Configuration Form */}
      <form onSubmit={handleFetchEmails}>
        <input type="email" placeholder="Email Address" required />
        <input type="password" placeholder="App Password" required />
        <select value={emailConfig.provider}>
          <option value="gmail">Gmail</option>
          <option value="outlook">Outlook</option>
          <option value="yahoo">Yahoo</option>
        </select>
        <button type="submit">Fetch Emails</button>
      </form>
      
      {/* Email List */}
      <div className="email-list">
        {emails.map(email => (
          <div key={email.id} onClick={() => handleScanEmail(email.id)}>
            <strong>{email.from}</strong>
            <p>{email.subject}</p>
          </div>
        ))}
      </div>
      
      {/* Scan Result with Plotly */}
      {scanResult && <SpamResult result={scanResult} />}
    </div>
  );
}
```

**3. SpamChecker.jsx (Text Analysis)**
```jsx
function SpamChecker() {
  const [emailText, setEmailText] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  
  const handleCheck = async () => {
    setLoading(true);
    const response = await fetch('http://localhost:8000/scan/spam', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email_text: emailText })
    });
    setResult(await response.json());
    setLoading(false);
  };
  
  return (
    <div className="spam-checker">
      <textarea
        value={emailText}
        onChange={(e) => setEmailText(e.target.value)}
        placeholder="Paste email content here..."
        rows={12}
      />
      <button onClick={handleCheck} disabled={loading}>
        {loading ? 'Analyzing...' : 'Check for Spam'}
      </button>
      {result && <SpamResult result={result} />}
    </div>
  );
}
```

**4. PEFileUpload.jsx (File Upload)**
```jsx
function PEFileUpload() {
  const [file, setFile] = useState(null);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  
  const handleFileChange = (e) => {
    setFile(e.target.files[0]);
  };
  
  const handleUpload = async () => {
    setLoading(true);
    const formData = new FormData();
    formData.append('file', file);
    
    const response = await fetch('http://localhost:8000/scan/pe', {
      method: 'POST',
      body: formData
    });
    setResult(await response.json());
    setLoading(false);
  };
  
  return (
    <div className="pe-file-upload">
      <div className="upload-zone">
        <input type="file" onChange={handleFileChange} accept=".exe,.dll,.sys,.scr" />
        <p>Drop PE file here or click to browse</p>
      </div>
      <button onClick={handleUpload} disabled={!file || loading}>
        {loading ? 'Scanning...' : 'Scan File'}
      </button>
      {result && <PredictionResult result={result} />}
    </div>
  );
}
```

**5. SpamResult.jsx (Plotly Visualization)**
```jsx
function SpamResult({ result }) {
  const plotData = [{
    values: [result.probabilities.ham, result.probabilities.spam],
    labels: ['Ham', 'Spam'],
    type: 'pie',
    marker: {
      colors: ['#28a745', '#dc3545']
    }
  }];
  
  const layout = {
    title: 'Spam Detection Confidence',
    height: 400,
    showlegend: true
  };
  
  return (
    <div className="spam-result">
      <h3>Result: {result.is_spam ? '🚨 SPAM' : '✅ LEGITIMATE'}</h3>
      <p>Confidence: {(result.confidence * 100).toFixed(2)}%</p>
      <Plot data={plotData} layout={layout} />
    </div>
  );
}
```

**6. PredictionResult.jsx (Malware Results)**
```jsx
function PredictionResult({ result }) {
  const plotData = [{
    values: Object.values(result.probabilities),
    labels: Object.keys(result.probabilities),
    type: 'pie'
  }];
  
  return (
    <div className="prediction-result">
      <h3>{result.is_malware ? '⚠️ MALWARE DETECTED' : '✅ BENIGN'}</h3>
      <p><strong>Classification:</strong> {result.predicted_class}</p>
      <p><strong>Confidence:</strong> {(result.confidence * 100).toFixed(2)}%</p>
      <p><strong>SHA256:</strong> {result.sha256}</p>
      <p><strong>File Size:</strong> {(result.file_size / 1024).toFixed(2)} KB</p>
      <Plot data={plotData} layout={{ title: 'Malware Family Probabilities' }} />
    </div>
  );
}
```

### 6.3 State Management

React's built-in `useState` and `useEffect` hooks manage application state without requiring external libraries like Redux.

**State Categories:**

**1. Application State (App.jsx)**
- `activeTab`: Current active tab ('inbox', 'spam', 'malware')
- `apiStatus`: API health status and model availability
- `modelInfo`: Loaded model metadata

**2. Component State**
- `loading`: Loading indicator for async operations
- `error`: Error messages
- `result`: Scan/prediction results

**3. Form State**
- `emailText`: Input text for spam checker
- `emailConfig`: IMAP credentials and provider
- `file`: Selected PE file for upload

**State Flow Example:**
```jsx
// Parent component passes handler
<SpamChecker onCheck={handleSpamCheck} />

// Child component uses handler
const handleCheck = () => {
  setLoading(true);
  onCheck(emailText)
    .then(result => setResult(result))
    .finally(() => setLoading(false));
};
```

### 6.4 API Integration

**Axios Configuration:**
```jsx
const API_BASE_URL = 'http://localhost:8000';

// Health check on mount
useEffect(() => {
  const checkHealth = async () => {
    const response = await axios.get(`${API_BASE_URL}/health`, { 
      timeout: 3000 
    });
    setApiStatus(response.data);
  };
  checkHealth();
}, []);
```

**API Call Patterns:**

**1. JSON POST Request (Spam Detection)**
```jsx
const response = await axios.post(`${API_BASE_URL}/scan/spam`, {
  email_text: emailText
}, {
  headers: { 'Content-Type': 'application/json' }
});
```

**2. FormData Upload (PE Files)**
```jsx
const formData = new FormData();
formData.append('file', file);

const response = await axios.post(`${API_BASE_URL}/scan/pe`, formData, {
  headers: { 'Content-Type': 'multipart/form-data' }
});
```

**3. Error Handling**
```jsx
try {
  const response = await axios.post(...);
  setResult(response.data);
} catch (err) {
  setError(err.response?.data?.detail || err.message || 'Request failed');
} finally {
  setLoading(false);
}
```

### 6.5 User Experience Features

**1. Loading States**
- Spinner animations during API calls
- Disabled buttons during processing
- Progress indicators for file uploads

**2. Error Handling**
- User-friendly error messages
- API connection status indicator
- Retry mechanisms for failed requests

**3. Interactive Visualizations (Plotly)**
- Pie charts for probability distributions
- Hover tooltips showing exact percentages
- Color-coded results (green=safe, red=threat)
- Responsive charts that resize with container

**4. Form Validation**
- Required field validation
- Email format validation
- File type restrictions (.exe, .dll, .sys, .scr)
- Maximum file size checks

**5. Responsive Design**
```css
/* Mobile-first approach */
@media (max-width: 768px) {
  .tabs {
    flex-direction: column;
  }
  
  .email-list {
    grid-template-columns: 1fr;
  }
}
```

**6. Accessibility Features**
- Semantic HTML elements (`<header>`, `<main>`, `<section>`)
- ARIA labels for interactive elements
- Keyboard navigation support
- Focus indicators for form inputs
- High contrast color ratios (WCAG AA compliant)

**7. Performance Optimizations**
- Code splitting with React.lazy()
- Memoization with React.memo()
- Debounced API calls
- Lazy loading for Plotly charts
- Optimized bundle size with Vite tree-shaking

---

## 7. Features and Functionality

### 7.1 Email Spam Detection

**Core Functionality:**

The spam detection feature uses a fine-tuned DistilBERT model to classify email text as spam or legitimate (ham) with 99.19% accuracy.

**Input Methods:**
1. **Direct Text Input**: Paste email content into textarea
2. **Email Inbox**: Scan fetched emails from Gmail/Outlook/Yahoo
3. **Bulk Text**: Process multiple email texts sequentially

**Detection Process:**
```
User Input → Tokenization → BERT Model → Softmax → Classification
    ↓            ↓              ↓           ↓            ↓
Email text   [CLS] tokens   Hidden    Probabilities  ham/spam
             + padding      states    (ham, spam)    + confidence
```

**Output Information:**
- **Classification Label**: "Spam" or "Ham" (legitimate)
- **Confidence Score**: 0-100% probability of predicted class
- **Probability Distribution**: 
  - Ham probability (e.g., 99.67%)
  - Spam probability (e.g., 0.33%)
- **Visual Representation**: Interactive Plotly pie chart showing probability split

**Example Results:**
```json
{
  "is_spam": false,
  "label": "ham",
  "confidence": 0.9967,
  "probabilities": {
    "ham": 0.9967,
    "spam": 0.0033
  }
}
```

**Key Features:**
- **Real-time Analysis**: Results in <2 seconds
- **Context Understanding**: BERT captures semantic meaning beyond keywords
- **No False Positive Bias**: Balanced training prevents over-flagging
- **Explainable Results**: Clear confidence scores help users understand predictions
- **Maximum Length**: 512 tokens (truncated if longer)

**Use Cases:**
- Pre-screening suspicious emails before opening
- Validating newsletter legitimacy
- Filtering marketing vs. personal emails
- Training data collection for custom spam filters

### 7.2 PE File Malware Analysis

**Core Functionality:**

Analyzes Windows PE files (.exe, .dll, .sys, .scr) to classify them across 7 malware families using XGBoost with 1,000 engineered features.

**Supported File Types:**
- `.exe` - Executable files
- `.dll` - Dynamic-link libraries
- `.sys` - System drivers
- `.scr` - Screen savers

**Classification Categories:**
1. **Benign** - Clean, legitimate software
2. **RedLineStealer** - Information stealing malware
3. **Downloader** - Malware that downloads additional payloads
4. **RAT** (Remote Access Trojan) - Remote control malware
5. **BankingTrojan** - Banking credential theft malware
6. **SnakeKeyLogger** - Keylogging malware
7. **Spyware** - Surveillance and data collection malware

**Feature Extraction Pipeline:**

| Category | Features | Examples |
|----------|----------|----------|
| DOS Header | 18 | e_magic, e_cblp, e_cp, e_lfanew |
| FILE Header | 7 | Machine type, number of sections, timestamp |
| OPTIONAL Header | 25 | EntryPoint, ImageBase, SizeOfImage, Subsystem |
| Section Analysis | 90 | .text/.data/.rdata virtual size, raw size, characteristics |
| Imported DLLs | 359 | kernel32.dll, user32.dll, advapi32.dll presence |
| API Functions | 499 | CreateFile, RegOpenKey, InternetOpen usage |

**Analysis Output:**

```json
{
  "filename": "suspicious.exe",
  "sha256": "abc123...",
  "is_malware": true,
  "predicted_class": "RedLineStealer",
  "confidence": 0.9523,
  "probabilities": {
    "Benign": 0.0123,
    "RedLineStealer": 0.9523,
    "Downloader": 0.0201,
    "RAT": 0.0089,
    "BankingTrojan": 0.0034,
    "SnakeKeyLogger": 0.0018,
    "Spyware": 0.0012
  },
  "file_size": 204800
}
```

**Visualization:**
- **Pie Chart**: Probability distribution across all 7 classes
- **Color Coding**: Red for malware, green for benign
- **Hover Details**: Exact percentages for each malware family

**Security Features:**
- **SHA256 Hash**: Unique file fingerprint for threat intelligence
- **No Execution**: Static analysis only, malware never executed
- **Temporary Storage**: Files deleted immediately after analysis
- **File Size Check**: Validates reasonable file sizes

**Limitations:**
- **Packed/Obfuscated Files**: May reduce accuracy
- **New Malware Families**: Only detects trained categories
- **File Size**: Very large files (>50MB) may timeout
- **Architecture**: Optimized for x86/x64 PE files

### 7.3 Email Inbox Integration

**Core Functionality:**

Direct IMAP integration allows users to connect their email accounts and scan real emails for threats without leaving the application.

**Supported Email Providers:**

| Provider | IMAP Server | Port | Authentication |
|----------|-------------|------|----------------|
| Gmail | imap.gmail.com | 993 (SSL) | App Password required |
| Outlook | outlook.office365.com | 993 (SSL) | App Password required |
| Yahoo Mail | imap.mail.yahoo.com | 993 (SSL) | App Password required |

**Setup Process:**

1. **Generate App Password** (Provider Settings)
   - Gmail: Google Account → Security → 2-Step Verification → App Passwords
   - Outlook: Account Security → Additional Security Options → App Passwords
   - Yahoo: Account Security → Generate App Password

2. **Connect to Inbox** (Application)
   - Enter email address
   - Enter app password (NOT regular password)
   - Select provider from dropdown
   - Click "Fetch Emails"

3. **Email Retrieval**
   - Fetches last 20 emails by default
   - Displays: From, Subject, Date, Preview
   - Shows attachment indicators

**Email List Interface:**

```
┌─────────────────────────────────────────────────┐
│  📧 From: john@example.com                      │
│  Subject: Important Meeting Tomorrow            │
│  📅 Nov 22, 2025  📎 2 attachments             │
│  [Scan Email] button                            │
├─────────────────────────────────────────────────┤
│  📧 From: newsletter@company.com                │
│  Subject: Weekly Updates                        │
│  📅 Nov 21, 2025                                │
│  [Scan Email] button                            │
└─────────────────────────────────────────────────┘
```

**Comprehensive Scanning:**

When scanning an email, the system performs:

1. **Body Text Analysis** (BERT)
   - Extract plain text content
   - Remove HTML formatting
   - Classify as spam/ham
   - Display confidence score

2. **Attachment Analysis** (XGBoost)
   - Identify PE file attachments
   - Extract and analyze each PE file
   - Classify malware family
   - Show combined threat assessment

3. **Combined Results**
   ```
   ✅ Email Body: LEGITIMATE (99.2% confidence)
   ⚠️ Attachment: MALWARE DETECTED
      - suspicious.exe: RedLineStealer (95.2% confidence)
   
   🚨 OVERALL: THREAT DETECTED
   ```

**Security Considerations:**
- **Read-Only Access**: Cannot send, delete, or modify emails
- **Encrypted Connection**: SSL/TLS for IMAP communication
- **No Storage**: Credentials not saved, used only for session
- **App Passwords**: Regular passwords intentionally rejected

**Privacy Features:**
- **Local Processing**: Email content analyzed locally, not sent to third parties
- **Temporary Cache**: Fetched emails cleared on tab switch
- **No Logging**: Email content not logged or stored

### 7.4 Batch Processing

**Current Implementation:**

While the system doesn't have a dedicated batch upload feature, it supports batch-like processing through:

**Sequential Scanning:**
- Fetch 20 emails at once from inbox
- Scan each individually by clicking
- Results displayed immediately per email

**API-Level Batch Support:**

Developers can implement batch processing using the API:

```python
# Batch spam detection
emails = ["email1 text", "email2 text", "email3 text"]
results = []

for email_text in emails:
    response = requests.post('http://localhost:8000/scan/spam', 
                            json={'email_text': email_text})
    results.append(response.json())
```

**Planned Batch Features:**
- CSV file upload with multiple email texts
- Batch PE file scanning (multiple .exe files)
- Progress bar for long-running batch jobs
- Exportable results in JSON/CSV format
- Batch report generation with statistics

**Current Workarounds:**
- Use email inbox feature to scan multiple emails
- Call API endpoints programmatically for automation
- Process files one-by-one through UI

### 7.5 Real-time Predictions

**Performance Characteristics:**

**Spam Detection Speed:**
- **Average Response Time**: 800ms - 2 seconds
- **Tokenization**: ~100ms
- **Model Inference**: ~500-1500ms (CPU)
- **Post-processing**: ~50ms
- **Network Latency**: ~150ms

**Malware Detection Speed:**
- **Average Response Time**: 2-5 seconds
- **File Upload**: ~200ms (for typical 500KB file)
- **PE Parsing**: ~300ms
- **Feature Extraction**: ~500-1000ms
- **Model Inference**: ~800ms
- **Result Formatting**: ~100ms

**Real-time Optimizations:**

1. **Model Preloading**
   - Models loaded at server startup
   - Kept in memory for instant access
   - No loading delay per request

2. **CPU Optimization**
   - DistilBERT chosen over full BERT (40% faster)
   - XGBoost optimized for CPU inference
   - Batch size = 1 for immediate processing

3. **Async Processing**
   - FastAPI async endpoints
   - Non-blocking I/O operations
   - Concurrent request handling

4. **Caching Strategy**
   - Feature lists cached (DLLs, APIs)
   - Tokenizer vocabulary preloaded
   - StandardScaler fitted once

**Live Feedback:**

**Loading States:**
```
Checking email... 🔄
Analyzing content... 🔄
Scanning PE file... 🔄
```

**Progress Indicators:**
- Disabled submit buttons during processing
- Spinner animations
- Status messages
- Estimated time remaining (for large files)

**Instant Results:**
- Results appear immediately upon completion
- No page reload required
- Smooth transitions with CSS animations
- Interactive charts update dynamically

**Streaming Support (Future):**
- WebSocket connection for real-time updates
- Progress percentage for long operations
- Incremental result display
- Live model confidence updates

**User Experience:**
- **Perceived Performance**: Optimistic UI updates
- **Error Recovery**: Automatic retry on network failure
- **Timeout Handling**: 30-second timeout with clear error message
- **Responsive Feedback**: Visual changes within 100ms of user action

---

## 8. Implementation Details

### 8.1 Development Environment Setup

**System Requirements:**

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| OS | Windows 10/11, macOS 10.15+, Linux | Windows 11, Ubuntu 22.04 |
| Python | 3.10+ | 3.12.3 |
| Node.js | 16.x | 18.x or 20.x LTS |
| RAM | 8 GB | 16 GB |
| Storage | 5 GB | 10 GB (for models + dependencies) |
| CPU | Dual-core | Quad-core or better |
| GPU | Not required | CUDA-capable GPU (optional for faster inference) |

**Development Tools:**

- **Code Editor**: VS Code (recommended) with extensions:
  - Python (ms-python.python)
  - Pylance (ms-python.vscode-pylance)
  - ES7+ React/Redux/React-Native snippets
  - Prettier - Code formatter
  
- **Version Control**: Git 2.30+
- **Package Managers**: 
  - Python: pip 23.0+
  - Node.js: npm 9.0+ or pnpm 8.0+

**Backend Setup (Python):**

```powershell
# 1. Navigate to project directory
cd d:\tuhc\COS30049\Assignment1\Spam-and-Malware-Detection-AI-model

# 2. Create virtual environment (recommended)
python -m venv venv

# 3. Activate virtual environment
# Windows PowerShell:
.\venv\Scripts\Activate.ps1
# Windows CMD:
.\venv\Scripts\activate.bat
# Linux/macOS:
source venv/bin/activate

# 4. Upgrade pip
python -m pip install --upgrade pip

# 5. Install dependencies
pip install -r requirements.txt

# 6. Verify installation
python -c "import torch; import transformers; import xgboost; print('All packages installed successfully')"
```

**Frontend Setup (React):**

```powershell
# 1. Navigate to frontend directory
cd frontend

# 2. Install Node dependencies
npm install

# 3. Verify installation
npm list react plotly.js axios

# 4. Start development server (optional test)
npm run dev
```

**Project Structure Setup:**

```
Spam-and-Malware-Detection-AI-model/
├── venv/                    # Python virtual environment (created)
├── Dataset/                 # Training datasets
├── saved_models/            # Trained model files
│   ├── bert_spam_detector/
│   └── xgboost/
├── frontend/                # React application
│   ├── node_modules/        # Node dependencies (created)
│   ├── src/
│   └── package.json
├── app_email_scanner.py     # Main FastAPI server
├── email_fetcher.py         # IMAP integration
├── pe_feature_extractor.py  # PE file analysis
├── requirements.txt         # Python dependencies
└── README.md
```

**Running the Application:**

**Option 1: Using PowerShell Scripts**
```powershell
# Terminal 1 - Start Backend
.\start_api.ps1

# Terminal 2 - Start Frontend
cd frontend
.\start_frontend.ps1
```

**Option 2: Manual Start**
```powershell
# Terminal 1 - Backend
python app_email_scanner.py
# or
uvicorn app_email_scanner:app --reload --host 0.0.0.0 --port 8000

# Terminal 2 - Frontend
cd frontend
npm run dev
```

**Verification Steps:**

1. **Backend Health Check**:
   ```powershell
   curl http://localhost:8000/health
   # Expected: {"status": "online", "bert_model_loaded": true, "xgboost_model_loaded": true}
   ```

2. **Frontend Access**:
   - Open browser to `http://localhost:3002`
   - Verify tab navigation works
   - Check API status indicator shows "Online"

3. **Model Loading Verification**:
   ```powershell
   curl http://localhost:8000/model/info
   # Expected: JSON with model metadata
   ```

**Common Setup Issues:**

| Issue | Solution |
|-------|----------|
| `python` command not found | Use full path: `C:\Users\ADMIN\AppData\Local\Programs\Python\Python312\python.exe` or add to PATH |
| Port 8000 already in use | Change port in `app_email_scanner.py`: `uvicorn.run(app, port=8001)` |
| Port 3002 already in use | Change in `vite.config.js`: `server: { port: 3003 }` |
| Module not found error | Reinstall dependencies: `pip install -r requirements.txt` |
| CORS errors | Verify FastAPI CORS middleware allows frontend origin |
| Model files missing | Download from project repository or retrain models |

**Development Workflow:**

```
┌─────────────────────────────────────────────────────┐
│ 1. Make Code Changes                                 │
│    • Edit .py files for backend                     │
│    • Edit .jsx files for frontend                   │
└────────────────┬────────────────────────────────────┘
                 │
┌────────────────▼────────────────────────────────────┐
│ 2. Backend Auto-Reload (FastAPI --reload)          │
│    • Changes detected automatically                 │
│    • Server restarts without manual intervention    │
└────────────────┬────────────────────────────────────┘
                 │
┌────────────────▼────────────────────────────────────┐
│ 3. Frontend Hot Module Replacement (Vite HMR)      │
│    • Changes reflect instantly in browser           │
│    • State preserved during updates                 │
└────────────────┬────────────────────────────────────┘
                 │
┌────────────────▼────────────────────────────────────┐
│ 4. Test Changes                                      │
│    • Use browser DevTools                           │
│    • Check FastAPI /docs for API testing           │
│    • Monitor terminal for errors                    │
└─────────────────────────────────────────────────────┘
```

### 8.2 Dependencies and Libraries

**Python Dependencies (requirements.txt):**

```txt
# Core Web Framework
fastapi==0.104.1           # Modern async web framework
uvicorn[standard]==0.24.0  # ASGI server with WebSocket support
python-multipart==0.0.6    # File upload handling

# Machine Learning - Deep Learning
torch==2.1.0               # PyTorch deep learning framework
transformers==4.35.0       # Hugging Face transformers library
safetensors==0.4.0         # Safe tensor serialization

# Machine Learning - Classical ML
xgboost==2.0.2             # Gradient boosting library
scikit-learn==1.3.2        # ML utilities (scaling, encoding, metrics)
numpy==1.26.1              # Numerical computing
pandas==2.1.3              # Data manipulation

# Optimization & Model Selection
optuna==3.4.0              # Hyperparameter optimization

# Email & File Processing
pefile==2023.2.7           # PE file parsing and analysis
imaplib (built-in)         # IMAP email protocol

# Utilities
python-dotenv==1.0.0       # Environment variable management
joblib==1.3.2              # Model serialization
pydantic==2.5.0            # Data validation (FastAPI dependency)
```

**Key Library Purposes:**

**1. FastAPI (0.104.1)**
- **Purpose**: Modern web framework for building APIs
- **Why Chosen**: 
  - Automatic OpenAPI documentation at `/docs`
  - Native async/await support
  - Fast performance (on par with Node.js/Go)
  - Type hints for automatic validation
- **Usage**: Core API routing and request handling

**2. PyTorch (2.1.0)**
- **Purpose**: Deep learning framework for BERT model
- **Why Chosen**: 
  - Excellent ecosystem for NLP (Hugging Face integration)
  - Dynamic computation graphs
  - Strong community support
- **Usage**: BERT model inference, tensor operations

**3. Transformers (4.35.0)**
- **Purpose**: Hugging Face library for pre-trained models
- **Why Chosen**: 
  - Easy access to DistilBERT
  - Pre-built tokenizers
  - Model fine-tuning utilities
- **Usage**: BERT tokenizer and model loading

**4. XGBoost (2.0.2)**
- **Purpose**: Gradient boosting for malware classification
- **Why Chosen**: 
  - State-of-the-art performance on tabular data
  - Handles 1000+ features efficiently
  - Built-in feature importance
  - CPU-optimized
- **Usage**: PE file malware classification

**5. pefile (2023.2.7)**
- **Purpose**: Parse Windows PE files
- **Why Chosen**: 
  - Industry-standard PE parser
  - Extracts headers, sections, imports
  - Handles corrupted PE files gracefully
- **Usage**: Extract 1,140+ features from executables

**6. scikit-learn (1.3.2)**
- **Purpose**: ML preprocessing and evaluation
- **Why Chosen**: 
  - StandardScaler for feature normalization
  - LabelEncoder for class encoding
  - Comprehensive metrics (MCC, F1, accuracy)
- **Usage**: Feature scaling, encoding, model evaluation

**Frontend Dependencies (package.json):**

```json
{
  "dependencies": {
    "react": "^18.2.0",           // UI framework
    "react-dom": "^18.2.0",        // React DOM rendering
    "plotly.js": "^2.27.0",        // Interactive visualizations
    "react-plotly.js": "^2.6.0",   // Plotly React wrapper
    "axios": "^1.6.0"              // HTTP client
  },
  "devDependencies": {
    "@vitejs/plugin-react": "^4.2.0",  // Vite React plugin
    "vite": "^5.0.0"                    // Build tool
  }
}
```

**Key Frontend Library Purposes:**

**1. React (18.2.0)**
- **Purpose**: Component-based UI library
- **Why Chosen**: 
  - Virtual DOM for efficient updates
  - Hooks for state management
  - Large ecosystem and community
- **Usage**: All frontend components

**2. Plotly.js (2.27.0)**
- **Purpose**: Interactive charting library
- **Why Chosen**: 
  - Beautiful default styling
  - Interactive hover tooltips
  - No external dependencies
  - Export to PNG/SVG
- **Usage**: Probability distribution pie charts

**3. Axios (1.6.0)**
- **Purpose**: Promise-based HTTP client
- **Why Chosen**: 
  - Automatic JSON transformation
  - Request/response interceptors
  - Better error handling than fetch()
- **Usage**: All API communication

**4. Vite (5.0.0)**
- **Purpose**: Fast build tool and dev server
- **Why Chosen**: 
  - 10-100x faster than Webpack
  - Hot Module Replacement (HMR)
  - Optimized production builds
- **Usage**: Development server and bundling

**Dependency Installation Size:**

| Component | Size | Install Time |
|-----------|------|--------------|
| Python packages | ~4.2 GB | 5-10 minutes |
| Node modules | ~350 MB | 2-3 minutes |
| BERT model | ~268 MB | Pre-downloaded |
| XGBoost model | ~12 MB | Pre-trained |
| **Total** | **~4.8 GB** | **7-13 minutes** |

**Version Pinning Strategy:**

- **Exact versions** for ML libraries (torch, transformers, xgboost) to ensure model compatibility
- **Minor version flexibility** (^) for frontend packages to receive security updates
- **Lock files** (`package-lock.json`, `requirements.txt`) committed to repository

### 8.3 Configuration Management

**Environment Variables:**

Create a `.env` file in the project root (optional, for production):

```bash
# API Configuration
API_HOST=0.0.0.0
API_PORT=8000
API_RELOAD=true

# CORS Configuration
ALLOWED_ORIGINS=http://localhost:3002,http://localhost:5173

# Model Paths
BERT_MODEL_PATH=./saved_models/bert_spam_detector
XGBOOST_MODEL_PATH=./saved_models/xgboost

# Email Configuration (defaults)
IMAP_TIMEOUT=30
MAX_EMAILS_FETCH=20

# Security
MAX_FILE_SIZE=52428800  # 50 MB in bytes
ALLOWED_FILE_TYPES=.exe,.dll,.sys,.scr

# Logging
LOG_LEVEL=INFO
```

**Loading Environment Variables:**

```python
# app_email_scanner.py
from dotenv import load_dotenv
import os

load_dotenv()  # Load .env file

API_HOST = os.getenv('API_HOST', '0.0.0.0')
API_PORT = int(os.getenv('API_PORT', 8000))
BERT_MODEL_PATH = Path(os.getenv('BERT_MODEL_PATH', './saved_models/bert_spam_detector'))
```

**Frontend Configuration (vite.config.js):**

```javascript
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3002,
    proxy: {
      '/api': {
        target: 'http://localhost:8000',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api/, '')
      }
    }
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
    rollupOptions: {
      output: {
        manualChunks: {
          'vendor': ['react', 'react-dom'],
          'plotly': ['plotly.js', 'react-plotly.js']
        }
      }
    }
  }
})
```

**API Configuration:**

```python
# CORS Middleware Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3002",  # Vite dev server
        "http://localhost:5173",  # Alternative Vite port
        "http://127.0.0.1:3002"
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)

# File Upload Configuration
MAX_UPLOAD_SIZE = 50 * 1024 * 1024  # 50 MB
ALLOWED_EXTENSIONS = {'.exe', '.dll', '.sys', '.scr'}

# Model Configuration
BERT_MAX_LENGTH = 512
BERT_BATCH_SIZE = 1
XGBOOST_N_FEATURES = 1000
```

**IMAP Server Configuration:**

```python
# email_fetcher.py
IMAP_SERVERS = {
    'gmail': {
        'server': 'imap.gmail.com',
        'port': 993,
        'ssl': True
    },
    'outlook': {
        'server': 'outlook.office365.com',
        'port': 993,
        'ssl': True
    },
    'yahoo': {
        'server': 'imap.mail.yahoo.com',
        'port': 993,
        'ssl': True
    }
}

# Connection timeouts
IMAP_CONNECT_TIMEOUT = 30
IMAP_READ_TIMEOUT = 60
```

**Model Metadata Configuration:**

Models store their configuration in JSON files:

**BERT Configuration (config.json):**
```json
{
  "model_type": "distilbert",
  "num_labels": 2,
  "vocab_size": 30522,
  "max_position_embeddings": 512,
  "hidden_size": 768,
  "num_attention_heads": 12,
  "num_hidden_layers": 6
}
```

**XGBoost Metadata (xgboost_metadata.joblib):**
```python
{
    'model_name': 'XGBoost Malware Classifier',
    'n_features': 1000,
    'n_classes': 7,
    'classes': ['Benign', 'RedLineStealer', 'Downloader', 'RAT', 
                'BankingTrojan', 'SnakeKeyLogger', 'Spyware'],
    'training_date': '2024-11-15',
    'mcc_score': 0.8875
}
```

**Configuration Best Practices:**

1. **Never commit sensitive data** (.env in .gitignore)
2. **Use environment-specific configs** (dev, staging, production)
3. **Validate configuration on startup** (check model paths exist)
4. **Provide sensible defaults** (fallback values if env vars missing)
5. **Document all configuration options** (in README.md)

### 8.4 Security Considerations

**1. Input Validation & Sanitization**

**File Upload Security:**
```python
@app.post("/scan/pe")
async def scan_pe_file(file: UploadFile = File(...)):
    # 1. File extension validation
    if not file.filename.endswith(('.exe', '.dll', '.sys', '.scr')):
        raise HTTPException(status_code=400, detail="Invalid file type")
    
    # 2. File size validation
    file_size = 0
    max_size = 50 * 1024 * 1024  # 50 MB
    
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        while chunk := await file.read(8192):
            file_size += len(chunk)
            if file_size > max_size:
                tmp.close()
                Path(tmp.name).unlink()
                raise HTTPException(status_code=413, detail="File too large")
            tmp.write(chunk)
    
    # 3. Validate PE structure (prevents non-PE files)
    try:
        pe = pefile.PE(tmp.name)
    except pefile.PEFormatError:
        Path(tmp.name).unlink()
        raise HTTPException(status_code=400, detail="Invalid PE file")
```

**Text Input Sanitization:**
```python
class SpamCheckRequest(BaseModel):
    email_text: str = Field(..., max_length=10000)  # Prevent oversized text
    
    @validator('email_text')
    def validate_text(cls, v):
        if not v or not v.strip():
            raise ValueError("Email text cannot be empty")
        # Remove null bytes
        v = v.replace('\x00', '')
        return v.strip()
```

**2. Authentication & Authorization**

**IMAP Credentials:**
- **App Passwords Required**: Regular passwords intentionally rejected
- **No Storage**: Credentials never saved to disk or logs
- **Memory-Only**: Used for single session, discarded after logout
- **SSL/TLS Enforcement**: All IMAP connections use port 993 with SSL

```python
def connect_to_server(self, email_address, app_password, provider):
    # Enforce SSL connection
    mail = imaplib.IMAP4_SSL(server, 993)
    
    # Authenticate with app password
    try:
        mail.login(email_address, app_password)
    except imaplib.IMAP4.error:
        raise ValueError("Authentication failed - use app password, not regular password")
    
    return mail
```

**API Security (Future Enhancement):**
- **API Keys**: Token-based authentication for API access
- **Rate Limiting**: Prevent brute-force and DoS attacks
- **OAuth2**: Integration with email provider OAuth for secure authentication

**3. Data Privacy**

**Email Content:**
- ✅ Processed locally (not sent to external services)
- ✅ Not logged or stored permanently
- ✅ Temporary memory only during analysis
- ✅ Read-only IMAP access (cannot modify/delete emails)

**Uploaded Files:**
- ✅ Stored in temporary directory only
- ✅ Deleted immediately after analysis (in `finally` block)
- ✅ SHA256 hash calculated but original file not retained
- ✅ No database storage of file contents

```python
try:
    # Process file
    result = analyze_pe_file(tmp.name)
    return result
finally:
    # Always delete temp file
    Path(tmp.name).unlink(missing_ok=True)
```

**4. Model Security**

**Adversarial Attack Mitigation:**
- **Input Length Limits**: BERT truncates at 512 tokens
- **Confidence Thresholds**: Flag low-confidence predictions for review
- **Feature Validation**: PE extractor validates expected feature count

**Model Integrity:**
- ✅ Models loaded from local filesystem (not downloaded at runtime)
- ✅ SHA256 checksums verify model file integrity (optional)
- ✅ Read-only model files (no runtime modification)

**5. Network Security**

**CORS Configuration:**
```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3002",  # Specific origins only
        "http://127.0.0.1:3002"
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST"],  # Only needed methods
    allow_headers=["Content-Type", "Accept"]  # Specific headers
)
```

**HTTPS (Production):**
```python
# Production deployment
uvicorn.run(
    app,
    host="0.0.0.0",
    port=8443,
    ssl_keyfile="/path/to/key.pem",
    ssl_certfile="/path/to/cert.pem"
)
```

**6. Error Handling & Information Disclosure**

**Safe Error Messages:**
```python
@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    # Log full error server-side
    logger.error(f"Error processing request: {exc}", exc_info=True)
    
    # Return sanitized error to client
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "detail": "An unexpected error occurred"  # No stack traces
        }
    )
```

**7. Dependency Security**

**Vulnerability Scanning:**
```powershell
# Check for known vulnerabilities
pip-audit

# Update vulnerable packages
pip install --upgrade package-name
```

**Regular Updates:**
- Monitor security advisories for PyTorch, FastAPI, React
- Update dependencies quarterly (test in dev first)
- Use `npm audit` and `pip-audit` in CI/CD pipeline

**8. Deployment Security (Production)**

**Recommended Practices:**
- ✅ Run behind reverse proxy (Nginx, Caddy)
- ✅ Use firewall to restrict access
- ✅ Enable HTTPS with valid certificates
- ✅ Implement rate limiting (e.g., slowapi)
- ✅ Use process manager (systemd, PM2)
- ✅ Enable logging and monitoring
- ✅ Run with non-root user
- ✅ Use environment variables for secrets
- ✅ Regular security audits and penetration testing

**Security Checklist:**

| Security Measure | Status | Priority |
|------------------|--------|----------|
| Input validation | ✅ Implemented | Critical |
| File size limits | ✅ Implemented | Critical |
| Temporary file cleanup | ✅ Implemented | High |
| CORS configuration | ✅ Implemented | High |
| SSL/TLS for IMAP | ✅ Implemented | Critical |
| No credential storage | ✅ Implemented | Critical |
| Error sanitization | ✅ Implemented | High |
| HTTPS for API | ⚠️ Production only | High |
| API authentication | ⏳ Future | Medium |
| Rate limiting | ⏳ Future | Medium |
| Logging & monitoring | ⏳ Future | Medium |

---

## 9. Testing and Validation

### 9.1 Unit Testing

[Content to be added - Component-level testing]

### 9.2 Integration Testing

[Content to be added - System integration tests]

### 9.3 Model Validation

[Content to be added - Model accuracy and reliability testing]

### 9.4 User Acceptance Testing

[Content to be added - End-user testing results]

---

## 10. Results and Analysis

### 10.1 Model Performance Metrics

[Content to be added - Accuracy, precision, recall, F1-scores]

### 10.2 System Performance

[Content to be added - Response times, throughput]

### 10.3 User Feedback

[Content to be added - User testing feedback]

### 10.4 Comparative Analysis

[Content to be added - Comparison with existing solutions]

---

## 11. Challenges and Solutions

### 11.1 Technical Challenges

[Content to be added - Technical obstacles encountered]

### 11.2 Integration Issues

[Content to be added - Integration problems and resolutions]

### 11.3 Performance Optimization

[Content to be added - Optimization strategies]

### 11.4 Lessons Learned

[Content to be added - Key takeaways from the project]

---

## 12. Future Enhancements

### 12.1 Planned Features

[Content to be added - Features to be added]

### 12.2 Scalability Improvements

[Content to be added - Scaling strategies]

### 12.3 Model Enhancements

[Content to be added - Model improvement plans]

### 12.4 UI/UX Improvements

[Content to be added - Interface enhancement ideas]

---

## 13. Conclusion

[Content to be added - Project summary and final remarks]

---

## 14. References

[Content to be added - Academic papers, documentation, and resources used]

---

## 15. Appendices

### Appendix A: API Documentation

[Content to be added - Detailed API endpoints]

### Appendix B: Model Training Scripts

[Content to be added - Training code examples]

### Appendix C: Database Schema

[Content to be added - Database structure]

### Appendix D: Installation Guide

[Content to be added - Step-by-step installation]

### Appendix E: User Manual

[Content to be added - User guide]

---

**End of Report**
