"""
Email Attachment Scanner for Malware Detection
Processes emails with PE file attachments and predicts malware type
"""

# Set environment variables BEFORE importing transformers to avoid TensorFlow
import os
os.environ['TRANSFORMERS_NO_TF'] = '1'
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Dict, List, Optional
import joblib
import pandas as pd
import numpy as np
from pathlib import Path
import tempfile
import shutil
import torch
import torch.nn.functional as F
from transformers import DistilBertTokenizerFast, DistilBertForSequenceClassification
from pe_feature_extractor import PEFeatureExtractor
from email_fetcher import EmailFetcher

app = FastAPI(
    title="Email Security API",
    description="Detect spam emails and scan PE file attachments for malware",
    version="3.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global variables for PE malware detection
loaded_model = None
loaded_encoder = None
loaded_features = None
loaded_scaler_header = None
loaded_scaler_section = None
loaded_metadata = None
pe_extractor = None

# Global variables for BERT spam detection
bert_model = None
bert_tokenizer = None
bert_device = None
bert_max_length = 128


@app.on_event("startup")
async def load_model():
    """Load models: XGBoost for malware detection and BERT for spam detection"""
    global loaded_model, loaded_encoder, loaded_features, loaded_scaler_header
    global loaded_scaler_section, loaded_metadata, pe_extractor
    global bert_model, bert_tokenizer, bert_device
    
    # Load XGBoost malware detection model
    try:
        models_dir = Path('./backend/saved_models/xgboost')
        print(f"models_dir: {models_dir}")
        loaded_model = joblib.load(models_dir / 'xgboost_best_model.joblib')
        loaded_encoder = joblib.load(models_dir / 'xgboost_label_encoder.joblib')
        loaded_features = joblib.load(models_dir / 'xgboost_top_features.joblib')
        loaded_scaler_header = joblib.load(models_dir / 'xgboost_scaler_header.joblib')
        loaded_scaler_section = joblib.load(models_dir / 'xgboost_scaler_section.joblib')
        loaded_metadata = joblib.load(models_dir / 'xgboost_metadata.joblib')
        
        # Malware family names mapping
        malware_family_names = {
            0: 'Benign',
            1: 'RedLineStealer',
            2: 'Downloader',
            3: 'RAT',
            4: 'BankingTrojan',
            5: 'SnakeKeyLogger',
            6: 'Spyware'
        }
        
        loaded_encoder.classes_ = np.array([malware_family_names[i] for i in range(len(loaded_encoder.classes_))])
        loaded_metadata['class_names'] = [malware_family_names[i] for i in range(loaded_metadata['n_classes'])]
        
        # Initialize PE extractor with expected features to filter DLLs/APIs
        pe_extractor = PEFeatureExtractor(
            model_features_path=models_dir / 'xgboost_top_features.joblib',
            expected_features=loaded_features
        )
        
        print("[OK] Model and PE extractor loaded successfully!")
        print(f"  Model type: XGBoost")
        print(f"  Number of features: {loaded_metadata['n_features']}")
        print(f"  Number of classes: {loaded_metadata['n_classes']}")
        print(f"  Class names: {loaded_metadata['class_names']}")
        print(f"  Recognized DLLs: {len(pe_extractor.dll_list)}")
        print(f"  Recognized APIs: {len(pe_extractor.api_functions)}")
    except Exception as e:
        print(f"Error loading XGBoost model: {str(e)}")
        raise
    
    # Load BERT spam detection model
    try:
        bert_dir = Path('./backend/saved_models/bert_spam_detector')
        bert_device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        
        bert_tokenizer = DistilBertTokenizerFast.from_pretrained(bert_dir)
        bert_model = DistilBertForSequenceClassification.from_pretrained(bert_dir)
        bert_model.to(bert_device)
        bert_model.eval()
        
        print("[OK] BERT spam detector loaded successfully!")
        print(f"  Model: DistilBERT")
        print(f"  Device: {bert_device}")
        print(f"  Vocabulary size: {bert_tokenizer.vocab_size}")
    except Exception as e:
        print(f"Warning: BERT model not loaded: {str(e)}")
        print("  Spam detection will not be available")


class ScanResult(BaseModel):
    """Result of PE file scan"""
    filename: str
    sha256: str
    is_malware: bool
    predicted_class: str
    confidence: float
    probabilities: Dict[str, float]
    file_size: int


class SpamCheckRequest(BaseModel):
    """Request for spam detection"""
    email_text: str


class SpamCheckResult(BaseModel):
    """Result of spam detection"""
    is_spam: bool
    label: str
    confidence: float
    probabilities: Dict[str, float]


class EmailConnectRequest(BaseModel):
    """Request to connect to email account"""
    email_address: str
    app_password: str
    provider: str = 'gmail'  # gmail, outlook, yahoo


class EmailListResponse(BaseModel):
    """Response with list of emails"""
    success: bool
    emails: List[Dict]
    total: int
    message: Optional[str] = None


class EmailScanRequest(BaseModel):
    """Request to scan specific email"""
    email_address: str
    app_password: str
    provider: str
    email_id: str


@app.get("/")
async def root():
    return {
        "message": "Email Security API - Spam Detection & Malware Scanning",
        "version": "3.0.0",
        "endpoints": {
            "/health": "Health check",
            "/model/info": "Model information",
            "/scan/spam": "Check email text for spam (BERT)",
            "/scan/pe": "Scan PE file attachment for malware (XGBoost)",
            "/email/fetch": "Fetch emails from Gmail/Outlook",
            "/email/scan": "Scan a specific email for threats"
        }
    }


@app.get("/health")
async def health():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "xgboost_model_loaded": loaded_model is not None,
        "pe_extractor_ready": pe_extractor is not None,
        "bert_model_loaded": bert_model is not None
    }


@app.get("/model/info")
async def model_info():
    """Get model information"""
    info = {}
    
    # XGBoost malware detection info
    if loaded_metadata is not None:
        info["malware_detection"] = {
            "model_type": "XGBoost",
            "n_features": loaded_metadata['n_features'],
            "n_classes": loaded_metadata['n_classes'],
            "class_names": loaded_metadata['class_names'],
            "test_metrics": {
                "mcc": loaded_metadata.get('test_mcc_score', 0),
                "f1": loaded_metadata.get('test_macro_f1', 0),
                "precision": loaded_metadata.get('test_macro_precision', 0),
                "recall": loaded_metadata.get('test_macro_recall', 0)
            }
        }
    
    # BERT spam detection info
    if bert_model is not None:
        info["spam_detection"] = {
            "model_type": "DistilBERT",
            "model_name": "distilbert-base-uncased",
            "vocab_size": bert_tokenizer.vocab_size if bert_tokenizer else 0,
            "max_length": bert_max_length,
            "device": str(bert_device) if bert_device else "N/A"
        }
    
    if not info:
        raise HTTPException(status_code=503, detail="No models loaded")
    
    return info


@app.post("/scan/spam", response_model=SpamCheckResult)
async def check_spam(request: SpamCheckRequest):
    """
    Check if email text is spam using BERT model
    
    Send email text to analyze for spam content
    """
    if bert_model is None or bert_tokenizer is None:
        raise HTTPException(status_code=503, detail="BERT model not loaded")
    
    try:
        # Tokenize the input text
        encoding = bert_tokenizer(
            request.email_text,
            truncation=True,
            padding=True,
            max_length=bert_max_length,
            return_tensors='pt'
        )
        
        # Move to device
        input_ids = encoding['input_ids'].to(bert_device)
        attention_mask = encoding['attention_mask'].to(bert_device)
        
        # Make prediction
        with torch.no_grad():
            outputs = bert_model(input_ids, attention_mask=attention_mask)
            logits = outputs['logits']
            
            # Get probabilities
            probabilities = F.softmax(logits, dim=1)
            predicted_label = torch.argmax(logits, dim=1).item()
            confidence = probabilities[0][predicted_label].item()
        
        # Convert to readable format
        label_names = {0: 'Ham', 1: 'Spam'}
        is_spam = predicted_label == 1
        
        return SpamCheckResult(
            is_spam=is_spam,
            label=label_names[predicted_label],
            confidence=float(confidence),
            probabilities={
                'ham': float(probabilities[0][0].item()),
                'spam': float(probabilities[0][1].item())
            }
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error checking spam: {str(e)}")


@app.post("/scan/pe", response_model=ScanResult)
async def scan_pe_file(file: UploadFile = File(...)):
    """
    Scan a PE file (exe, dll) for malware
    
    Upload a Windows executable file to analyze for malware
    """
    if loaded_model is None or pe_extractor is None:
        raise HTTPException(status_code=503, detail="Model not loaded")
    
    # Validate file extension
    allowed_extensions = ['.exe', '.dll', '.sys', '.scr']
    file_ext = Path(file.filename).suffix.lower()
    if file_ext not in allowed_extensions:
        raise HTTPException(
            status_code=400, 
            detail=f"Invalid file type. Allowed: {allowed_extensions}"
        )
    
    # Save uploaded file temporarily
    temp_dir = Path(tempfile.mkdtemp())
    temp_file = temp_dir / file.filename
    
    try:
        # Save uploaded file
        with temp_file.open("wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        
        file_size = temp_file.stat().st_size
        
        # Extract features
        print(f"Extracting features from: {file.filename}")
        features = pe_extractor.extract_features_from_file(temp_file, file_type="unknown")
        
        if features is None:
            raise HTTPException(status_code=400, detail="Failed to parse PE file. File may be corrupted or not a valid PE file.")
        
        # Convert to DataFrame
        df = pd.DataFrame([features])
        
        # Prepare for prediction (pass expected features to ensure compatibility)
        df = pe_extractor.prepare_for_prediction(
            df, 
            loaded_scaler_header, 
            loaded_scaler_section,
            expected_features=loaded_features
        )
        
        # Select only the features used by the model
        X = df[loaded_features]
        
        # Make prediction
        prediction = loaded_model.predict(X)[0]
        prediction_proba = loaded_model.predict_proba(X)[0]
        predicted_class = loaded_encoder.inverse_transform([prediction])[0]
        
        # Prepare probabilities dict
        probabilities = {
            str(class_name): float(prob) 
            for class_name, prob in zip(loaded_metadata['class_names'], prediction_proba)
        }
        
        # Determine if malware (anything except Benign)
        is_malware = predicted_class != "Benign"
        
        return ScanResult(
            filename=file.filename,
            sha256=features['SHA256'],
            is_malware=is_malware,
            predicted_class=str(predicted_class),
            confidence=float(prediction_proba.max()),
            probabilities=probabilities,
            file_size=file_size
        )
        
    except HTTPException:
        raise
    except Exception as e:
        import traceback
        print(f"ERROR: {str(e)}")
        print(traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Error processing file: {str(e)}")
    finally:
        # Cleanup temp files
        if temp_dir.exists():
            shutil.rmtree(temp_dir)


@app.post("/email/fetch", response_model=EmailListResponse)
async def fetch_emails(request: EmailConnectRequest):
    """
    Fetch recent emails from Gmail/Outlook
    
    Requires:
    - email_address: Your email address
    - app_password: App-specific password (not regular password)
    - provider: 'gmail', 'outlook', or 'yahoo'
    
    Note: For Gmail, generate app password at: https://myaccount.google.com/apppasswords
          For Outlook, generate at: https://account.live.com/proofs/AppPassword
    """
    try:
        # Create email fetcher
        fetcher = EmailFetcher(
            email_address=request.email_address,
            password=request.app_password,
            provider=request.provider
        )
        
        # Connect to email server
        if not fetcher.connect():
            return EmailListResponse(
                success=False,
                emails=[],
                total=0,
                message="Failed to connect. Check your credentials and make sure you're using an App Password."
            )
        
        try:
            # Select inbox
            if not fetcher.select_folder('INBOX'):
                return EmailListResponse(
                    success=False,
                    emails=[],
                    total=0,
                    message="Failed to access inbox"
                )
            
            # Fetch emails
            emails = fetcher.fetch_emails(max_emails=20, search_criteria='ALL')
            
            # Format response (don't include attachment data in list view)
            formatted_emails = []
            for email_data in emails:
                formatted_emails.append({
                    'id': email_data['id'],
                    'subject': email_data['subject'],
                    'from': email_data['from'],
                    'date': email_data['date'],
                    'body_preview': email_data['body'][:200] + ('...' if len(email_data['body']) > 200 else ''),
                    'has_attachments': email_data['has_attachments'],
                    'attachment_count': len(email_data['attachments']),
                    'attachment_names': [att['filename'] for att in email_data['attachments']]
                })
            
            return EmailListResponse(
                success=True,
                emails=formatted_emails,
                total=len(formatted_emails),
                message=f"Successfully fetched {len(formatted_emails)} emails"
            )
        
        finally:
            fetcher.disconnect()
    
    except Exception as e:
        import traceback
        print(f"Error fetching emails: {str(e)}")
        print(traceback.format_exc())
        return EmailListResponse(
            success=False,
            emails=[],
            total=0,
            message=f"Error: {str(e)}"
        )


@app.post("/email/scan")
async def scan_email(request: EmailScanRequest):
    """
    Scan a specific email for spam and malware
    
    Fetches the email, scans the body for spam using BERT,
    and scans any PE file attachments for malware using XGBoost.
    """
    try:
        # Create email fetcher
        fetcher = EmailFetcher(
            email_address=request.email_address,
            password=request.app_password,
            provider=request.provider
        )
        
        # Connect
        if not fetcher.connect():
            raise HTTPException(
                status_code=401,
                detail="Failed to connect to email server. Check credentials."
            )
        
        try:
            # Select inbox
            if not fetcher.select_folder('INBOX'):
                raise HTTPException(status_code=500, detail="Failed to access inbox")
            
            # Fetch specific email
            status, msg_data = fetcher.mail.fetch(request.email_id.encode(), '(RFC822)')
            
            if status != 'OK':
                raise HTTPException(status_code=404, detail="Email not found")
            
            # Parse email
            import email as email_lib
            raw_email = msg_data[0][1]
            email_message = email_lib.message_from_bytes(raw_email)
            
            # Extract details
            email_body = fetcher.get_email_body(email_message)
            attachments = fetcher.get_attachments(email_message)
            
            # Scan email body for spam
            spam_result = None
            if bert_model and email_body:
                encoding = bert_tokenizer(
                    email_body,
                    truncation=True,
                    padding=True,
                    max_length=bert_max_length,
                    return_tensors='pt'
                )
                
                input_ids = encoding['input_ids'].to(bert_device)
                attention_mask = encoding['attention_mask'].to(bert_device)
                
                with torch.no_grad():
                    outputs = bert_model(input_ids, attention_mask=attention_mask)
                    logits = outputs['logits']
                    probabilities = F.softmax(logits, dim=1)
                    predicted_label = torch.argmax(logits, dim=1).item()
                    confidence = probabilities[0][predicted_label].item()
                
                label_names = {0: 'Ham', 1: 'Spam'}
                spam_result = {
                    'is_spam': predicted_label == 1,
                    'label': label_names[predicted_label],
                    'confidence': float(confidence),
                    'probabilities': {
                        'ham': float(probabilities[0][0].item()),
                        'spam': float(probabilities[0][1].item())
                    }
                }
            
            # Scan PE file attachments for malware
            malware_results = []
            for attachment in attachments:
                filename = attachment['filename'].lower()
                
                # Check if it's a PE file
                if any(filename.endswith(ext) for ext in ['.exe', '.dll', '.sys', '.scr', '.cpl', '.ocx', '.drv']):
                    try:
                        # Save to temp file
                        temp_dir = Path(tempfile.mkdtemp())
                        temp_file = temp_dir / attachment['filename']
                        
                        with temp_file.open('wb') as f:
                            f.write(attachment['data'])
                        
                        # Extract features and scan
                        if loaded_model and pe_extractor:
                            features = pe_extractor.extract_features_from_file(temp_file, file_type="unknown")
                            
                            if features:
                                df = pd.DataFrame([features])
                                df = pe_extractor.prepare_for_prediction(
                                    df, loaded_scaler_header, loaded_scaler_section,
                                    expected_features=loaded_features
                                )
                                X = df[loaded_features]
                                
                                prediction = loaded_model.predict(X)[0]
                                prediction_proba = loaded_model.predict_proba(X)[0]
                                predicted_class = loaded_encoder.inverse_transform([prediction])[0]
                                
                                probabilities = {
                                    str(class_name): float(prob)
                                    for class_name, prob in zip(loaded_metadata['class_names'], prediction_proba)
                                }
                                
                                malware_results.append({
                                    'filename': attachment['filename'],
                                    'size': attachment['size'],
                                    'is_malware': predicted_class != "Benign",
                                    'predicted_class': str(predicted_class),
                                    'confidence': float(prediction_proba.max()),
                                    'probabilities': probabilities
                                })
                        
                        # Cleanup
                        shutil.rmtree(temp_dir)
                    
                    except Exception as e:
                        print(f"Error scanning attachment {attachment['filename']}: {e}")
                        malware_results.append({
                            'filename': attachment['filename'],
                            'error': str(e)
                        })
            
            return {
                'success': True,
                'email': {
                    'subject': fetcher.decode_text(email_message.get('Subject', '')),
                    'from': fetcher.decode_text(email_message.get('From', '')),
                    'date': email_message.get('Date', ''),
                    'body': email_body[:500] + ('...' if len(email_body) > 500 else '')
                },
                'spam_scan': spam_result,
                'malware_scans': malware_results,
                'total_attachments': len(attachments),
                'pe_files_scanned': len(malware_results),
                'threats_detected': (spam_result and spam_result['is_spam']) or any(r.get('is_malware', False) for r in malware_results)
            }
        
        finally:
            fetcher.disconnect()
    
    except HTTPException:
        raise
    except Exception as e:
        import traceback
        print(f"Error scanning email: {str(e)}")
        print(traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Error scanning email: {str(e)}")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
