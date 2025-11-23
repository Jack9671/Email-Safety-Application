from fastapi import FastAPI, HTTPException, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Dict, List, Optional
import joblib
import pandas as pd
import numpy as np
from pathlib import Path
import json

# Initialize FastAPI app
app = FastAPI(
    title="Malware Detection API",
    description="API for malware detection using XGBoost model",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global variables for loaded model components
loaded_model = None
loaded_encoder = None
loaded_features = None
loaded_scaler_header = None
loaded_scaler_section = None
loaded_metadata = None

# Load model on startup
@app.on_event("startup")
async def load_model():
    """Load the trained model and all components on startup"""
    global loaded_model, loaded_encoder, loaded_features, loaded_scaler_header, loaded_scaler_section, loaded_metadata
    
    try:
        models_dir = Path('./saved_models/xgboost')
        
        loaded_model = joblib.load(models_dir / 'xgboost_best_model.joblib')
        loaded_encoder = joblib.load(models_dir / 'xgboost_label_encoder.joblib')
        loaded_features = joblib.load(models_dir / 'xgboost_top_features.joblib')
        loaded_scaler_header = joblib.load(models_dir / 'xgboost_scaler_header.joblib')
        loaded_scaler_section = joblib.load(models_dir / 'xgboost_scaler_section.joblib')
        loaded_metadata = joblib.load(models_dir / 'xgboost_metadata.joblib')
        
        # Define malware family names mapping
        malware_family_names = {
            0: 'Benign',
            1: 'RedLineStealer',
            2: 'Downloader',
            3: 'RAT',
            4: 'BankingTrojan',
            5: 'SnakeKeyLogger',
            6: 'Spyware'
        }
        
        # Update label encoder classes to use family names
        loaded_encoder.classes_ = np.array([malware_family_names[i] for i in range(len(loaded_encoder.classes_))])
        
        # Update metadata with family names
        loaded_metadata['class_names'] = [malware_family_names[i] for i in range(loaded_metadata['n_classes'])]
        
        print("✓ Model and components loaded successfully!")
        print(f"  Model type: XGBoost")
        print(f"  Number of features: {loaded_metadata['n_features']}")
        print(f"  Number of classes: {loaded_metadata['n_classes']}")
        print(f"  Class names: {loaded_metadata['class_names']}")
    except Exception as e:
        print(f"Error loading model: {str(e)}")
        raise


# Pydantic models for request/response
class PredictionRequest(BaseModel):
    """Request model for single prediction"""
    model_config = {
        "json_schema_extra": {
            "example": {
                "features": {
                    "feature1": 0.5,
                    "feature2": 1.0,
                    # Add more features as needed
                }
            }
        }
    }
    
    features: Dict[str, float]


class PredictionResponse(BaseModel):
    """Response model for prediction"""
    model_config = {
        "json_schema_extra": {
            "example": {
                "predicted_class": "benign",
                "confidence": 0.95,
                "probabilities": {
                    "benign": 0.95,
                    "malware": 0.05
                }
            }
        }
    }
    
    predicted_class: str
    confidence: float
    probabilities: Dict[str, float]


class BatchPredictionResponse(BaseModel):
    """Response model for batch predictions"""
    predictions: List[PredictionResponse]
    total_samples: int


class ModelInfoResponse(BaseModel):
    """Response model for model information"""
    model_config = {"protected_namespaces": ()}
    
    model_type: str
    n_features: int
    n_classes: int
    class_names: List[str]
    test_metrics: Dict[str, float]


# API Endpoints
@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "Malware Detection API",
        "version": "1.0.0",
        "endpoints": {
            "GET /": "This endpoint",
            "GET /health": "Health check",
            "GET /model/info": "Get model information",
            "POST /predict": "Single prediction",
            "POST /predict/batch": "Batch predictions",
            "POST /predict/csv": "Predictions from CSV file"
        }
    }


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    if loaded_model is None:
        raise HTTPException(status_code=503, detail="Model not loaded")
    
    return {
        "status": "healthy",
        "model_loaded": loaded_model is not None
    }


@app.get("/model/info")
async def get_model_info():
    """Get information about the loaded model"""
    if loaded_model is None:
        raise HTTPException(status_code=503, detail="Model not loaded")
    
    return {
        "model_type": "XGBoost",
        "n_features": int(loaded_metadata['n_features']),
        "n_classes": int(loaded_metadata['n_classes']),
        "class_names": [str(name) for name in loaded_metadata['class_names']],
        "test_metrics": {
            "mcc": float(loaded_metadata['test_mcc_score']),
            "f1": float(loaded_metadata['test_macro_f1']),
            "precision": float(loaded_metadata['test_macro_precision']),
            "recall": float(loaded_metadata['test_macro_recall'])
        }
    }


@app.post("/predict")
async def predict_single(request: PredictionRequest):
    """Make a single prediction"""
    if loaded_model is None:
        raise HTTPException(status_code=503, detail="Model not loaded")
    
    try:
        # Convert features dict to DataFrame
        features_df = pd.DataFrame([request.features])
        
        # Ensure all required features are present
        missing_features = set(loaded_features) - set(features_df.columns)
        if missing_features:
            # Fill missing features with 0
            for feature in missing_features:
                features_df[feature] = 0
        
        # Select only the features used during training
        features_df = features_df[loaded_features]
        
        # Make prediction
        prediction = loaded_model.predict(features_df)[0]
        probabilities = loaded_model.predict_proba(features_df)[0]
        
        # Decode prediction
        predicted_class = str(loaded_encoder.inverse_transform([prediction])[0])
        
        # Create probability dictionary
        prob_dict = {
            str(class_name): float(prob) 
            for class_name, prob in zip(loaded_metadata['class_names'], probabilities)
        }
        
        return {
            "predicted_class": predicted_class,
            "confidence": float(probabilities.max()),
            "probabilities": prob_dict
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Prediction error: {str(e)}")


@app.post("/predict/batch", response_model=BatchPredictionResponse)
async def predict_batch(requests: List[PredictionRequest]):
    """Make batch predictions"""
    if loaded_model is None:
        raise HTTPException(status_code=503, detail="Model not loaded")
    
    try:
        predictions = []
        
        for req in requests:
            # Convert features dict to DataFrame
            features_df = pd.DataFrame([req.features])
            
            # Ensure all required features are present
            missing_features = set(loaded_features) - set(features_df.columns)
            if missing_features:
                for feature in missing_features:
                    features_df[feature] = 0
            
            # Select only the features used during training
            features_df = features_df[loaded_features]
            
            # Make prediction
            prediction = loaded_model.predict(features_df)[0]
            probabilities = loaded_model.predict_proba(features_df)[0]
            
            # Decode prediction
            predicted_class = str(loaded_encoder.inverse_transform([prediction])[0])
            
            # Create probability dictionary
            prob_dict = {
                str(class_name): float(prob) 
                for class_name, prob in zip(loaded_metadata['class_names'], probabilities)
            }
            
            predictions.append(PredictionResponse(
                predicted_class=predicted_class,
                confidence=float(probabilities.max()),
                probabilities=prob_dict
            ))
        
        return BatchPredictionResponse(
            predictions=predictions,
            total_samples=len(predictions)
        )
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Batch prediction error: {str(e)}")


@app.post("/predict/csv")
async def predict_from_csv(file: UploadFile = File(...)):
    """Make predictions from uploaded CSV file"""
    if loaded_model is None:
        raise HTTPException(status_code=503, detail="Model not loaded")
    
    try:
        # Read CSV file
        contents = await file.read()
        
        # Parse CSV
        from io import StringIO
        csv_string = contents.decode('utf-8')
        df = pd.read_csv(StringIO(csv_string))
        
        # Ensure all required features are present
        missing_features = set(loaded_features) - set(df.columns)
        if missing_features:
            for feature in missing_features:
                df[feature] = 0
        
        # Select only the features used during training
        df_features = df[loaded_features]
        
        # Make predictions
        predictions = loaded_model.predict(df_features)
        probabilities = loaded_model.predict_proba(df_features)
        
        # Decode predictions
        predicted_classes = loaded_encoder.inverse_transform(predictions)
        
        # Create results DataFrame
        results = pd.DataFrame({
            'predicted_class': predicted_classes,
            'confidence': probabilities.max(axis=1)
        })
        
        # Add probability for each class
        for i, class_name in enumerate(loaded_metadata['class_names']):
            results[f'prob_{class_name}'] = probabilities[:, i]
        
        # If original CSV has SHA256 or ID column, include it
        if 'SHA256' in df.columns:
            results.insert(0, 'SHA256', df['SHA256'])
        elif 'id' in df.columns:
            results.insert(0, 'id', df['id'])
        
        # Convert to list of dictionaries
        results_list = results.to_dict(orient='records')
        
        return {
            "total_samples": len(results),
            "predictions": results_list
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"CSV prediction error: {str(e)}")


if __name__ == "__main__":
    import uvicorn
    print("\n" + "="*80)
    print("STARTING MALWARE DETECTION API SERVER")
    print("="*80)
    print("API will be available at: http://localhost:8000")
    print("Interactive docs: http://localhost:8000/docs")
    print("\nPress CTRL+C to stop the server")
    print("="*80 + "\n")
    uvicorn.run(app, host="0.0.0.0", port=8000)
