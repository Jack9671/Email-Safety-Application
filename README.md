# Spam and Malware Detection AI Models

A comprehensive machine learning project implementing multiple AI models for:
1. **PE Malware Classification** - Detecting and classifying malware types from PE file features
2. **Email Spam Detection** - Identifying spam emails using advanced NLP techniques

## 🎯 Project Overview

This repository contains two main AI systems:

### 1. PE Malware Classification
Multi-class classification of Portable Executable (PE) malware using machine learning models:
- **Logistic Regression** - Baseline linear classifier
- **Naive Bayes** - Probabilistic classifier
- **Random Forest** - Ensemble tree-based classifier
- **XGBoost** - Gradient boosted trees with Bayesian optimization

### 2. Email Spam Detection
Binary classification of emails using:
- **BERT (DistilBERT)** - State-of-the-art transformer-based NLP model

## 📋 Requirements

- Python 3.11.9
- PyTorch (for BERT model)
- Transformers (Hugging Face)
- XGBoost
- Scikit-learn
- Pandas, NumPy
- Plotly (for visualizations)
- See `requirements.txt` for all dependencies

## 🚀 Installation

1. Clone the repository:
```bash
git clone https://github.com/Jack9671/Spam-and-Malware-Detection-AI-model.git
cd Spam-and-Malware-Detection-AI-model
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. **Dataset**: Due to file size limitations, some large CSV files are not included in the repository:
   - PE Malware dataset files (place in `Dataset/` folder)
   - Email spam dataset: `raw_email_data.csv` (included)

## � Project Structure

```
Spam-and-Malware-Detection-AI-model/
├── Dataset/
│   ├── pe_header.csv              # PE header features
│   ├── pe_section.csv             # PE section features
│   ├── dlls_imported.csv          # Imported DLL features
│   ├── api_functions.csv          # API function calls
│   ├── top_500_api_functions.csv  # Selected API features
│   ├── merged_data.csv            # Combined PE features
│   └── raw_email_data.csv         # Email spam dataset
│
├── saved_models/                  # Trained models
│   ├── logistic_regression/       # Logistic Regression model files
│   ├── naive_bayes/               # Naive Bayes model files
│   ├── random_forest/             # Random Forest model files
│   ├── xgboost/                   # XGBoost model files
│   └── bert_spam_detector/        # BERT email classifier
│
├── logistic_regression.ipynb      # Logistic Regression training
├── naive_bayes.ipynb              # Naive Bayes training
├── random_forest.ipynb            # Random Forest training
├── XGboost.ipynb                  # XGBoost training
├── email_spam_classification.ipynb # BERT spam detection
├── api_functions_selection.ipynb  # Feature selection notebook
├── spam_detection_bert_report.txt # BERT model report
├── requirements.txt               # Python dependencies
└── README.md                      # This file
```

## 🔧 Usage

### PE Malware Classification

Run the notebooks in order:

1. **Feature Selection** (Optional):
   ```
   api_functions_selection.ipynb
   ```

2. **Train Models**:
   ```
   logistic_regression.ipynb    # Logistic Regression classifier
   naive_bayes.ipynb            # Naive Bayes classifier
   random_forest.ipynb          # Random Forest classifier
   XGboost.ipynb                # XGBoost classifier (best performance)
   ```

### Email Spam Detection

Run the complete BERT training pipeline:
```
email_spam_classification.ipynb
```

## 🎓 Methodology

### PE Malware Classification

1. **Data Loading & Preprocessing**
   - Merge PE Header, Section, DLL, and API features
   - StandardScaler normalization for numeric features
   - Handle missing values and data imbalance

2. **Feature Selection**
   - Top 500-1000 features based on importance
   - Reduce dimensionality while maintaining performance

3. **Model Training**
   - Bayesian hyperparameter optimization (XGBoost)
   - GridSearchCV for other models
   - Class weighting for imbalanced datasets
   - Cross-validation for robust evaluation

4. **Model Saving**
   - Trained models saved with joblib
   - Scalers and encoders saved for inference
   - Metadata includes performance metrics and configuration

### Email Spam Detection

1. **Data Preprocessing**
   - Text cleaning and tokenization
   - Train/validation/test split (60%/20%/20%)
   - BERT tokenization with max length 128

2. **Model Architecture**
   - DistilBERT base model (66M parameters)
   - Binary classification head
   - Fine-tuning on email spam dataset

3. **Training**
   - Adam optimizer with learning rate 5e-5
   - Binary cross-entropy loss
   - GPU acceleration (CUDA if available)

4. **Comprehensive Evaluation**
   - 11 performance metrics
   - Confusion matrix analysis
   - Confidence score analysis
   - Training dynamics visualization

## 📈 Performance Metrics

All models are evaluated using comprehensive metrics:

- **Area Under Precision-Recall Curve (AUC-PR)**
- **TPR (True Positive Rate / Recall / Sensitivity)**
- **Precision**
- **F1-Score**
- **TNR (True Negative Rate / Specificity)**
- **NPV (Negative Predictive Value)**
- **FPR (False Positive Rate)**
- **FNR (False Negative Rate)**
- **MCC (Matthews Correlation Coefficient)**
- **Accuracy**

## 🏆 Model Performance Summary

### PE Malware Classification
- **XGBoost**: Best overall performance with Bayesian optimization
- **Random Forest**: Strong ensemble performance
- **Naive Bayes**: Fast training, good baseline
- **Logistic Regression**: Interpretable linear model

### Email Spam Detection
- **BERT (DistilBERT)**: State-of-the-art accuracy with transformer architecture
- Detailed performance report in `spam_detection_bert_report.txt`

## 💾 Saved Models

All trained models are saved in `saved_models/` directory with:
- Model weights (`.joblib` for sklearn/xgboost, `.safetensors` for BERT)
- Label encoders
- Feature scalers
- Top features list
- Metadata (performance metrics, configuration, training history)

### Loading Saved Models

Each notebook includes example code for loading and using saved models on new data without retraining.

## ⚡ Optimization Features

- **Fast Training Mode**: Reduced cross-validation for faster iteration
- **Bayesian Optimization**: Efficient hyperparameter search
- **GPU Support**: CUDA acceleration for BERT training
- **Feature Selection**: Dimensionality reduction for faster training
- **Class Weighting**: Handle imbalanced datasets effectively


## � Key Features

### PE Malware Classification
- **Multiple ML Models**: Compare Logistic Regression, Naive Bayes, Random Forest, and XGBoost
- **Feature Engineering**: Advanced feature extraction from PE files
- **Hyperparameter Optimization**: Bayesian optimization for XGBoost
- **Class Imbalance Handling**: Weighted training for balanced performance
- **Comprehensive Metrics**: 11 evaluation metrics for thorough analysis
- **Model Persistence**: Save/load trained models for production use

### Email Spam Detection
- **Transformer Architecture**: BERT-based deep learning model
- **Advanced NLP**: Context-aware text understanding
- **High Accuracy**: State-of-the-art performance on spam detection
- **Confidence Scoring**: Prediction confidence analysis
- **Interactive Visualizations**: Plotly-based performance dashboards
- **Production Ready**: Complete inference pipeline with examples

## 📊 Visualizations

All notebooks include comprehensive visualizations:
- Confusion matrices (counts and percentages)
- Precision-Recall curves
- ROC curves
- Feature importance plots
- Training history plots
- Performance metric comparisons
- Confidence distribution analysis

## 🔬 Technical Highlights

- **Scikit-optimize**: Bayesian hyperparameter optimization
- **Class Weighting**: Automatic handling of imbalanced datasets
- **Feature Standardization**: StandardScaler for numeric features
- **Cross-Validation**: Stratified K-fold for robust evaluation
- **GPU Acceleration**: CUDA support for BERT training
- **Modular Code**: Clean, well-documented implementation

## 📝 Notes

- Large dataset files (>100MB) may be excluded from the repository
- All models include complete save/load functionality
- Each notebook is self-contained and fully documented
- Comprehensive performance reports generated automatically
- Production-ready inference examples included

## 🤝 Contributing

Feel free to open issues or submit pull requests for improvements.

## 📄 License

This project is for educational and research purposes.

## �‍💻 Author

**Jack9671**
- GitHub: [@Jack9671](https://github.com/Jack9671)

## 🙏 Acknowledgments

- Hugging Face for the Transformers library
- Scikit-learn community
- XGBoost developers
- PE malware research community

---

**Last Updated**: October 2025
