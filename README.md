# PE Malware Classification using XGBoost

A machine learning project for classifying Portable Executable (PE) malware using XGBoost with Bayesian hyperparameter optimization.

## 🎯 Project Overview

This project implements a malware classification system that analyzes PE file features to detect and classify different types of malware. The system uses XGBoost with optimized hyperparameters to achieve high accuracy in malware detection.

## 📋 Requirements

- Python 3.11.9
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

3. **Dataset**: Due to file size limitations, large CSV files are not included in the repository. You need to:
   - Download or obtain the PE malware dataset
   - Place the following files in the `Dataset/` folder:
     - `API_Functions.csv` (1.2 GB)
     - Other required dataset files

## 📊 Features

- **Feature Extraction**: Analyzes PE header, sections, and imported DLLs
- **Data Preprocessing**: StandardScaler normalization for numeric features
- **Feature Selection**: XGBoost-based feature importance ranking
- **Hyperparameter Optimization**: Bayesian optimization using scikit-optimize
- **Class Imbalance Handling**: Weighted training for balanced performance
- **Comprehensive Metrics**: MCC, Precision, Recall, F1, TNR, NPV, FPR, FNR, AUC-PR

## 🔧 Usage

Open and run the Jupyter notebooks in order:

1. `preprocessing.ipynb` - Data preprocessing and exploration
2. `XGboost.ipynb` - Main XGBoost training and evaluation pipeline
3. `test_on_lightweight_data.ipynb` - Testing on smaller datasets

## 📁 Project Structure

```
PEMalwareClassification/
├── Dataset/
│   ├── PE_Header.csv          # PE header features
│   ├── PE_Section.csv         # PE section features
│   ├── DLLs_Imported.csv      # Imported DLL features
│   ├── API_Functions.csv      # API function calls (not in repo - too large)
│   └── 2ndSource/             # Alternative data sources
├── Resource/                   # Research papers and documentation
├── XGboost.ipynb              # Main training notebook
├── preprocessing.ipynb        # Data preprocessing
├── test.ipynb                 # Testing utilities
├── requirements.txt           # Python dependencies
└── README.md                  # This file
```

## 🎓 Methodology

1. **Data Loading & Standardization**
   - StandardScaler for PE Header and Section features
   - Binary features (DLLs, APIs) kept as-is

2. **Feature Selection**
   - XGBoost feature importance analysis
   - Top N features selected based on cumulative importance

3. **Model Training**
   - Bayesian hyperparameter optimization
   - Matthews Correlation Coefficient (MCC) as primary metric
   - Fast mode: No cross-validation (single train/validation split)

4. **Evaluation**
   - Confusion matrix
   - Precision-Recall curves
   - Comprehensive multi-class metrics

## 📈 Performance Metrics

The model is evaluated using:
- **Matthews Correlation Coefficient (MCC)**
- **Macro-average Precision, Recall, F1-Score**
- **True Negative Rate (TNR/Specificity)**
- **Negative Predictive Value (NPV)**
- **False Positive Rate (FPR)**
- **False Negative Rate (FNR)**
- **Area Under Precision-Recall Curve (AUC-PR)**

## ⚡ Optimization

The project uses fast training mode:
- Bayesian optimization with `cv=2` (minimal cross-validation)
- 30 iterations for hyperparameter search
- ~60 models trained (vs 150 with 5-fold CV)
- Significant speed improvement while maintaining performance

## 📝 Notes

- Large dataset files (>100MB) are excluded from the repository
- Download datasets separately and place in `Dataset/` folder
- The model uses class weighting to handle imbalanced datasets

## 🤝 Contributing

Feel free to open issues or submit pull requests for improvements.

## 📄 License

This project is for educational and research purposes.

## 📚 References

See the `Resource/` folder for research papers and documentation used in this project.
