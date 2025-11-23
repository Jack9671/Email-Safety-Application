"""
Setup script to download and prepare models for the Email Security System.
Run this script after cloning the repository to set up the BERT spam detection model.
"""

import os
import sys
from pathlib import Path

def check_requirements():
    """Check if required packages are installed."""
    try:
        import torch
        import transformers
        print("✓ PyTorch and Transformers are installed")
        return True
    except ImportError as e:
        print(f"✗ Missing required packages: {e}")
        print("\nPlease install required packages:")
        print("  pip install -r requirements.txt")
        return False

def download_pretrained_bert():
    """Download the pre-trained DistilBERT model as a starting point."""
    from transformers import DistilBertTokenizerFast, DistilBertForSequenceClassification
    
    models_dir = Path('./saved_models/bert_spam_detector')
    
    # Check if model already exists
    if (models_dir / 'model.safetensors').exists():
        print(f"\n✓ BERT model already exists at: {models_dir}")
        response = input("Do you want to re-download? (y/N): ").strip().lower()
        if response != 'y':
            print("Skipping download.")
            return
    
    print("\n" + "="*70)
    print("DOWNLOADING PRE-TRAINED DISTILBERT MODEL")
    print("="*70)
    print("\nThis will download the base DistilBERT model (~250 MB)")
    print("You will need to fine-tune it on the spam dataset using the notebook.")
    print()
    
    try:
        # Create directory
        models_dir.mkdir(parents=True, exist_ok=True)
        
        # Download tokenizer
        print("Downloading tokenizer...")
        tokenizer = DistilBertTokenizerFast.from_pretrained('distilbert-base-uncased')
        tokenizer.save_pretrained(models_dir)
        print("✓ Tokenizer downloaded")
        
        # Download model
        print("Downloading model (this may take a few minutes)...")
        model = DistilBertForSequenceClassification.from_pretrained(
            'distilbert-base-uncased',
            num_labels=2
        )
        model.save_pretrained(models_dir)
        print("✓ Model downloaded")
        
        print("\n" + "="*70)
        print("✓ PRE-TRAINED MODEL DOWNLOADED SUCCESSFULLY")
        print("="*70)
        print(f"\nModel saved to: {models_dir.absolute()}")
        print("\n⚠️  IMPORTANT: This is the BASE model, NOT trained for spam detection!")
        print("You MUST fine-tune it using 'email_spam_classification.ipynb'")
        print("\nNext steps:")
        print("  1. Open email_spam_classification.ipynb in Jupyter/VS Code")
        print("  2. Run all cells to train the model on spam data")
        print("  3. The notebook will save the trained model automatically")
        
    except Exception as e:
        print(f"\n✗ Error downloading model: {e}")
        print("\nPlease check your internet connection and try again.")
        sys.exit(1)

def main():
    print("="*70)
    print("EMAIL SECURITY SYSTEM - MODEL SETUP")
    print("="*70)
    
    # Check requirements
    if not check_requirements():
        sys.exit(1)
    
    print("\nThis script will help you set up the BERT spam detection model.")
    print("\nYou have two options:")
    print("  1. Download pre-trained DistilBERT (base model, needs training)")
    print("  2. Train from scratch using the notebook")
    print("\nOption 1 is faster to get started, but you still need to fine-tune.")
    print("Option 2 trains everything from scratch (recommended for learning).")
    
    choice = input("\nDownload pre-trained base model? (Y/n): ").strip().lower()
    
    if choice in ['', 'y', 'yes']:
        download_pretrained_bert()
    else:
        print("\n✓ Skipping download")
        print("\nTo train the model from scratch:")
        print("  1. Open email_spam_classification.ipynb")
        print("  2. Run all cells in the notebook")
        print("  3. The trained model will be saved automatically")
    
    print("\n" + "="*70)
    print("SETUP COMPLETE")
    print("="*70)

if __name__ == "__main__":
    main()
