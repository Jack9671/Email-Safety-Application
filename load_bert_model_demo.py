"""
Demo: Load and Use Saved BERT Spam Detection Model
This script demonstrates how to load the trained DistilBERT model and use it for predictions.
"""

import torch
import torch.nn.functional as F
from transformers import DistilBertTokenizerFast, DistilBertForSequenceClassification
from pathlib import Path
import json

# Configuration
MODEL_DIR = Path('./saved_models/bert_spam_detector')
DEVICE = torch.device('cuda' if torch.cuda.is_available() else 'cpu')

print("="*80)
print("LOADING SAVED BERT SPAM DETECTION MODEL")
print("="*80)

# 1. Load the tokenizer
print("\n1. Loading tokenizer...")
tokenizer = DistilBertTokenizerFast.from_pretrained(MODEL_DIR)
print(f"   ✓ Tokenizer loaded from: {MODEL_DIR}")
print(f"   Vocabulary size: {tokenizer.vocab_size}")

# 2. Load the model
print("\n2. Loading model...")
model = DistilBertForSequenceClassification.from_pretrained(MODEL_DIR)
model.to(DEVICE)
model.eval()  # Set to evaluation mode
print(f"   ✓ Model loaded from: {MODEL_DIR}")
print(f"   Model device: {DEVICE}")
print(f"   Number of labels: {model.config.num_labels}")

# 3. Load metadata (optional but helpful)
print("\n3. Loading model metadata...")
metadata_path = MODEL_DIR / 'model_metadata.json'
with open(metadata_path, 'r') as f:
    metadata = json.load(f)
print(f"   ✓ Metadata loaded")
print(f"   Model accuracy: {metadata['test_metrics']['accuracy']*100:.2f}%")
print(f"   F1 Score: {metadata['test_metrics']['f1_score']:.4f}")

# 4. Define prediction function
def predict_spam(text, model, tokenizer, device, max_length=128):
    """
    Predict whether an email is spam or ham.
    
    Args:
        text (str): Email text to classify
        model: Loaded BERT model
        tokenizer: Loaded tokenizer
        device: torch device (CPU or CUDA)
        max_length (int): Maximum sequence length
    
    Returns:
        dict: Prediction results including label, confidence, and probabilities
    """
    # Tokenize the input text
    encoding = tokenizer(
        text,
        truncation=True,
        padding=True,
        max_length=max_length,
        return_tensors='pt'
    )
    
    # Move to device
    input_ids = encoding['input_ids'].to(device)
    attention_mask = encoding['attention_mask'].to(device)
    
    # Make prediction
    with torch.no_grad():
        outputs = model(input_ids, attention_mask=attention_mask)
        logits = outputs['logits']
        
        # Get probabilities
        probabilities = F.softmax(logits, dim=1)
        predicted_label = torch.argmax(logits, dim=1).item()
        confidence = probabilities[0][predicted_label].item()
    
    # Convert to readable format
    label_names = {0: 'Ham', 1: 'Spam'}
    
    return {
        'label': label_names[predicted_label],
        'label_id': predicted_label,
        'confidence': confidence,
        'probabilities': {
            'ham': probabilities[0][0].item(),
            'spam': probabilities[0][1].item()
        }
    }

print("\n" + "="*80)
print("TESTING THE MODEL WITH SAMPLE EMAILS")
print("="*80)

# 5. Test with sample emails
test_emails = [
    {
        'text': "Hi John, Are we still meeting for lunch tomorrow at 12pm? Let me know!",
        'expected': 'Ham'
    },
    {
        'text': "CONGRATULATIONS! You've WON $1,000,000! Click here NOW to claim your prize! Limited time offer!!!",
        'expected': 'Spam'
    },
    {
        'text': "Dear customer, your package has been shipped and will arrive in 2-3 business days. Track your order using code XYZ123.",
        'expected': 'Ham'
    },
    {
        'text': "URGENT: Your account has been suspended! Verify your identity immediately by clicking this link and entering your password!",
        'expected': 'Spam'
    },
    {
        'text': "Hey! Thanks for helping me with the project yesterday. Really appreciate it. See you next week!",
        'expected': 'Ham'
    }
]

for idx, email in enumerate(test_emails, 1):
    print(f"\n--- Email {idx} ---")
    print(f"Text: {email['text'][:80]}{'...' if len(email['text']) > 80 else ''}")
    print(f"Expected: {email['expected']}")
    
    result = predict_spam(email['text'], model, tokenizer, DEVICE)
    
    print(f"\nPrediction: {result['label']}")
    print(f"Confidence: {result['confidence']*100:.2f}%")
    print(f"Probabilities:")
    print(f"  - Ham:  {result['probabilities']['ham']*100:.2f}%")
    print(f"  - Spam: {result['probabilities']['spam']*100:.2f}%")
    
    # Check if prediction is correct
    is_correct = result['label'] == email['expected']
    print(f"Result: {'✓ CORRECT' if is_correct else '✗ INCORRECT'}")
    print("-" * 80)

print("\n" + "="*80)
print("BATCH PREDICTION EXAMPLE")
print("="*80)

# 6. Batch prediction (more efficient for multiple emails)
def predict_batch(texts, model, tokenizer, device, max_length=128, batch_size=16):
    """
    Predict spam for multiple emails at once (more efficient).
    
    Args:
        texts (list): List of email texts
        model: Loaded BERT model
        tokenizer: Loaded tokenizer
        device: torch device
        max_length (int): Maximum sequence length
        batch_size (int): Batch size for processing
    
    Returns:
        list: List of prediction dictionaries
    """
    model.eval()
    all_results = []
    
    # Process in batches
    for i in range(0, len(texts), batch_size):
        batch_texts = texts[i:i+batch_size]
        
        # Tokenize batch
        encodings = tokenizer(
            batch_texts,
            truncation=True,
            padding=True,
            max_length=max_length,
            return_tensors='pt'
        )
        
        input_ids = encodings['input_ids'].to(device)
        attention_mask = encodings['attention_mask'].to(device)
        
        # Predict
        with torch.no_grad():
            outputs = model(input_ids, attention_mask=attention_mask)
            logits = outputs['logits']
            probabilities = F.softmax(logits, dim=1)
            predicted_labels = torch.argmax(logits, dim=1)
        
        # Convert to results
        label_names = {0: 'Ham', 1: 'Spam'}
        for j in range(len(batch_texts)):
            label_id = predicted_labels[j].item()
            all_results.append({
                'label': label_names[label_id],
                'label_id': label_id,
                'confidence': probabilities[j][label_id].item(),
                'probabilities': {
                    'ham': probabilities[j][0].item(),
                    'spam': probabilities[j][1].item()
                }
            })
    
    return all_results

# Test batch prediction
batch_texts = [email['text'] for email in test_emails]
print(f"\nPredicting {len(batch_texts)} emails in batch mode...")
batch_results = predict_batch(batch_texts, model, tokenizer, DEVICE)

print("\nBatch Prediction Results:")
for idx, (email, result) in enumerate(zip(test_emails, batch_results), 1):
    print(f"\nEmail {idx}: {result['label']} ({result['confidence']*100:.1f}% confidence)")

print("\n" + "="*80)
print("INTERACTIVE PREDICTION")
print("="*80)

# 7. Interactive prediction
def interactive_prediction():
    """
    Interactive mode for testing custom emails.
    """
    print("\nEnter email text to classify (or 'quit' to exit):")
    print("-" * 80)
    
    while True:
        user_input = input("\nEmail text: ").strip()
        
        if user_input.lower() in ['quit', 'exit', 'q']:
            print("Exiting interactive mode.")
            break
        
        if not user_input:
            print("Please enter some text.")
            continue
        
        result = predict_spam(user_input, model, tokenizer, DEVICE)
        
        print(f"\n{'='*80}")
        print(f"Prediction: {result['label']}")
        print(f"Confidence: {result['confidence']*100:.2f}%")
        print(f"Probabilities: Ham={result['probabilities']['ham']*100:.1f}% | Spam={result['probabilities']['spam']*100:.1f}%")
        print(f"{'='*80}")

# Uncomment to run interactive mode
# interactive_prediction()

print("\n" + "="*80)
print("MODEL LOADING AND PREDICTION DEMO COMPLETED")
print("="*80)
print("\nKey Points:")
print("1. Load tokenizer with: DistilBertTokenizerFast.from_pretrained(MODEL_DIR)")
print("2. Load model with: DistilBertForSequenceClassification.from_pretrained(MODEL_DIR)")
print("3. Set model to eval mode: model.eval()")
print("4. Use torch.no_grad() for inference (saves memory)")
print("5. Apply softmax to get probabilities: F.softmax(logits, dim=1)")
print("6. Use batch processing for multiple predictions (more efficient)")
print("\n✓ Model is ready for production use!")
