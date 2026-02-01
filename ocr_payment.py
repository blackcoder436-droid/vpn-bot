"""
OCR Payment Verification System
Reads payment screenshots and extracts amount for auto-verification
"""

import easyocr
import re
import os
import requests
from io import BytesIO
from PIL import Image
import logging

logger = logging.getLogger(__name__)

# Initialize EasyOCR reader (English + Myanmar)
# First run will download models (~100MB)
reader = None

def get_reader():
    """Lazy load OCR reader to avoid slow startup"""
    global reader
    if reader is None:
        logger.info("🔄 Loading OCR models (first time may take a while)...")
        # Use English for numbers, add 'my' for Myanmar if needed
        reader = easyocr.Reader(['en'], gpu=False, verbose=False)
        logger.info("✅ OCR models loaded successfully")
    return reader

def download_telegram_image(bot, file_id):
    """Download image from Telegram"""
    try:
        file_info = bot.get_file(file_id)
        file_path = file_info.file_path
        file_url = f"https://api.telegram.org/file/bot{bot.token}/{file_path}"
        
        response = requests.get(file_url, timeout=30)
        if response.status_code == 200:
            return BytesIO(response.content)
        else:
            logger.error(f"Failed to download image: {response.status_code}")
            return None
    except Exception as e:
        logger.error(f"Error downloading image: {e}")
        return None

def extract_amount_from_image(image_data):
    """
    Extract payment amount from screenshot using OCR
    
    Args:
        image_data: BytesIO object or file path
        
    Returns:
        dict: {
            'success': bool,
            'amount': int or None,
            'raw_text': str,
            'confidence': float
        }
    """
    try:
        ocr = get_reader()
        
        # Read image
        if isinstance(image_data, BytesIO):
            image = Image.open(image_data)
        else:
            image = Image.open(image_data)
        
        # Convert to RGB if necessary
        if image.mode != 'RGB':
            image = image.convert('RGB')
        
        # Run OCR
        results = ocr.readtext(image)
        
        # Combine all detected text
        all_text = ' '.join([result[1] for result in results])
        logger.info(f"📝 OCR Raw text: {all_text[:200]}...")
        
        # Extract amounts using various patterns
        amount = extract_amount_from_text(all_text)
        
        # Calculate average confidence
        if results:
            avg_confidence = sum([result[2] for result in results]) / len(results)
        else:
            avg_confidence = 0
        
        return {
            'success': amount is not None,
            'amount': amount,
            'raw_text': all_text,
            'confidence': avg_confidence
        }
        
    except Exception as e:
        logger.error(f"OCR Error: {e}")
        import traceback
        traceback.print_exc()
        return {
            'success': False,
            'amount': None,
            'raw_text': '',
            'confidence': 0,
            'error': str(e)
        }

def extract_amount_from_text(text):
    """
    Extract payment amount from OCR text
    Handles various formats:
    - 3,000 Ks
    - 3000 Ks
    - MMK 3,000
    - 3,000 MMK
    - Amount: 3,000
    - ငွေပမာဏ 3,000
    """
    # Clean text
    text = text.replace('\n', ' ').replace('  ', ' ')
    
    # Patterns to find amounts (prioritized)
    patterns = [
        # Amount with Ks/MMK suffix
        r'(\d{1,3}(?:,\d{3})*|\d+)\s*(?:Ks|KS|ks|MMK|mmk|Kyat|kyat)',
        # MMK/Ks prefix
        r'(?:Ks|KS|ks|MMK|mmk)\s*(\d{1,3}(?:,\d{3})*|\d+)',
        # Amount followed by numbers (for KBZ/Wave format)
        r'(?:Amount|amount|Total|total|ငွေပမာဏ|ငွေ|ပမာဏ)[:\s]*(\d{1,3}(?:,\d{3})*|\d+)',
        # Transfer amount patterns
        r'(?:Transfer|transfer|Send|send|ငွေလွှဲ)[:\s]*(\d{1,3}(?:,\d{3})*|\d+)',
        # Generic large numbers (3000+) that could be amounts
        r'\b(\d{1,3}(?:,\d{3})+)\b',  # Numbers with commas like 3,000
        r'\b([3-9]\d{3}|\d{5,})\b',  # Numbers 3000+ without commas
    ]
    
    amounts_found = []
    
    for pattern in patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        for match in matches:
            # Remove commas and convert to int
            amount_str = match.replace(',', '').replace(' ', '')
            try:
                amount = int(amount_str)
                # Filter reasonable amounts (1000 - 1,000,000 Ks)
                if 1000 <= amount <= 1000000:
                    amounts_found.append(amount)
            except ValueError:
                continue
    
    if amounts_found:
        # Return most common amount, or largest if all unique
        from collections import Counter
        amount_counts = Counter(amounts_found)
        most_common = amount_counts.most_common(1)
        if most_common:
            return most_common[0][0]
    
    return None

def verify_payment_amount(ocr_amount, expected_amount, tolerance=100):
    """
    Verify if OCR amount matches expected amount
    
    Args:
        ocr_amount: Amount detected by OCR
        expected_amount: Expected payment amount
        tolerance: Allowed difference (default 100 Ks for rounding)
        
    Returns:
        dict: {
            'match': bool,
            'ocr_amount': int,
            'expected_amount': int,
            'difference': int
        }
    """
    if ocr_amount is None:
        return {
            'match': False,
            'ocr_amount': None,
            'expected_amount': expected_amount,
            'difference': None,
            'reason': 'Could not detect amount from screenshot'
        }
    
    difference = abs(ocr_amount - expected_amount)
    match = difference <= tolerance
    
    return {
        'match': match,
        'ocr_amount': ocr_amount,
        'expected_amount': expected_amount,
        'difference': difference,
        'reason': 'Amount matches' if match else f'Amount mismatch: detected {ocr_amount}, expected {expected_amount}'
    }

def process_payment_screenshot(bot, file_id, expected_amount):
    """
    Complete payment verification process
    
    Args:
        bot: Telegram bot instance
        file_id: Telegram file ID of screenshot
        expected_amount: Expected payment amount
        
    Returns:
        dict: Complete verification result
    """
    # Download image
    image_data = download_telegram_image(bot, file_id)
    if not image_data:
        return {
            'success': False,
            'verified': False,
            'error': 'Failed to download screenshot'
        }
    
    # Extract amount using OCR
    ocr_result = extract_amount_from_image(image_data)
    
    if not ocr_result['success']:
        return {
            'success': False,
            'verified': False,
            'error': ocr_result.get('error', 'OCR failed'),
            'raw_text': ocr_result.get('raw_text', '')
        }
    
    # Verify amount
    verification = verify_payment_amount(ocr_result['amount'], expected_amount)
    
    return {
        'success': True,
        'verified': verification['match'],
        'ocr_amount': ocr_result['amount'],
        'expected_amount': expected_amount,
        'confidence': ocr_result['confidence'],
        'raw_text': ocr_result['raw_text'][:500],  # Limit text length
        'reason': verification['reason']
    }


# Test function
if __name__ == "__main__":
    # Test with a sample image
    print("Testing OCR system...")
    
    # Test text extraction
    test_text = "KBZPay Transfer Amount: 3,000 Ks to Myo Ko Aung"
    amount = extract_amount_from_text(test_text)
    print(f"Test 1 - Extracted amount: {amount}")
    assert amount == 3000, f"Expected 3000, got {amount}"
    
    test_text2 = "WaveMoney ငွေလွှဲ 8,000 MMK"
    amount2 = extract_amount_from_text(test_text2)
    print(f"Test 2 - Extracted amount: {amount2}")
    assert amount2 == 8000, f"Expected 8000, got {amount2}"
    
    print("✅ All tests passed!")
