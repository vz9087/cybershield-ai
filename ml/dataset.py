"""
CyberShield AI — Cybersecurity Threat Detection Dataset
Contains realistic curated training samples across multi-channel attack vectors:
- Phishing & Typosquatting URLs
- Phishing emails & Social Engineering
- Smishing (SMS scams, KYC fraud, OTP theft)
- Safe benign communications
"""

DATASET = [
    # Phishing / Malicious Samples (Label: 1)
    {"text": "https://g00gle.com/login-verify-account", "label": 1, "type": "url_phishing"},
    {"text": "http://amaz0n-security-update.com/signin", "label": 1, "type": "url_phishing"},
    {"text": "http://192.168.1.100/paypal/login.php", "label": 1, "type": "url_phishing"},
    {"text": "https://secure-appleid-support-alert.com", "label": 1, "type": "url_phishing"},
    {"text": "http://netflix-billing-renewal-notice.xyz", "label": 1, "type": "url_phishing"},
    {"text": "URGENT: Your SBI bank account will be blocked today. Click to update KYC: https://sbi-kyc-update.xyz", "label": 1, "type": "sms_smishing"},
    {"text": "Dear Customer, Your debit card has been suspended. Share OTP 482910 to verify immediately.", "label": 1, "type": "sms_smishing"},
    {"text": "Congratulations! You won Rs 50,000 cash lottery prize. Claim now by paying fee: http://lottery-claim.top", "label": 1, "type": "sms_scam"},
    {"text": "Exclusive Work From Home Internship guaranteed Rs 40,000 stipend. Pay Rs 500 registration deposit: http://work-jobs.online", "label": 1, "type": "link_scam"},
    {"text": "From: Security Team <alert@amaz0n-security.com> Subject: Immediate Account Suspension. Enter password and credit card details now.", "label": 1, "type": "email_phishing"},
    {"text": "Your package delivery failed due to incorrect address. Confirm payment of $1.50 re-delivery fee here: http://fedx-parcel-track.com", "label": 1, "type": "sms_smishing"},
    {"text": "Incoming wire transfer of $4,500 waiting. Log in with your bank credentials to accept funds: https://bank-wire-transfer-login.com", "label": 1, "type": "email_phishing"},
    {"text": "Your Netflix membership has expired. Click here to update your card information immediately or lose service: http://netflx-update.co", "label": 1, "type": "email_phishing"},
    {"text": "URGENT: Income tax refund of Rs 15,200 approved. Fill bank account number and UPI PIN: http://incometax-refund-gov.in.xyz", "label": 1, "type": "sms_smishing"},
    {"text": "Security Alert: Unauthorized login attempt from Russia. Change your Google password here: https://g00gle-accounts-security.com", "label": 1, "type": "email_phishing"},

    # Safe / Benign Samples (Label: 0)
    {"text": "https://google.com/search?q=cybersecurity+defense", "label": 0, "type": "safe_url"},
    {"text": "https://amazon.com/gp/help/customer/display.html", "label": 0, "type": "safe_url"},
    {"text": "https://microsoft.com/en-us/security", "label": 0, "type": "safe_url"},
    {"text": "https://apple.com/support/system-status", "label": 0, "type": "safe_url"},
    {"text": "https://github.com/torvalds/linux", "label": 0, "type": "safe_url"},
    {"text": "Your monthly bank e-statement for September is now available for download in NetBanking. Do not share credentials with anyone.", "label": 0, "type": "safe_sms"},
    {"text": "Meeting reminder: Team sync scheduled for tomorrow at 10:00 AM on Google Meet. See calendar for agenda.", "label": 0, "type": "safe_email"},
    {"text": "Hi Dad, I will reach home around 6 PM today after college. See you soon!", "label": 0, "type": "safe_message"},
    {"text": "Your Amazon order #402-12345 has been shipped and will arrive tomorrow by 8 PM.", "label": 0, "type": "safe_notification"},
    {"text": "Thank you for attending the CSE Department seminar on Machine Learning and Network Defense.", "label": 0, "type": "safe_email"},
    {"text": "https://en.wikipedia.org/wiki/Computer_security", "label": 0, "type": "safe_url"},
    {"text": "Your library book is due in 3 days. Return or renew online at your university portal.", "label": 0, "type": "safe_email"},
    {"text": "https://stackoverflow.com/questions/tagged/python", "label": 0, "type": "safe_url"},
    {"text": "Hello, here is the syllabus and schedule for the upcoming semester examinations.", "label": 0, "type": "safe_email"},
    {"text": "Your one-time password for login is 592813. It is valid for 5 minutes. CyberShield will never ask for your OTP.", "label": 0, "type": "safe_sms"},
]

def get_dataset():
    texts = [item["text"] for item in DATASET]
    labels = [item["label"] for item in DATASET]
    return texts, labels
