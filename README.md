# Phishing Detection System

A comprehensive web-based system for detecting phishing URLs using Machine Learning.

## Features

- **Single URL Checker**: Analyze individual URLs with 95%+ accuracy
- **Batch URL Checker**: Upload files with up to 100 URLs
- **Email Scanner**: Extract and analyze URLs from email content
- **QR Code Scanner**: Decode QR codes and check embedded URLs
- **User Authentication**: Secure registration and login system
- **Admin Panel**: System-wide statistics and user management
- **Export Features**: PDF and Excel report generation
- **REST API**: Programmatic access with rate limiting

## Tech Stack

- **Backend**: Python, Flask
- **Machine Learning**: Random Forest Classifier (scikit-learn)
- **Database**: SQLite
- **Frontend**: HTML5, CSS3, Bootstrap 5, JavaScript
- **Export**: ReportLab (PDF), OpenPyXL (Excel)

## Installation

1. Clone the repository
2. Create a virtual environment:
   ```bash
   python -m venv venv
   ```

3. Activate the virtual environment:
   - Windows: `venv\Scripts\activate`
   - Linux/Mac: `source venv/bin/activate`

4. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

5. Generate the dataset:
   ```bash
   python combine_datasets.py
   ```

6. Train the model:
   ```bash
   python train_model.py
   ```

7. Run the application:
   ```bash
   python app.py
   ```

8. Open browser and go to: `http://localhost:5000`

## Default Admin Credentials

- Username: `admin`
- Password: `admin123`

## Project Structure

```
phishing-detection/
├── app.py                  # Main Flask application
├── feature_extraction.py   # URL feature extraction
├── train_model.py          # Model training script
├── combine_datasets.py     # Dataset generation
├── requirements.txt        # Python dependencies
├── phishing_model.pkl      # Trained model (generated)
├── phishing_data.csv       # Dataset (generated)
├── phishing_detector.db    # SQLite database (auto-created)
├── templates/              # HTML templates
│   ├── base.html
│   ├── index.html
│   ├── login.html
│   ├── signup.html
│   ├── dashboard.html
│   ├── check_url.html
│   ├── batch.html
│   ├── batch_results.html
│   ├── email_scanner.html
│   ├── email_results.html
│   ├── qr_scanner.html
│   ├── qr_results.html
│   ├── history.html
│   ├── admin.html
│   └── api_docs.html
├── static/                 # Static files
│   ├── css/style.css
│   └── js/main.js
└── uploads/               # File uploads directory
```

## API Documentation

### Check Single URL
```bash
POST /api/check_url
Content-Type: application/json

{
  "url": "https://example.com",
  "api_key": "your-api-key"
}
```

### Batch Check
```bash
POST /api/batch_check
Content-Type: application/json

{
  "urls": ["url1", "url2"],
  "api_key": "your-api-key"
}
```

## Model Performance

- **Algorithm**: Random Forest Classifier (100 estimators)
- **Accuracy**: 95%+
- **Features**: 25+ URL-based features
- **Training Data**: 50,000+ synthetic + real URLs

## Security Features

- Password hashing with werkzeug
- Session management
- CSRF protection
- Rate limiting (100 requests/hour)
- SQL injection prevention
- Secure file uploads

## License

MIT License
