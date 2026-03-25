@echo off
REM Quick Start Script for Email ML Model (Windows)
REM ================================================

echo ==================================================
echo Email Phishing Detection ML Model - Quick Start
echo ==================================================
echo.

REM Check Python version
python --version
if %errorlevel% neq 0 (
    echo ERROR: Python not found. Please install Python 3.8+
    pause
    exit /b 1
)

echo.
echo Checking dependencies...
python -c "import pandas, numpy, sklearn" 2>nul
if %errorlevel% neq 0 (
    echo Installing dependencies...
    pip install pandas numpy scikit-learn
)

echo.
echo ==================================================
echo STEP 1: Validate Implementation
echo ==================================================
echo Running validation tests...
python validate_model.py
if %errorlevel% neq 0 (
    echo ERROR: Validation failed
    pause
    exit /b 1
)

echo.
echo ==================================================
echo STEP 2: Generate Test Dataset
echo ==================================================
echo Creating synthetic phishing email dataset...
python generate_test_dataset.py 500 phishing_test_dataset.csv
if %errorlevel% neq 0 (
    echo ERROR: Dataset generation failed
    pause
    exit /b 1
)

echo.
echo ==================================================
echo STEP 3: Train Model
echo ==================================================
echo Training RandomForest model (this may take 2-5 minutes)...
python email_ml_model.py phishing_test_dataset.csv
if %errorlevel% neq 0 (
    echo ERROR: Training failed
    pause
    exit /b 1
)

echo.
echo ==================================================
echo SUCCESS - SETUP COMPLETE!
echo ==================================================
echo.
echo Your email phishing detection model is ready!
echo.
echo Files created:
echo   - phishing_test_dataset.csv (training data)
echo   - ..\models\email_phishing_model.pkl (trained model)
echo   - ..\models\email_model_metadata.json (metrics)
echo.
echo To use the classifier in your code:
echo.
echo   from email_ml_model import classify_email
echo.
echo   result = classify_email(
echo       email_text='Suspicious email text...',
echo       sender='scammer@phish.xyz',
echo       subject='URGENT!'
echo   )
echo.
echo   print(result['label'])       # 'phishing' or 'legitimate'
echo   print(result['risk_score'])  # 0-100
echo   print(result['confidence'])  # 0.0-1.0
echo.
echo Next steps:
echo   1. Review metrics in ..\models\email_model_metadata.json
echo   2. Test with your own emails using classify_email()
echo   3. Integrate with your backend API
echo.
pause
