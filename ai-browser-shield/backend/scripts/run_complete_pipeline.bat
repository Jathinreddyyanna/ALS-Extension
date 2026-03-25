@echo off
REM Complete Email ML Pipeline - One Command Setup (Windows)
REM ========================================================

setlocal enabledelayedexpansion

echo ==========================================================
echo EMAIL PHISHING ML MODEL - COMPLETE PIPELINE
echo ==========================================================
echo.

REM Check if we're in the right directory
if not exist "email_ml_model.py" (
    echo ERROR: Please run this from the backend/scripts directory
    echo    cd ai-browser-shield\backend\scripts
    pause
    exit /b 1
)

REM Check Python
echo Checking Python installation...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Python not found. Please install Python 3.8+
    pause
    exit /b 1
)

for /f "tokens=2" %%i in ('python --version 2^>^&1') do set python_version=%%i
echo OK: Python %python_version% found
echo.

REM Check dependencies
echo Checking dependencies...
python -c "import pandas, numpy, sklearn" 2>nul
if %errorlevel% neq 0 (
    echo Installing dependencies...
    pip install pandas numpy scikit-learn
)
echo OK: All dependencies installed
echo.

echo ==========================================================
echo STEP 1: PREPARE DATASET
echo ==========================================================
echo.

if not exist "..\data\cleaned_emails.csv" (
    echo Cleaning and preparing email dataset...
    python prepare_email_dataset.py
    if %errorlevel% neq 0 (
        echo ERROR: Dataset preparation failed
        pause
        exit /b 1
    )
) else (
    for %%A in ("..\data\cleaned_emails.csv") do set size=%%~zA
    echo OK: Cleaned dataset already exists (size: !size! bytes)
    set /p response="Re-run dataset preparation? (y/N): "
    if /i "!response!"=="y" (
        python prepare_email_dataset.py
    )
)

echo.
echo ==========================================================
echo STEP 2: VALIDATE DATASET
echo ==========================================================
echo.

python validate_cleaned_dataset.py
if %errorlevel% neq 0 (
    echo WARNING: Dataset validation found issues
    set /p response="Continue anyway? (y/N): "
    if /i not "!response!"=="y" (
        pause
        exit /b 1
    )
)

echo.
echo ==========================================================
echo STEP 3: TRAIN ML MODEL
echo ==========================================================
echo.

if exist "..\models\email_phishing_model.pkl" (
    echo WARNING: Model already exists
    set /p response="Re-train model? This will take 5-10 minutes. (y/N): "
    if /i not "!response!"=="y" (
        echo Skipping training. Using existing model.
        goto test_model
    )
)

echo Training model (this will take 5-10 minutes)...
python email_ml_model.py ..\data\cleaned_emails.csv
if %errorlevel% neq 0 (
    echo ERROR: Model training failed
    pause
    exit /b 1
)

:test_model
echo.
echo ==========================================================
echo STEP 4: TEST MODEL
echo ==========================================================
echo.

echo Testing classification with sample phishing email...
python -c "from email_ml_model import classify_email; result = classify_email('URGENT! Your account has been SUSPENDED. Click here: http://192.168.1.1/verify', 'security123@amaz0n-verify.xyz', 'URGENT: Account Suspended'); print('\nTest 1: Phishing Email'); print(f\"  Label: {result['label']}\"); print(f\"  Risk Score: {result['risk_score']}/100\"); print(f\"  Confidence: {result['confidence']:.2%%}\"); print(f\"  Expected: phishing with high risk score (>80)\"); result2 = classify_email('Hi team, the project meeting is scheduled for tomorrow at 3 PM. Please review the documents.', 'colleague@company.com', 'Project Meeting Tomorrow'); print('\nTest 2: Legitimate Email'); print(f\"  Label: {result2['label']}\"); print(f\"  Risk Score: {result2['risk_score']}/100\"); print(f\"  Confidence: {result2['confidence']:.2%%}\"); print(f\"  Expected: legitimate with low risk score (<30)\"); print('\n' + '='*60); print('ALL TESTS PASSED!' if result['label'] == 'phishing' and result2['label'] == 'legitimate' else 'Some tests failed - review results above')"

echo.
echo ==========================================================
echo SETUP COMPLETE!
echo ==========================================================
echo.
echo Files Created:
dir /b ..\data\cleaned_emails.csv 2>nul && echo   - ..\data\cleaned_emails.csv
dir /b ..\models\email_phishing_model.pkl 2>nul && echo   - ..\models\email_phishing_model.pkl
dir /b ..\models\email_model_metadata.json 2>nul && echo   - ..\models\email_model_metadata.json
echo.

if exist "..\models\email_model_metadata.json" (
    echo Model Performance:
    python -c "import json; m = json.load(open('../models/email_model_metadata.json'))['metrics']; print(f\"  Accuracy:  {m['accuracy']:.2%%}\"); print(f\"  Precision: {m['precision']:.2%%}\"); print(f\"  Recall:    {m['recall']:.2%%}\"); print(f\"  F1-Score:  {m['f1_score']:.2%%}\"); print(f\"  FPR:       {m['fpr']:.2%%}\")"
    echo.
)

echo Next Steps:
echo   1. Review metrics: type ..\models\email_model_metadata.json
echo   2. Test classification: python email_ml_model.py
echo   3. Integrate with backend API
echo.
echo Usage in Python:
echo   from email_ml_model import classify_email
echo   result = classify_email(text, sender, subject)
echo.
echo Your email phishing ML model is ready for demo!
echo.
pause
