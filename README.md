Phishing URL Detection Using Machine Learning

A machine learning-based web application designed to classify URLs as safe, phishing, or non-existing and help users review suspicious links.

Overview

Phishing attacks use deceptive URLs to trick users into visiting malicious websites or revealing sensitive information. This project explores the use of machine learning for phishing URL detection through a Flask-based web application.

Features

- **URL Classification:** Classifies submitted URLs into Safe, Phishing, or Non-Existing categories.
- **Machine Learning:** Uses trained classification models for phishing detection.
- **User Authentication:** Provides signup and login functionality.
- **Dashboard:** Displays detection-related information to users.
- **URL History:** Maintains a history of URL checks.
- **Model Training:** Includes a Jupyter notebook for model-training experiments.

Technology Stack

- **Programming Language:** Python
- **Backend:** Flask
- **Machine Learning:** scikit-learn, Random Forest and other classification models
- **Data Processing:** pandas and NumPy, if used in the training pipeline
- **Frontend:** HTML, CSS
- **Database:** MySQL, if configured in the application
- **Development Tools:** Visual Studio Code, Jupyter Notebook, Git and GitHub

 Project Structure

```text
Phishing_detection/
├── app.py
├── model_training.ipynb
├── phishing_model.pkl
├── decision_tree.pkl
├── logistic_regression.pkl
├── dataset/
├── static/
│   └── style.css
└── templates/
    ├── check_url.html
    ├── dashboard.html
    ├── login.html
    └── signup.html
```

The trained model files and datasets may be excluded from the public repository because of file-size constraints. The project structure above illustrates the main application components.

Getting Started

Prerequisites

- Python installed on your system
- Git
- Visual Studio Code or another Python editor

1. Clone the repository

```bash
git clone https://github.com/Dishams-blip/Phishing-URL-Detection.git
cd Phishing-URL-Detection
```

2. Create a virtual environment

On Windows:

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

3. Install dependencies

If a `requirements.txt` file is provided:

```bash
python -m pip install -r requirements.txt
```

Otherwise, install the dependencies required by `app.py` and the model-training notebook.

4. Configure the application

Configure the database connection and any required environment variables according to your local setup. Ensure the required trained model files are available before starting the application.

Do not commit database passwords, secret keys, or other credentials to GitHub.

5. Run the application

```bash
python app.py
```

Open the local URL displayed in the terminal, commonly `http://127.0.0.1:5000`.

Machine Learning

The project includes a Random Forest model and additional saved classification models. The training notebook supports experimentation with the available datasets.

Model performance should be evaluated using appropriate classification metrics on held-out data. Actual accuracy and other evaluation results should be added here only after verifying the experimental results.

Research

The project relates to my research presentation, *Phishing Detection via URL Analysis: A Machine Learning Perspective*, presented at the National Conference on Cyber Security and Phishing Attacks in 2025.

Future Improvements

- Improve detection performance through systematic model evaluation.
- Expand testing against previously unseen URLs.
- Strengthen URL validation and error handling.
- Improve application security and input validation.
- Explore explainable machine learning for phishing classification.

Disclaimer

This project is intended for educational and defensive cybersecurity purposes. Classification results are predictions and should not be treated as a guarantee that a URL is safe.

Author

**Disha M S**

- GitHub: https://github.com/Dishams-blip
- LinkedIn: https://linkedin.com/in/disha-m-s-2126a3308
