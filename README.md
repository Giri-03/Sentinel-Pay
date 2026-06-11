# Sentinel Pay

## Overview

Sentinel Pay is a secure digital payment and transaction management application designed to provide users with a seamless and transparent financial experience. The platform offers OTP-based authentication, transaction tracking, spending analytics, and detailed transaction records through an intuitive dashboard.

## Features

* Secure OTP-based user authentication
* User dashboard with account overview
* Complete transaction history
* Transaction analytics and charts
* Detailed transaction information
* Responsive and user-friendly interface
* Secure login and logout functionality

## Project Structure

```text
Sentinel-Pay/
│
├── static/
│   ├── css/
│   ├── js/
│   └── images/
│       └── logo.jpeg
│
├── templates/
│   ├── login.html
│   ├── otp.html
│   ├── dashboard.html
│   ├── transactions.html
│   ├── transaction_details.html
│   └── charts.html
│
├── app.py
├── database.db
├── requirements.txt
└── README.md
```

## Technologies Used

### Frontend

* HTML5
* CSS3
* JavaScript

### Backend

* Python
* Flask

### Database

* SQLite / MySQL

### Visualization

* Chart.js

### Authentication

* OTP Verification

## Installation

1. Clone the repository

```bash
git clone https://github.com/your-username/Sentinel-Pay.git
```

2. Navigate to the project directory

```bash
cd Sentinel-Pay
```

3. Install dependencies

```bash
pip install -r requirements.txt
```

4. Run the application

```bash
python app.py
```

5. Open your browser and visit

```text
http://127.0.0.1:5000
```

## How It Works

1. User logs in to the application.
2. OTP verification is performed for secure access.
3. User is redirected to the dashboard.
4. Transactions can be viewed and managed.
5. Analytics charts display transaction trends.
6. Detailed information is available for each transaction.

## Security Features

* OTP-based authentication
* Secure session management
* Protected user access
* Transaction transparency

## Future Enhancements

* UPI integration
* QR code payments
* AI-powered fraud detection
* Real-time notifications
* Expense categorization
* Multi-user support
* Advanced financial analytics

## Objectives

* Provide secure digital transactions
* Improve transaction monitoring
* Enable financial transparency
* Deliver a user-friendly payment experience
* Enhance account security through OTP verification

## Conclusion

Sentinel Pay is a modern payment management solution that combines security, usability, and analytics. The application helps users track transactions, monitor spending patterns, and manage digital payments efficiently through a secure and intuitive platform.

## Author

Developed as a Digital Payment Management Project using Flask, Python, HTML, CSS, JavaScript, and Database Technologies.
