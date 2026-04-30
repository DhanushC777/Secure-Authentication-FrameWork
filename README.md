# 🔐 Secure Authentication Framework for OS

A Flask-based secure authentication system that simulates an Operating System login framework with advanced security features like password policies, account lockout, and multi-factor authentication (OTP).

---

## 📌 Project Description

This project implements a secure authentication mechanism similar to what is used in operating systems. It ensures that only authorized users can access the system using:

- Strong password enforcement  
- Account lock after multiple failures  
- OTP-based multi-factor authentication  
- Secure session handling  

---

## 🎯 Objectives

- Build a secure login system  
- Implement multi-factor authentication (MFA)  
- Enforce strong password policies  
- Prevent brute-force attacks  
- Simulate OS-level authentication security  

---

## 🏗️ Project Modules

### 🔹 1. Authentication Backend (`app.py`)
- Built using Flask  
- Handles:
  - Login & Registration  
  - Password validation  
  - OTP generation & verification  
  - Session management  

---

### 🔹 2. Frontend UI (`templates/`)
- `login.html` → User login  
- `register.html` → New user registration  
- `otp.html` → OTP verification  
- `dashboard.html` → Protected page  

Styled using modern UI in `style.css`

---

### 🔹 3. Database (`users.db`)
SQLite database storing:
- Username  
- Hashed password (bcrypt)  
- Login attempts  
- Lock time  
- Account creation timestamp  

---

## 🔐 Security Features

### ✅ Strong Password Policy
- Minimum 10 characters  
- Must include:
  - Uppercase letter  
  - Lowercase letter  
  - Number  
  - Special character  

---

### 🔑 Multi-Factor Authentication (MFA)
- 6-digit OTP  
- Valid for 5 minutes  
- Required after successful login  

---

### 🚫 Brute Force Protection
- Max 5 failed login attempts  
- Account locked for 60 seconds  

---

### 🔒 Password Security
- Passwords hashed using bcrypt  
- No plain-text storage  

---

### 🔐 Session Protection
- OTP cleared after verification  
- Dashboard protected (login + OTP required)  

---

## ⚙️ Workflow

Register → Login → OTP Verification → Dashboard Access

---

## 📂 Project Structure
Secure-Auth-Framework/
│
├── app.py
├── users.db
│
├── templates/
│ ├── login.html
│ ├── register.html
│ ├── otp.html
│ └── dashboard.html
│
├── static/
│ └── style.css
│
└── README.md


---

## 🧪 Testing Scenarios

- ✔️ Register with valid password  
- ❌ Register with weak password  
- ❌ Enter wrong password multiple times → account lock  
- ✔️ Login → OTP required  
- ❌ Enter wrong OTP  
- ❌ Enter expired OTP  
- ✔️ Successful login → dashboard  

---

## ⚠️ Important Note

OTP is displayed on screen for demo purposes only.  
In real applications:
- Use Email/SMS APIs  
- Never expose OTP in UI  

---

## 📈 Future Enhancements

- Email/SMS OTP integration  
- Biometric authentication  
- JWT authentication  
- Role-based access control  
- OS-level integration (Linux PAM)  

---

## 🧠 Learning Outcomes

- Authentication system design  
- Password hashing (bcrypt)  
- MFA implementation  
- Session handling  
- Web security fundamentals  

---

## 👨‍💻 Author
Dhanush  

---

## ⭐ If you like this project
Give it a star on GitHub ⭐
