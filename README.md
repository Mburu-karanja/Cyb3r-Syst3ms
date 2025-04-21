# 2FA System with Flask and SQLite

This project demonstrates a two-factor authentication (2FA) system built with Flask and SQLite. It includes user registration, login, and OTP (One-Time Password) verification features, using the popular `pyotp` library to implement TOTP-based 2FA.

---

## Features

- **User Registration:** Users can register with a username and password.
- **Password Hashing:** Passwords are securely hashed using `bcrypt` before storing them in the database.
- **2FA (TOTP) Setup:** After registration, a QR code is generated for the user to scan with their authenticator app.
- **Login:** Users can log in using their username and password.
- **2FA Verification:** After login, users must enter an OTP to complete the authentication process.

---

## Setup
> This will guide anyone through the setup and usage of your 2FA system, along with the cool ASCII banner that welcomes users when they access the application.

### Requirements

To run this project, you'll need the following:

- Python 3.x
- Flask
- SQLite (default database)
- pyotp
- bcrypt
- qrcode

### Install Dependencies

```bash
pip install flask pyotp bcrypt qrcode
