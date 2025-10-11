https://github.com/InternPulse/wasteworth-backend-django/blob/main/Screenshot%202025-10-11%20132329.png
# WasteWorth Django Backend API

## Project Overview

**WasteWorth – Waste Recycling Management Platform**

WasteWorth is a Django-based waste recycling management platform that leverages the Django REST Framework, OTP-based authentication, and JWT for secure API authentication. It provides a comprehensive API with endpoints across multiple apps:

- **Users** – User registration, login, OTP verification, and JWT-based authentication.
- **Wallet** – Wallet management, transactions, fund transfers, and withdrawals.
- **Marketplace** – Connect waste disposers with recyclers for efficient waste collection.
- **Payments** – Paystack integration for secure escrow payments and payouts.
- **OTP** – OTP generation, verification, and management for secure operations.
- **Referral** – User referral system with rewards tracking.
- **Contact** – Contact form and automated email notifications.

WasteWorth is a robust platform that connects waste disposers with recyclers, promoting environmental sustainability while providing financial incentives. The platform addresses waste management challenges by offering secure payments, real-time tracking, and a reward-based ecosystem. This API contains User Authentication, Wallet Operations, Marketplace Transactions, and Payment Integration.

## Live Link

Live Project [https://www.wasteworth.com.ng/](#)

## Documentation Link

Postman API Documentation [https://documenter.getpostman.com/view/31085830/2sB3QDxDi5#intro](#).

---

## Installation Instructions

### Prerequisites

Ensure the following tools are installed:
- Python (>= 3.9 recommended)
- pip (Python package manager)
- Git
- Virtual environment tool (e.g., `venv` or `virtualenv`)
- PostgreSQL (for production) or SQLite (for development)
- Redis (for caching and background tasks)

### How to Run the API Locally

1. **Clone the repository:**
```shell
git clone https://github.com/InternPulse/wasteworth-backend-django.git
cd wasteworth-backend-django
```

2. **Set up a virtual environment:**

**Windows:**
```shell
python -m venv venv
venv\Scripts\activate
```

**macOS/Linux:**
```shell
python -m venv venv
source venv/bin/activate
```

3. **Install dependencies:**
```shell
pip install -r requirements.txt
```

4. **Set up environment variables:**

Create a `.env` file in the project root directory and configure the following variables:

```env
# Django Settings
SECRET_KEY=your-secret-key-here
DEBUG=True
ALLOWED_HOSTS=localhost,127.0.0.1

# Database Configuration
USE_POSTGRES=False  # Set to True for PostgreSQL, False for SQLite

# PostgreSQL Settings (if USE_POSTGRES=True)
DATABASE_NAME=wasteworth_db
DATABASE_USER=your_db_user
DATABASE_PASSWORD=your_db_password
DATABASE_HOST=localhost
DATABASE_PORT=5432
SSL_MODE=disable

# Email Configuration
EMAIL_BACKEND=utils.email_backend.SMTPBackendWithTimeout
EMAIL_HOST=smtp-relay.brevo.com
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_HOST_USER=your-email@example.com
EMAIL_HOST_PASSWORD=your-smtp-password
DEFAULT_FROM_EMAIL=noreply@wasteworth.com
EMAIL_TIMEOUT=120

# Redis Configuration
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=

# Paystack Integration
PAYSTACK_SECRET_KEY=your-paystack-secret-key
PAYSTACK_PUBLIC_KEY=your-paystack-public-key
PAYSTACK_WEBHOOK_SECRET=your-webhook-secret

# Frontend URL
FRONTEND_URL=http://localhost:3000

# CORS Settings
CORS_ALLOWED_ORIGINS=http://localhost:3000,http://localhost:5173

# Cloudinary (Optional - for image uploads)
CLOUDINARY_CLOUD_NAME=your-cloud-name
CLOUDINARY_API_KEY=your-api-key
CLOUDINARY_API_SECRET=your-api-secret
```

5. **Run database migrations:**
```shell
python manage.py migrate
```

6. **Create a superuser (optional):**
```shell
python manage.py createsuperuser
```

7. **Start Redis server** (in a separate terminal):
```shell
redis-server
```

8. **Run the development server:**
```shell
python manage.py runserver
```

The API will be available at `http://127.0.0.1:8000/`

---

## API Endpoints

Base URL: `http://127.0.0.1:8000/api/v1/`

### Authentication & User Management

| **Endpoint**                      | **Method** | **Description**                          | **Auth Required** |
|-----------------------------------|------------|------------------------------------------|-------------------|
| `/users/signup/`                  | POST       | Register a new user (disposer/recycler)  | No                |
| `/users/login/`                   | POST       | Login and obtain JWT tokens              | No                |
| `/users/logout/`                  | POST       | Logout user                              | Yes               |
| `/users/forgotPassword/`          | POST       | Request password reset OTP               | No                |
| `/users/resetPassword/`           | POST       | Reset password using OTP                 | No                |
| `/users/updatePassword/`          | PATCH      | Update user password (requires OTP)      | Yes               |
| `/users/user-dashboard/`          | GET        | Get user dashboard statistics            | Yes               |
| `/users/update-user/`             | PATCH      | Update user profile information          | Yes               |
| `/auth/token/refresh/`            | POST       | Refresh JWT access token                 | No                |

### OTP Management

| **Endpoint**                      | **Method** | **Description**                          | **Auth Required** |
|-----------------------------------|------------|------------------------------------------|-------------------|
| `/otp/send/`                      | POST       | Send OTP to email or phone               | No                |
| `/otp/verify/`                    | POST       | Verify OTP code                          | No                |

### Wallet Operations

| **Endpoint**                      | **Method** | **Description**                          | **Auth Required** |
|-----------------------------------|------------|------------------------------------------|-------------------|
| `/wallet/balance/`                | GET        | Get current wallet balance               | Yes               |
| `/wallet/transactions/`           | GET        | Get transaction history                  | Yes               |
| `/wallet/fund/`                   | POST       | Add funds to wallet                      | Yes               |
| `/wallet/transfer/`               | POST       | Transfer funds to another user           | Yes               |
| `/wallet/withdraw/`               | POST       | Withdraw funds to bank account           | Yes               |

### Payment Integration (Paystack)

| **Endpoint**                      | **Method** | **Description**                          | **Auth Required** |
|-----------------------------------|------------|------------------------------------------|-------------------|
| `/payments/initialize/`           | POST       | Initialize Paystack payment              | Yes               |
| `/payments/verify/`               | GET        | Verify payment transaction               | Yes               |
| `/payments/webhook/`              | POST       | Paystack webhook handler                 | No                |

### Contact

| **Endpoint**                      | **Method** | **Description**                          | **Auth Required** |
|-----------------------------------|------------|------------------------------------------|-------------------|
| `/contact/`                       | POST       | Submit contact form message              | No                |

---

## Tech Stack

**Backend Framework:**
- Django 5.2.6
- Django REST Framework

**Authentication & Security:**
- JWT (djangorestframework-simplejwt)
- OTP-based verification
- django-axes (brute force protection)
- Rate limiting

**Database:**
- PostgreSQL (production)
- SQLite (development)

**Caching & Background Tasks:**
- Redis
- django-rq

**Payment Processing:**
- Paystack

**Email Services:**
- Custom async email backend
- SMTP integration (Brevo/SendinBlue recommended)

**Cloud Storage:**
- Cloudinary (image uploads)

**Other Libraries:**
- python-decouple (environment variables)
- django-cors-headers (CORS management)

---

## Project Structure

```
wasteworth-backend-django/
├── apps/
│   ├── contact/              # Contact form functionality
│   ├── core/                 # Core utilities and health checks
│   ├── listings/             # Waste listings management
│   ├── marketplace/          # Marketplace transactions
│   ├── notifications/        # Notification system
│   ├── otp/                  # OTP generation and verification
│   ├── payments/             # Paystack payment integration
│   ├── referral/             # Referral system
│   ├── users/                # User authentication and management
│   └── wallet/               # Wallet and transaction management
├── config/
│   ├── settings.py           # Django settings
│   ├── urls.py               # Main URL configuration
│   └── wsgi.py               # WSGI configuration
├── utils/
│   ├── email_backend.py      # Custom email backend with timeout
│   ├── error_handler.py      # Centralized error handling
│   ├── logging.py            # Logging configuration and filters
│   ├── otp.py                # OTP utilities
│   ├── rate_limiter.py       # Rate limiting decorator
│   └── tasks.py              # Background tasks
├── .env.example              # Environment variables template
├── .gitignore
├── manage.py
├── README.md
└── requirements.txt
```

---

## Key Features

### 1. **User Management**
- Role-based access (Disposer, Recycler, Admin)
- Secure JWT authentication
- OTP-based email verification
- Password reset with OTP
- User profile management

### 2. **Wallet System**
- Points-based reward system
- Cash wallet for transactions
- Fund transfers between users
- Withdrawal to bank accounts
- Complete transaction history

### 3. **Marketplace**
- Connect disposers with recyclers
- Waste listing management
- Real-time transaction tracking
- Escrow-based payments for security

### 4. **Payment Integration**
- Paystack payment processing
- Secure escrow system
- Automated payouts to recyclers
- Payment verification and webhooks
- Transaction audit trail

### 5. **Security Features**
- JWT token authentication
- OTP verification for sensitive operations
- Rate limiting on API endpoints
- Brute force protection (django-axes)
- CORS configuration
- Password strength validation
- Secure payment handling

### 6. **Referral System**
- User referral tracking
- Referral code generation
- Reward distribution
- Referral analytics

### 7. **Notification System**
- Email notifications
- Transaction alerts
- OTP delivery
- Contact form responses

### 8. **Admin Dashboard**
- User statistics
- Transaction monitoring
- System health checks
- Performance metrics

---

## Environment Variables

### Django Settings
- `SECRET_KEY` – Django secret key for cryptographic signing
- `DEBUG` – Set to `True` for development, `False` for production
- `ALLOWED_HOSTS` – Comma-separated list of allowed hosts

### Database
- `USE_POSTGRES` – Set to `True` for PostgreSQL, `False` for SQLite
- `DATABASE_NAME` – PostgreSQL database name
- `DATABASE_USER` – PostgreSQL username
- `DATABASE_PASSWORD` – PostgreSQL password
- `DATABASE_HOST` – PostgreSQL host address
- `DATABASE_PORT` – PostgreSQL port (default: 5432)
- `SSL_MODE` – SSL mode for database connection

### Email Configuration
- `EMAIL_BACKEND` – Email backend class
- `EMAIL_HOST` – SMTP server host
- `EMAIL_PORT` – SMTP server port
- `EMAIL_USE_TLS` – Use TLS encryption
- `EMAIL_HOST_USER` – SMTP username
- `EMAIL_HOST_PASSWORD` – SMTP password
- `DEFAULT_FROM_EMAIL` – Default sender email address
- `EMAIL_TIMEOUT` – Email operation timeout in seconds

### Redis
- `REDIS_HOST` – Redis server host
- `REDIS_PORT` – Redis server port
- `REDIS_PASSWORD` – Redis password (if required)

### Paystack
- `PAYSTACK_SECRET_KEY` – Paystack secret API key
- `PAYSTACK_PUBLIC_KEY` – Paystack public API key
- `PAYSTACK_WEBHOOK_SECRET` – Webhook secret for verification

### Frontend
- `FRONTEND_URL` – Frontend application URL for CORS and redirects

### CORS
- `CORS_ALLOWED_ORIGINS` – Comma-separated list of allowed origins

### Cloudinary (Optional)
- `CLOUDINARY_CLOUD_NAME` – Cloudinary cloud name
- `CLOUDINARY_API_KEY` – Cloudinary API key
- `CLOUDINARY_API_SECRET` – Cloudinary API secret

---

## Testing

Run all tests:
```shell
python manage.py test
```

Run tests for a specific app:
```shell
python manage.py test apps.users
python manage.py test apps.wallet
python manage.py test apps.otp
python manage.py test apps.payments
```

Run tests with coverage:
```shell
coverage run manage.py test
coverage report
coverage html  # Generate HTML coverage report
```

---

## Deployment

### Production Checklist

1. ✅ Set `DEBUG=False` in environment variables
2. ✅ Configure `ALLOWED_HOSTS` with your production domain
3. ✅ Set up PostgreSQL database
4. ✅ Configure Redis for production use
5. ✅ Set all security-related environment variables
6. ✅ Configure production SMTP server for emails
7. ✅ Set up Paystack production API keys
8. ✅ Configure CORS with production frontend URLs
9. ✅ Collect static files: `python manage.py collectstatic`
10. ✅ Run database migrations: `python manage.py migrate`
11. ✅ Set up SSL certificates for HTTPS
12. ✅ Configure backup strategy for database
13. ✅ Set up monitoring and logging
14. ✅ Configure firewall and security groups

### Deployment Platforms

This project is configured for deployment on:
- **Render** – Uses `render.yaml` configuration
- **Railway** – Auto-detection compatible
- **Heroku** – Includes `Procfile`
- **DigitalOcean** – Manual deployment supported
- **AWS/GCP** – Docker-ready

### Deployment Commands

**Render/Railway (automatic):**
```shell
git push origin main
```

**Manual deployment:**
```shell
# Collect static files
python manage.py collectstatic --noinput

# Run migrations
python manage.py migrate

# Start gunicorn server
gunicorn config.wsgi:application --bind 0.0.0.0:8000
```

---

## Contributing

We welcome contributions to WasteWorth! Please follow these guidelines:

### How to Contribute

1. **Fork the repository**
2. **Create a feature branch:**
   ```shell
   git checkout -b feature/your-feature-name
   ```
3. **Make your changes and commit using conventional commits**
4. **Write or update tests for your changes**
5. **Push to your fork:**
   ```shell
   git push origin feature/your-feature-name
   ```
6. **Submit a pull request**

### Commit Message Standards

Use conventional commit format:

| **Type**     | **Description**                              | **Example**                                    |
|--------------|----------------------------------------------|------------------------------------------------|
| `feat`       | New feature                                  | `feat: add wallet withdrawal endpoint`         |
| `fix`        | Bug fix                                      | `fix: resolve OTP verification timeout issue`  |
| `docs`       | Documentation changes                        | `docs: update API endpoint documentation`      |
| `style`      | Code style changes (formatting, etc.)        | `style: format wallet models with black`       |
| `refactor`   | Code refactoring                             | `refactor: optimize database queries`          |
| `test`       | Adding or updating tests                     | `test: add unit tests for payment service`     |
| `chore`      | Maintenance tasks                            | `chore: update dependencies`                   |
| `perf`       | Performance improvements                     | `perf: optimize wallet balance calculation`    |

**Example:**
```shell
git commit -m "feat: add email verification for new users"
```

### Code Style

- Follow [PEP 8](https://pep8.org/) style guide for Python code
- Use meaningful variable and function names
- Write docstrings for functions and classes
- Keep functions small and focused
- Add comments for complex logic

### Pull Request Guidelines

- Provide a clear description of the changes
- Reference any related issues
- Ensure all tests pass
- Update documentation if needed
- Request review from maintainers

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## Support

For issues, questions, or feature requests:

- **GitHub Issues:** [Create an issue](https://github.com/InternPulse/wasteworth-backend-django/issues)
- **Email:** support@wasteworth.com
- **Documentation:** [API Documentation](#)

---

## Acknowledgments

- **InternPulse Team** – Development and maintenance
- **Django & DRF** – Robust framework for API development
- **Paystack** – Secure payment processing
- **Brevo** – Email service provider
- **Cloudinary** – Media management

---

**WasteWorth** – Making waste management rewarding and sustainable 🌍♻️
