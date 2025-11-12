# Health Care Management System — FastAPI Backend

A modern, robust healthcare management API built with FastAPI — delivering secure, scalable, and efficient healthcare services with real-time notifications.

## 🚀 Quick Start with Docker

### Prerequisites
- **Docker** & **Docker Compose**
- **Python 3.11+** (for local development)

### Production Deployment
```bash
# Clone and deploy in one command
docker-compose up --build -d
```

The API will be available at: [http://localhost:8000](http://localhost:8000)
API Documentation: [http://localhost:8000/docs](http://localhost:8000/docs)

---

## 🏗️ Tech Stack

### Backend & API
![FastAPI](https://img.shields.io/badge/FastAPI-009688?logo=fastapi&logoColor=white)
![Python](https://img.shields.io/badge/Python-3776AB?logo=python&logoColor=white)
![SQLAlchemy](https://img.shields.io/badge/SQLAlchemy-D71F00?logo=sqlalchemy&logoColor=white)
![Pydantic](https://img.shields.io/badge/Pydantic-E92063?logo=pydantic&logoColor=white)

### Database & Caching
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-4169E1?logo=postgresql&logoColor=white)
![Redis](https://img.shields.io/badge/Redis-DC382D?logo=redis&logoColor=white)
![RabbitMQ](https://img.shields.io/badge/RabbitMQ-FF6600?logo=rabbitmq&logoColor=white)

### Infrastructure & DevOps
![Docker](https://img.shields.io/badge/Docker-2496ED?logo=docker&logoColor=white)
![Docker Compose](https://img.shields.io/badge/Docker_Compose-2496ED?logo=docker&logoColor=white)
![JWT](https://img.shields.io/badge/JWT-000000?logo=jsonwebtokens&logoColor=white)

---

## 📁 Project Structure

```
.
├── app/
│   ├── api/
│   │   ├── routes/           # API endpoint handlers
│   │   │   ├── auth.py
│   │   │   ├── appointment.py
│   │   │   ├── doctor.py
│   │   │   └── patient.py
│   │   └── deps.py           # Dependency injection
│   ├── core/                 # Core application logic
│   │   ├── config.py         # Configuration management
│   │   ├── security.py       # Authentication & authorization
│   │   ├── cache.py          # Redis caching layer
│   │   ├── rate_limiter.py   # Request rate limiting
│   │   └── notifications.py  # Notification utilities
│   ├── crud/                 # Database operations layer
│   │   ├── crud_base.py      # Base CRUD operations
│   │   ├── crud_user.py
│   │   ├── crud_patient.py
│   │   ├── crud_doctor.py
│   │   └── crud_appointment.py
│   ├── db/                   # Database layer
│   │   ├── models.py         # SQLAlchemy models
│   │   └── session.py        # Database session management
│   ├── schemas/              # Pydantic schemas
│   │   ├── user.py
│   │   ├── patient.py
│   │   ├── doctor.py
│   │   ├── appointment.py
│   │   └── medical_record.py
│   └── tests/                # Test suites
│       ├── test_api.py
│       ├── test_crud.py
│       └── test_security.py
├── docker-compose.yml        # Multi-service orchestration
├── Dockerfile               # Main application container
├── Dockerfile.notification  # Notification worker container
└── notification_service.py  # Async notification processor
```

---

## 🐳 Docker Services

The system runs as a multi-container application:

| Service | Purpose | Port | Health Check |
|---------|---------|------|--------------|
| **app** | FastAPI Application | 8000 | HTTP 200 on /health |
| **db** | PostgreSQL Database | 5432 | `pg_isready` |
| **redis** | Redis Cache | 6379 | `redis-cli ping` |
| **rabbitmq** | Message Queue | 5672/15672 | Built-in |

---

## 🛠️ Getting Started

### Option 1: Docker (Recommended)
```bash
# Production deployment
docker-compose up --build -d

# View logs
docker-compose logs -f app

# Stop services
docker-compose down
```

### Option 2: Local Development
```bash
# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/Mac
# OR
.\.venv\Scripts\Activate.ps1  # Windows

# Install dependencies
pip install -r requirements.txt

# Run the application
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

---

## 📜 Available Commands

### Docker Commands
| Command | Description |
|---------|-------------|
| `docker-compose up --build -d` | Build and start all services |
| `docker-compose logs -f [service]` | Follow service logs |
| `docker-compose down` | Stop and remove containers |
| `docker-compose exec app [cmd]` | Execute command in app container |

### Development Commands
| Command | Description |
|---------|-------------|
| `uvicorn app.main:app --reload` | Start development server |
| `pytest -q` | Run test suite quietly |
| `pytest -v` | Run tests with verbose output |
| `pytest --cov=app` | Run tests with coverage |

---

## 🎯 Core Features

- **🔐 Secure Authentication** – JWT-based auth with password hashing
- **👥 Role-Based Access Control** – Patient, Doctor, and Admin roles
- **📅 Appointment Management** – Schedule, reschedule, and cancel appointments
- **⚡ Real-time Notifications** – Async notification system with RabbitMQ
- **💾 Intelligent Caching** – Redis-powered response caching
- **🚀 Rate Limiting** – Request throttling for API protection
- **📊 Health Checks** – Container and service health monitoring
- **🔒 Security Hardened** – Password validation, SQL injection protection

---

## 📦 Key Dependencies

### Core Framework
- `fastapi` – Modern, fast web framework
- `uvicorn` – ASGI server implementation
- `pydantic` – Data validation and settings management

### Database & ORM
- `sqlalchemy` – SQL toolkit and ORM
- `asyncpg` – Async PostgreSQL driver
- `alembic` – Database migrations

### Security & Auth
- `python-jose` – JWT implementation
- `passlib` – Password hashing
- `bcrypt` – Secure password hashing

### Cache & Messaging
- `redis` – Redis client for Python
- `celery` – Distributed task queue
- `pika` – RabbitMQ client

### Utilities
- `python-multipart` – Form data handling
- `email-validator` – Email validation
- `python-dotenv` – Environment variable management

---

## ⚙️ Configuration

### Environment Variables
```bash
# Database
DATABASE_URL=postgresql://user:pass@db:5432/healthcare_db
DB_PASSWORD=your_secure_password

# Cache
REDIS_URL=redis://redis:6379/0

# Message Queue
RABBITMQ_URL=amqp://user:pass@rabbitmq:5672/
RABBITMQ_USER=admin
RABBITMQ_PASSWORD=your_rabbitmq_password

# Security
SECRET_KEY=your_jwt_secret_key
```

### Configuration Files
- `app/core/config.py` – Centralized configuration management
- `docker-compose.yml` – Service orchestration
- `Dockerfile` – Application container definition
- `Dockerfile.notification` – Worker container definition

---

## 🚀 Deployment

### Production with Docker Compose
1. Set environment variables in `.env` file
2. Run `docker-compose up --build -d`
3. Access API at `http://your-server:8000`
4. Monitor services with `docker-compose logs -f`

### Health Checks
- API: `GET /health`
- Database: Automatic health checks in compose
- Redis: Automatic health checks in compose

---

## ⚡ Performance & Security

- **Multi-stage Docker builds** for optimized image sizes
- **Non-root user execution** for enhanced security
- **Connection pooling** for database efficiency
- **Request rate limiting** to prevent abuse
- **JWT token expiration** for session security
- **Password strength validation** with bcrypt hashing

---

## 🧪 Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=app --cov-report=html

# Run specific test module
pytest app/tests/test_api.py -v
```

---

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch
   ```bash
   git checkout -b feature/amazing-feature
   ```
3. Commit your changes
   ```bash
   git commit -m 'Add amazing feature'
   ```
4. Push to the branch
   ```bash
   git push origin feature/amazing-feature
   ```
5. Open a Pull Request

---

## 📄 License

This project is licensed under the **MIT License**.
See the `LICENSE` file for more information.

---

### 🏥 Built with ❤️ for Modern Healthcare Management

Delivering secure, scalable healthcare APIs with cutting-edge technology.
