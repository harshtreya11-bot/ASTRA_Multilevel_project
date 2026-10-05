# ASTRA - SOC Log Analyzer Platform (Backend)

ASTRA is a high-performance **Security Operations Center (SOC) Log Analyzer Platform** backend built using Django, Django REST Framework (DRF), SimpleJWT, and PostgreSQL. It allows SOC Analysts to upload, parse, and analyze security logs (CSV, LOG, TXT), while providing HQ Admins with complete visibility over cross-analyst log records, audit compliance trails, and live system log streams.

---

## 🌟 Key Features

- **Multi-Tenant / Role-Based Access Control (RBAC):**
  - **SOC Analyst (`is_staff = False`):** Can upload log files, view parsed entries for their own uploads (`/api/dashboard/my-data/`).
  - **HQ Admin (`is_staff = True` / `is_superuser = True`):** Full system visibility over all analyst logs (`/api/dashboard/all-data/`), compliance audit trails (`/api/audit-log/`), and live system logs (`/api/logs/system-reader/`).
- **Log Parsing Engine:**
  - Standardized parsing for `.csv`, `.log`, and `.txt` files.
  - Regex-based text parsing & dynamic header mapping for CSV files.
  - Generates normalized `LogEntry` records with timestamps, log levels (`DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`), sources, raw lines, and dynamic JSON `extra_data`.
- **High Performance Storage & Batch Processing:**
  - Database dynamic indexing for real-time filtering on log levels, timestamps, and owners.
  - Atomic database transactions with `bulk_create(batch_size=1000)` for fast ingestion.
- **Compliance & Audit Logging:**
  - Automated tracking of user login, log file upload events, IP addresses, and user agents in `AuditLog`.
- **JWT Authentication & CORS:**
  - Secure stateless JWT authentication with customizable token lifetime and user profile payloads.
  - Pre-configured CORS support for multi-dashboard React frontends.

---

## 🛠️ Tech Stack

| Technology | Purpose |
| :--- | :--- |
| **Python 3.10+** | Core programming language |
| **Django** | Web framework (ORM, Security, Admin Interface) |
| **Django REST Framework (DRF)** | RESTful API views, serializers, pagination, and permissions |
| **SimpleJWT** | JSON Web Token (JWT) based authentication |
| **PostgreSQL + psycopg2** | Production-grade relational database engine |
| **django-cors-headers** | Cross-Origin Resource Sharing (CORS) handling |

---

## 📁 Project Structure

```text
backend/
├── api/                        # Main API Application
│   ├── admin.py                # Django Admin configurations for models
│   ├── apps.py                 # App initialization configuration
│   ├── models.py               # Database schemas (UploadedFile, LogEntry, AuditLog)
│   ├── pagination.py           # Custom pagination configurations
│   ├── parsers.py              # Log parsing engine (CSV, LOG, TXT regex parsing)
│   ├── permissions.py          # Custom DRF permissions (IsAnalyst, IsHQAdmin)
│   ├── serializers.py          # Model serializers & file validation logic
│   ├── urls.py                 # API endpoints route declarations
│   └── views.py                # Business logic, bulk ingestion & endpoints
├── astra_backend/              # Django Project Root Config
│   ├── settings.py             # App configuration, DB settings, JWT & CORS setup
│   ├── urls.py                 # Root URL router
│   ├── wsgi.py / asgi.py       # WSGI & ASGI entry points
├── media/                      # Store uploaded log files (auto-generated)
├── manage.py                   # Django CLI management script
└── requirements.txt            # Python dependencies list
```

---

## 📊 Database Schema & Data Models

### 1. `UploadedFile`
Stores metadata for all uploaded log files.
- `user` *(ForeignKey -> User)*: Analyst who uploaded the file.
- `file` *(FileField)*: Path to uploaded log file stored in `media/logs/%Y/%m/%d/`.
- `original_filename` *(CharField)*: Original filename uploaded by user.
- `file_format` *(CharField)*: Choice between `csv`, `log`, `txt`.
- `file_size_bytes` *(BigIntegerField)*: Total size in bytes.
- `status` *(CharField)*: Lifecycle state (`PENDING`, `PROCESSING`, `COMPLETED`, `FAILED`).
- `total_records` / `error_records` *(IntegerField)*: Ingested lines metadata.
- `uploaded_at` / `processed_at` *(DateTimeField)*: Timestamp tracking.

### 2. `LogEntry`
Stores normalized log entries parsed from uploaded files.
- `uploaded_file` *(ForeignKey -> UploadedFile)*: Associated file record.
- `user` *(ForeignKey -> User)*: Owner analyst.
- `timestamp` *(DateTimeField)*: Normalized timestamp with database index.
- `raw_timestamp` *(CharField)*: Unparsed raw timestamp string from log source.
- `log_level` *(CharField)*: Normalized severity (`DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`, `UNKNOWN`).
- `source` *(CharField)*: Host, service, or IP address source.
- `message` *(TextField)*: Normalized log message body.
- `raw_line` *(TextField)*: Full untouched original log line for forensic accuracy.
- `extra_data` *(JSONField)*: Flexible key-value pairs for non-standard CSV/LOG fields.
- `line_number` *(IntegerField)*: Line index in original file.

### 3. `AuditLog`
Stores compliance logs of activities across the platform.
- `user` *(ForeignKey -> User, on_delete=SET_NULL)*: User performing the action.
- `action` *(CharField)*: Activity code (e.g., `log_upload`).
- `details` *(JSONField)*: Action-specific details (filename, records parsed, etc.).
- `ip_address` *(GenericIPAddressField)*: Request client IP.
- `user_agent` *(CharField)*: Browser / Client user agent string.

---

## 🔒 Access Matrix & Permissions

| Endpoint | Method | Required Role | Description |
| :--- | :--- | :--- | :--- |
| `/api/auth/login/` | `POST` | Public | Authenticate user and receive JWT tokens + user info |
| `/api/logs/upload/` | `POST` | Analyst / Admin | Upload log files (.csv, .log, .txt up to 50MB) |
| `/api/dashboard/my-data/` | `GET` | Analyst / Admin | View log entries uploaded by current analyst |
| `/api/dashboard/all-data/` | `GET` | HQ Admin | View all system-wide log entries across analysts |
| `/api/audit-log/` | `GET` | HQ Admin | View administrative & compliance audit activity |
| `/api/logs/system-reader/` | `GET` | HQ Admin | Read real-time server system logs |

---

## ⚙️ Setup & Installation

### 1. Prerequisites
- Python 3.10+
- PostgreSQL server (running locally or remotely)

### 2. Set Up PostgreSQL Database
Open your PostgreSQL terminal:
```sql
CREATE DATABASE astra_db;
CREATE USER astra_user WITH PASSWORD 'astra123';
ALTER DATABASE astra_db OWNER TO astra_user;
GRANT ALL PRIVILEGES ON DATABASE astra_db TO astra_user;
```

### 3. Setup Virtual Environment & Dependencies
```bash
# Clone repository and enter directory
cd backend

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install requirements
pip install django djangorestframework djangorestframework-simplejwt django-cors-headers psycopg2-binary
```

### 4. Database Migrations & Admin Setup
```bash
# Create migration blueprints
python manage.py makemigrations

# Apply migrations to PostgreSQL
python manage.py migrate

# Create HQ Admin superuser
python manage.py createsuperuser
```

### 5. Run Local Development Server
```bash
python manage.py runserver 8000
```
The API backend will be available at `http://localhost:8000/api/`.

---

## 🧪 Testing API Endpoints

### 1. User Login (Obtain JWT Token)
```bash
curl -X POST http://localhost:8000/api/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{"username": "analyst1", "password": "password123"}'
```
**Response:**
```json
{
  "refresh": "<REFRESH_TOKEN>",
  "access": "<ACCESS_TOKEN>",
  "user": {
    "id": 1,
    "username": "analyst1",
    "email": "analyst@astra.local",
    "is_staff": false,
    "is_superuser": false
  }
}
```

### 2. Upload Log File
```bash
curl -X POST http://localhost:8000/api/logs/upload/ \
  -H "Authorization: Bearer <ACCESS_TOKEN>" \
  -F "file=@/path/to/sample_firewall.log"
```

### 3. Fetch Analyst Dashboard Logs
```bash
curl -X GET http://localhost:8000/api/dashboard/my-data/?page=1&page_size=50 \
  -H "Authorization: Bearer <ACCESS_TOKEN>"
```

---

## 🔐 Production & Security Guidelines

1. **Environment Variables:** Keep `SECRET_KEY`, `DATABASES`, and `DEBUG = False` managed via environment variables (e.g. `python-dotenv`).
2. **HTTPS & Secure Cookies:** Enforce SSL in production using Nginx/Gunicorn.
3. **CORS Origins:** Configure `CORS_ALLOWED_ORIGINS` in `astra_backend/settings.py` strictly to trusted frontend domain URLs.
