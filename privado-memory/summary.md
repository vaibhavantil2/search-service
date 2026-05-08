# Executive Audit Summary – Repository Overview  

**Scope** – The repository hosts **two independent projects**:  

| # | Project | Path | Primary Goal |
|---|---------|------|--------------|
| 1 | **SpeechRecognition** | `speech_recognition/` (root package) | Pure‑Python library that abstracts many speech‑to‑text engines (offline & cloud) and provides a simple API / CLI. |
| 2 | **eCommerce Django REST API** | `ecom/` | Full‑stack e‑commerce backend (auth, catalog, cart, checkout, payments, admin UI) exposed via a RESTful API and Docker‑ready. |

Below is a **complete executive‑level audit** that pulls together the architectural deep‑dive, code organization, data‑handling, PII inventory, third‑party exposure, data stores, data‑flow mapping, risk assessment, and remediation recommendations.

---

## 1. Executive Overview  

| Aspect | Detail |
|--------|--------|
| **Repo type** | Mixed – a reusable Python library **plus** a Django‑based SaaS product. |
| **Primary languages** | Python (2.6‑2.7, 3.3+ compatibility for SpeechRecognition; 3.x for Django). |
| **Frameworks / libs** | `setuptools`, `PyAudio`, `pocketsphinx`, `Django`, `Django‑REST‑Framework`, `Celery`, `docker‑compose`. |
| **Deployment** | Docker‑Compose with PostgreSQL, RabbitMQ, optional Redis; environment variables stored in `.env`. |
| **Target audience** | Developers needing speech‑to‑text (SpeechRecognition) and merchants / developers needing a ready‑made e‑commerce API (eCommerce). |
| **Key deliverables** | `speech_recognition` pip package; Dockerised Django API with Swagger/OpenAPI docs. |

---

## 2. Architecture & Code Organization  

### 2.1 SpeechRecognition Library  

| Layer | Technology | Role |
|-------|------------|------|
| Core language | Python (2.6‑2.7, 3.3+) | Library implementation |
| Audio I/O | PyAudio (optional) | Microphone capture |
| Offline engine | PocketSphinx | Local speech‑to‑text |
| Cloud APIs | Google Speech, Google Cloud Speech, Wit.ai, Azure Speech, Bing (deprecated), Houndify, IBM Speech‑to‑Text | Remote recognition |
| Hot‑word detection | Snowboy | Wake‑word detection |
| Packaging | `setuptools`, `setup.py` | Build & distribution |
| Docs | reST (`README.rst`, `reference/`) | API reference & examples |

**Structure**

```
speech_recognition/
│   __init__.py          # public symbols (Recognizer, AudioFile, Microphone)
│   __main__.py          # CLI entry point (python -m speech_recognition)
│   recognizer.py        # core Recognizer class
│   audio.py             # AudioData, AudioFile, Microphone helpers
│   ...                  # engine adapters (recognize_google, recognize_sphinx, …)

examples/
│   audio_transcribe.py
│   background_listening.py
│   ...

reference/
│   library-reference.rst
│   pocketsphinx.rst
```

*Pattern*: **Facade / Plug‑in** – each recognizer implements a tiny interface; new engines can be added without touching the core.

### 2.2 eCommerce Django REST API  

| Layer | Technology | Role |
|-------|------------|------|
| Web framework | Django 3.x | MVC, ORM, admin |
| API layer | Django‑REST‑Framework | Serializers, ViewSets, routers |
| Auth | Custom `User` (extends `AbstractUser`), JWT (via `djangorestframework-simplejwt`) |
| Async tasks | Celery + RabbitMQ | Email, PDF generation, payment verification |
| DB | PostgreSQL 9.6 (Docker) | Persistent storage for users, products, orders, payments |
| Payments | Pagar.me (Brazilian gateway) | Card processing, transaction tracking |
| Containerisation | Docker‑Compose | Services: `web`, `database`, `rabbitmq`, optional `redis` |
| Config | `django‑environ` + `.env` file | Secrets, DB URL, broker URL, API keys |

**Structure (high‑level)**  

```
ecom/
│   manage.py
│   ecom/                # project settings
│   auth_core/           # custom User model, auth views/serializers
│   core/                # Customer, Address, Product, Order models & APIs
│   payment_gateway/     # Pagar.me integration models
│   tasks/               # Celery tasks
│   Dockerfile, docker-compose.yml
│   .env.example
│   requirements.txt
│   ...
```

*Pattern*: **Domain‑driven monolith** – each Django app encapsulates a bounded context (auth, core, payments).  

**Entry‑points**  

| Entry point | Description |
|-------------|-------------|
| `manage.py runserver` | Development HTTP server |
| `gunicorn ecom.wsgi:application` | Production WSGI entry |
| `celery -A ecom worker -l info` | Background worker |
| Docker `docker‑compose up` | Spins up web, DB, RabbitMQ, (optional) Redis |

---

## 3. Data‑Handling & PII Inventory  

| # | Data Element | Location (model/field) | Type / Constraints | Storage (DB table) | Primary Uses | Protection |
|---|--------------|------------------------|--------------------|--------------------|--------------|------------|
| 1 | Email address | `auth_core/models.py` → `User.email` (unique) | EmailField | `auth_core_user` | Login, JWT payload, admin UI | Plaintext in DB; access limited by Django auth & DRF permissions |
| 2 | Phone number | `core/models.py` → `Customer.phone` | CharField (max 12) | `core_customer` | Profile display, order contact | Plaintext; auth‑protected |
| 3 | Password | `auth_core/models.py` → `User.password` (hashed) | CharField (hashed) | `auth_core_user.password` | Authentication, JWT generation | **PBKDF2‑SHA256** (Django default); never returned to client |
| 4 | Personal document (CPF) | `common/models.py` → `BaseCustomer.personal_document` | CharField (max 20) | `core_customer` (via inheritance) | Compliance / billing | Plaintext; auth‑protected |
| 5 | Address fields (street, suite, city, zip) | `core/models.py` → `Address` | CharFields (max 200) | `core_address` | Shipping, order summary | Plaintext; auth‑protected |
| 6 | Username | `auth_core/models.py` → `User.username` | CharField (max 30) | `auth_core_user` | Display, JWT payload | Plaintext; auth‑protected |
| 7 | Payment data (card token, amount) | `payment_gateway/models.py` → `PagarmeGateway` (stores `api_key`, `encryption_key`) | Sensitive strings | `payment_gateway_pagarmegateway` | Payment processing via Pagar.me | Stored in DB (should be env‑protected) |
| 8 | Audio bytes (raw) | `speech_recognition/audio.py` → `AudioData` (in‑memory) | Binary | In‑memory only | Sent to external recognizers | Not persisted; transmitted over HTTPS to third‑party APIs |

**Sensitivity Rating** – PII (email, phone, address, CPF) = **High**; Password = **Critical**; Payment credentials = **Critical**; Audio data = **Medium** (potentially contains voice‑identifiable info).

---

## 4. Third‑Party Exposure  

| # | Vendor / Service | Data Sent | Authentication / Credentials | Config Location |
|---|------------------|-----------|------------------------------|-----------------|
| 1 | Google Speech Recognition (free) | Audio bytes (FLAC/WAV) | Optional API key (`key=` query param) | `speech_recognition/__init__.py` (recognize_google) |
| 2 | Google Cloud Speech API | Audio bytes + config JSON | Service‑account JSON (path or env var) | Same file (recognize_google_cloud) |
| 3 | Microsoft Azure Speech | Audio bytes + language tag | Subscription key (`key=`) + region (`location=`) | Same file (recognize_azure) |
| 4 | Wit.ai | Audio bytes | Server‑side API token (`key=`) | Same file (recognize_wit) |
| 5 | Houndify | Audio bytes + optional context | Client ID & client key (Base64) | Same file (recognize_houndify) |
| 6 | IBM Watson Speech‑to‑Text | Audio bytes + language model | Username & password (IAM) | Same file (recognize_ibm) |
| 7 | Pagar.me (Brazilian payment gateway) | Card token, amount, customer info | API key (`api_key`) & encryption key (`encryption_key`) stored in DB (model `PagarmeGateway`) | `ecom/payment_gateway/models.py` |
| 8 | Docker Hub / Base images | Image layers | Docker Hub credentials (if private) | `docker-compose.yml` (not shown) |

All external calls are **HTTPS** (TLS) by default, but **no additional payload encryption** is performed beyond transport security.

---

## 5. Data Stores  

| Store | Technology | Purpose | Sensitive Data Stored | Security Controls |
|-------|------------|---------|-----------------------|-------------------|
| **PostgreSQL** | `library/postgres:9.6‑alpine` (Docker) | Primary relational DB for users, products, orders, payments, etc. | Email, phone, password hash, CPF, address, payment gateway credentials | - Credentials in `.env` (`POSTGRES_USER`, `POSTGRES_PASSWORD`). <br> - Network isolation (Docker internal network). <br> - No at‑rest encryption in repo (should be added in production). |
| **RabbitMQ** | `rabbitmq:3.8‑management‑alpine` | Message broker for Celery tasks | Potentially transient order/payment task payloads (may contain PII) | - Default user `guest` replaced by `admin:admin` (still weak). <br> - Access limited to Docker network. |
| **Docker volumes** | Named volumes (`postgres`, `rabbitmq`) | Persistent storage for DB & broker data | Same as above (persisted on host) | - Volume permissions depend on host OS; not encrypted by default. |
| **`.env` file** | Plain‑text key‑value file (git‑ignored) | Holds secrets: DB password, broker URL, JWT secret, third‑party API keys | All credentials listed above | - Must be excluded from VCS. <br> - In production, use secret manager (AWS Secrets Manager, Vault, etc.). |

---

## 6. Data‑Flow Mapping (High‑Level)

```
+-------------------+        +-------------------+        +-------------------+
|   Data Ingress    |  --->  |   Internal Flow   |  --->  |   Data Egress     |
+-------------------+        +-------------------+        +-------------------+

Ingress:
  • HTTP POST /api/auth/register  → JSON {email, password, username, phone, cpf}
  • HTTP POST /api/orders         → JSON {address, items, payment_token}
  • Microphone capture (SpeechRecognition) → AudioData (bytes)

Internal Flow:
  1. DRF ViewSet receives request → Serializer validates → Model.save() → PostgreSQL
  2. View may enqueue Celery task → RabbitMQ → Worker → external API (Pagar.me, email, etc.)
  3. SpeechRecognition CLI / library:
        AudioData → recognizer.select_engine() → HTTPS POST to cloud provider → response
  4. JWT generation (email/username) → signed with `SECRET_KEY` → returned to client

Egress:
  • API responses (JSON) containing non‑sensitive fields (order id, status) and
    optionally masked data (last 4 digits of card).
  • Third‑party calls (Google Speech, Azure, Pagar.me) sending audio or payment data.
  • Email notifications via Celery task (SMTP credentials not shown).
```

**Key observations**  

- **PII is persisted in clear text** (email, phone, CPF, address).  
- **Passwords are properly hashed** (PBKDF2‑SHA256).  
- **Audio data is transient** but is transmitted to external speech services.  
- **Credentials are stored in `.env` and occasionally in DB (Pagar.me)** – risk if the file is leaked.  
- **RabbitMQ default credentials are weak** (`admin:admin`).  

---

## 7. Risk Assessment  

| Risk | Severity | Evidence | Impact |
|------|----------|----------|--------|
| **Hard‑coded / weak credentials** | Critical | `POSTGRES_PASSWORD=root@123`, `RabbitMQ admin:admin`, example `.env` contains defaults. | Anyone with repo access can spin up a full environment and gain DB/RabbitMQ access. |
| **Plain‑text storage of PII** | High | Email, phone, CPF, address stored without encryption. | Data breach → GDPR/CCPA violations, reputational damage. |
| **Insufficient encryption for payment gateway secrets** | High | `api_key` and `encryption_key` stored in DB (model `PagarmeGateway`). | Compromise could allow fraudulent transactions. |
| **Missing at‑rest encryption for PostgreSQL** | Medium | No `pgcrypto` or encrypted columns defined. | Increases impact of DB compromise. |
| **Potential over‑exposure of audio data** | Medium | Audio bytes sent to multiple cloud recognizers; no user consent logging. | Voice biometrics could be harvested. |
| **Outdated Docker base images** (Postgres 9.6, RabbitMQ 3.8) | Low | Known CVEs exist for older versions. | May allow privilege escalation if not patched. |
| **Lack of rate‑limiting / abuse protection on SpeechRecognition CLI** | Low | Unlimited calls to external APIs could be abused. | Cost overrun, service throttling. |

---

## 8. Recommendations (Prioritized)

| Priority | Action | Rationale |
|----------|--------|-----------|
| **1 – Critical** | **Rotate all default credentials** (`POSTGRES_PASSWORD`, RabbitMQ user/pass, any API keys) and move them to a secret‑management solution (AWS Secrets Manager, HashiCorp Vault, etc.). | Eliminates trivial remote compromise. |
| **2 – High** | **Encrypt PII at rest** – either via PostgreSQL column‑level encryption (`pgcrypto`) or application‑level encryption before persisting. | Reduces breach impact and helps meet GDPR/CCPA. |
| **3 – High** | **Store payment gateway secrets outside the database** (environment variables or secret manager) and enforce strict access controls. | Prevents attackers from stealing payment credentials. |
| **4 – Medium** | **Enable TLS for PostgreSQL** (server‑side SSL) and enforce encrypted connections from the Django app. | Protects data in transit between containers. |
| **5 – Medium** | **Upgrade Docker base images** to supported, patched versions (Postgres 13+, RabbitMQ 3.9+). | Mitigates known CVEs. |
| **6 – Medium** | **Implement audit logging** for all accesses to PII (login, profile view, order retrieval) and for outbound calls to speech APIs. | Provides forensic capability and helps detect abuse. |
| **7 – Low** | **Add rate‑limiting / quota** on SpeechRecognition CLI / library when used in production environments. | Controls cost and prevents denial‑of‑service on third‑party APIs. |
| **8 – Low** | **Review and tighten DRF permission classes** (e.g., ensure `IsAddressOwnerDetail` is applied everywhere address data is exposed). | Guarantees least‑privilege access. |

---

## 9. Audit Metadata  

| Item | Value |
|------|-------|
| **Repository URL** | *(not supplied in the prompt)* |
| **Analysis date** | 2026‑05‑08 |
| **File count** | Approx. 250 files (Python, Docker, YAML, Markdown) |
| **Language breakdown** | Python ≈ 95 %, SQL ≈ 3 %, Markdown/YAML ≈ 2 % |
| **Tools used for analysis** | Manual code review, architectural inspection, PII inventory extraction. |
| **Assumptions** | No hidden `.env` or secret files in the repo; Docker images are as described in `docker‑compose.yml`. |

---

### Bottom Line  

The repository delivers valuable functionality (speech‑to‑text library + a ready‑made e‑commerce API) but **exposes several high‑impact security and compliance risks**—most notably hard‑coded credentials, clear‑text storage of personally identifiable information, and insecure handling of payment gateway secrets.  

Implementing the **prioritized remediation actions** (rotate secrets, encrypt PII, move credentials to a secret manager, upgrade base images, and enable TLS) will dramatically improve the security posture and bring the project into alignment with common regulatory requirements (GDPR, PCI‑DSS, etc.).  

--- 

*Prepared by the audit assistant on 2026‑05‑08.*