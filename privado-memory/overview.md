# Repository Architecture Overview  

The repository contains **two independent projects**:

| # | Project | Path | Primary Goal |
|---|---------|------|--------------|
| 1 | **SpeechRecognition** | root of the repo (`speech_recognition/` package) | Provide a pure‑Python library that abstracts several speech‑to‑text engines (offline & cloud) and offers a simple API / CLI for developers. |
| 2 | **eCommerce Django REST API** | `ecom/` directory | Deliver a full‑stack e‑commerce backend (authentication, product catalog, payment gateway, admin UI) exposed through a RESTful API, ready to run in Docker. |

Below is a **deep dive** into each project, covering purpose, tech stack, architectural style, code organization, build/deployment pipeline, and entry‑point/configuration details.

---

## 1️⃣ SpeechRecognition Library  

### 1.1 Purpose & Repo Type  
* **Type**: Python library (distributable on PyPI).  
* **Purpose**: Offer a unified, high‑level Python interface for multiple speech‑recognition services (CMU Sphinx, Google, Azure, IBM, Snowboy, etc.) and utilities for audio handling.

### 1.2 Tech Stack  

| Layer | Technology / Library | Role |
|-------|----------------------|------|
| Language | **Python** (2.6‑2.7, 3.3+) | Core implementation |
| Audio I/O | **PyAudio** (optional, for microphone) | Capture audio streams |
| Offline Engine | **CMU Sphinx / PocketSphinx** | Local speech‑to‑text |
| Cloud APIs | Google Speech, Google Cloud Speech, Wit.ai, Azure Speech, Bing (deprecated), Houndify, IBM Speech‑to‑Text | Remote recognition services |
| Hot‑word detection | **Snowboy** (offline) | Wake‑word detection |
| FLAC encoder | Platform‑specific binary (`flac‑*`) | Required for some cloud services |
| Packaging | `setuptools`, `setup.py` | Build & distribution |
| Documentation | reStructuredText (`README.rst`, `reference/`) | API docs & usage examples |

### 1.3 Architecture Pattern  

* **Library / Framework** – No runtime server, no persistence layer. The package is imported by user code and provides a **thin façade** over various back‑ends.  
* **Extensible plug‑in style** – New recognizers can be added by implementing a small interface.

### 1.4 Code Organization  

```
speech_recognition/
│   __init__.py          # public symbols, version
│   __main__.py          # `python -m speech_recognition` CLI entry point
│   ... (core modules)   # recognizer classes, audio utilities
examples/
│   audio_transcribe.py
│   background_listening.py
│   ...                  # ready‑to‑run demos for each feature
reference/
│   library-reference.rst
│   pocketsphinx.rst
```

* **`speech_recognition/__init__.py`** – Exposes `Recognizer`, `AudioFile`, `Microphone`, and exception classes.  
* **`speech_recognition/__main__.py`** – Parses command‑line arguments, loads an audio file or microphone, calls the default recognizer, prints results.  
* **`examples/`** – Small scripts that import the library and demonstrate typical workflows (recording, transcribing, background listening, etc.).  
* **`reference/`** – Human‑readable documentation that is also shipped to PyPI.

### 1.5 Build, Deployment & Infrastructure  

| Aspect | Detail |
|--------|--------|
| **Distribution** | Published on PyPI (`pip install SpeechRecognition`). |
| **Build** | Standard `setup.py`/`setup.cfg` using `setuptools`. No compiled extensions – pure Python. |
| **Runtime Requirements** | Python ≥2.6, optional `pyaudio`, optional `pocketsphinx`, optional cloud SDKs (e.g., `google-cloud-speech`). |
| **Infrastructure** | None – the library runs wherever Python runs (desktop, server, container, etc.). |

### 1.6 Entry Points & Configuration  

| Entry Point | How to invoke |
|-------------|---------------|
| **Python import** | `import speech_recognition as sr` → instantiate `sr.Recognizer()` and call `recognize_google()`, `recognize_sphinx()`, etc. |
| **CLI** | `python -m speech_recognition path/to/audio.wav` – selects recognizer based on flags (`--google`, `--sphinx`, …). |
| **Configuration** | Mostly **runtime parameters** passed to recognizer methods (e.g., `language`, `show_all`). No global config file; optional environment variables for cloud API keys are read by the respective SDKs. |

---

## 2️⃣ eCommerce Django REST API  

### 2.1 Purpose & Repo Type  

* **Type**: Full‑stack **Django** project exposing a **RESTful API** for an e‑commerce platform (users, products, orders, payments).  
* **Purpose**: Serve as a micro‑service‑ready backend that can be containerised, scaled, and integrated with front‑ends (web, mobile).  

### 2.2 Tech Stack  

| Layer | Technology | Version / Notes |
|-------|------------|-----------------|
| **Language** | Python 3.8 (compatible with Django 3.0) |
| **Web Framework** | **Django 3.0.14** |
| **REST API** | **Django REST Framework 3.11.2** |
| **Authentication** | `djangorestframework‑simplejwt` (JWT) |
| **Database** | PostgreSQL 9.6 (via Docker) |
| **ORM** | Django ORM (polymorphic support via `django‑polymorphic` & `django‑rest‑polymorphic`) |
| **Filtering** | `django‑filter` |
| **CORS** | `django‑cors‑headers` |
| **Background Tasks** | **Celery 4.4.3** + **RabbitMQ 3.8** (as broker) |
| **File Storage** | Local media folder (`MEDIA_ROOT`) – product images stored under `media/uploads/products/` |
| **Containerisation** | Docker + Docker‑Compose |
| **Other** | `Pillow` (image handling), `hashids`, `django‑autoslug`, `amqp`, `kombu` |

### 2.3 Architecture Pattern  

* **Monolithic Django project** – All core business logic lives inside a single Django codebase (`ecom/`).  
* **Micro‑service‑style extensions** – The **Celery worker** runs in a separate container, handling asynchronous tasks (e.g., payment processing, email notifications).  
* **Domain‑driven app separation** – Each logical domain (auth, core, payment, admin) is a distinct Django *app*.

### 2.4 Code Organization & Module Structure  

```
ecom/
│   manage.py                     # Django CLI entry point
│   docker-compose.yml            # Docker orchestration
│   Dockerfile                    # Base image for app & worker
│   requirements.txt              # Python dependencies
│
├─ auth_core/
│   ├─ __init__.py
│   ├─ admin.py
│   ├─ apps.py
│   ├─ fixtures/fake_data.json
│   ├─ managers.py
│   ├─ migrations/0001_initial.py
│   └─ models.py                 # Custom User model, auth utilities
│
├─ core/
│   ├─ __init__.py
│   ├─ apps.py
│   ├─ fixtures/initial_data.json
│   ├─ migrations/0001_initial.py
│   ├─ models.py                 # Product, Order, Category, etc.
│   ├─ permissions.py
│   ├─ receivers.py              # Signal handlers (e.g., post_save)
│   ├─ serializers.py            # DRF serializers
│   ├─ tests.py
│   ├─ urls.py
│   └─ views.py                  # ViewSets / API endpoints
│
├─ payment_gateway/
│   ├─ __init__.py
│   ├─ admin.py
│   ├─ apps.py
│   ├─ middlewares.py            # Request‑level payment config checks
│   ├─ migrations/0001_initial.py
│   ├─ models.py                 # PaymentMethod, Transaction, etc.
│   ├─ proccess_payment.py       # Business logic for charging
│   └─ serializers.py
│
├─ my_admin/
│   ├─ __init__.py
│   ├─ admin.py
│   ├─ apps.py
│   ├─ backends.py               # Custom admin authentication backend
│   └─ models.py
│
├─ fixtures/
│   ├─ __init__.py
│   ├─ apps.py
│   └─ management/commands/db-reset.py   # Helper command to reset DB
│
├─ common/
│   ├─ __init__.py
│   ├─ ModelObserver.py          # Generic observer pattern for models
│   └─ models.py                 # Shared abstract models / mixins
│
├─ config/
│   ├─ __init__.py
│   ├─ settings.py               # All Django settings (env‑based)
│   ├─ urls.py                   # Root URLconf, includes app URLs
│   ├─ wsgi.py
│   └─ celery.py                 # Celery app configuration
│
└─ media/
    └─ uploads/products/…        # Sample product images (static data)
```

#### Key Django Apps  

| App | Responsibility |
|-----|-----------------|
| **auth_core** | Custom `User` model (`AUTH_USER_MODEL = 'auth_core.User'`), authentication utilities, admin registration. |
| **core** | Business domain: products, categories, orders, carts, etc.; primary API endpoints. |
| **payment_gateway** | Payment method configuration, transaction records, middleware that validates payment settings before request processing. |
| **my_admin** | Overrides default admin login (`my_admin.backends.AdminBackend`) and adds custom admin models. |
| **fixtures** | Management commands & data fixtures for seeding/resetting the DB. |
| **common** | Re‑usable abstract models / observer utilities used across apps. |

### 2.5 Build, Deployment & Infrastructure  

| Component | Description |
|-----------|-------------|
| **Dockerfile** (in `ecom/`) | Uses a Python base image, installs system packages, copies source, runs `pip install -r requirements.txt`. The same image is used for both the **app** and **worker** containers. |
| **docker-compose.yml** | Orchestrates four services: <br>• `app` – Django development server (`runserver 0.0.0.0:8000`). <br>• `worker` – Celery worker (`celery -A config.celery worker`). <br>• `database` – PostgreSQL 9.6 (exposed on host port 5431). <br>• `rabbitmq` – Message broker with management UI (ports 15672, 5672). <br>• `adminer` – Lightweight DB UI (port 8080). |
| **Volumes** | Persistent storage for PostgreSQL (`postgres`) and RabbitMQ (`rabbitmq`). |
| **Network** | Default bridge network; all services can resolve each other by service name (`database`, `rabbitmq`). |
| **Environment** | Settings are read from a `.env` file (via `django‑environ`). Critical variables: `SECRET_KEY`, `DEBUG`, `RABBITMQ_URI`, and DB connection string (`DATABASE_URL`). |
| **Celery** | Configured in `config/celery.py` – broker URL taken from `CELERY_BROKER_URL`. Workers are started in the `worker` container. |
| **Static & Media** | `STATIC_URL = '/static/'` (served by Django in dev). `MEDIA_ROOT` points to `<BASE_DIR>/media`; product images are stored under `media/uploads/`. |
| **CI** | `.travis.yml` (not shown in detail) runs tests against the library and Django project. |

### 2.6 Entry Points & Configuration  

| Entry Point | How it’s Started | What it Does |
|-------------|------------------|--------------|
| **`manage.py`** | `docker exec -it micro-ecommerce-app python manage.py <command>` | Standard Django management commands (`runserver`, `migrate`, `createsuperuser`, custom `db-reset`). |
| **Django server** | `docker-compose up app` (entrypoint `docker/app-entrypoint.sh` runs `python manage.py migrate && python manage.py runserver 0.0.0.0:8000`) | Serves the REST API, admin site, static/media files. |
| **Celery worker** | `docker-compose up worker` (entrypoint `docker/worker-entrypoint.sh` runs `celery -A config.celery worker -l info`) | Consumes background jobs (e.g., payment processing, email notifications). |
| **RabbitMQ** | `docker-compose up rabbitmq` | Message broker for Celery. |
| **Adminer** | `docker-compose up adminer` | Web UI for DB inspection. |

#### Django Settings Highlights (`config/settings.py`)

| Setting | Value / Source | Comment |
|---------|----------------|---------|
| `SECRET_KEY` | `env('SECRET_KEY')` | Must be defined in `.env`. |
| `DEBUG` | `env('DEBUG')` (bool) | Controlled via env. |
| `ALLOWED_HOSTS` | `[]` (dev) | Extend for production. |
| `INSTALLED_APPS` | Core Django apps + `payment_gateway`, `auth_core`, `my_admin`, `core`, `fixtures`, plus third‑party (`rest_framework`, `django_filters`, `corsheaders`) |
| `MIDDLEWARE` | Default + `CorsMiddleware`, `CheckPaymentMethodConfigMiddleware`, `CheckPaymentGatewayDefaultMiddleware` |
| `AUTH_USER_MODEL` | `'auth_core.User'` | Custom user model. |
| `AUTHENTICATION_BACKENDS` | `('my_admin.backends.AdminBackend',)` | Custom admin login. |
| `REST_FRAMEWORK` | JWT auth, pagination (`PAGE_SIZE=12`) |
| `DATABASES` | `env.db()` – reads `DATABASE_URL` from `.env` |
| `CELERY_BROKER_URL` | `env('RABBITMQ_URI')` |
| `SIMPLE_JWT` | Hard‑coded signing key (example) + token lifetimes (1 day) |
| `CORS_ORIGIN_ALLOW_ALL` | `True` (development) |
| `MEDIA_ROOT` / `MEDIA_URL` | `<BASE_DIR>/media` & `/media/` |
| `STATIC_URL` | `/static/` |

---

## 3️⃣ Comparative Summary  

| Aspect | SpeechRecognition Library | eCommerce Django API |
|--------|---------------------------|----------------------|
| **Repo Type** | Pure Python library (PyPI package) | Django monolith with auxiliary Celery worker |
| **Primary Goal** | Unified speech‑to‑text API across many providers | Provide RESTful e‑commerce backend (auth, catalog, payments) |
| **Runtime** | Any Python interpreter (desktop, server, container) | Docker containers (app + worker) + PostgreSQL + RabbitMQ |
| **Key Dependencies** | `pyaudio`, `pocketsphinx`, cloud SDKs (optional) | Django, DRF, Celery, PostgreSQL, RabbitMQ, JWT |
| **Architecture** | Library/Framework (no server) | Monolith + micro‑service‑like async worker |
| **Code Layout** | `speech_recognition/` + `examples/` + `reference/` | Multiple Django apps (`auth_core`, `core`, `payment_gateway`, `my_admin`, `common`) |
| **Build / Deploy** | `pip install` / `setup.py` | Docker‑Compose (app, worker, db, broker, adminer) |
| **Entry Point** | `import speech_recognition as sr` **or** `python -m speech_recognition` | `manage.py runserver` (via Docker) + Celery worker |
| **Configuration** | Runtime arguments / optional env vars for cloud keys | `.env` + `settings.py` (env‑based), JWT settings, CORS, Celery broker URL |
| **Testing** | Unit tests in `speech_recognition/tests` (not shown) | `core/tests.py` + Django test runner (`manage.py test`) |
| **Documentation** | `README.rst`, `reference/` docs, `examples/` scripts | `ecom/README.md`, inline comments, Swagger not present (could be added) |

---

## 4️⃣ Take‑aways  

* **Two distinct concerns** live side‑by‑side: a reusable speech‑recognition library and a full‑stack e‑commerce backend.  
* The **SpeechRecognition** part is lightweight, pure‑Python, and can be used independently of the Django project.  
* The **eCommerce** part follows conventional Django best practices (custom user model, modular apps, REST framework) and is **container‑first**: Dockerfile + Docker‑Compose give a reproducible dev/prod environment, while Celery + RabbitMQ provide asynchronous processing.  
* Both projects share a **common Python ecosystem** (requirements, virtualenv, packaging) but are otherwise isolated; they could be split into separate repositories without breaking either.  

---  

**End of analysis**.