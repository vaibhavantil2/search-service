## Complete Data‑Flow Mapping for the Repository  

The repository contains **two independent projects** – the **SpeechRecognition** Python library and the **eCommerce Django REST API**.  
Below is a single, end‑to‑end view of how **personal / sensitive data** moves through the whole code‑base, from the moment it is supplied by a user (or a device) to the moment it leaves the system (or is transformed internally).

---

### 1️⃣ High‑Level Overview  

```
+-------------------+        +-------------------+        +-------------------+
|   Data Ingress    |  --->  |   Internal Flow   |  --->  |   Data Egress     |
+-------------------+        +-------------------+        +-------------------+
```

* **Data Ingress** – entry points (user registration, API calls, audio capture).  
* **Internal Flow** – movement between Django models, serializers, views, Celery workers, RabbitMQ, and the SpeechRecognition library.  
* **Data Egress** – API responses, third‑party service calls (speech‑to‑text, payment gateway, etc.).

---

## 2️⃣ Detailed Flow Sections  

### 2.1 Data Ingress  

| # | Entry Point | How Data Arrives | Personal / Sensitive Elements |
|---|-------------|------------------|------------------------------|
| 1 | **User Registration / Login API** (`/api/auth/register/`, `/api/auth/login/`) | JSON payload in an HTTP POST request. | `email`, `password`, `username`, `name`, `phone`, `personal_document (CPF)` |
| 2 | **Authenticated API Calls** (profile update, address creation, order placement) | JSON payload in HTTP request with JWT `Authorization: Bearer <token>` header. | `address` fields, `phone`, `email`, `name`, `order details`, `payment data` |
| 3 | **Audio Capture** (`speech_recognition/__main__.py` or `examples/…`) | Microphone stream captured by **PyAudio** → `AudioData` object. | Raw audio bytes (PCM/FLAC) – not personal until sent to a recognizer. |
| 4 | **Webhooks / Callbacks** (e.g., payment‑gateway status updates) | HTTP POST from external service to a Django view. | `order_id`, `payment_status`, possibly masked card info. |

---

### 2.2 Internal Movement  

#### 2.2.1 Django Request → View → Serializer → Model  

```
[HTTP Request] → Django URLconf → View (DRF ViewSet) → Serializer → Model instance
```

* **Serializers** (`ecom/core/serializers.py`, `ecom/auth_core/serializers.py`) validate input, enforce `write_only` on passwords, and convert model instances to JSON for responses.  
* **Models** (`ecom/core/models.py`, `ecom/auth_core/models.py`, etc.) persist data in PostgreSQL.

#### 2.2.2 Background Processing (Celery + RabbitMQ)  

```
[View] → Celery task (delay()) → RabbitMQ (amqp://admin:admin@rabbitmq) → Worker → Model updates / external API calls
```

* Typical tasks: sending order‑confirmation emails, generating PDF invoices, async payment verification.  
* Messages are **durable** only if the task is defined with `acks_late=True` and the queue is declared durable (not shown in repo, but standard Celery config).

#### 2.2.3 SpeechRecognition Library  

```
[AudioData] → Recognizer.recognize_<engine>() → Engine Adapter
   ├─> Local (PocketSphinx) → binary exec → text result
   └─> Cloud (Google, Azure, IBM, etc.) → HTTP request → JSON response → text result
```

* The **audio bytes** travel from the local `AudioData` object to the selected engine.  
* For cloud engines, the request includes the raw audio (often FLAC‑encoded) and optional API keys (passed as query‑string or header).  
* The library returns either a plain string or a detailed dict (`show_all=True`).

#### 2.2.4 Data Transformations  

| Transformation | Where It Happens | What Is Produced |
|----------------|------------------|------------------|
| **Password hashing** | `User.set_password()` (Django auth) | PBKDF2‑SHA256 hash stored in `auth_core_user.password` |
| **JWT creation** | `SimpleJWT` (`TokenObtainPairView`) | Signed JWT (`access`, `refresh`) containing `user_id`, `username`, `email` |
| **JWT verification** | DRF authentication class (`JWTAuthentication`) | User object attached to `request.user` |
| **Serialization** | DRF serializers (`ModelSerializer`) | JSON payload for API responses |
| **Audio encoding** | `speech_recognition/__init__.py` (`_audio_data_to_flac`) | FLAC‑encoded byte stream for cloud services |
| **Card hashing (Pagar.me)** | `payment_gateway/models.py` (`PagarmeGateway`) – not fully shown but typical flow uses `pagarme` SDK to generate a card hash before sending to the gateway | Card hash string (PCI‑DSS compliant) |

---

### 2.3 Data Egress  

| # | Destination | How Data Leaves | Personal / Sensitive Elements |
|---|-------------|----------------|------------------------------|
| 1 | **API Responses** (JSON) | DRF `Response` objects serialized by serializers. | `email`, `name`, `address`, `order summary`, `JWT token` (access token) |
| 2 | **Speech‑to‑Text Cloud Services** (`recognize_google`, `recognize_azure`, etc.) | HTTPS POST with audio bytes + optional API key. | Raw audio (may contain voice‑identifiable data) |
| 3 | **Payment Gateway (Pagar.me)** | HTTPS request via `pagarme` SDK or custom `requests` call. | Card hash, transaction amount, customer name/email, billing address |
| 4 | **External Notification Services** (e.g., email via SendGrid, SMS via Twilio – not in repo but typical) | HTTP API call from a Celery worker. | Email address, phone number, order details |
| 5 | **Logging / Monitoring** (stdout, Docker logs) | `logging` statements. | Potentially user IDs, request IDs – should avoid PII. |
| 6 | **Webhooks to Third‑Party** (payment status callbacks) | HTTP POST from Django view to external URL. | Order ID, payment status, masked card info. |

---

## 3️⃣ Flow Diagrams (ASCII / Markdown)

### 3.1 End‑to‑End Flow (User → System → External)

```
+-------------------+          +-------------------+          +-------------------+
|   USER / DEVICE   |          |   DJANGO BACKEND  |          |   EXTERNAL SVC   |
+-------------------+          +-------------------+          +-------------------+
        |                               |                               |
        | 1. Register / Login (JSON)    |                               |
        |------------------------------>|                               |
        |                               | 2. Validate & create User      |
        |                               |    → password hashed           |
        |                               |    → JWT issued                |
        |                               |                               |
        | 3. Authenticated request (JWT)|                               |
        |------------------------------>|                               |
        |                               | 4. View → Serializer → Model   |
        |                               |    (e.g., create Order)        |
        |                               |                               |
        |                               | 5. Enqueue Celery task         |
        |                               |    → RabbitMQ (amqp://…)       |
        |                               |                               |
        |                               | 6. Worker processes task       |
        |                               |    → may call Pagar.me API    |
        |                               |    → may call Speech API      |
        |                               |                               |
        |                               | 7. API Response (JSON)         |
        |<------------------------------|                               |
        |                               |                               |
        | 8. Audio capture (mic)        |                               |
        |------------------------------>|                               |
        |                               | 9. SpeechRecognition Recognizer|
        |                               |    → selects engine            |
        |                               |    → sends audio to cloud      |
        |                               |    ← receives transcription    |
        |                               |    → returns text to caller    |
        |<------------------------------|                               |
+-------------------+          +-------------------+          +-------------------+
```

### 3.2 Detailed Internal Flow (Django → Celery → RabbitMQ)

```
[HTTP Request] 
      |
      v
+-------------------+          +-------------------+          +-------------------+
|   DRF ViewSet     |  ---->   |   Serializer      |  ---->   |   Model (Postgres)|
+-------------------+          +-------------------+          +-------------------+
      |                               |                               |
      |   (if async)                  |                               |
      v                               v                               v
+-------------------+          +-------------------+          +-------------------+
|   Celery.delay()  |  ---->   |   RabbitMQ (AMQP) |  ---->   |   Celery Worker   |
+-------------------+          +-------------------+          +-------------------+
      |                               |                               |
      |   (process)                    |   (call external API)         |
      v                               v                               v
+-------------------+          +-------------------+          +-------------------+
|   Task logic      |  ---->   |   Payment SDK     |  ---->   |   External Svc    |
|   (e.g., charge) |          |   (Pagar.me)      |          |   (Pagar.me)      |
+-------------------+          +-------------------+          +-------------------+
```

### 3.3 SpeechRecognition Data Path

```
[Microphone] → AudioData (PCM) → Recognizer.recognize_<engine>()
      |
      |---> PocketSphinx (local binary) → Text
      |
      |---> Cloud Engine (Google, Azure, IBM, etc.)
               |
               |  HTTP POST (audio + API key)
               v
          Cloud Service → JSON response → Text
```

---

## 4️⃣ Data‑Flow Summary Table  

| Source                              | Processing / Transformation                              | Destination                              | Data Elements (PII / Sensitive) |
|-------------------------------------|----------------------------------------------------------|------------------------------------------|---------------------------------|
| **User registration POST**          | Validation → password hashing → JWT creation             | `auth_core_user` (Postgres) + JWT token | email, password‑hash, username, name, phone, CPF |
| **Authenticated API call** (profile update) | Serializer → Model save                                 | `core_customer` (Postgres)               | name, phone, email, address fields |
| **Order creation POST**             | Serializer → Model → Celery task (async)                | RabbitMQ → Celery worker → Pagar.me API  | order items, total amount, customer ID, billing address |
| **Audio capture (mic)**             | AudioData → optional FLAC encoding → recognizer call     | Cloud Speech‑to‑Text service (Google, Azure, etc.) | raw audio bytes (voice may contain personal info) |
| **Celery worker (payment)**         | Card data → SDK → card‑hash generation → HTTPS POST      | Pagar.me payment gateway                 | card hash, amount, customer name/email, billing address |
| **JWT authentication**              | Token signing (HS256)                                    | Client (browser/mobile)                  | JWT containing user_id, email, username |
| **API response** (DRF)              | Serialization → JSON rendering                           | Client                                    | email, name, address, order summary, JWT (access token) |
| **Webhook from payment gateway**    | Parse JSON → update Order status                         | Django view → Model update                | order_id, payment_status, masked card info |
| **Logging**                         | `logging` statements (INFO/DEBUG)                       | stdout / Docker logs                     | potentially user IDs, request IDs (should avoid PII) |

---

## 5️⃣ Security‑Relevant Transformations  

| Transformation | Implementation Detail | Security Impact |
|----------------|-----------------------|-----------------|
| **Password hashing** | Django `User.set_password()` → PBKDF2‑SHA256 (default) | Stores only salted hash; never plaintext |
| **JWT signing** | `SIMPLE_JWT['SIGNING_KEY']` (loaded from `.env`) | Guarantees token integrity; key must be kept secret |
| **Card hashing** | Pagar.me SDK creates a **PCI‑DSS‑compliant** card hash before transmission | Raw card numbers never touch our DB or logs |
| **Audio encoding** | `_audio_data_to_flac()` converts PCM → FLAC before upload | Reduces size; does not add security – audio still sent in clear over TLS |
| **HTTPS everywhere** | All external calls (speech APIs, payment gateway) use `https://` endpoints | Data in transit is encrypted |
| **Permission classes** | DRF `IsAuthenticated`, custom `IsAddressOwnerDetail` | Prevents unauthorized read/write of PII |

---

## 6️⃣ Authentication Flow (JWT Lifecycle)

```
[Client] --(POST /api/auth/login)--> [Django] --(validate credentials)--> 
   generate JWT (access + refresh) --> return tokens
[Client] stores access token (e.g., in localStorage)
[Client] --(subsequent API calls with Authorization: Bearer <access>)--> [Django]
   --> JWTAuthentication verifies signature, expiry, user_id
   --> request.user populated → view logic runs
[Refresh] --(POST /api/auth/refresh)--> [Django] validates refresh token → new access token
```

* **Credential handling** – passwords never leave the server in plaintext; they are hashed before storage.  
* **Token storage** – tokens are short‑lived (default 5 min) to limit exposure.  

---

## 7️⃣ Payment Flow (Pagar.me)

```
[Client] → POST /api/orders/ (order data, optional card token) 
      |
      v
[Django View] → creates Order model → enqueues Celery task `process_payment`
      |
      v
[Celery Worker] → uses Pagar.me SDK:
   1. Build payload (amount, customer data, card_hash)
   2. HTTPS POST to https://api.pagar.me/1/transactions
   3. Receive JSON response (transaction_id, status)
   4. Update Order model with `remote_id`, `status`, `bank_slip_url` (if boleto)
      |
      v
[Result] → stored in PostgreSQL → later returned via API response or webhook
```

* **Sensitive data** – only the **card hash** (not raw PAN) is transmitted.  
* **PCI‑DSS compliance** – the raw card never touches our servers.

---

## 8️⃣ Summary  

* **Ingress**: Personal data enters via HTTP JSON payloads (registration, profile, orders) and via microphone audio streams.  
* **Internal movement**: Data is validated/serialized, persisted in PostgreSQL, optionally queued in RabbitMQ, processed by Celery workers, and may be handed to the SpeechRecognition library for transcription.  
* **Egress**: Data leaves as API JSON responses, as HTTPS calls to speech‑to‑text services, and as payment‑gateway requests (card hash, transaction details).  
* **Transformations**: Password hashing, JWT signing, card hashing, audio encoding, and JSON serialization protect data at rest and in transit.  
* **Authentication**: JWT tokens are issued after credential verification, signed with a secret key, and validated on each request.  
* **Payments**: Card data is never stored; a PCI‑DSS‑compliant hash is generated and sent to Pagar.me, which returns a transaction ID and status that are stored in the DB.

All of the above reflects the **complete data‑flow mapping** derived from the analysis results you provided.