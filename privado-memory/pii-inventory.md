**Personal / Sensitive Data Handling – Full Review**

Below is a complete catalog of every personal‑ or sensitive‑data element that appears in the two projects (the **SpeechRecognition** library and the **eCommerce Django API**), together with where it is defined, how it is stored, how it is used, what protections are in place, and its sensitivity rating.  Hard‑coded credentials and other secrets are also flagged.

---

## 1. Data‑Element Inventory

| # | Data element | Definition location (file / model / field) | Type & constraints | DB table / storage location | Primary uses | Current protection measures | Sensitivity level |
|---|--------------|--------------------------------------------|--------------------|----------------------------|--------------|-----------------------------|-------------------|
| 1 | **Email address** | `ecom/auth_core/models.py` – `User.email` (EmailField, unique) <br> `ecom/core/models.py` – `Customer.__str__` returns `self.user.email` <br> `ecom/core/serializers.py` – `ClientSerializer.email` | string, validated as email, unique | `auth_core_user` (custom User table) and `core_customer` (FK to User) | login / JWT token payload, user lookup, display in admin & API responses | • Stored **plain** in DB (no encryption) <br> • Access limited by Django auth + DRF permission classes (`IsAuthenticated`, custom `IsAddressOwnerDetail`) | **PII** |
| 2 | **Phone number** | `ecom/core/models.py` – `Customer.phone` (CharField max 12) | string, max 12 chars | `core_customer` | displayed on profile, used in order‑related logic | No hashing/encryption; protected only by app‑level auth | **PII** |
| 3 | **Password** | `ecom/auth_core/models.py` – inherits `AbstractUser.password` (CharField max 128) <br> `ecom/core/serializers.py` – `ClientSerializer.password` (write‑only, sourced from `auth_core.user.password`) | string (hashed by Django) | `auth_core_user.password` column | authentication, JWT token generation | **Django’s built‑in password hashing** (PBKDF2‑SHA256 by default) <br> Password never sent back to client (write‑only serializer) | **Sensitive PII** |
| 4 | **Personal document (CPF)** | `ecom/common/models.py` – `BaseCustomer.personal_document` (CharField max 20) <br> `ecom/core/models.py` – inherits via `Customer` | string, max 20 chars | `core_customer` (via abstract base) | displayed in admin, possibly used for compliance / billing | Stored in clear text; only guarded by auth/permissions | **Sensitive PII** |
| 5 | **Address fields** (street, suite, city, zipcode) | `ecom/core/models.py` – `Address` model (CharFields max 200) | strings, max 200 each | `core_address` | shipping, order summary, admin UI | No encryption; access limited by auth & `IsAddressOwnerDetail` permission | **PII** |
| 6 | **User name / username** | `ecom/auth_core/models.py` – `User.username` (CharField max 30) | string | `auth_core_user.username` | display, JWT payload (`username`) | Plain text; protected by auth | **PII** |
| 7 | **Customer name** | `ecom/common/models.py` – `BaseCustomer.name` (CharField max 255) | string | `core_customer.name` | display in UI, admin | Plain text; protected by auth | **PII** |
| 8 | **Product image file name** | `ecom/core/models.py` – `Product.image` (ImageField, custom `upload_to`) | file path (UUID‑based filename) | Media storage (`MEDIA_ROOT/uploads/product/…`) | product catalog display | Filenames are UUIDs, not personally identifying | **Low** |
| 9 | **Bank slip URL** | `ecom/core/models.py` – `Checkout.bank_slip_url` (URLField) | URL string | `core_checkout.bank_slip_url` | payment receipt link | Plain URL; access limited by auth | **Sensitive PII** (could expose payment info) |
|10| **Remote invoice ID** | `ecom/core/models.py` – `Checkout.remote_id` (CharField) | string | `core_checkout.remote_id` | correlation with external gateway | Plain text; auth‑protected | **Sensitive PII** |
|11| **JWT secret / signing key** | `ecom/config/settings.py` – `SIMPLE_JWT['SIGNING_KEY']` (hard‑coded) | string | In source code (settings) | signing JWTs | **Hard‑coded secret** – not rotated, visible to anyone with repo access | **Credential** |
|12| **Django `SECRET_KEY`** | `ecom/config/settings.py` – `SECRET_KEY = env('SECRET_KEY')` (loaded from .env) | string | Environment variable / .env file | Django cryptographic signing, CSRF, session cookies | Loaded from env (good) but fallback prints warning if missing | **Credential** |
|13| **IBM Speech‑to‑Text credentials** | `examples/*.py` – `IBM_USERNAME`, `IBM_PASSWORD` placeholders (hard‑coded strings like `"INSERT IBM SPEECH TO TEXT PASSWORD HERE"`) | string | Source files (example scripts) | external API calls | **Hard‑coded placeholder** – not a real secret, but shows where real credentials would be placed; should be moved to env vars | **Credential (potential)** |
|14| **Azure / Bing / AWS / other cloud keys** (used in `speech_recognition/__init__.py`) | Functions `recognize_azure`, `recognize_ibm`, `recognize_lex` accept `key`, `username`, `password`, `access_key_id`, `secret_access_key` parameters | string | Passed at runtime (not stored) | external speech services | No storage; caller must supply securely | **Credential (runtime)** |
|15| **RabbitMQ URI** | `ecom/config/settings.py` – `CELERY_BROKER_URL = env('RABBITMQ_URI')` | string | Environment variable | Celery broker connection | Loaded from env – good practice | **Credential** |

---

## 2. Detailed Findings & Reasoning

### a. Email, Phone, Name, Address, CPF
* **Where defined & stored:** All live in Django models that map directly to relational tables.  
* **How used:**  
  * Email is the primary identifier for authentication (`USERNAME_FIELD = 'email'`).  
  * Email, name, phone, address, CPF appear in API responses (e.g., `CheckoutItem.__str__`, admin list displays, serializers).  
* **Protection:** No field‑level encryption or hashing; reliance is on Django’s authentication/authorization layers (`IsAuthenticated`, custom permission classes).  
* **Risk:** If an attacker gains DB read access, they can retrieve full PII.  

### b. Password
* **Handled by Django’s `AbstractUser`.** Passwords are automatically hashed (default PBKDF2‑SHA256).  
* **Serializer:** `ClientSerializer.password` is write‑only, never returned.  

### c. JWT Signing Key
* **Hard‑coded in settings** (`SIMPLE_JWT['SIGNING_KEY']`). This is a **critical secret**; if the repo is public or leaked, attackers can forge valid JWTs.  
* **Recommendation:** Move to environment variable (e.g., `JWT_SIGNING_KEY`) and rotate regularly.  

### d. Django `SECRET_KEY`
* **Loaded from `.env`** – good, but the code prints a warning if the file is missing, which could expose the key in logs if a default were added later.  

### e. IBM Speech‑to‑Text credentials (example scripts)
* **Placeholders** are present; real credentials would need to be supplied by the user. The pattern shows that developers might be tempted to hard‑code real keys.  
* **Recommendation:** Document that these must be supplied via environment variables or a secrets manager.  

### f. External cloud keys (Azure, Bing, AWS Lex)
* **Passed as function arguments** – not stored. The code caches access tokens in memory (`self.azure_cached_access_token`). No persistence, so no at‑rest risk.  

### g. RabbitMQ URI
* **Loaded from env** – appropriate.  

### h. Media files (product images)
* Filenames are UUIDs, which reduces correlation with user data. No personal data in filenames.  

### i. Bank slip URL & Remote invoice ID
* Contain payment‑related information; stored in clear text. Access is limited to authenticated users, but still considered **sensitive PII**.  

---

## 3. Summary Table (Condensed)

| Data Element | Where Stored | Primary Use | Protection | Sensitivity |
|--------------|--------------|-------------|------------|-------------|
| Email | `auth_core_user.email`, `core_customer.email` | Auth, JWT payload, API display | Auth‑only (plain) | PII |
| Phone | `core_customer.phone` | Profile, order | Auth‑only (plain) | PII |
| Password | `auth_core_user.password` | Auth | Django hash (PBKDF2) | Sensitive PII |
| CPF (personal_document) | `core_customer.personal_document` | Billing/verification | Auth‑only (plain) | Sensitive PII |
| Address (street, suite, city, zipcode) | `core_address.*` | Shipping, order summary | Auth‑only (plain) | PII |
| Username | `auth_core_user.username` | JWT payload, display | Auth‑only (plain) | PII |
| Customer name | `core_customer.name` | Display | Auth‑only (plain) | PII |
| Bank slip URL | `core_checkout.bank_slip_url` | Payment receipt | Auth‑only (plain) | Sensitive PII |
| Remote invoice ID | `core_checkout.remote_id` | Gateway correlation | Auth‑only (plain) | Sensitive PII |
| JWT signing key | Hard‑coded in settings | Token signing | **Hard‑coded** (no rotation) | Credential |
| Django `SECRET_KEY` | Env (`.env`) | Django signing, CSRF | Env‑based (good) | Credential |
| IBM STT credentials (example) | Hard‑coded placeholder | External API | Placeholder only (should be env) | Credential (potential) |
| RabbitMQ URI | Env (`RABBITMQ_URI`) | Celery broker | Env‑based (good) | Credential |
| Cloud service keys (Azure, Bing, AWS) | Runtime args | External speech services | Not persisted | Credential (runtime) |

---

## 4. Recommendations & Mitigations

| Issue | Recommendation |
|-------|----------------|
| **Plain‑text PII in DB (email, phone, CPF, address, bank‑slip URL, remote ID)** | • Consider field‑level encryption (e.g., Django‑Encrypted‑Fields or custom `EncryptedCharField`). <br> • Enable database‑level encryption at rest (e.g., PostgreSQL `pgcrypto`). |
| **Hard‑coded JWT signing key** | • Move the key to an environment variable or secret‑management service (AWS Secrets Manager, HashiCorp Vault, etc.). <br> • Rotate the key periodically. |
| **Hard‑coded example credentials** | • Replace placeholders with environment‑variable look‑ups in examples, or clearly document that users must supply credentials via env vars. |
| **Potential exposure of Django `SECRET_KEY`** | • Ensure `.env` is never committed; add to `.gitignore`. <br> • In production, load from a secure secret store. |
| **Lack of audit logging for PII access** | • Add Django signals or middleware to log read/write access to sensitive fields. |
| **No explicit data‑retention / deletion policy** | • Implement GDPR‑style “right to be forgotten” endpoints that delete or anonymize PII. |
| **Password reset / recovery not shown** | • Verify that password reset tokens are short‑lived and stored hashed. |
| **Media files not protected** | • Serve media over authenticated endpoints if they ever contain personal data; otherwise keep them public as they are non‑PII. |
| **Token lifetime (1 day) may be long** | • Evaluate if shorter lifetimes are acceptable; enable token rotation/blacklisting for compromised tokens. |
| **Permissions on address detail** | Already using `IsAddressOwnerDetail`; ensure similar checks exist for all endpoints returning PII. |
| **Testing / example scripts** | Remove any real credentials before publishing; keep only placeholders. |

---

### Final Note

All identified personal data is currently protected **only** by the application’s authentication and permission layers. While this is acceptable for many internal systems, best‑practice security for a production e‑commerce API recommends **encryption at rest**, **strict secret management**, and **audit logging** for any operation that reads or writes PII. Implementing the recommendations above will substantially reduce the risk of data leakage or credential compromise.