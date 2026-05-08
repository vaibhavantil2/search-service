## Overview  

The repository is a Django‑based e‑commerce platform that also bundles the **SpeechRecognition** library.  
Both parts rely on a number of external services / APIs:

| # | Vendor / Service | Primary Purpose | How It Is Integrated | What Data Is Sent | Authentication / Credentials | Where It Is Configured |
|---|------------------|----------------|----------------------|-------------------|------------------------------|------------------------|
| 1 | **Google Speech Recognition** | Speech‑to‑text (free web API) | Direct HTTP POST to Google’s endpoint (see `recognize_google` in `speech_recognition/__init__.py`) | Raw audio bytes (usually FLAC/PCM) | API key passed as `key=` query‑parameter (optional) | `speech_recognition/__init__.py` (lines ~850‑860) |
| 2 | **Google Cloud Speech API** | Cloud‑based speech‑to‑text (paid, higher accuracy) | Google Cloud client library / raw REST call (`recognize_google_cloud`) | Audio bytes + optional configuration JSON | Service‑account JSON credentials (file path or env var) – token obtained via Google OAuth flow | `speech_recognition/__init__.py` (lines ~910‑925) |
| 3 | **Microsoft Azure Speech API** | Speech‑to‑text (Azure Cognitive Services) | REST call (`recognize_azure`) | Audio bytes + language tag | Azure subscription key (`key=`) and region (`location=`) – token fetched from Azure auth endpoint | `speech_recognition/__init__.py` (lines ~1020‑1085) |
| 4 | **Microsoft Bing Speech API** (deprecated) | Speech‑to‑text (legacy Azure) | REST call (`recognize_bing`) | Audio bytes + language tag | Azure subscription key (`key=`) – token fetched from Azure auth endpoint | `speech_recognition/__init__.py` (lines ~1110‑1130) |
| 5 | **Wit.ai** | Speech‑to‑text (NLP‑enhanced) | REST call (`recognize_wit`) | Audio bytes (WAV/FLAC) | Server‑side API token (`key=`) | `speech_recognition/__init__.py` (lines ~985‑1005) |
| 6 | **Houndify API** | Speech‑to‑text (offline‑capable hot‑word) | REST call (`recognize_houndify`) | Audio bytes + optional context | Client ID and client key (both Base64 strings) | `speech_recognition/__init__.py` (lines ~1240‑1265) |
| 7 | **IBM Speech to Text** | Speech‑to‑text (IBM Watson) | REST call (`recognize_ibm`) | Audio bytes + language model | Username & password (IBM Cloud IAM) | `speech_recognition/__init__.py` (lines ~1290‑1315) |
| 8 | **Pagar.me** | Payment gateway (Brazilian market) | Django model `PagarmeGateway` stores credentials; actual HTTP calls would be made elsewhere in the payment flow (not shown) | Card data, transaction amount, customer info, etc. (via Pagar.me API) | API key (`api_key`) and encryption key (`encryption_key`) stored in DB | `ecom/payment_gateway/models.py` (class `PagarmeGateway`) |
| 9 | **Django** (framework) | Web application framework, ORM, admin, auth, etc. | Imported as a Python package; not an external SaaS but a third‑party library | Configuration data, request/response payloads | No external auth – uses project‑level `SECRET_KEY` | `ecom/config/settings.py` |
|10| **PyAudio** | Access to microphone hardware for live audio capture | Imported in `speech_recognition/__init__.py` (`Microphone` class) | Audio stream captured locally (never sent unless a recognizer sends it) | No external auth | `speech_recognition/__init__.py` (class `Microphone`) |
|11| **PocketSphinx** (optional) | Offline speech‑to‑text engine | Imported when `recognize_sphinx` is used | Audio data processed locally | No external auth | `speech_recognition/__init__.py` (Sphinx integration) |
|12| **Other Python packages** (e.g., `hashids`, `celery`, `amqp`, `django‑rest‑framework`, `django‑cors‑headers`, etc.) | Utility / background task / API support | Imported as libraries; not external services | N/A | N/A | Various files (`requirements.txt`, `settings.py`, etc.) |

---

## Detailed Reasoning  

### 1. SpeechRecognition Library (speech_recognition/__init__.py)  

The library ships with wrappers for **seven** cloud speech‑to‑text services plus **Snowboy** (offline hot‑word detection) and **PocketSphinx** (offline speech‑to‑text).  

* Each wrapper builds a URL, adds query parameters (including the API key or token), and sends the audio payload via `urllib.request.urlopen`.  
* Authentication is always performed **client‑side** by passing a key/token in the request header or query string.  
* The only data transmitted to the vendor is the **audio payload** (raw PCM/FLAC) and optional metadata (language tag, preferred phrases, etc.).  

Relevant grep lines (excerpted) show the URLs and docs:

```
url = "http://www.google.com/speech-api/v2/recognize?{}".format(urlencode({ ... }))
url = "https://speech.googleapis.com/v1p1beta1/speech:recognize?..."
url = "https://{location}.stt.speech.microsoft.com/speech/recognition/..."
url = "https://api.wit.ai/speech?v=20170307"
url = "https://api.houndify.com/v1/audio"
url = "https://stream.watsonplatform.net/speech-to-text/api/v1/recognize?..."
```

All of these are **REST API** integrations; no SDKs are bundled.

### 2. Pagar.me Integration (ecom/payment_gateway/models.py)  

* The `PagarmeGateway` model stores `api_key` and `encryption_key`.  
* The actual HTTP calls to Pagar.me are not shown in the provided snippets, but the presence of these fields indicates that elsewhere in the code (likely in a service layer) the app will call Pagar.me’s REST endpoints to create charges, handle webhooks, etc.  
* Data sent would include **card hashes**, **customer details**, **order amount**, and **installment options** (as defined in the `PaymentMethod` and `PaymentMethodConfig` models).  
* Authentication is performed via the **API key** (sent in request headers) and the **encryption key** (used to encrypt sensitive fields).  

### 3. Django Framework  

* Django itself is a third‑party library (installed via `requirements.txt`).  
* It provides the web server, ORM, authentication, admin UI, and REST framework integration.  
* No external network calls are made by Django itself; it is a **local** framework.  

### 4. PyAudio & PocketSphinx  

* `PyAudio` is required only for microphone capture; it is a native wrapper around PortAudio.  
* `PocketSphinx` is an optional offline recognizer; both are **local** libraries, not external services.  

### 5. Other Dependencies  

* Packages such as `hashids`, `celery`, `amqp`, `django‑rest‑framework`, `django‑cors‑headers`, etc., are third‑party **Python libraries** that run inside the process. They do not involve outbound API calls, so they are listed for completeness but are not “vendor integrations” in the sense of external SaaS.

---

## Summary Table (Condensed)

| Vendor / Service | Purpose | Integration Type | Data Sent | Auth Method | Config Location |
|------------------|---------|------------------|-----------|-------------|-----------------|
| Google Speech Recognition | Speech‑to‑text | REST API | Audio bytes | API key (`key=`) | `speech_recognition/__init__.py` |
| Google Cloud Speech API | Speech‑to‑text (cloud) | REST API / Google client lib | Audio bytes + config | Service‑account JSON (OAuth token) | `speech_recognition/__init__.py` |
| Microsoft Azure Speech API | Speech‑to‑text | REST API | Audio bytes | Subscription key (`key=`) + region token | `speech_recognition/__init__.py` |
| Microsoft Bing Speech API (deprecated) | Speech‑to‑text | REST API | Audio bytes | Subscription key (`key=`) | `speech_recognition/__init__.py` |
| Wit.ai | Speech‑to‑text + NLP | REST API | Audio bytes | API token (`key=`) | `speech_recognition/__init__.py` |
| Houndify API | Speech‑to‑text (hot‑word) | REST API | Audio bytes | Client ID & client key | `speech_recognition/__init__.py` |
| IBM Speech to Text | Speech‑to‑text | REST API | Audio bytes | Username & password (IAM) | `speech_recognition/__init__.py` |
| Pagar.me | Payment processing | REST API (via Django models) | Card hash, amount, customer data, installment config | API key + encryption key (stored in DB) | `ecom/payment_gateway/models.py` |
| Django | Web framework / ORM | Python package | N/A (local) | N/A | `ecom/config/settings.py` |
| PyAudio | Microphone capture | Native library (C extension) | Audio captured locally | N/A | `speech_recognition/__init__.py` |
| PocketSphinx | Offline speech‑to‑text | Native library | Audio processed locally | N/A | `speech_recognition/__init__.py` |

---

### Final Remarks  

* All **speech‑recognition** services are **client‑side REST integrations** that transmit **only the audio payload** (and optional language/phrase hints).  
* **Authentication** is always performed by passing a **key/token** that the developer must obtain from the respective vendor’s developer console.  
* The **payment gateway** (`Pagar.me`) is the only e‑commerce‑specific external service; it handles **financial transactions** and requires both an API key and an encryption key.  
* The rest of the third‑party packages (`Django`, `PyAudio`, `PocketSphinx`, etc.) are **local libraries** that do not involve outbound network traffic.  

This analysis captures every external vendor referenced in the codebase, the way each is used, what data leaves the application, and where the integration points live.