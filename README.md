<p align="center">
  <h1 align="center">⚡ Mega Forum Sistemi</h1>
  <p align="center">
    Yüksek performanslı, ölçeklenebilir ve güvenli RESTful forum API'si
    <br />
    <strong>Go • Chi • PostgreSQL • Redis • JWT</strong>
  </p>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Go-1.26.5-00ADD8?style=flat-square&logo=go" alt="Go Version">
  <img src="https://img.shields.io/badge/PostgreSQL-16-4169E1?style=flat-square&logo=postgresql" alt="PostgreSQL">
  <img src="https://img.shields.io/badge/Redis-7-DC382D?style=flat-square&logo=redis" alt="Redis">
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License">
</p>

---

## 📋 İçindekiler

- [Proje Hakkında](#-proje-hakkında)
- [Özellikler](#-özellikler)
- [Mimari Kararlar](#-mimari-kararlar)
- [Kullanılan Teknolojiler](#-kullanılan-teknolojiler)
- [Başlarken](#-başlarken)
- [Konfigürasyon](#-konfigürasyon)
- [API Dokümantasyonu](#-api-dokümantasyonu)
- [Veritabanı Şeması](#-veritabanı-şeması)
- [Güvenlik](#-güvenlik)
- [Rate Limiting](#-rate-limiting)
- [Proje Yapısı](#-proje-yapısı)
- [Yol Haritası](#-yol-haritası)

---

## 🚀 Proje Hakkında

**Mega Forum Sistemi**, modern forum uygulamaları için geliştirilmiş, tamamen RESTful bir backend API'sidir. Kullanıcı kaydı, email doğrulama, JWT tabanlı kimlik doğrulama, gönderi yönetimi, yorum sistemi ve beğeni mekanizması gibi temel forum özelliklerini sunar.

Saf Go ile yazılmış olup, yüksek performanslı PostgreSQL + Redis altyapısı sayesinde ölçeklenebilir ve düşük gecikmeli bir deneyim sağlar. Herhangi bir frontend bağımlılığı olmadan, istemci olarak herhangi bir uygulama (web, mobil, masaüstü) tarafından tüketilebilir.

---

## ✨ Özellikler

### 🔐 Kimlik Doğrulama & Kullanıcı Yönetimi
- **Kullanıcı Kaydı** — Kullanıcı adı, email ve şifre ile kayıt
- **Email Doğrulama** — 6 haneli OTP kodu ile email doğrulama (HMAC-SHA256 korumalı)
- **JWT Access Token** — 15 dakika geçerli, imzalı access token
- **Refresh Token Rotasyonu** — 30 gün geçerli, her kullanımda yenilenen refresh token
- **Bcrypt Şifreleme** — Şifreler bcrypt ile hash'lenerek saklanır

### 📝 Gönderi Yönetimi
- **Gönderi Oluşturma** — Başlık + içerik ile yeni gönderi
- **Gönderi Listeleme** — En güncel 50 gönderiyi getirme
- **Kullanıcı Gönderileri** — Belirli bir kullanıcıya ait tüm gönderiler
- **Tam Metin Arama** — Gönderi başlığı ve içeriğinde ILIKE ile arama

### 💬 Yorum Sistemi
- **Yorum Ekleme** — Gönderilere yorum yapma
- **Yorum Listeleme** — Bir gönderideki tüm yorumları görüntüleme

### ❤️ Beğeni Sistemi
- **Beğeni Ekleme** — Gönderileri beğenme (çift beğeni korumalı, UNIQUE constraint)
- **Beğeni Listeleme** — Bir gönderinin tüm beğenilerini görüntüleme

### 🛡️ Güvenlik & Rate Limiting
- **IP Tabanlı Rate Limiting** — Redis ile her endpoint için ayrı limitler
- **JWT Middleware** — Korumalı endpoint'lerde Bearer token doğrulaması
- **OTP Süre Sınırı** — 15 dakika geçerli, maksimum 5 deneme hakkı
- **Refresh Token Hash** — Token'lar SHA-256 ile hash'lenerek saklanır

---

## 🏗️ Mimari Kararlar

| Karar | Sebep |
|---|---|
| **Tek `main` paketi** | Küçük proje ölçeğinde basitlik ve hızlı geliştirme |
| **Ham SQL (pgx)** | ORM katmanı olmadan tam kontrol ve maksimum performans |
| **Chi Router** | Hafif, standart `net/http` uyumlu, middleware dostu |
| **Redis Rate Limiting** | IP bazlı sayaçlar için in-memory'den daha güvenilir ve dağıtılabilir |
| **Denormalize username** | JOIN ihtiyacını ortadan kaldırarak okuma performansını artırır |
| **OTP HMAC + Static Secret** | OTP'yi düz metin yerine hash'li saklayarak veritabanı sızıntısına karşı koruma |
| **Refresh Token Rotasyonu** | Token çalınması durumunda eski token'ı geçersiz kılar |

---

## 🛠️ Kullanılan Teknolojiler

| Teknoloji | Amaç |
|---|---|
| [Go](https://go.dev/) | Yüksek performanslı, eşzamanlılık dostu sistem dili |
| [Chi v5](https://github.com/go-chi/chi) | Hafif, kompakt HTTP router |
| [PostgreSQL](https://www.postgresql.org/) | İlişkisel veritabanı |
| [pgx v5](https://github.com/jackc/pgx) | PostgreSQL sürücüsü (en hızlı Go pg driver) |
| [Redis](https://redis.io/) | In-memory cache & rate limiter |
| [JWT (golang-jwt)](https://github.com/golang-jwt/jwt) | JSON Web Token imzalama/doğrulama |
| [bcrypt](https://golang.org/x/crypto) | Şifre hash'leme |
| [Go SMTP](https://pkg.go.dev/net/smtp) | Gmail SMTP ile email gönderimi |
| [godotenv](https://github.com/joho/godotenv) | Çevre değişkenleri yönetimi |

---

## 🧪 Başlarken

### Gereksinimler

- Go 1.26+
- PostgreSQL 16+
- Redis 7+

### Kurulum

```bash
# Depoyu klonla
git clone https://github.com/aliicli/mega-forum-system.git
cd mega-forum-system

# Bağımlılıkları indir
go mod download

# .env dosyasını yapılandır (bkz: Konfigürasyon)
# Projeyi çalıştır
go run .
```

Server varsayılan olarak **`http://localhost:8080`** adresinde ayağa kalkar.

---

## ⚙️ Konfigürasyon

`.env` dosyası ile yapılandırılır:

```env
DB_URL=postgres://kullanici:sifre@localhost:5432/megaforum?sslmode=disable
JWT_SECRET=guclu-bir-jwt-imza-anahtari
PASSWORD_SMTP=gmail-smtp-uygulama-sifresi
OTP_SECRET=otp-hmac-anahtari
SENDER=ornek@gmail.com
```

| Değişken | Açıklama |
|---|---|
| `DB_URL` | PostgreSQL bağlantı URI'si |
| `JWT_SECRET` | JWT token imzalama anahtarı |
| `PASSWORD_SMTP` | Gmail SMTP uygulama şifresi |
| `OTP_SECRET` | OTP HMAC-SHA256 gizli anahtarı |
| `SENDER` | Email gönderimi için kullanılacak adres |

> **Not:** Veritabanı tabloları uygulama ilk çalıştığında otomatik oluşturulur.

---

## 📡 API Dokümantasyonu

Tüm endpoint'ler `/api/v1` prefix'i altında sunulur.

### 🔑 Kimlik Doğrulama

#### `POST /api/v1/auth/register`
Yeni kullanıcı kaydı oluşturur. Email adresine 6 haneli doğrulama kodu gönderir.

```
Rate Limit: 3 istek / dakika / IP
```

```json
{
  "username": "johndoe",
  "email": "john@example.com",
  "password": "GüçlüŞifre!123"
}
```

**Yanıt:** `201 Created`
```json
{
  "message": "Kayıt başarılı. Email adresinize doğrulama kodu gönderildi."
}
```

---

#### `POST /api/v1/auth/verify-email`
Email adresini 6 haneli OTP kodu ile doğrular.

```
Rate Limit: 3 istek / dakika / IP
Maksimum Deneme: 5
Kod Geçerlilik Süresi: 15 dakika
```

```json
{
  "email": "john@example.com",
  "code": "482916"
}
```

**Yanıt:** `200 OK`
```json
{
  "message": "Email doğrulandı."
}
```

---

#### `POST /api/v1/auth/login`
Kullanıcı adı ve şifre ile giriş yapar. JWT access token + refresh token döndürür.

```
Rate Limit: 5 istek / dakika / IP
```

```json
{
  "username": "johndoe",
  "password": "GüçlüŞifre!123"
}
```

**Yanıt:** `200 OK`
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "rt_7f8g3h2k1j9d..."
}
```

| Token | Geçerlilik |
|---|---|
| `access_token` | 15 dakika |
| `refresh_token` | 30 gün (her kullanımda yenilenir) |

---

#### `POST /api/v1/auth/refresh`
Refresh token ile yeni access token alır.

```
Rate Limit: 3 istek / dakika / IP
```

```json
{
  "refresh_token": "rt_7f8g3h2k1j9d..."
}
```

**Yanıt:** `200 OK`
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "rt_new_token..."
}
```

---

### 📝 Gönderiler

#### `GET /api/v1/posts`
En güncel 50 gönderiyi listeler.

```
Herhangi bir rate limit veya auth gerektirmez.
```

**Yanıt:** `200 OK`
```json
[
  {
    "id": 1,
    "username": "johndoe",
    "title": "Go ile REST API Geliştirme",
    "content": "Bu yazıda...",
    "created_at": "2026-07-26T14:30:00Z"
  }
]
```

---

#### `POST /api/v1/post`
Yeni bir gönderi oluşturur.

```
Auth: Bearer Token (gerekli)
Rate Limit: 3 istek / dakika / IP
```

```json
{
  "title": "Go ile REST API Geliştirme",
  "content": "Bu yazıda Go ile nasıl REST API yazılacağını anlatacağım..."
}
```

**Yanıt:** `201 Created`
```json
{
  "message": "Gönderi oluşturuldu.",
  "id": 1
}
```

---

#### `GET /api/v1/posts/{username}`
Belirli bir kullanıcıya ait tüm gönderileri listeler.

**Yanıt:** `200 OK`
```json
[
  {
    "id": 1,
    "username": "johndoe",
    "title": "Go ile REST API Geliştirme",
    "content": "Bu yazıda...",
    "created_at": "2026-07-26T14:30:00Z"
  }
]
```

---

#### `GET /api/v1/posts/search?q={query}`
Gönderi başlığı ve içeriğinde tam metin araması yapar.

```
Rate Limit: 10 istek / dakika / IP
```

**Örnek:** `GET /api/v1/posts/search?q=golang`

**Yanıt:** `200 OK`
```json
[
  {
    "id": 1,
    "username": "johndoe",
    "title": "Go ile REST API Geliştirme",
    "content": "Bu yazıda Go ile...",
    "created_at": "2026-07-26T14:30:00Z"
  }
]
```

---

### 💬 Yorumlar

#### `POST /api/v1/comment`
Bir gönderiye yorum ekler.

```
Auth: Bearer Token (gerekli)
Rate Limit: 3 istek / dakika / IP
```

```json
{
  "post_id": 1,
  "content": "Harika bir yazı, teşekkürler!"
}
```

**Yanıt:** `201 Created`
```json
{
  "message": "Yorum eklendi.",
  "id": 1
}
```

---

#### `GET /api/v1/post/{post_id}/comments`
Bir gönderideki tüm yorumları listeler.

**Yanıt:** `200 OK`
```json
[
  {
    "id": 1,
    "post_id": 1,
    "username": "janedoe",
    "content": "Harika bir yazı, teşekkürler!",
    "created_at": "2026-07-26T16:45:00Z"
  }
]
```

---

### ❤️ Beğeniler

#### `POST /api/v1/post/{post_id}/like`
Bir gönderiyi beğenir. Aynı kullanıcı aynı gönderiyi birden fazla beğenemez.

```
Auth: Bearer Token (gerekli)
Rate Limit: 5 istek / dakika / IP
```

**Yanıt:** `201 Created`
```json
{
  "message": "Beğenildi."
}
```

**Hata:** `409 Conflict`
```json
{
  "error": "Bu gönderiyi zaten beğendiniz."
}
```

---

#### `GET /api/v1/post/{post_id}/like`
Bir gönderinin beğeni listesini getirir.

```
Rate Limit: 10 istek / dakika / IP
```

**Yanıt:** `200 OK`
```json
[
  {
    "id": 1,
    "post_id": 1,
    "username": "janedoe",
    "created_at": "2026-07-26T17:00:00Z"
  }
]
```

---

### ❌ Hata Yanıtları

| HTTP Kodu | Anlamı |
|---|---|
| `400 Bad Request` | Geçersiz veya eksik alanlar |
| `401 Unauthorized` | Geçersiz/eksik JWT token |
| `404 Not Found` | Kaynak bulunamadı |
| `409 Conflict` | Çakışma (örn. zaten beğenilmiş) |
| `429 Too Many Requests` | Rate limit aşıldı (`Retry-After` header ile) |
| `500 Internal Server Error` | Sunucu hatası |

---

## 🗄️ Veritabanı Şeması

```sql
-- Kullanıcılar
USERS (
    id              BIGINT  PK  (GENERATED ALWAYS AS IDENTITY)
    username        TEXT    NOT NULL, UNIQUE
    email           TEXT    NOT NULL, UNIQUE
    password        TEXT    NOT NULL  -- bcrypt hash
    email_verified  BOOLEAN NOT NULL DEFAULT FALSE
)

-- Email doğrulama kodları
EMAIL_VERIFICATIONS (
    id          BIGINT  PK
    user_id     BIGINT  FK → USERS(id) ON DELETE CASCADE
    code_hash   TEXT    NOT NULL  -- HMAC-SHA256(code)
    expires_at  TIMESTAMP NOT NULL  -- 15 dk
    attempts    INTEGER NOT NULL DEFAULT 0  -- max 5
)

-- Refresh token'lar
REFRESH_TOKENS (
    id          BIGINT  PK
    user_id     BIGINT  FK → USERS(id) ON DELETE CASCADE
    token       TEXT    NOT NULL  -- SHA256(raw_token)
    expires_at  TIMESTAMP NOT NULL  -- 30 gün
)

-- Gönderiler
POSTS (
    id          BIGINT  PK
    user_id     BIGINT  FK → USERS(id) ON DELETE CASCADE
    username    TEXT    NOT NULL  -- denormalize
    title       TEXT    NOT NULL
    content     TEXT    NOT NULL
    created_at  TIMESTAMP NOT NULL DEFAULT NOW()
)

-- Yorumlar
COMMENTS (
    id          BIGINT  PK
    post_id     BIGINT  FK → POSTS(id) ON DELETE CASCADE
    user_id     BIGINT  FK → USERS(id) ON DELETE CASCADE
    username    TEXT    NOT NULL  -- denormalize
    content     TEXT    NOT NULL
    created_at  TIMESTAMP NOT NULL DEFAULT NOW()
)

-- Beğeniler
LIKES (
    id          BIGSERIAL PK
    post_id     BIGINT  FK → POSTS(id) ON DELETE CASCADE
    user_id     BIGINT  FK → USERS(id) ON DELETE CASCADE
    username    TEXT    NOT NULL  -- denormalize
    created_at  TIMESTAMP NOT NULL DEFAULT NOW()
    UNIQUE(post_id, user_id)
)
```

Tüm foreign key'ler `ON DELETE CASCADE` ile tanımlıdır.

---

## 🔒 Güvenlik

| Katman | Önlem |
|---|---|
| **Şifre Saklama** | Bcrypt (maliyet faktörü: varsayılan) |
| **JWT** | HMAC-SHA256 imzalı, 15 dk access + 30 gün refresh |
| **Refresh Token** | SHA-256 hash'li saklama, rotasyonlu |
| **OTP Kodu** | HMAC-SHA256 hash'li, 15 dk geçerli, 5 deneme limiti |
| **Rate Limiting** | Redis tabanlı, endpoint bazlı, IP kovalı |
| **SQL Injection** | `pgx` parametreize sorgular ile önlenmiş |
| **Email Doğrulama Zorunluluğu** | Doğrulanmamış email ile giriş engellenir |

---

## ⏱️ Rate Limiting

Tüm rate limit'ler **Redis** üzerinde **sliding window** algoritması ile çalışır. Limit aşıldığında `429 Too Many Requests` dönülür ve `Retry-After` header'ı ile bekleme süresi belirtilir.

| Endpoint | Limit | Açıklama |
|---|---|---|
| `POST /auth/register` | 3/dk | Kötü niyetli kayıt girişimlerini engeller |
| `POST /auth/login` | 5/dk | Brute-force saldırılarına karşı koruma |
| `POST /auth/verify-email` | 3/dk | OTP deneme sınırlaması |
| `POST /auth/refresh` | 3/dk | Token yenileme limiti |
| `POST /post` | 3/dk | Spam gönderi engelleme |
| `POST /comment` | 3/dk | Spam yorum engelleme |
| `GET /posts/search` | 10/dk | Arama abuse koruması |
| `POST /post/{id}/like` | 5/dk | Beğeni spam koruması |
| `GET /post/{id}/like` | 10/dk | Beğeni sorgulama limiti |

---

## 📁 Proje Yapısı

```
mega-forum-system/
├── .env                  # Çevre değişkenleri
├── go.mod                # Go modül tanımı
├── go.sum                # Bağımlılık checksum'ları
├── main.go               # Giriş noktası, server kurulumu, route'lar
├── handlers.go           # Tüm HTTP handler fonksiyonları
├── models.go             # Request/response struct'ları
├── databases.go          # PostgreSQL + Redis bağlantısı, tablo oluşturma
├── middleware.go          # JWT auth middleware + Redis rate limiter
├── helpers.go            # OTP üreteci, SMTP email gönderici, token üreteci
├── template/
│   └── email.html        # HTML email doğrulama şablonu (Türkçe, responsive)
└── README.md             # Bu dosya
```

**7 Go kaynak dosyası** + **1 HTML template** ile sade ve anlaşılır bir mimari.

---

## 🧭 Yol Haritası

- [ ] **Beğeni Kaldırma** — Unlike endpoint'i eklenmesi
- [ ] **Sayfalama** — Tüm liste endpoint'lerine cursor/offset tabanlı pagination
- [ ] **Kullanıcı Profili** — Kullanıcı adı, email güncelleme, şifre değiştirme
- [ ] **Admin Paneli** — Kullanıcı/gönderi/yorum yönetimi
- [ ] **Push Notification** — Yeni yorum/beğeni bildirimleri
- [ ] **Docker Desteği** — Dockerfile + docker-compose.yml
- [ ] **Testler** — Unit test + entegrasyon testleri
- [ ] **Swagger/OpenAPI** — Otomatik API dokümantasyonu
- [ ] **HTTPS** — TLS/SSL desteği
- [ ] **S3/R2 Medya Yükleme** — Görsel/dosya ekleme desteği

---

## 📄 Lisans

Bu proje **MIT** lisansı ile lisanslanmıştır.

---

<p align="center">
  <strong>Mega Forum Sistemi</strong> — Modern forumlar için güçlü backend altyapısı
  <br />
  <a href="https://github.com/aliicli/mega-forum-system">GitHub</a>
</p>
