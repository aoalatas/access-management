# Erişim Yönetimi İhtiyaçlarının Belirlenmesi - Araştırma Dokümanı

> **Sprint Task:** Mikroservis mimarisinde erişim yönetimi (authentication, authorization, token management) stratejisinin belirlenmesi.
>
> **Amaç:** Servisler arası ve client-servis erişiminin nasıl yönetileceğinin belirlenmesi ve mimari kararlara temel oluşturacak bir doküman ortaya çıkarmak.

---

## 1. Problem Tanımı ve Kapsam

### 1.1. Temel Sorular

- Client → servis ve servis → servis erişiminde:
  - Kimler, hangi kanallardan erişecek? (web, mobile, backend-to-backend, batch jobs vs.)
  - Hangi tip client'lar var? (public SPA, mobile, machine-to-machine, 3rd party integrasyonlar)
- Mikroservisler birbirini nasıl tüketecek?
  - Sadece internal network mü, yoksa dışarı açık API'lar da var mı?
  - Sync (REST/gRPC) ve async (Kafka, message bus) iletişim senaryoları neler?
- Token nereye kadar gidecek?
  - Gateway'de terminate mi edilecek?
  - Her mikroservise token forward edilecek mi, yoksa internal token/claim mi üretilecek?
- Mikroservisler token doğrulayacak mı?
  - Her servis kendi token doğrulamasını mı yapar, centralized component mi olur (API Gateway / sidecar)?
- Her mikroservis "context" oluşturacak mı?
  - Request context'te hangi bilgiler standart olacak? (`userId`, `tenantId`, `roles`, `permissions`, `correlationId` vs.)
  - Bu context loglama, audit ve authorization'da nasıl kullanılacak?

### 1.2. Yapılacaklar

- [ ] Mevcut mimari / planlanan mimariyi kabaca çizmek (context diagram).
- [ ] Erişim yapan aktörlerin listesini çıkarmak.
- [ ] Araştırmanın sınırlarını tanımlamak (örn. sadece HTTP API'ler mi, event-driven flow'lar da dahil mi?).

---

## 2. Mevcut Gereksinimlerin Toplanması

### 2.1. Güvenlik Seviyeleri

- Hangi servisler high-risk (ör. ödeme, PII barındıran), hangileri low-risk?
- Compliance gereksinimleri var mı? (KVKK, PCI-DSS, ISO 27001 vs.)

### 2.2. Performans ve Latency Beklentileri

- AuthZ/AuthN mekanizması ne kadar ek latency tolere edebilir?
- Her request'te external call yapmaya izin var mı? (ör. PDP/OPA call)

### 2.3. Operasyonel Gereksinimler

- Merkezi konfigürasyon, centralized policy management isteniyor mu?
- Rollout/rollback kolaylığı, backward compatibility ihtiyaçları.

### 2.4. Geliştirici Deneyimi

- Takımlar için auth/authorization ne kadar "self-service" olmalı?
- Mümkün olduğunca framework/library ile mi halledilsin, yoksa platform (gateway/sidecar) mı yapsın?

---

## 3. Authentication (Kimlik Doğrulama) Stratejisi

### 3.1. Client → API (Public veya Semi-Public Endpoint'ler)

#### Araştırılacak Konular

- **Kullanılacak protokol ve standard:**
  - OAuth2.1 / OIDC mi?
  - Sadece JWT access token ile custom çözüm mü?
- **Client tiplerine göre auth yöntemi** (Authentication Matrix çıktısına girdi):
  - **Public SPA (Single Page App):** PKCE, implicit yok, refresh token kullanım politikası.
  - **Mobile app:** PKCE + refresh token, device binding var mı?
  - **Backend-to-backend (machine-to-machine):** Client Credentials, mTLS, static API key kullanılacak mı?
  - **3rd party integrasyon:** OAuth2 authorization code flow, API Keys, IP whitelisting ihtiyacı.
- **Token provider:**
  - Harici IdP (Keycloak, Auth0, Cognito vs.) mi, internal IdP mi?
  - Key rotation, JWKS endpoint, discovery endpoint kullanımı.

#### Çıktı

> `client type → auth method → token type` matrisinin taslağı.

| Client Tipi | Auth Method | Token Tipi | Notlar |
|---|---|---|---|
| Public SPA | OAuth2 + PKCE | JWT Access Token | Refresh token politikası belirlenecek |
| Mobile App | OAuth2 + PKCE | JWT Access Token + Refresh Token | Device binding değerlendirilecek |
| Machine-to-Machine | Client Credentials / mTLS | JWT Access Token | Static API key değerlendirilecek |
| 3rd Party | OAuth2 Auth Code Flow | JWT Access Token | IP whitelisting opsiyonel |

### 3.2. Service → Service (Internal Communication)

#### Araştırılacak Konular

- **mTLS kullanımı:**
  - Sadece north-south trafiğinde mi (client → gateway), yoksa east-west (service → service) için de mi?
  - mTLS termination noktaları (LB, API gateway, service mesh, pod).
- **Service identity:**
  - Her servisin kendi "service account"ı olacak mı?
  - SPIFFE/SPIRE, service mesh (Istio/Linkerd) ile identity çözümü düşünülecek mi?
- **Hangi senaryoda mTLS, hangi senaryoda JWT/OAuth2 token?**
  - Sadece mTLS (service → service trust) + internal authorization.
  - mTLS + short-lived JWT (service identity'i token içinde taşımak).
- **Non-HTTP protokoller:**
  - gRPC, messaging (Kafka, RabbitMQ vs.) için authentication nasıl olacak?
  - SASL/OAuthBearer, mTLS, client cert vs.

#### Çıktı

> Service-to-service auth strateji tablosu (protokol → auth method).

| Protokol | Auth Method | Identity Kaynağı | Notlar |
|---|---|---|---|
| REST (HTTP) | | | |
| gRPC | | | |
| Kafka | | | |
| RabbitMQ | | | |

---

## 4. Authorization (Yetkilendirme) Modeli

### 4.1. Model Seçimi: RBAC vs ABAC vs Policy-Based

#### Araştırılacak Sorular

- **RBAC:**
  - Role'ler hangi seviyede tutulacak? (global, tenant-specific, service-specific)
  - Role explosion riski var mı?
- **ABAC:**
  - Hangi attribute'lar mevcut? (user attributes, resource attributes, environment attributes).
  - Policy tanımlama karmaşıklığı ve yönetilebilirliği.
- **Policy-based (ör: OPA, OpenFGA, Cedar vs.):**
  - Merkezi PDP (Policy Decision Point) mi, embedded (library/sidecar) mi?
  - Performans/latency etkisi, caching stratejisi.
- **Hibrit modeller:**
  - "Role + permission + attribute" kombinasyonuna ihtiyaç var mı?
  - Basit senaryoları RBAC ile, karmaşıkları ABAC/policy ile çözmek mümkün mü?

### 4.2. Enforcement Point'ler

- **Yetkilendirme kararı nerede verilecek:**
  - API Gateway'de coarse-grained checks (örn: endpoint bazlı).
  - Mikroservis içinde fine-grained checks (örn: "sadece kendi datamı görebilirim").
  - Domain layer'de policy enforcement.
- **Merkezi vs dağıtık policy:**
  - Policy'ler tek bir yerde tutulup (central policy store), servislere push/cached mi edilecek?
  - Policy değişikliklerinin anında etkili olması için mekanizma (event, polling vs.)?

#### Çıktı

> Seçilecek model(ler) ve kullanım alanları (hangi senaryoda hangi model).

| Senaryo | Model | Enforcement Point | Notlar |
|---|---|---|---|
| Endpoint erişim kontrolü | | | |
| Kaynak bazlı yetkilendirme | | | |
| Tenant izolasyonu | | | |
| Admin operasyonları | | | |

---

## 5. Token Stratejisi ve Yaşam Döngüsü

### 5.1. Token Tipi ve Yapısı

- **Access token:**
  - JWT mi opaque token mı?
  - İçerilecek claim'ler:

    ```json
    {
      "sub": "userId veya serviceId",
      "iss": "token issuer",
      "aud": "hedef audience",
      "exp": "expiry timestamp",
      "iat": "issued at",
      "jti": "unique token id",
      "tenantId": "tenant identifier",
      "roles": ["role1", "role2"],
      "permissions": ["resource:action:scope"],
      "scopes": ["openid", "profile"],
      "correlationId": "trace/correlation id"
    }
    ```

  - Token boyutu / HTTP header limitleri.
- **Refresh token:**
  - Hangi client tiplerinde verilecek?
  - Rotating refresh token kullanımı.
- **Internal token:**
  - Gateway, dış token'ı doğrulayıp microservisler arası kısa ömürlü internal token üretir mi?
  - "Downstream token exchange" (OAuth2 Token Exchange, RFC 8693) ihtiyacı var mı?

### 5.2. Token TTL ve Refresh Mekanizması

| Token Tipi | Client Tipi | TTL | Refresh | Notlar |
|---|---|---|---|---|
| Access Token | Public SPA | | | |
| Access Token | Mobile | | | |
| Access Token | M2M | | | |
| Refresh Token | Public SPA | | | |
| Refresh Token | Mobile | | | |
| Internal Token | Service-to-Service | | | |

- **Sliding session vs fixed session:**
  - Kullanıcı aktif kaldıkça session uzatılacak mı?
- **Refresh token kullanımı:**
  - Hangi durumlarda refresh token verilmeyecek? (ör: public SPA? güvenlik politikası)
  - Revocation veya theft tespiti durumunda behavior.

### 5.3. Token Revocation ve Blacklist/Whitelist

- **Revocation senaryoları:**
  - Kullanıcı logout olduğunda.
  - Hesap disable olduğunda.
  - Credential reset (password reset, MFA reset) sonrası.
- **Teknik mekanizma:**
  - JWT için centralized revocation list/cache mi?
  - Short-lived access token + refresh token revocation yaklaşımı.
  - `jti` bazlı blacklist mi, `tokenVersion` claim ile invalidation mı?

### 5.4. Token Yaşam Döngüsü Diyagramı

```
┌──────────┐    ┌───────────┐    ┌──────────────┐    ┌───────────────┐
│  Issue    │───▶│   Use     │───▶│   Refresh    │───▶│  Revoke /     │
│  Token    │    │   Token   │    │   Token      │    │  Expire       │
└──────────┘    └───────────┘    └──────────────┘    └───────────────┘
     │                │                  │                    │
     ▼                ▼                  ▼                    ▼
  IdP/Auth         Gateway/           Refresh              Blacklist/
  Server           Service            Endpoint             Revocation
                   Validate                                Cache
```

---

## 6. API Gateway / Service Mesh Kararları

### 6.1. Merkezi Gateway mi, Domain Gateway mi?

| Yaklaşım | Avantajlar | Dezavantajlar |
|---|---|---|
| **Merkezi Gateway** | Tek entry point, centralized auth, rate limiting, logging | Tekil hata noktası, domain ownership'ten uzak |
| **Domain Gateway** | Her domain kendi gateway'i, otonom takımlar | Cross-cutting concern'lerin dağılması |
| **Hybrid (Edge + Domain)** | Global concerns edge'de, domain concerns domain'de | Operasyonel karmaşıklık artabilir |

### 6.2. Gateway'de Hangi Security Özellikleri Olacak?

- [ ] **Authentication offloading:** Gateway token doğrulayıp, downstream'e sadece claims/context header'ları mı geçecek?
- [ ] **Authorization:** Coarse-grained vs fine-grained.
- [ ] **Rate limiting / throttling:** User, tenant, clientId, IP bazlı rate limiting.
- [ ] **Request/response transformation:** Sensitive header/body filter'lama.
- [ ] **Circuit breaking, retries vs.** (servis güvenilirliği ile bağlantısı).

#### Çıktı

> Gateway mimari diyagramı ve gateway'de uygulanacak security responsibility matrix.

---

## 7. Multi-Tenancy ve Tenant İzolasyonu

### 7.1. Tenant Isolation Modeli

| Model | Açıklama | Avantaj | Dezavantaj |
|---|---|---|---|
| Database per tenant | Her tenant için ayrı DB | Tam izolasyon | Yönetim maliyeti yüksek |
| Schema per tenant | Aynı DB farklı schema | İyi izolasyon | Migration karmaşıklığı |
| Row-level multi-tenant | Aynı tablo, tenant_id filtre | Maliyet düşük | Veri sızıntısı riski |

### 7.2. Tenant Context Propagation

- `tenantId` nereden geliyor, token içinde mi, header'da mı?
- Tüm mikroservisler için zorunlu context alanları neler?

### 7.3. Cross-Tenant Erişim

- Admin / support rolleri için "multi-tenant visibility" nasıl yönetilecek?
- Audit log'larda tenant bilgisi nasıl tutulacak?

### 7.4. Tenant Bazlı Rate Limiting & Quotas

- Tenant bazlı rate limiting / usage quota.

### 7.5. Data Residency / Regulatory

- Tenant bazlı veri lokasyonu zorunluluğu var mı (farklı region/cluster)?

#### Çıktı

> Tenant context standardı (zorunlu claim/headers) ve tenant isolation kararı (logical/physical).

---

## 8. Permission ve Naming Konvansiyonları

### 8.1. Permission Model

Format: `resource:action:scope`

| Örnek | Resource | Action | Scope | Açıklama |
|---|---|---|---|---|
| `order:read:self` | order | read | self | Kendi siparişlerini görüntüleme |
| `order:read:tenant` | order | read | tenant | Tenant'taki tüm siparişleri görüntüleme |
| `user:update:self` | user | update | self | Kendi profilini güncelleme |
| `user:update:any` | user | update | any | Herhangi bir kullanıcıyı güncelleme |

### 8.2. Naming Konvansiyonu

- **Resource isimlendirme:** kebab-case / snake_case / domain prefix → karar verilecek.
- **Action listesi standardizasyonu:**
  - `read`, `create`, `update`, `delete`, `list`, `export`, `approve`, `reject` vs.
- **Scope tanımı:**
  - `self`, `tenant`, `all`, `delegated` vs.

### 8.3. Permission Saklama Stratejisi

- Token içinde mi, external store'da mı?
- Çok sayıda permission varsa token şişmesi sorunu.
- Sadece roles token'da, permission'lar central store'dan mı resolve edilecek?

#### Çıktı

> Permission naming guideline dokümanı + örnek permission listesi.

---

## 9. Security Zones ve Network Segmentation

### 9.1. Security Zone Tanımları

| Zone | Açıklama | Auth Gereksinimi | Örnek |
|---|---|---|---|
| **Public** | Anonymous veya public client erişimi | Yok veya API key | Health check, public content |
| **Authenticated** | Login gerektiren alanlar | JWT / OAuth2 | Kullanıcı dashboard |
| **Privileged** | Yüksek riskli operasyonlar | JWT + MFA / Step-up auth | Ödeme, PII erişimi, admin panel |
| **Internal** | Sadece service-to-service | mTLS / internal token | Inter-service communication |

### 9.2. Zone Bazlı Kurallar

- Hangi zone'da hangi authentication zorunlu? (örn. privileged → MFA zorunlu mu?)
- Network-level kontroller (security groups, firewall rules).

### 9.3. Deployment Topology

- DMZ, internal network, admin network ayrımı var mı?
- Service mesh veya Kubernetes namespace'leri zone'lara göre ayrılacak mı?

#### Çıktı

> Security zones diyagramı ve her zone için required controls listesi.

---

## 10. Rate Limiting ve Abuse Protection

### 10.1. Rate Limiting Dimensions

| Dimension | Açıklama | Örnek |
|---|---|---|
| IP | IP adresine göre limit | 100 req/min |
| userId | Kullanıcı bazlı limit | 500 req/min |
| clientId | Uygulama bazlı limit | 1000 req/min |
| tenantId | Tenant bazlı limit | 5000 req/min |
| endpoint | Endpoint bazlı limit | Kritik endpoint'ler için daha düşük |

### 10.2. Global vs Service-Specific Limitler

- Bazı kritik endpoint'ler için daha sıkı limit.

### 10.3. Burst ve Sustained Limit Ayarları

- Örn. `X requests / second` (burst) + `Y requests / minute` (sustained).

### 10.4. Throttling Response Stratejisi

- HTTP 429 formatı, `Retry-After` header kullanımı.

### 10.5. DDoS / Bot Protection

- WAF entegrasyonu.
- Captcha, bot detection vs. gerekli mi?

#### Çıktı

> Rate limiting policy dokümanı ve konfigürasyon örnekleri.

---

## 11. Logging, Auditing ve Observability

### 11.1. Loglanacak Bilgiler

| Alan | Açıklama | Zorunlu? |
|---|---|---|
| `userId` | İşlemi yapan kullanıcı | Evet |
| `tenantId` | Tenant bilgisi | Evet |
| `clientId` | Client uygulaması | Evet |
| `requestId` / `correlationId` | İstek takip ID'si | Evet |
| `permission` | Kontrol edilen yetki | Evet |
| `result` | allowed / denied | Evet |

### 11.2. Audit Log Gereksinimleri

- Hangi aksiyonlar audit'lenmeli?
  - Login, logout, role change, permission grant/revoke, critical domain actions.

### 11.3. PII Loglama Kuralları

- Masking, token bilgilerini loglamama, sadece `jti` gibi id'leri loglama.

### 11.4. Tracing

- TraceId propagasyonu (W3C Trace Context vs.) ve auth context ile korelasyon.

---

## 12. Non-Functional ve Operasyonel Konular

### 12.1. Key Management

- Signing/encryption keys nerede tutulacak? (HSM, KMS, Vault).
- Key rotation stratejisi ve sıklığı.

### 12.2. Incident Response

- Token theft, credential leakage durumunda atılacak adımlar.
- Hangi config/policy değişiklikleri "acil" olarak propagate edilmeli?

### 12.3. Backward Compatibility

- Eski token formatından yeni formata geçiş planı (varsa).
- Versioning stratejisi.

### 12.4. Local Development ve Test Ortamları

- Mock IdP, test token generation, developer experience.
- Lokal ortamda auth/authz'ın nasıl bypass/simüle edileceği.

---

## 13. Özet Kararlar ve Açık Kalan Konular

### Karar Tablosu

| # | Konu | Karar | Alternatifler | Durum |
|---|---|---|---|---|
| 1 | Authentication Protokolü | | OAuth2.1/OIDC, Custom JWT | ⬜ Bekliyor |
| 2 | Authorization Modeli | | RBAC, ABAC, Policy-based, Hibrit | ⬜ Bekliyor |
| 3 | Token Tipi | | JWT, Opaque Token | ⬜ Bekliyor |
| 4 | Token TTL Stratejisi | | Short-lived + Refresh, Long-lived | ⬜ Bekliyor |
| 5 | API Gateway Modeli | | Merkezi, Domain, Hybrid | ⬜ Bekliyor |
| 6 | Multi-Tenancy İzolasyonu | | DB per tenant, Schema, Row-level | ⬜ Bekliyor |
| 7 | Service-to-Service Auth | | mTLS, JWT, mTLS + JWT | ⬜ Bekliyor |
| 8 | Policy Engine | | OPA, OpenFGA, Cedar, Custom | ⬜ Bekliyor |
| 9 | IdP Seçimi | | Keycloak, Auth0, Cognito, Custom | ⬜ Bekliyor |
| 10 | Rate Limiting Stratejisi | | Gateway-level, Service-level, Hybrid | ⬜ Bekliyor |

### Açık Kalan Konular

- [ ] ...
- [ ] ...
- [ ] ...

---

## Referanslar

- [OAuth 2.1 Draft](https://oauth.net/2.1/)
- [OpenID Connect](https://openid.net/connect/)
- [RFC 8693 - OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693)
- [SPIFFE / SPIRE](https://spiffe.io/)
- [Open Policy Agent (OPA)](https://www.openpolicyagent.org/)
- [OpenFGA](https://openfga.dev/)
- [W3C Trace Context](https://www.w3.org/TR/trace-context/)