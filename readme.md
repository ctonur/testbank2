# OpenShift Security Foundations — Day 1 Instructor Guide

> **Süre:** 09:00 – 16:00
> **Seviye:** Başlangıç / Orta
> **Ön Koşul:** Linux temelleri, Docker, temel Kubernetes bilgisi

---

## Günün Programı

| Saat | Konu | Klasör |
|------|------|--------|
| 09:00–09:45 | OpenShift Architecture & Security Model | `01-architecture-security-model/` |
| 10:00–10:45 | Container Security & SCC Deep Dive | `02-container-security-scc/` |
| 11:00–11:45 | RBAC Fundamentals | `03-rbac-fundamentals/` |
| 12:00–13:00 | **Öğle Arası** | — |
| 13:00–13:45 | Secret Management | `04-secret-management/` |
| 14:00–14:45 | Azure Key Vault Integration | `05-azure-key-vault/` |
| 15:00–16:00 | Hands-on Labs | `06-hands-on-labs/` |

---

## 09:00–09:45 · OpenShift Architecture & Security Model

### 09:00–09:10 · Giriş: Kubernetes vs OpenShift Güvenlik Modeli

**Açılış cümlesi (tahtaya yaz):**

> *"Kubernetes ve OpenShift arasındaki en büyük fark güvenliktir.
> Kubernetes kurulduğu anda genellikle birçok şeyi serbest bırakır.
> OpenShift ise güvenliği **varsayılan olarak aktif** getirir."*

**Tahtaya çiz — Mimari Karşılaştırma:**

```
Kubernetes                     OpenShift
│                              │
├── API Server                 ├── Kubernetes (core)
├── Scheduler                  ├── SCC (Security Context Constraints)
├── Controller Manager         ├── OAuth Server (kimlik doğrulama)
└── Worker Nodes               ├── Routes (HTTP/HTTPS ingress)
                               ├── Operators (uygulama yönetimi)
                               ├── Image Registry (dahili)
                               └── Security Defaults (varsayılan kapalı)
```

**Öğrencilere Sor:**

> "Kubernetes'te root container çalıştırabilir miyiz?"

- **Cevap:** Vanilla Kubernetes'te genellikle **evet** — özel bir politika yapılandırılmamışsa.

> "Peki OpenShift'te?"

- **Cevap:** **Hayır.** `restricted-v2` SCC ile root container varsayılan olarak reddedilir.

---

### Demo 1 · Root Container Reddi

**Namespace oluştur:**

```bash
oc new-project security-demo
```

**YAML:** [01-architecture-security-model/01-root-pod-rejected.yaml](01-architecture-security-model/01-root-pod-rejected.yaml)

```bash
oc apply -f 01-architecture-security-model/01-root-pod-rejected.yaml
```

**Beklenen çıktı:**

```
Error from server (Forbidden): error when creating "01-root-pod-rejected.yaml":
pods "root-pod-rejected" is forbidden: unable to validate against any security
context constraint: [spec.containers[0].securityContext.runAsUser: Invalid
value: 0: UID 0 is not allowed]
```

**Anlat — API Server akışını tahtaya çiz:**

```
Developer
    │
    │  oc apply -f pod.yaml
    ▼
API Server (kube-apiserver)
    │
    ▼
Admission Controller
    │
    ▼
SCC Validation
    │
    ├── PASS ──► Scheduler ──► Worker Node ──► Pod Running ✅
    │
    └── FAIL ──► Forbidden ❌ (403/422)
```

**Olayları göster:**

```bash
oc get events --sort-by=.metadata.creationTimestamp -n security-demo
```

**Çıktı:**

```
LAST SEEN   TYPE      REASON        OBJECT               MESSAGE
10s         Warning   FailedCreate  replicationcontroller/...
            unable to validate against any SCC: [...]
```

---

### 09:10–09:25 · SCC Derinlemesine

**SCC Nedir?**

| Linux Kontrolü | SCC Karşılığı |
|----------------|---------------|
| UID / GID | `runAsUser`, `fsGroup` |
| Linux Capabilities | `allowedCapabilities`, `requiredDropCapabilities` |
| SELinux | `seLinuxContext` |
| Seccomp | `seccompProfiles` |
| Host erişimi | `allowHostNetwork`, `allowHostPID`, `allowHostPorts` |

**SCC'leri Listele:**

```bash
oc get scc
```

**Çıktı:**

```
NAME                 PRIV    CAPS              SELINUX    RUNASUSER      FSGROUP
anyuid               false   <no value>        MustRunAs  RunAsAny       RunAsAny
hostaccess           false   <no value>        MustRunAs  MustRunAsRange RunAsAny
hostnetwork          false   <no value>        MustRunAs  MustRunAsRange MustRunAs
nonroot              false   <no value>        MustRunAs  MustRunAsNonRoot RunAsAny
nonroot-v2           false   NET_BIND_SERVICE  MustRunAs  MustRunAsNonRoot RunAsAny
privileged           true    [*]               RunAsAny   RunAsAny       RunAsAny
restricted           false   <no value>        MustRunAs  MustRunAsRange MustRunAs
restricted-v2        false   NET_BIND_SERVICE  MustRunAs  MustRunAsRange MustRunAs
```

**restricted-v2 Detay:**

```bash
oc describe scc restricted-v2
```

**Özellikle göster:**

```
Allow Privileged:               false
Allow Privilege Escalation:     false
Default Add Capabilities:       NET_BIND_SERVICE
Required Drop Capabilities:     ALL
Allowed Capabilities:           NET_BIND_SERVICE

Run As User Strategy:           MustRunAsRange
  UID Range Min:                <namespace'ten alınır>
  UID Range Max:                <namespace'ten alınır>
```

**Öğrencilere Sor:**

> "Bu SCC root kullanıcıya izin veriyor mu?"

```bash
oc describe scc restricted-v2 | grep "Run As User"
```

**Çıktı:**

```
Run As User Strategy: MustRunAsRange
```

**Namespace UID Range'ini Göster:**

```bash
oc describe namespace security-demo | grep uid-range
```

**Çıktı:**

```
openshift.io/sa.scc.uid-range=1000700000/10000
```

> "Bu namespace'teki tüm pod'lar **1000700000 – 1000709999** arasında bir UID ile çalışmak zorunda. UID 0 (root) bu aralıkta yok."

---

### Demo 2 · Non-Root Pod (Çalışan Örnek)

**YAML:** [01-architecture-security-model/02-non-root-pod.yaml](01-architecture-security-model/02-non-root-pod.yaml)

```bash
oc apply -f 01-architecture-security-model/02-non-root-pod.yaml
oc get pods -n security-demo
```

**Beklenen:**

```
NAME           READY   STATUS    RESTARTS   AGE
non-root-pod   1/1     Running   0          10s
```

**Hangi SCC kullanıldı?**

```bash
oc get pod non-root-pod \
  -o jsonpath='{.metadata.annotations.openshift\.io/scc}' \
  -n security-demo
```

**Çıktı:** `restricted-v2`

**Öğrencilere Sor:**

> "Neden bu çalıştı?"

**Cevap:** `restricted-v2` şartlarına uydu — non-root UID, privilege escalation yok, capabilities DROP ALL.

---

### 09:25–09:45 · SCC Assignment Lab

**Senaryo:** Bazı eski uygulamalar root olarak çalışmak zorunda.
Tüm namespace'e izin vermek yerine **sadece belirli bir Service Account'a** istisna veriyoruz.

**Adım 1 — Service Account Oluştur:**

```bash
oc apply -f 01-architecture-security-model/03-demo-service-account.yaml
```

**Adım 2 — Mevcut Yetkiyi Kontrol Et:**

```bash
oc adm policy who-can use scc anyuid
```

> demo-sa henüz listede yok.

**Adım 3 — anyuid SCC Ver:**

```bash
oc adm policy add-scc-to-user anyuid \
  -z demo-sa \
  -n security-demo
```

**Adım 4 — Tekrar Kontrol:**

```bash
oc adm policy who-can use scc anyuid
```

> demo-sa artık listede görünüyor.

**Adım 5 — Root Pod Deploy Et:**

**YAML:** [01-architecture-security-model/04-root-pod-with-anyuid.yaml](01-architecture-security-model/04-root-pod-with-anyuid.yaml)

```bash
oc apply -f 01-architecture-security-model/04-root-pod-with-anyuid.yaml
oc get pods -n security-demo
```

**Adım 6 — Kullanılan SCC:**

```bash
oc get pod root-pod-with-sa \
  -o jsonpath='{.metadata.annotations.openshift\.io/scc}' \
  -n security-demo
```

**Çıktı:** `anyuid`

**Ders:**

> *"Biz sadece `demo-sa` service account'una istisna verdik.
> Namespace'teki diğer pod'lar hâlâ `restricted-v2` ile çalışıyor.
> Bu **Least Privilege** prensibinin ta kendisidir."*

**UI'da Göster:**

```
Administrator → User Management → Security Context Constraints
→ restricted-v2 / anyuid / privileged
```

---

## 10:00–10:45 · Container Security & SCC Deep Dive

### 10:00–10:15 · SecurityContext vs SCC

**Fark Nedir?**

| | SecurityContext | SCC |
|--|--|--|
| **Nerede?** | Pod / Container YAML | Cluster-level policy |
| **Kim yazar?** | Developer | Platform Admin |
| **Amacı** | İstek (request) | Kısıtlama (constraint) |
| **Örnek** | `runAsUser: 1001` | `MustRunAsRange: 1000–65535` |
| **Kazanan?** | — | **SCC her zaman kazanır** |

**Tahtaya çiz:**

```
Developer                          Platform Admin
    │                                    │
    │  securityContext                   │  SCC (cluster policy)
    │  runAsUser: 1001      vs           │  MustRunAsRange
    │                                    │
    └──────────────► API Server ◄────────┘
                          │
                          ▼
                   SCC Validation
                (SCC > SecurityContext)
```

**Demo:**

```bash
oc apply -f 02-container-security-scc/02-pod-with-securitycontext.yaml -n security-demo
oc get pod secure-pod -n security-demo
oc get pod secure-pod -o jsonpath='{.metadata.annotations.openshift\.io/scc}' -n security-demo
```

**YAML:** [02-container-security-scc/02-pod-with-securitycontext.yaml](02-container-security-scc/02-pod-with-securitycontext.yaml)

---

### 10:15–10:30 · Linux Capabilities

**Capabilities Nedir?**

Root yetkisi parçalara bölünmüş halidir. Root olmak yerine sadece gerekli parçayı ver.

| Capability | Ne Yapar | Risk Seviyesi |
|---|---|---|
| `CAP_NET_ADMIN` | Network interface yönetimi | 🔴 Yüksek |
| `CAP_SYS_ADMIN` | mount, hostname değişikliği | 🔴 Çok Yüksek (neredeyse root) |
| `CAP_DAC_OVERRIDE` | File permission bypass | 🔴 Yüksek |
| `CAP_SETUID` | UID değiştirme (privilege escalation) | 🔴 Yüksek |
| `CAP_NET_BIND_SERVICE` | Port 1024 altına bind olma | 🟡 Düşük |
| `CAP_CHOWN` | Dosya sahipliği değiştirme | 🟡 Orta |

**restricted-v2 tüm capabilities'i drop ediyor:**

```bash
oc describe scc restricted-v2 | grep -A3 "Required Drop"
```

**Çıktı:**

```
Required Drop Capabilities:
  ALL
```

**Capabilities Demo:**

**YAML:** [02-container-security-scc/04-capabilities-demo.yaml](02-container-security-scc/04-capabilities-demo.yaml)

```bash
oc apply -f 02-container-security-scc/04-capabilities-demo.yaml -n security-demo
oc exec -it capabilities-demo -n security-demo -- cat /proc/1/status | grep Cap
```

---

### 10:30–10:45 · Custom SCC Lab

**Senaryo:** Bir uygulama 443 portuna bind olmak için `NET_BIND_SERVICE` capability'sine ihtiyaç duyuyor ama root olmamalı.

**YAML:** [02-container-security-scc/01-custom-restricted-scc.yaml](02-container-security-scc/01-custom-restricted-scc.yaml)

```bash
oc apply -f 02-container-security-scc/01-custom-restricted-scc.yaml
oc get scc | grep custom
oc describe scc custom-restricted
```

**Öğrencilere Sor:**

> "Bu custom SCC ile root çalıştırabilir miyiz?"

```bash
oc describe scc custom-restricted | grep "Run As User"
```

**Çıktı:** `MustRunAsRange` — hayır, root yasak.

> "Privileged container çalıştırabilir miyiz?"

```bash
oc describe scc custom-restricted | grep "Allow Privileged"
```

**Çıktı:** `false` — hayır.

**Privileged Pod Örneği (eğitim amaçlı):**

**YAML:** [02-container-security-scc/03-privileged-pod-example.yaml](02-container-security-scc/03-privileged-pod-example.yaml)

> Bu YAML'ı göster ama **çalıştırma**. Neyin yanlış olduğunu tartışın.

---

## 11:00–11:45 · RBAC Fundamentals

### 11:00–11:15 · RBAC Nedir?

**RBAC = Role-Based Access Control**

> *"Kim, hangi resource'a, hangi işlemi yapabilir?"*

**Temel Kavramlar:**

```
Subject (Kim?)        Verb (Ne Yapabilir?)    Resource (Neye?)
──────────────        ────────────────────    ────────────────
User                  get                     pods
Group                 list                    services
ServiceAccount        watch                   secrets
                      create                  deployments
                      update                  configmaps
                      patch                   namespaces
                      delete
                      exec
```

**Role vs ClusterRole:**

| | Role | ClusterRole |
|--|--|--|
| **Kapsam** | Tek namespace | Tüm cluster |
| **Kullanım** | Namespace izinleri | Cluster-wide veya namespace izinleri |
| **Örnek** | `dev` namespace'te pod okuma | Tüm cluster'da node okuma |

**RoleBinding vs ClusterRoleBinding:**

| | RoleBinding | ClusterRoleBinding |
|--|--|--|
| **Bağlar** | Role veya ClusterRole | Sadece ClusterRole |
| **Kapsam** | Tek namespace | Tüm cluster |
| **Tavsiye** | Varsayılan tercih | Sadece gerektiğinde |

---

### 11:15–11:35 · RBAC Lab

**Senaryo:** `developer1` kullanıcısı `rbac-demo` namespace'inde pod ve deployment işlemleri yapabilmeli, ama secret okuyamamalı.

**Adım 1 — Namespace Oluştur:**

```bash
oc new-project rbac-demo
```

**Adım 2 — Role Oluştur:**

**YAML:** [03-rbac-fundamentals/01-developer-role.yaml](03-rbac-fundamentals/01-developer-role.yaml)

```bash
oc apply -f 03-rbac-fundamentals/01-developer-role.yaml
```

**Adım 3 — RoleBinding Oluştur:**

**YAML:** [03-rbac-fundamentals/02-developer-rolebinding.yaml](03-rbac-fundamentals/02-developer-rolebinding.yaml)

```bash
oc apply -f 03-rbac-fundamentals/02-developer-rolebinding.yaml
```

**Adım 4 — İzinleri Doğrula:**

```bash
oc auth can-i get pods --as developer1 -n rbac-demo
# yes

oc auth can-i create deployments --as developer1 -n rbac-demo
# yes

oc auth can-i get secrets --as developer1 -n rbac-demo
# no

oc auth can-i delete nodes --as developer1
# no

oc auth can-i get pods --as developer1 -n default
# no  (sadece rbac-demo namespace'i için yetki var)
```

**Adım 5 — Kim Erişebilir? (Hangi kullanıcı bu yetkiye sahip?)**

```bash
oc adm policy who-can get pods -n rbac-demo
```

**Adım 6 — ClusterRole Oluştur (Monitoring için):**

**YAML:** [03-rbac-fundamentals/03-readonly-clusterrole.yaml](03-rbac-fundamentals/03-readonly-clusterrole.yaml)

```bash
oc apply -f 03-rbac-fundamentals/03-readonly-clusterrole.yaml
```

**YAML:** [03-rbac-fundamentals/04-readonly-clusterrolebinding.yaml](03-rbac-fundamentals/04-readonly-clusterrolebinding.yaml)

```bash
oc apply -f 03-rbac-fundamentals/04-readonly-clusterrolebinding.yaml
```

**Doğrula:**

```bash
oc auth can-i get nodes --as monitoring-user
# yes (tüm cluster'da)

oc auth can-i delete pods --as monitoring-user -n default
# no

oc auth can-i get secrets --as monitoring-user -n default
# no
```

---

### 11:35–11:45 · Secret Exfiltration Senaryosu (Giriş)

**Tehlikeli RBAC Örneği — Öğrencilere Göster:**

```yaml
# YANLIŞ! list yetkisi tüm secret listesini açar
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "list"]   # list tehlikeli!
```

> "`list` yetkisi varsa bir pod, namespace'teki **TÜM** secret adlarını görebilir."

**Güvenli Yaklaşım:**

```yaml
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get"]                           # sadece get
  resourceNames: ["sadece-bu-secret"]      # sadece spesifik secret
```

**YAML:** [03-rbac-fundamentals/05-app-service-account-rbac.yaml](03-rbac-fundamentals/05-app-service-account-rbac.yaml)

```bash
oc apply -f 03-rbac-fundamentals/05-app-service-account-rbac.yaml

# Sadece kendi secret'ına erişebilir
oc auth can-i get secret app-config-secret \
  --as system:serviceaccount:rbac-demo:app-service-account \
  -n rbac-demo
# yes

# Başka bir secret'a erişemez
oc auth can-i get secret other-secret \
  --as system:serviceaccount:rbac-demo:app-service-account \
  -n rbac-demo
# no

# Secret listesi göremez
oc auth can-i list secrets \
  --as system:serviceaccount:rbac-demo:app-service-account \
  -n rbac-demo
# no
```

---

## 12:00–13:00 · Öğle Arası

---

## 13:00–13:45 · Secret Management

### 13:00–13:15 · Kubernetes Secret Nedir?

**Secret Tipleri:**

| Tip | Kullanım |
|-----|---------|
| `Opaque` | Genel amaçlı (username, password, API key) |
| `kubernetes.io/tls` | TLS sertifika ve private key |
| `kubernetes.io/dockerconfigjson` | Container registry kimlik doğrulama |
| `kubernetes.io/service-account-token` | Service Account JWT token |
| `kubernetes.io/ssh-auth` | SSH private key |

**Kritik Not — Öğrencilere Söyle:**

> *"Kubernetes Secret'ları **base64 ile encode edilir** — bu şifreleme DEĞİLDİR!
> `echo -n 'mysecret' | base64` → `bXlzZWNyZXQ=`
> `echo 'bXlzZWNyZXQ=' | base64 -d` → `mysecret`
> ETCD encryption at rest ayrıca yapılandırılmalıdır."*

**Secret Oluştur:**

**YAML:** [04-secret-management/01-opaque-secret.yaml](04-secret-management/01-opaque-secret.yaml)

```bash
oc new-project secret-demo
oc apply -f 04-secret-management/01-opaque-secret.yaml
```

**Secret Görüntüle:**

```bash
oc get secret app-credentials -n secret-demo -o yaml
```

**Çıktı:**

```yaml
data:
  api-key: bXktc3VwZXItc2VjcmV0LWFwaS1rZXktMTIzNDU=
  password: UzNjdXIzUEBzc3cwcmQh
  username: YXBwdXNlcg==
```

**Decode Et:**

```bash
oc get secret app-credentials \
  -o jsonpath='{.data.username}' \
  -n secret-demo | base64 -d
# Çıktı: appuser
```

---

### 13:15–13:30 · Secret Kullanım Yöntemleri

#### Yöntem 1: Environment Variable

**YAML:** [04-secret-management/02-pod-env-secret.yaml](04-secret-management/02-pod-env-secret.yaml)

```bash
oc apply -f 04-secret-management/02-pod-env-secret.yaml -n secret-demo
oc exec -it pod-env-secret -n secret-demo -- env | grep -E "DB_|API_"
```

**Çıktı:**

```
DB_USER=appuser
DB_PASS=S3cur3P@ssw0rd!
API_KEY=my-super-secret-api-key-12345
```

**Güvenlik Notu:**

| Avantaj | Dezavantaj |
|---------|-----------|
| Uygulama kodu değişmez | `oc exec` ile görülebilir |
| 12-factor app uyumlu | `/proc/<pid>/environ` ile leak olabilir |
| Kolay kullanım | Rotate için pod restart gerekir |

#### Yöntem 2: Volume Mount (Önerilen)

**YAML:** [04-secret-management/03-pod-volume-secret.yaml](04-secret-management/03-pod-volume-secret.yaml)

```bash
oc apply -f 04-secret-management/03-pod-volume-secret.yaml -n secret-demo
oc exec -it pod-volume-secret -n secret-demo -- ls -la /etc/app/secrets
```

**Çıktı:**

```
total 0
drwxrwxrwt. 3 root root  120 Jun 12 09:30 .
drwxr-xr-x. 1 root root   18 Jun 12 09:30 ..
-r--------. 1 1001 1001   26 Jun 12 09:30 api-key
-r--------. 1 1001 1001   14 Jun 12 09:30 password
-r--------. 1 1001 1001    7 Jun 12 09:30 username
```

> "Dosya permission `0400` — sadece sahip okuyabilir.
> Secret rotate edilince pod restart **gerekmez**, dosya otomatik güncellenir."

---

### 13:30–13:45 · Secret Exfiltration Demo

**YAML:** [04-secret-management/05-secret-exfiltration-demo.yaml](04-secret-management/05-secret-exfiltration-demo.yaml)

```bash
oc apply -f 04-secret-management/05-secret-exfiltration-demo.yaml -n secret-demo
oc logs secret-reader-pod -n secret-demo
```

**Pod içinde interaktif keşif:**

```bash
oc exec -it secret-reader-pod -n secret-demo -- sh

# Service Account token bilgisi
ls /var/run/secrets/kubernetes.io/serviceaccount/
# Dosyalar: token, ca.crt, namespace

# API'ye erişmeye çalış
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
APISERVER=https://kubernetes.default.svc
CA=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt

curl -s --cacert $CA \
  $APISERVER/api/v1/namespaces/secret-demo/secrets \
  -H "Authorization: Bearer $TOKEN"
```

**Beklenen:**

```json
{
  "kind": "Status",
  "status": "Failure",
  "reason": "Forbidden",
  "code": 403
}
```

> *"Default service account yeterli yetkiye sahip değil — bu güvenlidir.
> Ama biri yanlışlıkla `list secrets` yetkisi verseydi...
> tüm namespace'in secret adlarına erişilebilirdi."*

**Koruma Önlemleri:**

```
1. automountServiceAccountToken: false  →  Token gerekmeyen pod'larda kapat
2. RBAC ile secret erişimini kısıtla    →  resourceNames kullan
3. ETCD encryption at rest aktif et     →  EncryptionConfiguration
4. Audit log'ları izle                  →  secret'a erişim loglanır
5. External secret store kullan         →  Azure Key Vault (sonraki bölüm)
```

---

## 14:00–14:45 · Azure Key Vault Integration

### 14:00–14:15 · Neden External Secret Store?

**Kubernetes Secret Sorunları:**

| Sorun | Açıklama |
|-------|---------|
| Base64 encoding | Güvenlik değil, sadece encoding |
| ETCD'de plaintext | Varsayılan olarak şifrelenmez |
| Secret rotation | Manuel veya ek operator gerektirir |
| Audit eksikliği | Varsayılan secret erişim logu yok |
| GitOps problemi | Secret'ı Git'e commit etme riski |

**Azure Key Vault Avantajları:**

| Avantaj | Açıklama |
|---------|---------| 
| HSM destekli | Hardware Security Module ile korunur |
| Otomatik rotation | Key Vault'ta rotation policy tanımlanabilir |
| Tam audit | Her erişim Azure Monitor'a loglanır |
| Azure RBAC | Granüler erişim kontrolü |
| Zero-trust | Pod identity ile credential gereksiz |

---

### 14:15–14:35 · CSI Driver & SecretProviderClass

**Mimari:**

```
Azure Key Vault
      │
      │ (1) OIDC / Workload Identity kimlik doğrulama
      ▼
Secrets Store CSI Driver (OpenShift Operator)
      │
      │ (2) SecretProviderClass kurallarına göre secret çek
      ▼
Pod Volume Mount (/mnt/secrets/)
      │
      │ (3) İsteğe bağlı: Kubernetes Secret olarak sync
      ▼
K8s Secret (app-secrets-from-vault)
```

**Adım 1 — Namespace ve Service Account:**

**YAML:** [05-azure-key-vault/01-vault-service-account.yaml](05-azure-key-vault/01-vault-service-account.yaml)

```bash
oc new-project vault-demo
# Önce AZURE_CLIENT_ID ve AZURE_TENANT_ID değerlerini doldur
oc apply -f 05-azure-key-vault/01-vault-service-account.yaml
```

**Adım 2 — SecretProviderClass:**

**YAML:** [05-azure-key-vault/02-secretproviderclass.yaml](05-azure-key-vault/02-secretproviderclass.yaml)

```bash
oc apply -f 05-azure-key-vault/02-secretproviderclass.yaml
oc get secretproviderclass -n vault-demo
```

**Adım 3 — Pod ile Mount:**

**YAML:** [05-azure-key-vault/03-pod-with-vault-secret.yaml](05-azure-key-vault/03-pod-with-vault-secret.yaml)

```bash
oc apply -f 05-azure-key-vault/03-pod-with-vault-secret.yaml
oc get pods -n vault-demo
```

**Kontrol:**

```bash
# Secret dosyaları volume'da mı?
oc exec -it vault-secret-pod -n vault-demo -- ls /mnt/secrets

# K8s Secret otomatik oluştu mu?
oc get secret app-secrets-from-vault -n vault-demo

# Pod log'larına bak
oc logs vault-secret-pod -n vault-demo
```

---

### 14:35–14:45 · Workload Identity Flow (Zero-Trust)

**Tahtaya çiz:**

```
Pod (vault-workload-sa)
    │
    │ 1. OpenShift OIDC token üretir
    ▼
Azure AD (OIDC Federated Identity)
    │
    │ 2. Token doğrulandı: "Bu SA bu Managed Identity mi? Evet."
    ▼
Azure Key Vault (RBAC: Key Vault Secrets User rolü)
    │
    │ 3. "Bu identity'nin database-password'e erişim izni var."
    ▼
Secret değeri döner
    │
    │ 4. CSI Driver pod'a mount eder
    ▼
/mnt/secrets/database-password
```

**Anlat:**

> *"Hiçbir credential YAML'a yazılmadı.
> Service Account token'ı OIDC ile Azure'a gönderildi.
> Azure Key Vault bu pod'un kim olduğunu bildi ve izin verdi.
> Bu **zero-trust** mimarisidir — bildiğin şey değil, olduğun şey önemlidir."*

---

## 15:00–16:00 · Hands-on Labs

### Lab 1 · SCC Challenge (15:00–15:20)

**Amaç:** SCC hatasını tespit et ve düzelt.

**YAML:** [06-hands-on-labs/lab1-scc-challenge.yaml](06-hands-on-labs/lab1-scc-challenge.yaml)

**Görevler:**

1. YAML'ı uygula — pod neden başlamıyor?
   ```bash
   oc apply -f 06-hands-on-labs/lab1-scc-challenge.yaml
   oc get events -n lab1-scc --sort-by=.metadata.creationTimestamp
   ```

2. **Yöntem A** — SecurityContext'i düzelterek çalıştır
   (`runAsUser: 0` ve `privileged: true` kaldır, `runAsNonRoot: true` ekle)

3. **Yöntem B** — Service Account ile anyuid SCC vererek çalıştır
   ```bash
   oc adm policy add-scc-to-user anyuid -z lab1-sa -n lab1-scc
   ```

4. Kullanılan SCC'yi doğrula:
   ```bash
   oc get pod lab1-pod \
     -o jsonpath='{.metadata.annotations.openshift\.io/scc}' \
     -n lab1-scc
   ```

**Beklenen:** Pod `Running` — Yöntem A: `restricted-v2`, Yöntem B: `anyuid`

---

### Lab 2 · RBAC Challenge (15:20–15:40)

**Amaç:** Least-privilege RBAC yapılandırması oluştur.

**YAML:** [06-hands-on-labs/lab2-rbac-challenge.yaml](06-hands-on-labs/lab2-rbac-challenge.yaml)

**Senaryo:** `ci-bot` kullanıcısı `production` namespace'inde:
- ✅ Deployment güncelleyebilmeli (`update`, `patch`)
- ✅ Pod listesini görebilmeli (`get`, `list`)
- ❌ Pod silememeli
- ❌ Secret okuyamamalı
- ❌ Başka namespace'lere erişememeli

**Doğrulama:**

```bash
oc auth can-i update deployments --as ci-bot -n production   # yes
oc auth can-i patch deployments --as ci-bot -n production    # yes
oc auth can-i get pods --as ci-bot -n production             # yes
oc auth can-i delete pods --as ci-bot -n production          # no
oc auth can-i get secrets --as ci-bot -n production          # no
oc auth can-i get pods --as ci-bot -n default                # no
```

---

### Lab 3 · Secret Management Challenge (15:40–16:00)

**Amaç:** Secret oluştur, pod'a güvenli şekilde mount et, RBAC ile kısıtla.

**YAML:** [06-hands-on-labs/lab3-secret-challenge.yaml](06-hands-on-labs/lab3-secret-challenge.yaml)

**Görevler:**

1. `app-secrets` adında Opaque secret oluştur (`DB_HOST`, `DB_PASSWORD`, `app.crt`)
2. `DB_HOST` ve `DB_PASSWORD`'u env var olarak pod'a inject et
3. `app.crt`'yi `/etc/ssl/certs/` dizinine volume olarak mount et (permission `0400`)
4. Sadece `app-sa` service account'u bu secret'a erişebilsin (RBAC yaz)

**Doğrulama:**

```bash
oc exec -it lab3-app -n lab3-secrets -- env | grep DB_
oc exec -it lab3-app -n lab3-secrets -- ls -la /etc/ssl/certs/

oc auth can-i get secret app-secrets \
  --as system:serviceaccount:lab3-secrets:app-sa \
  -n lab3-secrets           # yes

oc auth can-i get secret app-secrets \
  --as system:serviceaccount:lab3-secrets:default \
  -n lab3-secrets           # no
```

---

## 16:00 · Günün Özeti

**Bugün Öğrendiklerimiz:**

```
✅ OpenShift güvenliği varsayılan olarak aktif getirir
✅ SCC: Pod'ların güvenlik profilini kontrol eden cluster-level policy
✅ Least Privilege: Sadece gerekli yetkiyi, sadece gerekli yere ver
✅ RBAC: Kim, hangi resource'a, hangi işlemi yapabilir
✅ Secret: Base64 = encoding, şifreleme değil
✅ Volume mount: Env var'dan daha güvenli secret yöntemi
✅ Azure Key Vault: Zero-trust, HSM destekli secret yönetimi
```

**Sorular & Cevaplar**

---

## Hızlı Komut Referansı

```bash
# ── SCC ──────────────────────────────────────────────────────
oc get scc
oc describe scc restricted-v2
oc adm policy add-scc-to-user anyuid -z <sa-adı> -n <namespace>
oc adm policy who-can use scc anyuid
oc get pod <pod> -o jsonpath='{.metadata.annotations.openshift\.io/scc}' -n <ns>

# ── RBAC ─────────────────────────────────────────────────────
oc auth can-i <verb> <resource> --as <kullanıcı> -n <namespace>
oc adm policy who-can <verb> <resource> -n <namespace>
oc get rolebindings,clusterrolebindings -A | grep <kullanıcı>
oc describe rolebinding <binding> -n <namespace>

# ── Secret ───────────────────────────────────────────────────
oc get secret <ad> -n <ns> -o yaml
oc get secret <ad> -o jsonpath='{.data.<key>}' -n <ns> | base64 -d
oc create secret generic <ad> \
  --from-literal=key=value \
  --from-file=dosya.crt=/path/to/file \
  -n <namespace>
oc set data secret/<ad> --from-literal=key=yeniDeger -n <ns>

# ── Debug & Events ───────────────────────────────────────────
oc get events --sort-by=.metadata.creationTimestamp -n <ns>
oc describe pod <pod> -n <ns>
oc logs <pod> -n <ns>
oc exec -it <pod> -n <ns> -- sh
```

---

## Klasör Yapısı

```
openshift/
├── day1-instructor-guide.md              ← Bu dosya
│
├── 01-architecture-security-model/
│   ├── 01-root-pod-rejected.yaml         ← Demo 1: root pod reddi
│   ├── 02-non-root-pod.yaml              ← Demo 2: non-root pod
│   ├── 03-demo-service-account.yaml      ← SCC assignment lab - SA
│   └── 04-root-pod-with-anyuid.yaml      ← SCC assignment lab - root pod
│
├── 02-container-security-scc/
│   ├── 01-custom-restricted-scc.yaml     ← Custom SCC oluşturma
│   ├── 02-pod-with-securitycontext.yaml  ← Güvenli pod örneği
│   ├── 03-privileged-pod-example.yaml    ← Privileged pod (eğitim amaçlı)
│   └── 04-capabilities-demo.yaml        ← Linux capabilities demo
│
├── 03-rbac-fundamentals/
│   ├── 01-developer-role.yaml            ← Namespace Role
│   ├── 02-developer-rolebinding.yaml     ← Kullanıcıya bağlama
│   ├── 03-readonly-clusterrole.yaml      ← Cluster-wide okuma
│   ├── 04-readonly-clusterrolebinding.yaml ← Monitoring kullanıcısı
│   └── 05-app-service-account-rbac.yaml  ← SA + kısıtlı secret erişimi
│
├── 04-secret-management/
│   ├── 01-opaque-secret.yaml             ← Temel secret oluşturma
│   ├── 02-pod-env-secret.yaml            ← Env var yöntemi
│   ├── 03-pod-volume-secret.yaml         ← Volume mount yöntemi
│   ├── 04-tls-secret.yaml               ← TLS secret
│   └── 05-secret-exfiltration-demo.yaml  ← Güvenlik demo
│
├── 05-azure-key-vault/
│   ├── 01-vault-service-account.yaml     ← Workload Identity SA
│   ├── 02-secretproviderclass.yaml       ← Key Vault bağlantısı
│   └── 03-pod-with-vault-secret.yaml     ← Pod + Key Vault mount
│
└── 06-hands-on-labs/
    ├── lab1-scc-challenge.yaml           ← Lab 1: SCC hatası bul & düzelt
    ├── lab2-rbac-challenge.yaml          ← Lab 2: RBAC tamamla
    └── lab3-secret-challenge.yaml        ← Lab 3: Secret mount + RBAC
```
