# Şamdan  
## AI-Based Next-Generation Android Malware Analysis Platform

Şamdan, Android zararlı yazılımlarını tespit etmek için statik analiz, ağ keşfi ve tehdit istihbaratını otonom bir mimaride birleştiren, yapay zeka destekli bir analiz platformudur.




---

## 📌 Genel Bakış

Şamdan; Android uygulamalarını çok katmanlı olarak analiz eder, elde edilen teknik verileri özel eğitilmiş bir Büyük Dil Modeli (LLM) ile yorumlar ve uygulamanın güvenlik durumunu otonom biçimde sınıflandırır.

Desteklenen çıktı sınıfları:
- **BENIGN**
- **SUSPICIOUS**
- **MALICIOUS**

---

## 🚀 Özellikler

- **Hibrit Analiz**
  - MobSF (Statik Analiz)
  - Subfinder (Ağ Keşfi)
  - VirusTotal (Tehdit İstihbaratı)

- **Özel Eğitilmiş LLM**
  - Llama-3.1-8B tabanlı
  - Siber güvenlik odaklı fine-tune edilmiş **Şamdan-AI**

- **Otonom Karar Mekanizması**
  - Teknik verileri bağlamsal olarak yorumlar
  - İnsan müdahalesi olmadan nihai karar üretir

- **Veri Gizliliği**
  - GGUF & Ollama desteği
  - Tamamen on-premise çalışabilir mimari

- **Detaylı Raporlama**
  - Excel formatında toplu analiz çıktısı
  - MITRE ATT&CK uyumlu teknik gerekçelendirme

---

## 🛠 Mimari Yapı

Uygulama, yüksek performans ve ölçeklenebilirlik için **FastAPI tabanlı asenkron mimari** üzerine inşa edilmiştir.

<img width="1920" height="1080" alt="Adsız tasarım (1)" src="https://github.com/user-attachments/assets/79d0ecc9-c1cd-453a-b019-1a9a643e0596" />

### Temel Bileşenler

- **Static Analysis**
  - MobSF API entegrasyonu
  - Permission ve API çağrısı analizi

- **Reconnaissance**
  - Docker üzerinde çalışan Subfinder
  - Pasif subdomain keşfi

- **AI Engine**
  - Hugging Face üzerinde yayınlanan özel model  
    https://huggingface.co/TolgaTD/samdan-llama3.1-8b-gguf

---

## 🧠 Kullanılan Teknolojiler

- Python 3.9+
- FastAPI
- Docker
- MobSF
- Subfinder
- VirusTotal API
- Ollama
- Llama-3.1-8B (Fine-Tuned)

---

## 🔧 Kurulum

### 1. Gereksinimler

- Python 3.9 veya üzeri
- Docker
- Ollama
- MobSF (Docker sürümü)
- Subfinder (Docker sürümü)

### 2. Modeli Hazırlama

Model Hugging Face üzerinden indirilir ve Ollama ile yerel olarak ayağa kaldırılır.  
Model adı: **samdan-ai**

### 3. Uygulamayı Çalıştırma

Gerekli Python bağımlılıkları kurulduktan sonra FastAPI sunucusu başlatılır.

**Not:**  
Bu aşamadan önce MobSF ve Subfinder servislerinin Docker üzerinde çalışır durumda olduğundan emin olun.  
Ayrıca Ollama servisinin aktif olması ve **samdan-ai** modelinin başarıyla yüklenmiş olması gerekmektedir.  
Uygulama, bu servislerle API üzerinden haberleşerek analiz sürecini yürütür.

---

## 📊 Ekran Görüntüleri

### 1. AI Analiz Sonuçları

<img width="779" height="405" alt="image" src="https://github.com/user-attachments/assets/e655e24f-3a68-4c0e-b357-ca3d9717469e" />
 
(BENIGN / SUSPICIOUS / MALICIOUS sınıflandırma çıktıları)

---

### 2. İşlenmemiş Uygulama Verileri

<img width="782" height="543" alt="image" src="https://github.com/user-attachments/assets/c8fe0eea-da72-4e34-87c6-cebf710beb8b" />


(MobSF, ağ keşfi ve tehdit istihbaratından elde edilen ham çıktılar)

---




Gazi Üniversitesi  
Bilgisayar Mühendisliği Bölümü  
2026
