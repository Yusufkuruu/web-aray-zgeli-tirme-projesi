# Şamdan AI-MAP

**Android Malware Analysis Platform** — APK dosyalarını VirusTotal, yapay zeka ve ağ keşfi araçlarıyla analiz eden web uygulaması.

![Şamdan AI-MAP](static/obscura_vision_hero.png)

---

## Özellikler

- **VirusTotal Entegrasyonu** — 70+ antivirüs motoru ile dosya ve URL taraması
- **Gemini AI Analizi** — Türkçe tehdit istihbaratı ve profesyonel güvenlik raporu
- **Statik Analiz** — İzin analizi, gizli anahtar tespiti, kod seviyesi bulgular
- **Ağ Keşfi** — Subfinder ile subdomain taraması
- **Gerçek Zamanlı İlerleme** — Adım adım analiz takibi
- **Excel Dışa Aktarım** — Toplu analiz sonuçları

---

## Kurulum

```bash
# Bağımlılıkları kur
pip install -r requirements.txt

# Environment değişkenlerini ayarla
cp .env.example .env
# .env dosyasına API key'lerini ekle

# Uygulamayı başlat
python app.py
```

Uygulama `http://localhost:8080` adresinde çalışır.

---

## Kullanılan Teknolojiler

| Katman | Teknoloji |
|---|---|
| Backend | Python, FastAPI, Uvicorn |
| Frontend | HTML5, Bootstrap 5.3, Vanilla JS |
| Yapay Zeka | Google Gemini 2.5 Flash |
| Güvenlik API | VirusTotal v3 |
| Ağ Keşfi | Subfinder (Docker) |
| Statik Analiz | MobSF |

---

## Proje Yapısı

```
├── app.py              # FastAPI backend, analiz pipeline
├── requirements.txt    # Python bağımlılıkları
├── templates/
│   └── index.html      # Tek sayfa arayüz
├── static/
│   ├── style.css       # Dark sci-fi tema
│   └── script.js       # Frontend mantığı
└── uploads/            # Geçici APK dosyaları
```

---

## Hackathon

**Generative Media Hackathon #3** — Komünite / Wiro AI — 2025
