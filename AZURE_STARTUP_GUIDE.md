# Azure App Service Startup Guide

## 🚀 Azure'da Uygulama Başlatma Rehberi

### 1. Azure App Service Konfigürasyonu

#### A. Startup Command Ayarlama
1. Azure Portal'a gidin
2. App Service'inizi seçin
3. **Configuration** > **General Settings**'e gidin
4. **Startup Command** alanına şunu yazın:
   ```
   python startup.py
   ```

#### B. Environment Variables
**Configuration** > **Application Settings**'de şu değişkenleri ekleyin:

```
DB_SERVER=pmbomft.database.windows.net
DB_NAME=PMboMft
DB_USER=mbomft_admin
DB_PASSWORD=Pp123456Pp123456
DB_DRIVER={ODBC Driver 17 for SQL Server}
SECRET_KEY=your-secret-key-here
WEBSITE_SITE_NAME=your-app-name
```

### 2. Deployment Dosyaları

Aşağıdaki dosyalar projenizde mevcut olmalı:

- ✅ `startup.py` - Azure startup script
- ✅ `web.config` - IIS konfigürasyonu
- ✅ `.deployment` - Deployment ayarları
- ✅ `requirements.txt` - Python bağımlılıkları
- ✅ `runtime.txt` - Python versiyonu

### 3. Azure SQL Server Ayarları

#### A. Firewall Rules
1. Azure SQL Server'ınızı seçin
2. **Security** > **Networking**'e gidin
3. **Allow Azure services and resources to access this server**'ı etkinleştirin
4. **Add current client IP address**'i ekleyin

#### B. SQL Server Authentication
1. **Security** > **Authentication**'a gidin
2. **SQL Server authentication**'ı etkinleştirin
3. Login credentials'ları doğrulayın

### 4. Deployment Adımları

#### A. Git ile Deployment
```bash
git add .
git commit -m "Azure deployment configuration"
git push azure main
```

#### B. ZIP Deployment
1. Tüm dosyaları ZIP'leyin
2. Azure Portal > App Service > Deployment Center
3. ZIP dosyasını yükleyin

### 5. Test Etme

#### A. Health Check
```
https://your-app.azurewebsites.net/health
```

#### B. Ana Sayfa
```
https://your-app.azurewebsites.net/
```

### 6. Sorun Giderme

#### A. Log Kontrolü
1. Azure Portal > App Service > Monitoring > Log stream
2. Hataları kontrol edin

#### B. Yaygın Hatalar

**1. ModuleNotFoundError**
- `requirements.txt`'deki paketlerin yüklendiğinden emin olun
- Deployment loglarını kontrol edin

**2. Database Connection Error**
- Environment variables'ları kontrol edin
- Azure SQL Server firewall ayarlarını kontrol edin
- Database credentials'ları doğrulayın

**3. Port Binding Error**
- `startup.py`'nin doğru çalıştığından emin olun
- PORT environment variable'ının ayarlandığından emin olun

**4. SSL Certificate Error**
- Azure'da SSL sertifikası otomatik yönetilir
- Local SSL ayarlarını Azure'da kullanmayın

### 7. Performance Optimizasyonu

#### A. Application Settings
```
WEBSITES_ENABLE_APP_SERVICE_STORAGE=true
WEBSITES_CONTAINER_START_TIME_LIMIT=1800
```

#### B. Scaling
- **Basic** plan: 1 instance
- **Standard** plan: 1-10 instances
- **Premium** plan: 1-20 instances

### 8. Monitoring

#### A. Application Insights
1. Azure Portal > App Service > Monitoring > Application Insights
2. Performance monitoring'ı etkinleştirin

#### B. Health Check
- `/health` endpoint'ini düzenli olarak kontrol edin
- Database bağlantı durumunu izleyin

## ✅ Checklist

- [ ] Startup command ayarlandı
- [ ] Environment variables eklendi
- [ ] Azure SQL Server firewall ayarlandı
- [ ] Deployment dosyaları hazırlandı
- [ ] Health check test edildi
- [ ] Log monitoring kuruldu

## 🆘 Acil Durum

Eğer uygulama hala başlamıyorsa:

1. **Log Stream**'i kontrol edin
2. **Health Check** endpoint'ini test edin
3. **Database Connection**'ı doğrulayın
4. **Environment Variables**'ları kontrol edin
5. **Startup Command**'ı doğrulayın
