# Azure Deployment Guide

## Sorun Çözümü: Uygulama Başlatma Hatası

Azure'da uygulama başlatma sorunları genellikle konfigürasyon ve bağımlılık sorunlarından kaynaklanır.

## Yapılan Değişiklikler

### 1. Azure SQL Server Konfigürasyonu
- Local SQL Server yerine Azure SQL Server kullanımına geçildi
- SSL şifreleme ve güvenlik ayarları eklendi
- Environment variable desteği eklendi

### 2. Hata Ayıklama
- Health check endpoint eklendi: `/health`
- Error handler'lar eklendi
- Database bağlantı logları eklendi

## Azure'da Yapılması Gerekenler

### 1. Startup Command Ayarlayın
Azure App Service'de Configuration > General Settings'de:
- **Startup Command**: `python startup.py`

### 2. Environment Variables Ayarlayın
Azure App Service'de aşağıdaki environment variables'ları ekleyin:

```
DB_SERVER=pmbomft.database.windows.net
DB_NAME=PMboMft
DB_USER=mbomft_admin
DB_PASSWORD=Pp123456Pp123456
DB_DRIVER={ODBC Driver 17 for SQL Server}
SECRET_KEY=your-secret-key-here
```

### 2. Azure SQL Server Ayarları
- Firewall rules'da Azure services'e erişim verin
- SQL Server authentication'ı etkinleştirin
- User'ın doğru permissions'ları olduğundan emin olun

### 3. Health Check
Deployment sonrası `/health` endpoint'ini kontrol edin:
```
https://your-app.azurewebsites.net/health
```

Bu endpoint size database bağlantı durumunu gösterecek.

## Sorun Giderme

### Database Bağlantı Sorunları
1. Azure SQL Server'ın çalıştığından emin olun
2. Firewall ayarlarını kontrol edin
3. Username/password'ün doğru olduğundan emin olun
4. Database'in mevcut olduğundan emin olun

### Log Kontrolü
Azure App Service'de Log Stream'i kontrol edin:
- Azure Portal > App Service > Monitoring > Log stream
- Database bağlantı hatalarını görebilirsiniz

### Test Etme
1. `/health` endpoint'ini test edin
2. Ana sayfaya erişmeyi deneyin
3. Login sayfasını test edin

## Yerel Geliştirme İçin

Yerel geliştirme için `app.py`'de local konfigürasyonu aktif edin:

```python
# Local SQL Server Configuration (for development)
params = {
    'DRIVER': '{ODBC Driver 17 for SQL Server}',
    'SERVER': 'DESKTOP-E62JOKI\SQLEXPRESS',
    'DATABASE': 'mbo-mft',
    'UID': 'mft_user',
    'PWD': '123456'
}
```

## Güvenlik Notları

- Production'da environment variables kullanın
- Database password'ları güçlü tutun
- Azure Key Vault kullanmayı düşünün
- SSL bağlantıları zorunlu tutun
