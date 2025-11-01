================================================================================
  NTFS Advanced Compression Tool v1.0.1
  Windows XPRESS/LZX Compression GUI
================================================================================

HIZLI BAŞLANGIÇ
---------------
1. NTFS-Compactor-v1.0.1.exe dosyasını SAĞ TIKLA
2. "Yönetici olarak çalıştır" seçeneğini seç
3. Sıkıştırmak istediğin klasörü seç
4. Algoritma ve davranış seçeneklerini ayarla
5. "Compress" butonuna tıkla

ÖNEMLİ UYARILAR
---------------
⚠️  MUTLAKA YÖNETİCİ OLARAK ÇALIŞTIRIN!
    Sıkıştırma işlemleri için administrator yetkileri gereklidir.

⚠️  BÜYÜK KLASÖRLER İÇİN "DEFER MEASUREMENT" KULLANIN!
    Eğer çok büyük bir klasör veya içinde çok sayıda dosya olan bir klasör
    seçecekseniz, klasör seçmeden önce "Defer measurement" seçeneğini 
    işaretleyin. Bu sayede program hemen başlar ve ilk ölçüm sıkıştırma
    sırasında yapılır. Aksi halde klasör seçimi çok uzun sürebilir.

⚠️  İLK ÇALIŞTIRMA YAVAŞ OLABİLİR!
    İlk çalıştırmada Windows Defender taraması yapabilir. Normal bir durumdur.

ALGORİTMA SEÇENEKLERİ
---------------------
XPRESS4K  - En hızlı, düşük sıkıştırma (günlük kullanım için ideal)
XPRESS8K  - Orta hızlı, dengeli sıkıştırma (önerilen)
XPRESS16K - Yavaş, yüksek sıkıştırma (arşiv dosyaları için)
LZX       - En yavaş, maksimum sıkıştırma (çok nadiren erişilen dosyalar)

DAVRANIŞ SEÇENEKLERİ
--------------------
Skip
  - Zaten sıkıştırılmış dosyalara dokunmaz
  - En hızlı seçenek
  - Sadece sıkıştırılmamış dosyaları işler

Recompress if algorithm differs
  - Farklı algoritma ile sıkıştırılmış dosyaları yeniden sıkıştırır
  - Tüm klasörü aynı algoritma ile standartlaştırmak için kullanın
  - Daha güvenli ama daha yavaş

SHOW STATUS BUTONU
------------------
Seçili klasördeki tüm dosyaların mevcut durumunu gösterir:
- Hangi dosyalar sıkıştırılmış?
- Hangi algoritma kullanılmış?
- Gerçek boyut vs. diskteki boyut
- Tasarruf yüzdesi
- Dosya yolları

Bu özelliği kullanarak sıkıştırma öncesi ve sonrası durumu karşılaştırabilirsiniz.

KULLANIM ÖRNEKLERİ
------------------
Örnek 1: Fotoğraf Arşivi
  Klasör: D:\Photos\Archive
  Algoritma: XPRESS8K (dengeli)
  Davranış: Skip
  Defer: ✓ (binlerce fotoğraf varsa)

Örnek 2: Eski Belgeler
  Klasör: C:\Users\Belgelerim\Eski_Dosyalar
  Algoritma: LZX (maksimum sıkıştırma)
  Davranış: Recompress if different
  Defer: Program otomatik ölçer

Örnek 3: Oyun Dosyaları
  Klasör: D:\Games\OldGames
  Algoritma: XPRESS4K (oyun açılışını yavaşlatmaz)
  Davranış: Skip
  Defer: ✓ (çok dosya varsa)

SIKI SORULAN SORULAR
--------------------
S: Sıkıştırma dosyaları bozar mı?
C: HAYIR! Windows'un kendi özelliğidir, tamamen güvenlidir.

S: Sıkıştırılmış dosyaları normal açabilir miyim?
C: EVET! Hiçbir fark görmezsiniz, otomatik açılır.

S: Her dosya için sıkıştırma faydalı mı?
C: HAYIR! Zaten sıkıştırılmış formatlar (.zip, .jpg, .mp4, .mp3) 
   için fayda görmezsiniz. En iyi sonuç için: Text dosyaları, 
   log dosyaları, kaynak kodlar, belgeler gibi sıkıştırılmamış 
   dosyalarda kullanın.

S: Sıkıştırma performansı etkiler mi?
C: Çok az. XPRESS algoritmaları modern CPU'larda neredeyse 
   fark edilmez gecikme yaratır. LZX biraz daha yavaş olabilir.

S: Stop butonu ne işe yarar?
C: İşlemi istediğiniz zaman durdurabilirsiniz. O ana kadar 
   sıkıştırılan dosyalar sıkıştırılmış kalır.

S: Geri almak mümkün mü?
C: EVET! Dosya üzerine sağ tıkla → Properties → Advanced → 
   "Compress contents to save disk space" seçeneğini kaldır.
   Ya da programa tekrar gelip uncompress işlemi yap.

TEKNİK BİLGİLER
---------------
- Windows 10/11 gereklidir
- NTFS dosya sistemi gereklidir (FAT32'de çalışmaz)
- compact.exe komutunu kullanır (Windows yerleşik)
- Tamamen ücretsiz ve açık kaynak (MIT License)
- İnternet bağlantısı gerektirmez

PERFORMANS İPUÇLARI
-------------------
✓ SSD'de daha hızlı çalışır
✓ "Defer measurement" büyük klasörleri hızlandırır
✓ "Skip" modu en hızlı seçenektir
✓ Antivirüs geçici olarak kapatılabilir (hızlanma için)
✓ Birden fazla küçük klasörü ayrı ayrı sıkıştırmak 
  tek büyük klasörden daha hızlıdır

GÜVENLİK NOTLARI
----------------
✓ Bu program hiçbir veri toplamaz
✓ İnternet bağlantısı kullanmaz
✓ Sadece yerel dosyalarınızla çalışır
✓ Açık kaynak kodludur, inceleyebilirsiniz
✓ Windows'un kendi compression özelliğini kullanır

DESTEK VE İLETİŞİM
------------------
GitHub: https://github.com/b-elci/ntfs-compactor
Issues: https://github.com/b-elci/ntfs-compactor/issues
License: MIT License (LICENSE.txt dosyasına bakın)

Versiyon: 1.0.1
Tarih: 01 Kasım 2025
Değişiklikler: CHANGELOG.txt dosyasına bakın

================================================================================
İyi kullanımlar! 🗜️
================================================================================
