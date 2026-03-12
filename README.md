![GitHub License](https://img.shields.io/github/license/ehsandftm/Cloudflare-L7-Analyzer?style=flat-square&color=blue)
![GitHub Release](https://img.shields.io/github/v/release/ehsandftm/Cloudflare-L7-Analyzer?style=flat-square&color=green)
![Android Badge](https://img.shields.io/badge/Platform-Android-brightgreen?style=flat-square&logo=android)
![Kotlin Badge](https://img.shields.io/badge/Language-Kotlin-purple?style=flat-square&logo=kotlin)


# 🚀 Advanced L7 Cloudflare Scanner & Analyzer (Android)
### آنالیزور و اسکنر پیشرفته لایه ۷ کلودفلر (نسخه اندروید)

## ✨ Minor changes (New in v1.5.5)

- Fixed host generation so empty host no longer becomes host=sni in output configs.

- Added (empty) option to ALPN / Flow / Fingerprint dropdowns.

- Improved smart import and URI builder to correctly preserve blank host values.

---

## 🇮🇷 توضیحات فارسی


### ✨تغییرات کوچک (نسخه 1.5.5)
اصلاح تولید پارامتر host تا وقتی خالی است دیگر به host=sni تبدیل نشود.

اضافه شدن گزینه (empty) به دراپ‌داون‌های ALPN ،Flow و Fingerprint.

بهبود Smart Import و URI builder برای حفظ درست مقدار خالی Host.

---




## ✨ Key Features (New in v1.5.4)

- **Xray Final Validation:** Final scan results can now be validated through an integrated Xray bridge for behavior closer to a real client.
- **Real Client-Like Scanning:** The scanner no longer relies only on basic handshake checks and now uses a deeper staged validation pipeline.
- **CloudFront Scanner Core:** Added a dedicated scanner core for CloudFront networks alongside the original Cloudflare workflow.
- **3-Stage Scan Pipeline:** Initial fast scan → automatic top 100 selection → final validation with optional Xray confirmation.
- **Pause / Resume / Stop Support:** Long scans can now be paused and resumed without losing progress.
- **Improved Config Parsing:** Better handling for VLESS / Trojan configs with smarter manual input and import flow.
- **File-Based IP Loading:** Supports loading IPs, CIDRs, dash ranges, and candidate lists from files.
- **New Ranked Result System:** Results are now scored and categorized by validation quality and confidence.
- **Modern Core-Based UI:** Separate Cloudflare / CloudFront workspaces with improved layout and action controls.
- **NetMod Integration:** One-click config copy and quick launch support for NetMod workflow.

---

## 🇮🇷 توضیحات فارسی

این نسخه، پروژه را از یک اسکنر ساده مبتنی بر هندشیک به یک **معماری چندمرحله‌ای پیشرفته‌تر** ارتقا می‌دهد که رفتار آن بسیار نزدیک‌تر به یک **کلاینت واقعی** است.

در نسخه `v1.5.4` تمرکز اصلی روی افزایش دقت نتایج، اضافه شدن هسته **Xray** برای اعتبارسنجی نهایی، و پشتیبانی از **CloudFront** در کنار Cloudflare بوده است.

### ✨ قابلیت‌های کلیدی (نسخه v1.5.4)

- **اعتبارسنجی نهایی مبتنی بر Xray:** نتایج نهایی اسکن اکنون می‌توانند از طریق هسته Xray بررسی شوند تا خروجی به رفتار واقعی کلاینت نزدیک‌تر شود.
- **اسکن واقعی‌تر:** منطق اسکن دیگر فقط بر پایه تست ساده هندشیک نیست و از یک فرآیند چندمرحله‌ای دقیق‌تر استفاده می‌کند.
- **افزودن هسته اختصاصی CloudFront:** علاوه بر Cloudflare، اکنون هسته جداگانه‌ای برای اسکن شبکه CloudFront نیز اضافه شده است.
- **پایپ‌لاین سه‌مرحله‌ای اسکن:** اسکن سریع اولیه → انتخاب خودکار 100 نتیجه برتر → اعتبارسنجی نهایی با امکان بررسی توسط Xray.
- **قابلیت Pause / Resume / Stop:** اسکن‌های طولانی حالا بدون از بین رفتن پیشرفت، قابل توقف موقت و ادامه دادن هستند.
- **بهبود پردازش کانفیگ‌ها:** پشتیبانی بهتر از لینک‌ها و ورودی‌های دستی VLESS / Trojan.
- **بارگذاری IP از فایل:** امکان دریافت IP، رنج CIDR، بازه‌های dash و لیست کاندیدها از فایل.
- **سیستم جدید رتبه‌بندی نتایج:** نتایج حالا بر اساس کیفیت اعتبارسنجی و confidence امتیازدهی و دسته‌بندی می‌شوند.
- **رابط کاربری مدرن‌تر:** محیط جداگانه برای Cloudflare و CloudFront با ساختار بهتر و کنترل‌های کاربردی‌تر.
- **اتصال به NetMod:** کپی سریع کانفیگ و آماده‌سازی بهتر برای استفاده در NetMod.

---

## 🧠 How It Works

This version uses a staged validation model:

1. **Initial Fast Scan** on all candidates  
2. **Top 100 Selection** based on score, latency, and stability  
3. **Final Validation** with deeper probing and optional **Xray** outbound delay test  

This reduces false positives and improves real-world usability.

---

## ⚙️ Supported Workflows

- **Cloudflare scanner**
- **CloudFront scanner**
- **Config scan**
- **IP / CIDR / range scan**
- **Manual config input**
- **File-based candidate loading**
- **NetMod export workflow**

---

## 📌 Release Highlights

- Added **Xray core integration**
- Added **CloudFront scanning support**
- Rebuilt the scanner into a **3-stage validation pipeline**
- Added **pause / resume / stop** scanning controls
- Improved config parsing and result scoring
- Redesigned UI around separate scanning cores

<img width="384" height="857" alt="image" src="https://github.com/user-attachments/assets/b1f2637f-c832-4569-a7b1-68ec8b8cfd5d" />
<img width="404" height="863" alt="image" src="https://github.com/user-attachments/assets/812f5610-18e8-42d9-98c2-f99459edc561" />
<img width="395" height="857" alt="image" src="https://github.com/user-attachments/assets/3239fd45-41e6-43da-8bf5-df9473c319f7" />



------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## 🌍 English Description
A high-performance Android application designed to discover and analyze Cloudflare nodes using **Layer 7 (Handshake 101)** verification. Unlike simple ping tools, this app performs deep stress testing to ensure the stability of V2Ray/VLESS connections.

### ✨ Key Features
- **L7 Deep Analysis:** Verifies connections up to the SSL/WS handshake level.
- **100-Step Stress Test:** Measures real-world stability with 10 batches of 10 concurrent requests.
- **Intelligent Classification:** Automatically labels IPs as **Gaming Grade** (Low Jitter), **Stream Ready**, or **Average**.
- **Massive Parallel Scanning:** Utilizes a semaphore-based multi-threading system (100+ threads).
- **Direct Integration:** One-click copy and connect for **NetMod Syna** and **v2rayNG**.
- **Automated CIDR Expansion:** Scans entire IP ranges (e.g., /20) with a single input.

---

## 🇮🇷 توضیحات فارسی
این اپلیکیشن اندرویدی ابزاری قدرتمند برای یافتن و تحلیل آی‌پی‌های تمیز کلودفلر با استفاده از روش **تست لایه ۷ (Handshake 101)** است. برخلاف ابزارهای پینگ ساده، این برنامه با شبیه‌سازی دقیق اتصال وی‌پی‌ان، پایداری واقعی را می‌سنجد.

### ✨ قابلیت‌های کلیدی:
- **آنالیز عمیق لایه ۷:** بررسی اتصال تا مرحله نهایی هندشیک SSL و WebSocket.
- **تست استرس ۱۰۰ مرحله‌ای:** محاسبه دقیق پکت‌لاست (Packet Loss) و جیتر در ۱۰ دسته ۱۰ تایی.
- **دسته‌بندی هوشمند:** تشخیص خودکار آی‌پی‌های مناسب برای **گیمینگ** (تأخیر بسیار کم) و **استریم**.
- **اسکن موازی فوق‌سریع:** استفاده از سیستم Semaphore برای مدیریت بیش از ۱۰۰ رشته همزمان.
- **اتصال مستقیم:** قابلیت کپی هوشمند و باز کردن خودکار در اپلیکیشن‌های **NetMod Syna** و **v2rayNG**.
- **پشتیبانی از رنج آی‌پی:** قابلیت تبدیل خودکار CIDR (مثل /20) به لیست آی‌پی برای اسکن انبوه.

---

<img width="377" height="813" alt="image" src="https://github.com/user-attachments/assets/7b562ded-2442-401f-a5e4-34f09fcf11c0" />
<img width="403" height="825" alt="image" src="https://github.com/user-attachments/assets/d287316b-413a-43ad-ac5b-e4a73aaec89d" />
<img width="387" height="832" alt="image" src="https://github.com/user-attachments/assets/f9e25fd2-6e2d-4506-8af1-43a696fb7a68" />
<img width="387" height="822" alt="image" src="https://github.com/user-attachments/assets/9c91fecb-cf51-4389-b576-2ec70f323616" />




---

## 📥 How to Install / نحوه نصب
1. Go to the **Releases** section on the right side of this page.
2. Download the latest `.apk` file.
3. Install it on your Android device.

۱. به بخش **Releases** در سمت راست همین صفحه بروید.
۲. آخرین فایل با پسوند `.apk` را دانلود کنید.
۳. آن را روی گوشی اندرویدی خود نصب کنید.

---

🛠 Setup Guide (For Beginners)

To start scanning, you must enter your personal server details in the INPUT tab:

SNI (Server Name Indication): Enter your subdomain address or Worker URL here.

Path: Enter the Path information exactly as it appears in your v2ray configuration.

UUID: Paste your VLESS config's unique identifier. This code is required for connection authentication.

Note: After entering the details, make sure to click the SAVE SETTINGS button to store them for future scans.


🇮🇷 راهنمای تنظیمات (برای کاربران مبتدی)
برای شروع اسکن، باید اطلاعات سرور شخصی خود را در تب INPUT وارد کنید:

SNI (Server Name Indication): 
در این قسمت آدرس ساب دامین یا ورکر را وارد کنید
Path: 
در این قسمت اطلاعاتی که در کانفیگ v2ray را زدید وارد کنید
UUID:
 کد شناسایی اختصاصی کانفیگ VLESS خود را در این کادر کپی کنید. این کد برای احراز هویت اتصال شماست.

نکته: پس از وارد کردن اطلاعات، حتماً دکمه SAVE SETTINGS را بزنید تا تنظیمات برای اسکن‌های بعدی ذخیره .


## 🛠 Tech Stack
- **Language:** Kotlin
- **UI:** Jetpack Compose
- **Concurrency:** Kotlin Coroutines & Semaphores
- **Network:** Java/Kotlin SSL Sockets (L7)

---
*Developed with ❤️ for a free and stable internet.*
حقوق معنوی این نرم افزار برای من محفوظ می باشد.
