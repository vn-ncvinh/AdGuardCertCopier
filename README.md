# Cert Installer (root)

- Cài chứng chỉ vào `/data/adb/modules/adguardcert/system/etc/security/cacerts/9a5ba575.0`
- Tự chuyển PEM/DER/PKCS#12 -> PEM (ưu tiên CA nếu có nhiều block)
- Hỏi lưu chứng chỉ vừa cài (đặt tên) -> quản lý danh sách -> cài lại từ danh sách
- Đếm ngược 5s và reboot sau khi cài thành công
- Yêu cầu thiết bị đã root (Magisk)

## Build
- Mở bằng Android Studio, sync Gradle
- Nếu thiếu libsu: đảm bảo `settings.gradle` có `maven { url 'https://jitpack.io' }`
- Run trên thiết bị đã root
