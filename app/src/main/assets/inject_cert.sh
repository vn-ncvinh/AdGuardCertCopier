#!/system/bin/sh
# Inject certificates - Namespace Fix

# [THAY ĐỔI QUAN TRỌNG] Dùng thư mục trung gian trên /data để Zygote có thể nhìn thấy
STAGE_DIR="/data/local/tmp/cert_staging"
SYSTEM_CERTS="/system/etc/security/cacerts"
APEX_CERTS="/apex/com.android.conscrypt/cacerts"
MODULE_CERTS="$1"

# 1. Dọn dẹp & Tạo điểm mount trung gian
umount -l $STAGE_DIR 2>/dev/null
rm -rf $STAGE_DIR
mkdir -p -m 755 $STAGE_DIR

# 2. Mount tmpfs vào thư mục trung gian (Thay vì mount thẳng vào System)
mount -t tmpfs tmpfs $STAGE_DIR
# Giới hạn quyền ngay lập tức
chmod 755 $STAGE_DIR

# 3. Copy chứng chỉ vào tmpfs này
# Copy từ APEX hoặc System gốc vào
cp $APEX_CERTS/* $STAGE_DIR/ 2>/dev/null || cp $SYSTEM_CERTS/* $STAGE_DIR/ 2>/dev/null || true

# Copy chứng chỉ mới từ Module
if [ -d "$MODULE_CERTS" ]; then
    cp $MODULE_CERTS/* $STAGE_DIR/ 2>/dev/null
fi

# 4. Set quyền và Context (Giữ nguyên như cũ)
chown -R root:root $STAGE_DIR
chmod 644 $STAGE_DIR/*
chmod 755 $STAGE_DIR
# Quan trọng: set context system_file để Settings đọc được
chcon -R u:object_r:system_file:s0 $STAGE_DIR

# 5. Inject vào Zygote & App
ZYGOTE_PID=$(pidof zygote || true)
ZYGOTE64_PID=$(pidof zygote64 || true)

for Z_PID in $ZYGOTE_PID $ZYGOTE64_PID; do
    if [ -n "$Z_PID" ]; then
        # [THAY ĐỔI] Bind từ STAGE_DIR (cái mà Zygote nhìn thấy được) vào APEX
        nsenter --mount=/proc/$Z_PID/ns/mnt -- /bin/mount --bind $STAGE_DIR $APEX_CERTS
    fi
done

# 6. Inject cho các App đang chạy
APP_PIDS=$(echo "$ZYGOTE_PID $ZYGOTE64_PID" | xargs -n1 ps -o 'PID' -P 2>/dev/null | grep -v PID || true)
for PID in $APP_PIDS; do
    nsenter --mount=/proc/$PID/ns/mnt -- /bin/mount --bind $STAGE_DIR $APEX_CERTS &
done
wait

echo "Inject Success!"