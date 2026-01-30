#!/system/bin/sh
# Inject certificates without reboot script

TEMP_DIR="/data/local/tmp/tmp-ca-copy"
SYSTEM_CERTS="/system/etc/security/cacerts"
APEX_CERTS="/apex/com.android.conscrypt/cacerts"
MODULE_CERTS="$1"

rm -rf $TEMP_DIR
mkdir -p -m 700 $TEMP_DIR
cp $APEX_CERTS/* $TEMP_DIR/ 2>/dev/null || cp $SYSTEM_CERTS/* $TEMP_DIR/ 2>/dev/null || true
mount -t tmpfs tmpfs $SYSTEM_CERTS
mv $TEMP_DIR/* $SYSTEM_CERTS/ 2>/dev/null || true
cp $MODULE_CERTS/* $SYSTEM_CERTS/ 2>/dev/null || true
chown root:root $SYSTEM_CERTS/*
chmod 644 $SYSTEM_CERTS/*
chcon u:object_r:system_file:s0 $SYSTEM_CERTS/*
rm -rf $TEMP_DIR

ZYGOTE_PID=$(pidof zygote || true)
ZYGOTE64_PID=$(pidof zygote64 || true)

for Z_PID in $ZYGOTE_PID $ZYGOTE64_PID; do
    [ -n "$Z_PID" ] && nsenter --mount=/proc/$Z_PID/ns/mnt -- /bin/mount --bind $SYSTEM_CERTS $APEX_CERTS 2>/dev/null
done

APP_PIDS=$(echo "$ZYGOTE_PID $ZYGOTE64_PID" | xargs -n1 ps -o 'PID' -P 2>/dev/null | grep -v PID || true)
for PID in $APP_PIDS; do
    nsenter --mount=/proc/$PID/ns/mnt -- /bin/mount --bind $SYSTEM_CERTS $APEX_CERTS 2>/dev/null &
done
wait
