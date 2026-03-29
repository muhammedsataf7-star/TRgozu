// TR-GOZU Batarya İzleme Modülü

let batteryMonitorInterval = null;
let lastBatteryWarning = 0;

// Batarya izlemeyi başlat
async function initBatteryMonitor() {
    // Battery API destekliyor mu?
    if (!('getBattery' in navigator)) {
        console.log('Battery API desteklenmiyor');
        // Device info ile alternatif
        monitorBatteryViaDeviceInfo();
        return;
    }

    try {
        const battery = await navigator.getBattery();

        // İlk değer
        updateBatteryUI(battery);

        // Değişiklik dinleyicileri
        battery.addEventListener('levelchange', () => {
            updateBatteryUI(battery);
            checkBatteryThreshold(battery.level);
        });

        battery.addEventListener('chargingchange', () => {
            updateBatteryUI(battery);
            if (battery.charging) {
                showToast('Şarj başladı! 🔌');
            }
        });

        // Periyodik kontrol (her 60 saniye)
        if (batteryMonitorInterval) clearInterval(batteryMonitorInterval);
        batteryMonitorInterval = setInterval(() => {
            checkBatteryThreshold(battery.level);
        }, 60000);

    } catch (error) {
        console.error('Battery API hatası:', error);
        monitorBatteryViaDeviceInfo();
    }
}

// Batarya UI'ı güncelle
function updateBatteryUI(battery) {
    const batteryDisplay = document.getElementById('batteryDisplay');
    const batteryPercent = document.getElementById('batteryPercent');

    if (!batteryDisplay) return;

    const level = Math.round(battery.level * 100);
    STATE.batteryLevel = level;

    batteryDisplay.classList.remove('hidden');

    // Renk belirle
    let color = 'var(--success)';
    if (level <= 10) color = 'var(--primary)';
    else if (level <= 30) color = 'var(--warning)';

    // İkon
    let icon = '🟢';
    if (level <= 10) icon = '🔴';
    else if (level <= 30) icon = '🟡';
    if (battery.charging) icon = '⚡';

    if (batteryPercent) {
        batteryPercent.innerHTML = `${icon} ${level}%`;
        batteryPercent.style.color = color;
    }

    // Kullanıcı verisine kaydet
    const email = getCurrentUserEmail();
    if (email) {
        updateCitizen(email, {
            battery: level,
            batteryCharging: battery.charging
        });
    }
}

// Batarya eşiği kontrol et
function checkBatteryThreshold(level) {
    const threshold = CONFIG.BATTERY_THRESHOLD / 100;
    const now = Date.now();

    // Her 5 dakikada bir uyar
    if (now - lastBatteryWarning < 300000) return;

    if (level <= threshold && !STATE.batteryWarningShown) {
        STATE.batteryWarningShown = true;
        lastBatteryWarning = now;

        showToast('⚠️ Batarya kritik seviyede! Otomatik konum paylaşımı aktif.', 5000);

        // Kritik batarya durumunda SOS otomatik gönder
        if (STATE.isLocationActive && STATE.currentLocation) {
            const email = getCurrentUserEmail();
            if (email) {
                updateCitizen(email, {
                    batteryCritical: true,
                    lastBatteryCriticalAt: new Date().toISOString()
                });
            }
        }

        // Sesli uyarı
        playSound('alert');
    }
}

// Alternatif batarya izleme (Device API yoksa)
function monitorBatteryViaDeviceInfo() {
    const batteryDisplay = document.getElementById('batteryDisplay');
    if (batteryDisplay) {
        batteryDisplay.classList.remove('hidden');
        document.getElementById('batteryPercent').textContent = '⚡ Cihaz';
    }

    // Periyodik güncelleme (cihaz bilgisi)
    if (batteryMonitorInterval) clearInterval(batteryMonitorInterval);
    batteryMonitorInterval = setInterval(() => {
        if (STATE.currentLocation && STATE.batteryLevel) {
            // %10 altında kontrol
            if (STATE.batteryLevel <= CONFIG.BATTERY_THRESHOLD) {
                checkBatteryThreshold(STATE.batteryLevel / 100);
            }
        }
    }, 60000);
}

// Batarya izlemeyi durdur
function stopBatteryMonitor() {
    if (batteryMonitorInterval) {
        clearInterval(batteryMonitorInterval);
        batteryMonitorInterval = null;
    }
}

// Kritik batarya uyarısı göster
function showCriticalBatteryWarning() {
    const modal = document.createElement('div');
    modal.className = 'modal-overlay';
    modal.innerHTML = `
        <div class="modal-content modal-sm" style="text-align: center; border-color: var(--warning);">
            <div style="font-size: 4rem; margin-bottom: 15px;">🔋</div>
            <h3 class="modal-title" style="color: var(--warning);">Kritik Batarya!</h3>
            <p style="color: var(--text-muted); margin: 15px 0;">
                Bataryanız %${STATE.batteryLevel} seviyesinde.<br>
                Acil durumlarda konumunuz otomatik paylaşılacak.
            </p>
            <button class="btn btn-primary" onclick="this.closest('.modal-overlay').remove()">
                ANLADIM
            </button>
        </div>
    `;
    document.body.appendChild(modal);

    setTimeout(() => {
        if (modal.parentNode) modal.remove();
    }, 10000);
}
