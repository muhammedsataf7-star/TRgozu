// TR-GOZU SOS Modülü

let sosCountdownTimer = null;
let sosCount = 0;
let lastSosTime = 0;

// SOS'i tetikle
function triggerSOS() {
    const modal = document.getElementById('sosModal');
    if (!modal) return;

    const now = Date.now();

    // Panik algılama - ardışık SOS basımları
    if (now - lastSosTime < CONFIG.PANIC_PRESS_INTERVAL) {
        sosCount++;
        if (sosCount >= CONFIG.PANIC_PRESS_COUNT) {
            STATE.isPanic = true;
            document.getElementById('sosBtn').classList.add('panic');
            document.body.classList.add('panic-flash');
            setTimeout(() => document.body.classList.remove('panic-flash'), 1500);
            showToast('🚨 PANİK DURUMU TESPİT EDİLDİ!');
        }
    } else {
        sosCount = 1;
    }
    lastSosTime = now;

    // SOS modalini göster
    modal.classList.remove('hidden');
    document.getElementById('sosCountdown').textContent = CONFIG.SOS_COUNTDOWN;
    document.getElementById('sosStatus').innerHTML = 'SOS sinyali gönderilecek...<br>İptal etmek için VAZGEÇ butonuna basın.';

    // Ses çal
    playSound('sos');

    // Geri sayımı başlat
    startSOSCountdown();
}

// SOS geri sayımı
function startSOSCountdown() {
    let count = CONFIG.SOS_COUNTDOWN;

    if (sosCountdownTimer) clearInterval(sosCountdownTimer);

    sosCountdownTimer = setInterval(() => {
        count--;
        const countdownEl = document.getElementById('sosCountdown');

        if (countdownEl) {
            countdownEl.textContent = count;
            countdownEl.style.transform = 'scale(1.2)';
            setTimeout(() => countdownEl.style.transform = 'scale(1)', 100);
        }

        if (count <= 0) {
            clearInterval(sosCountdownTimer);
            forceSendSOS();
        }
    }, 1000);
}

// SOS'i iptal et
function cancelSOS() {
    if (sosCountdownTimer) {
        clearInterval(sosCountdownTimer);
        sosCountdownTimer = null;
    }

    const modal = document.getElementById('sosModal');
    if (modal) modal.classList.add('hidden');

    document.getElementById('sosBtn').classList.remove('panic');
    STATE.isPanic = false;
    sosCount = 0;

    showToast('SOS sinyali iptal edildi.');
}

// SOS'i zorla gönder
async function forceSendSOS() {
    if (sosCountdownTimer) {
        clearInterval(sosCountdownTimer);
        sosCountdownTimer = null;
    }

    const modal = document.getElementById('sosModal');
    const statusEl = document.getElementById('sosStatus');

    // Konum kontrolü
    let lat, lng;
    if (STATE.currentLocation) {
        lat = STATE.currentLocation.lat;
        lng = STATE.currentLocation.lng;
    } else {
        // Konum al
        try {
            const position = await new Promise((resolve, reject) => {
                navigator.geolocation.getCurrentPosition(resolve, reject, {
                    enableHighAccuracy: true,
                    timeout: 5000
                });
            });
            lat = position.coords.latitude;
            lng = position.coords.longitude;
        } catch (err) {
            showToast('Konum alınamadı! Lütfen konum iznini verin.');
            if (modal) modal.classList.add('hidden');
            return;
        }
    }

    // SOS gönder
    const email = getCurrentUserEmail();
    if (!email) {
        showToast('Giriş yapmanız gerekiyor!');
        if (modal) modal.classList.add('hidden');
        return;
    }

    const wasPanic = STATE.isPanic;

    if (statusEl) {
        statusEl.innerHTML = '<span style="color: var(--secondary);">Kandilli ile bölge kontrol ediliyor…</span>';
    }

    let kCheck;
    try {
        kCheck = await verifyKandilliSeismicNear(lat, lng);
    } catch (e) {
        kCheck = {
            verified: true,
            reason: 'kontrol_hatasi',
            detail: 'Kontrol sırasında hata; güvenlik için yetkili bildirimi açık.'
        };
    }

    const forwardToAuthority = wasPanic || kCheck.verified;

    addSOS(email, lat, lng, wasPanic, {
        forwardToAuthority,
        kandilliCheck: kCheck
    });

    if (statusEl) {
        if (forwardToAuthority) {
            statusEl.innerHTML = wasPanic
                ? '<span style="color: var(--primary); font-weight: bold;">🚨 PANİK SİNYALİ GÖNDERİLDİ!</span>'
                : '<span style="color: var(--primary);">🆘 SOS SİNYALİ GÖNDERİLDİ!</span>';
        } else {
            statusEl.innerHTML =
                '<span style="color: var(--warning);">Kayıt oluşturuldu. Kandilli eşleşmesi yok — yetkili bildirimi yapılmadı.</span>';
        }
    }

    if (forwardToAuthority) {
        sendNotification(
            wasPanic ? '🚨 Panik Sinyali' : '🆘 SOS Sinyali',
            `${email} acil yardım talep ediyor!`,
            { requireInteraction: true }
        );
    }

    setTimeout(() => {
        if (modal) modal.classList.add('hidden');
        document.getElementById('sosBtn').classList.remove('panic');

        if (wasPanic && forwardToAuthority) {
            showToast('🚨 Panik sinyali yetkililere iletildi!', 5000);
        } else if (forwardToAuthority) {
            showToast('🆘 SOS yetkililere iletildi!', 3000);
        } else {
            showToast(
                `Kandilli: ${kCheck.detail || 'eşleşme yok'}. Yetkiliye gönderilmedi. Gerçek acil durumda ardışık hızlı SOS (panik) kullanın.`,
                6500
            );
        }

        if (typeof loadCitizensOnMap === 'function') {
            loadCitizensOnMap();
        }
        if (typeof updatePriorityZones === 'function') {
            updatePriorityZones();
        }
    }, 2000);

    STATE.isPanic = false;
    sosCount = 0;
}

// SOS durumunu al
function getSOSStatus(email) {
    const sosList = getSOSList();
    return sosList.find(s => s.user === email);
}

// SOS'i çözümlenmiş olarak işaretle
function resolveSOS(email) {
    let sosList = getSOSList();
    const sos = sosList.find(s => s.user === email);

    if (sos) {
        sos.resolved = true;
        sos.resolvedAt = new Date().toISOString();
        sos.resolvedBy = STATE.userRole === 'admin' ? getCurrentUserEmail() : 'SYSTEM';
        saveToStorage('sosList', sosList);

        // Vatandaşı güncelle
        updateCitizen(email, { isSOS: false, isPanic: false });
    }
}

// Aktif SOS sayısı
function getActiveSOSCount() {
    const sosList = getSOSList();
    return sosList.filter(s => !s.resolved).length;
}

// Bölgedeki SOS yoğunluğu
function getSOSDensity(lat, lng, radiusKm = 5) {
    const sosList = getSOSList();
    const citizens = getCitizens();

    let density = 0;
    const nearby = [];

    // SOS'leri kontrol et
    sosList.forEach(s => {
        if (s.resolved || s.forwardToAuthority === false) return;
        const dist = calculateDistance(lat, lng, s.lat, s.lng);
        if (dist <= radiusKm) {
            density++;
            nearby.push({ ...s, distance: dist });
        }
    });

    // Vatandaşları kontrol et
    citizens.forEach(c => {
        if (!c.lat || !c.lng || c.isSOS || c.isPanic) return;
        const dist = calculateDistance(lat, lng, c.lat, c.lng);
        if (dist <= radiusKm) {
            density += 0.5; // Normal vatandaş daha az ağırlıklı
        }
    });

    return { density, nearby, riskLevel: density >= 10 ? 'extreme' : density >= 5 ? 'high' : density >= 3 ? 'medium' : 'low' };
}

// SOS heatmap için veri
function getSOSHeatmapData() {
    const sosList = getSOSList();
    const heatmapData = [];

    sosList.forEach(s => {
        if (s.resolved || !s.lat || !s.lng) return;
        if (s.forwardToAuthority === false) return;
        heatmapData.push({
            lat: s.lat,
            lng: s.lng,
            intensity: s.isPanic ? 1.0 : 0.8
        });
    });

    return heatmapData;
}
