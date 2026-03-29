// TR-GOZU Sağlık Durumu Modülü

let lastHealthUpdate = 0;

// Sağlık durumunu gönder
function sendHealthStatus(status) {
    const now = Date.now();

    // 30 saniyede bir güncelleme sınırı
    if (now - lastHealthUpdate < 30000 && status === STATE.healthStatus) {
        showToast('Sağlık durumunuz zaten güncel.');
        return;
    }

    const email = getCurrentUserEmail();
    if (!email) {
        showToast('Giriş yapmanız gerekiyor!');
        return;
    }

    // UI'ı güncelle
    updateHealthButtons(status);

    // Not al (varsa)
    const note = document.getElementById('healthNote')?.value || '';

    // Vatandaş verisini güncelle
    updateCitizen(email, {
        healthStatus: status,
        healthNote: note,
        healthUpdatedAt: new Date().toISOString()
    });

    STATE.healthStatus = status;
    lastHealthUpdate = now;

    // Durum etiketini güncelle
    const labelEl = document.getElementById('healthStatusLabel');
    if (labelEl) {
        const statusInfo = CONFIG.HEALTH_STATUS[status];
        labelEl.innerHTML = `${statusInfo?.icon || ''} ${statusInfo?.label || status} durumu gönderildi!`;
        labelEl.style.color = statusInfo?.color || 'var(--secondary)';
    }

    // Kritik durumlarda bildirim
    if (status === 'kritik' || status === 'enkaz') {
        playSound('alert');
        sendNotification(
            '⚠️ Sağlık Durumu Güncellemesi',
            `${email} ${CONFIG.HEALTH_STATUS[status]?.label} durumunu bildirdi!`,
            { requireInteraction: true }
        );
    }

    showToast(`Sağlık durumu: ${CONFIG.HEALTH_STATUS[status]?.label || status}`);

    // Haritayı güncelle (yetkili görünümünde)
    if (typeof loadCitizensOnMap === 'function') {
        loadCitizensOnMap();
    }
}

// Sağlık butonlarını güncelle
function updateHealthButtons(activeStatus) {
    const buttons = document.querySelectorAll('.health-btn');
    buttons.forEach(btn => {
        const btnStatus = btn.dataset.status;
        if (btnStatus === activeStatus) {
            btn.classList.add('health-active');
            btn.style.borderColor = CONFIG.HEALTH_STATUS[btnStatus]?.color || 'white';
        } else {
            btn.classList.remove('health-active');
            btn.style.borderColor = 'transparent';
        }
    });
}

// Sağlık durumunu al
function getHealthStatus(email) {
    const citizens = getCitizens();
    const citizen = citizens.find(c => c.email === email);
    return citizen?.healthStatus || null;
}

// Sağlık geçmişini al
function getHealthHistory(email) {
    const citizens = getCitizens();
    const citizen = citizens.find(c => c.email === email);

    if (!citizen) return [];

    const history = [];
    if (citizen.healthUpdatedAt) {
        history.push({
            status: citizen.healthStatus,
            note: citizen.healthNote,
            time: citizen.healthUpdatedAt
        });
    }

    return history;
}

// Kritik sağlık durumundakileri bul
function getCriticalHealthCases() {
    const citizens = getCitizens();
    return citizens.filter(c =>
        c.healthStatus === 'kritik' ||
        c.healthStatus === 'enkaz'
    );
}

// Sağlık durumuna göre renk
function getHealthColor(status) {
    return CONFIG.HEALTH_STATUS[status]?.color || '#94a3b8';
}

// Sağlık durumuna göre öncelik
function getHealthPriority(status) {
    const priorities = {
        enkaz: 100,
        kritik: 80,
        yaraliyim: 50,
        iyiyim: 10
    };
    return priorities[status] || 0;
}

// Sağlık durumunu görselleştir (harita için)
function visualizeHealthOnMap(citizens) {
    if (!window.map) return;

    citizens.forEach(c => {
        if (!c.lat || !c.lng || !c.healthStatus) return;

        const color = getHealthColor(c.healthStatus);
        const priority = getHealthPriority(c.healthStatus);

        if (priority >= 50) {
            // Kritik vakalar için daire
            L.circleMarker([c.lat, c.lng], {
                radius: 12,
                color: color,
                fillColor: color,
                fillOpacity: 0.5,
                weight: 3
            }).addTo(window.map).bindPopup(`
                <b>${CONFIG.HEALTH_STATUS[c.healthStatus]?.icon || ''} ${c.healthStatus}</b><br>
                <small>${c.email}</small>
            `);
        }
    });
}
