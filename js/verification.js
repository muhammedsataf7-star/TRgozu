// TR-GOZU Topluluk Doğrulama Modülü

// Sahte ihbar engelleme sistemi
let pendingVerification = null;

// Afet bildirimi doğrula
function submitDisasterVerification(disasterType, location, description) {
    const verification = {
        id: generateId(),
        disasterType,
        location,
        description,
        reporter: getCurrentUserEmail(),
        reports: [{
            user: getCurrentUserEmail(),
            vote: null, // true, false, or null
            time: new Date().toISOString()
        }],
        status: 'pending',
        confirmed: false,
        debunked: false,
        createdAt: new Date().toISOString()
    };

    // Doğrulamaları kaydet
    const verifications = getVerifications();
    verifications.push(verification);
    saveToStorage('disasterVerifications', verifications);

    showToast('Bildiriminiz kaydedildi. Diğer kullanıcılar doğrulayacak.');

    // Bildirimi işaretle (2+ aynı bildirim = otomatik doğrulama)
    checkVerificationThreshold(disasterType, location);

    return verification;
}

// Doğrulama eşiği kontrol et
function checkVerificationThreshold(disasterType, location) {
    const verifications = getVerifications();

    // Aynı tür ve yakın konumdaki bildirimleri say
    const similar = verifications.filter(v => {
        if (v.debunked || v.confirmed) return false;
        if (v.disasterType !== disasterType) return false;
        if (!v.location || !location) return false;

        const dist = calculateDistance(
            v.location.lat, v.location.lng,
            location.lat, location.lng
        );
        return dist <= 5; // 5 km içinde
    });

    if (similar.length >= CONFIG.VERIFICATION_THRESHOLD) {
        // Otomatik olarak doğrulandı olarak işaretle
        similar.forEach(v => {
            v.confirmed = true;
            v.confirmedAt = new Date().toISOString();
        });
        saveToStorage('disasterVerifications', verifications);

        showToast(`⚠️ ${similar.length} benzer bildirim! Afet otomatik olarak doğrulandı.`);
        playSound('alert');

        // Bildirim gönder
        sendNotification(
            '🔴 Afet Doğrulandı',
            `${disasterType} bildirimi ${similar.length} kişi tarafından doğrulandı!`,
            { requireInteraction: true }
        );
    }
}

// Oy ver
function voteVerification(verificationId, isTrue) {
    const verifications = getVerifications();
    const verification = verifications.find(v => v.id === verificationId);

    if (!verification) return;

    const email = getCurrentUserEmail();

    // Kullanıcının daha önce oy verip vermediğini kontrol et
    const existingVote = verification.reports.find(r => r.user === email);
    if (existingVote) {
        existingVote.vote = isTrue;
        existingVote.time = new Date().toISOString();
    } else {
        verification.reports.push({
            user: email,
            vote: isTrue,
            time: new Date().toISOString()
        });
    }

    // Oy sayılarını hesapla
    const trueVotes = verification.reports.filter(r => r.vote === true).length;
    const falseVotes = verification.reports.filter(r => r.vote === false).length;
    const totalVotes = verification.reports.length;

    // Karar ver
    if (trueVotes >= 3 && trueVotes > falseVotes * 2) {
        verification.confirmed = true;
        verification.status = 'confirmed';
    } else if (falseVotes >= 3 && falseVotes > trueVotes * 2) {
        verification.debunked = true;
        verification.status = 'debunked';
    }

    saveToStorage('disasterVerifications', verifications);

    // Bildirim göster
    if (verification.confirmed) {
        showToast('✅ Bildirim DOĞRULANDI!');
    } else if (verification.debunked) {
        showToast('❌ Bildirim ÇÜRÜTÜLDÜ!');
    } else {
        showToast('Oy verildi!');
    }

    // UI'ı güncelle
    loadVerifications();
}

// Doğrulamaları al
function getVerifications() {
    return getFromStorage('disasterVerifications', []);
}

// Doğrulamaları yükle
function loadVerifications() {
    const list = document.getElementById('verificationList');
    if (!list) return;

    const verifications = getVerifications();

    // Aktif (henüz karara varılmamış) doğrulamaları göster
    const active = verifications.filter(v => !v.confirmed && !v.debunked);

    if (active.length === 0) {
        list.innerHTML = '<p style="font-size: 11px; color: var(--text-dim);">Aktif doğrulama yok.</p>';
        return;
    }

    list.innerHTML = active.slice(0, 5).map(v => {
        const trueVotes = v.reports.filter(r => r.vote === true).length;
        const falseVotes = v.reports.filter(r => r.vote === false).length;

        return `
            <div class="verification-card">
                <div style="font-weight: 600;">
                    ${CONFIG.DISASTER_TYPES.find(d => d.id === v.disasterType)?.icon || '⚠️'}
                    ${CONFIG.DISASTER_TYPES.find(d => d.id === v.disasterType)?.label || v.disasterType}
                </div>
                <div style="font-size: 11px; color: var(--text-muted); margin-top: 4px;">
                    ${v.description ? escapeHtml(v.description).substring(0, 50) + '...' : 'Açıklama yok'}
                </div>
                <div style="font-size: 10px; color: var(--text-dim); margin-top: 4px;">
                    ${trueVotes} doğru • ${falseVotes} yanlış • ${v.reports.length} oy
                </div>
                <div style="display: flex; gap: 5px; margin-top: 8px;">
                    <button class="btn btn-success btn-sm" style="flex: 1; padding: 5px; font-size: 11px;"
                            onclick="voteVerification('${v.id}', true)">
                        ✅ Doğru
                    </button>
                    <button class="btn btn-danger btn-sm" style="flex: 1; padding: 5px; font-size: 11px;"
                            onclick="voteVerification('${v.id}', false)">
                        ❌ Yanlış
                    </button>
                </div>
            </div>
        `;
    }).join('');
}

// Doğrulama modalını aç
function openVerificationModal(verificationId) {
    pendingVerification = verificationId;
    const verifications = getVerifications();
    const verification = verifications.find(v => v.id === verificationId);

    if (!verification) return;

    const descEl = document.getElementById('verificationDesc');
    const infoEl = document.getElementById('verificationInfo');

    if (descEl) {
        descEl.textContent = `${verification.disasterType} bildirimi hakkında ne düşünüyorsunuz?`;
    }

    if (infoEl) {
        infoEl.innerHTML = `
            <p><b>Afet Türü:</b> ${verification.disasterType}</p>
            <p><b>Açıklama:</b> ${verification.description || 'Yok'}</p>
            <p><b>Konum:</b> ${verification.location ? `${verification.location.lat.toFixed(4)}, ${verification.location.lng.toFixed(4)}` : 'Belirtilmemiş'}</p>
            <p><b>Rapor Sayısı:</b> ${verification.reports.length}</p>
        `;
    }

    document.getElementById('verificationModal').classList.remove('hidden');
}

// Doğrulama modalını kapat
function closeVerificationModal() {
    document.getElementById('verificationModal').classList.add('hidden');
    pendingVerification = null;
}

// Raporu doğrula
function verifyReport(isTrue) {
    if (pendingVerification) {
        voteVerification(pendingVerification, isTrue);
    }
    closeVerificationModal();
}

// Bildirim oluştur (yetkili için)
function createReport(disasterType, lat, lng, description) {
    const report = {
        id: generateId(),
        disasterType,
        location: { lat, lng },
        description,
        createdBy: getCurrentUserEmail(),
        status: 'new',
        createdAt: new Date().toISOString()
    };

    const reports = getFromStorage('activeReports', []);
    reports.push(report);
    saveToStorage('activeReports', reports);

    showToast('Bildirim oluşturuldu!');
    return report;
}
