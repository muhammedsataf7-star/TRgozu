// TR-GOZU Akıllı Yardım Modülü

// Yardım talep modalını aç
function openHelpRequestModal() {
    document.getElementById('helpRequestModal').classList.remove('hidden');
}

// Yardım talep modalını kapat
function closeHelpRequestModal() {
    document.getElementById('helpRequestModal').classList.add('hidden');
    document.getElementById('helpType').value = 'su';
    document.getElementById('helpDesc').value = '';
}

// Yardım talebi gönder
function submitHelpRequest() {
    const type = document.getElementById('helpType').value;
    const desc = document.getElementById('helpDesc').value.trim();
    const email = getCurrentUserEmail();

    if (!email) {
        showToast('Giriş yapmanız gerekiyor!');
        return;
    }

    const helpRequest = {
        id: generateId(),
        user: email,
        type,
        typeLabel: CONFIG.HELP_TYPES[type]?.label || type,
        typeIcon: CONFIG.HELP_TYPES[type]?.icon || '📦',
        description: desc,
        location: STATE.currentLocation,
        priority: CONFIG.HELP_TYPES[type]?.priority || 'low',
        status: 'pending',
        createdAt: new Date().toISOString()
    };

    // Yardım taleplerini kaydet
    const requests = getHelpRequests();
    requests.push(helpRequest);
    saveToStorage('helpRequests', requests);

    closeHelpRequestModal();
    loadHelpRequests();

    showToast('Yardım talebiniz iletildi!');
    playSound('success');
}

// Yardım taleplerini al
function getHelpRequests() {
    return getFromStorage('helpRequests', []);
}

// Yardım taleplerini yükle
function loadHelpRequests() {
    const list = document.getElementById('helpRequestsList');
    if (!list) return;

    const requests = getHelpRequests();
    const email = getCurrentUserEmail();

    // Kullanıcının taleplerini filtrele
    const userRequests = requests.filter(r => r.user === email);

    if (userRequests.length === 0) {
        list.innerHTML = '<p style="font-size: 11px; color: var(--text-dim);">Yardım talebiniz yok.</p>';
        return;
    }

    list.innerHTML = userRequests.map(r => `
        <div class="help-card" style="border-left-color: ${getPriorityColor(r.priority)};">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <span style="font-size: 1.1rem;">${r.typeIcon}</span>
                <span style="font-size: 10px; color: ${getPriorityColor(r.priority)};">${r.priority.toUpperCase()}</span>
            </div>
            <div style="font-size: 12px; font-weight: 600; margin-top: 4px;">
                ${r.typeLabel}
            </div>
            ${r.description ? `<div style="font-size: 11px; color: var(--text-muted);">${escapeHtml(r.description)}</div>` : ''}
            <div style="font-size: 10px; color: var(--text-dim); margin-top: 4px;">
                ${timeSince(r.createdAt)}
            </div>
            <div style="font-size: 10px; color: ${getStatusColor(r.status)};">
                ${getStatusIcon(r.status)} ${r.status.toUpperCase()}
            </div>
        </div>
    `).join('');
}

// Öncelik rengini al
function getPriorityColor(priority) {
    const colors = {
        critical: 'var(--primary)',
        high: 'var(--warning)',
        medium: 'var(--secondary)',
        low: 'var(--success)'
    };
    return colors[priority] || 'var(--text-muted)';
}

// Durum rengini al
function getStatusColor(status) {
    const colors = {
        pending: 'var(--warning)',
        in_progress: 'var(--secondary)',
        resolved: 'var(--success)',
        cancelled: 'var(--text-dim)'
    };
    return colors[status] || 'var(--text-muted)';
}

// Durum ikonu
function getStatusIcon(status) {
    const icons = {
        pending: '⏳',
        in_progress: '🔄',
        resolved: '✅',
        cancelled: '❌'
    };
    return icons[status] || '📋';
}

// Admin: Tüm yardım taleplerini yükle
function loadAllHelpRequests() {
    const requests = getHelpRequests();

    if (requests.length === 0) {
        return '<p style="font-size: 11px; color: var(--text-dim);">Yardım talebi yok.</p>';
    }

    return requests.map(r => `
        <div class="help-card" onclick="processHelpRequest('${r.id}')">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <span style="font-size: 1.2rem;">${r.typeIcon}</span>
                <span style="font-size: 10px; background: ${getPriorityColor(r.priority)}; padding: 2px 8px; border-radius: 8px; color: white;">
                    ${r.priority.toUpperCase()}
                </span>
            </div>
            <div style="font-size: 12px; font-weight: 600; margin-top: 4px;">
                ${r.typeLabel}
            </div>
            <div style="font-size: 11px; color: var(--text-muted);">
                👤 ${r.user}
            </div>
            ${r.location ? `
                <div style="font-size: 10px; color: var(--success); margin-top: 4px;">
                    📍 Konum paylaşıldı
                </div>
            ` : ''}
        </div>
    `).join('');
}

// Yardım talebini işle
function processHelpRequest(requestId) {
    const requests = getHelpRequests();
    const request = requests.find(r => r.id === requestId);

    if (!request) return;

    // Haritaya git
    if (request.location) {
        flyToLocation(request.location.lat, request.location.lng, 16);
    }

    showToast(`${request.typeLabel} talebi seçildi.`);
}

// Yakın yardım taleplerini bul
function findNearbyHelpRequests(lat, lng, radiusKm = 5) {
    const requests = getHelpRequests();

    return requests.filter(r => {
        if (!r.location || r.status === 'resolved') return false;
        const dist = calculateDistance(lat, lng, r.location.lat, r.location.lng);
        return dist <= radiusKm;
    }).map(r => ({
        ...r,
        distance: calculateDistance(lat, lng, r.location.lat, r.location.lng)
    })).sort((a, b) => {
        // Önce kritik, sonra mesafe
        const priorityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
        if (priorityOrder[a.priority] !== priorityOrder[b.priority]) {
            return priorityOrder[a.priority] - priorityOrder[b.priority];
        }
        return a.distance - b.distance;
    });
}
