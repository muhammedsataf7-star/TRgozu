// TR-GOZU Acil Duyuru Modülü

// Duyuru modalını aç
function openAnnouncementModal() {
    document.getElementById('announcementModal').classList.remove('hidden');
}

// Duyuru modalını kapat
function closeAnnouncementModal() {
    document.getElementById('announcementModal').classList.add('hidden');
    document.getElementById('announcementTitle').value = '';
    document.getElementById('announcementContent').value = '';
    document.getElementById('announcementPriority').value = 'medium';
}

// Duyuru yayınla
function submitAnnouncement() {
    const title = document.getElementById('announcementTitle').value.trim();
    const content = document.getElementById('announcementContent').value.trim();
    const priority = document.getElementById('announcementPriority').value;

    if (!title || !content) {
        showToast('Başlık ve içerik gerekli!');
        return;
    }

    if (STATE.userRole !== 'admin') {
        showToast('Sadece yetkililer duyuru yayınlayabilir!');
        return;
    }

    const announcement = {
        id: generateId(),
        title,
        content,
        priority,
        location: STATE.currentLocation,
        createdBy: getCurrentUserEmail(),
        createdAt: new Date().toISOString()
    };

    // Duyuruları kaydet
    const announcements = getAnnouncements();
    announcements.unshift(announcement);
    saveToStorage('announcements', announcements.slice(0, 100));

    closeAnnouncementModal();
    loadAnnouncements();

    // Ticker'ı güncelle
    updateAnnouncementTicker(announcements);

    // Bildirim gönder
    sendNotification('Yeni Duyuru', title, { requireInteraction: true });
    if (priority === 'critical' || priority === 'high') playSound('alert');

    showToast('Duyuru yayınlandı!');
}

// Duyuru ticker (kaydıran şerit) başlat
function initAnnouncementTicker() {
    let tickerDiv = document.getElementById('announcementTicker');
    if (!tickerDiv) {
        tickerDiv = document.createElement('div');
        tickerDiv.id = 'announcementTicker';
        tickerDiv.className = 'ticker-wrap hidden';
        tickerDiv.innerHTML = '<div class="ticker-content" id="tickerContent"></div>';
        const header = document.querySelector('header') || document.body.firstChild;
        if (header && header.parentNode) {
            header.parentNode.insertBefore(tickerDiv, header.nextSibling);
        } else {
            document.body.prepend(tickerDiv);
        }
    }

    const announcements = getAnnouncements();
    updateAnnouncementTicker(announcements);
}

// Ticker içeriğini güncelle
function updateAnnouncementTicker(announcements) {
    const tickerDiv = document.getElementById('announcementTicker');
    const tickerContent = document.getElementById('tickerContent');
    if (!tickerDiv || !tickerContent) return;

    const criticalAndHigh = announcements.filter(a =>
        a.priority === 'critical' || a.priority === 'high'
    );

    if (criticalAndHigh.length === 0) {
        tickerDiv.classList.add('hidden');
        return;
    }

    tickerDiv.classList.remove('hidden');

    const texts = criticalAndHigh.map(a => {
        const icon = a.priority === 'critical' ? '🔴' : '🟠';
        return `${icon} ${a.title}: ${a.content}`;
    }).join('   •••   ');

    tickerContent.textContent = texts;
}

// Vatandaş için duyuruları yükle (salt okunur)
function loadCitizenAnnouncements() {
    const container = document.getElementById('citizenAnnouncementList');
    if (!container) return;

    const announcements = getAnnouncements();

    if (announcements.length === 0) {
        container.innerHTML = '<p style="font-size: 11px; color: var(--text-dim); text-align:center">Duyuru yok.</p>';
        return;
    }

    container.innerHTML = announcements.slice(0, 5).map(a => `
        <div class="announcement-card ${a.priority === 'critical' ? 'critical' : a.priority === 'high' ? 'high' : ''}">
            <div style="display:flex;justify-content:space-between;align-items:center">
                <span style="font-weight:600;font-size:12px">${getPriorityIcon(a.priority)} ${escapeHtml(a.title)}</span>
                <span style="font-size:10px;color:var(--text-muted)">${timeSince(a.createdAt)}</span>
            </div>
            <div style="font-size:11px;color:var(--text-muted);margin-top:4px">${escapeHtml(a.content)}</div>
        </div>
    `).join('');
}

// Duyuruları al
function getAnnouncements() {
    return getFromStorage('announcements', []);
}

// Duyuruları yükle
function loadAnnouncements() {
    const list = document.getElementById('announcementList');
    if (!list) return;

    const announcements = getAnnouncements();

    if (announcements.length === 0) {
        list.innerHTML = '<p style="font-size: 11px; color: var(--text-dim);">Duyuru yok.</p>';
        return;
    }

    list.innerHTML = announcements.slice(0, 10).map(a => `
        <div class="announcement-card ${a.priority === 'critical' ? 'critical' : a.priority === 'high' ? 'high' : ''}"
             onclick="viewAnnouncement('${a.id}')">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <span style="font-weight: 600;">${escapeHtml(a.title)}</span>
                <span style="font-size: 10px; color: ${getPriorityColor(a.priority)};">
                    ${getPriorityIcon(a.priority)}
                </span>
            </div>
            <div style="font-size: 11px; color: var(--text-muted); margin-top: 4px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
                ${escapeHtml(a.content)}
            </div>
            <div style="font-size: 10px; color: var(--text-dim); margin-top: 4px;">
                ${timeSince(a.createdAt)} • ${a.createdBy?.split('@')[0] || 'Yetkili'}
            </div>
        </div>
    `).join('');
}

// Öncelik ikonu
function getPriorityIcon(priority) {
    const icons = {
        critical: '🔴',
        high: '🟠',
        medium: '🔵',
        low: '⚪'
    };
    return icons[priority] || '⚪';
}

// Duyuruyu görüntüle
function viewAnnouncement(id) {
    const announcements = getAnnouncements();
    const announcement = announcements.find(a => a.id === id);

    if (!announcement) return;

    // Haritaya git
    if (announcement.location) {
        flyToLocation(announcement.location.lat, announcement.location.lng, 14);
    }

    // Duyuru detayını göster
    alert(`
        📢 ${announcement.title}
        ───────────────────────
        ${announcement.content}

        Öncelik: ${getPriorityIcon(announcement.priority)} ${announcement.priority?.toUpperCase() || 'NORMAL'}
        Tarih: ${formatDate(announcement.createdAt)}
    `);
}

// Kritik duyuruları görüntüle
function showCriticalAnnouncements() {
    const announcements = getAnnouncements();
    const critical = announcements.filter(a =>
        a.priority === 'critical' || a.priority === 'high'
    );

    critical.forEach(a => {
        showToast(`⚠️ ${a.title}`, 5000);
    });
}

// Admin: Tüm duyuruları yönet
function manageAnnouncements() {
    const announcements = getAnnouncements();

    if (announcements.length === 0) {
        return '<p style="font-size: 11px; color: var(--text-dim);">Duyuru yok.</p>';
    }

    return announcements.map(a => `
        <div class="announcement-card ${a.priority === 'critical' ? 'critical' : a.priority === 'high' ? 'high' : ''}">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <span style="font-weight: 600;">${escapeHtml(a.title)}</span>
                <button class="btn btn-outline btn-sm" style="padding: 4px 8px;"
                        onclick="deleteAnnouncement('${a.id}')">
                    Sil
                </button>
            </div>
            <div style="font-size: 10px; color: var(--text-dim); margin-top: 4px;">
                ${timeSince(a.createdAt)}
            </div>
        </div>
    `).join('');
}

// Duyuru sil
function deleteAnnouncement(id) {
    if (!confirm('Bu duyuruyu silmek istediğinize emin misiniz?')) return;

    let announcements = getAnnouncements();
    announcements = announcements.filter(a => a.id !== id);
    saveToStorage('announcements', announcements);
    loadAnnouncements();

    showToast('Duyuru silindi.');
}
