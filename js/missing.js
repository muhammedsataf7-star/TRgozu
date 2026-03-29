// TR-GOZU Kayıp Kişi Modülü

// Kayıp kişi modalını aç
function openMissingPersonModal() {
    document.getElementById('missingPersonModal').classList.remove('hidden');
}

// Kayıp kişi modalını kapat
function closeMissingPersonModal() {
    document.getElementById('missingPersonModal').classList.add('hidden');
    // Formu temizle
    document.getElementById('missingName').value = '';
    document.getElementById('missingAge').value = '';
    document.getElementById('missingGender').value = 'erkek';
    document.getElementById('missingLastSeen').value = '';
    document.getElementById('missingLastSeenTime').value = '';
    document.getElementById('missingNotes').value = '';
}

// Kayıp kişi bildir
function submitMissingPerson() {
    const name = document.getElementById('missingName').value.trim();
    const age = document.getElementById('missingAge').value.trim();
    const gender = document.getElementById('missingGender').value;
    const lastSeen = document.getElementById('missingLastSeen').value.trim();
    const lastSeenTime = document.getElementById('missingLastSeenTime').value;
    const notes = document.getElementById('missingNotes').value.trim();
    const email = getCurrentUserEmail();

    if (!name) {
        showToast('İsim gerekli!');
        return;
    }

    const missing = {
        id: generateId(),
        reportedBy: email,
        name,
        age: age ? parseInt(age) : null,
        gender,
        lastSeen,
        lastSeenTime: lastSeenTime || null,
        notes,
        location: STATE.currentLocation,
        status: 'missing',
        found: false,
        createdAt: new Date().toISOString()
    };

    // Kayıp kişileri kaydet
    const missingList = getMissingPersons();
    missingList.push(missing);
    saveToStorage('missingPersons', missingList);

    closeMissingPersonModal();
    loadMissingPersons();

    showToast('Kayıp kişi bildirildi!');
    playSound('alert');
}

// Kayıp kişileri al
function getMissingPersons() {
    return getFromStorage('missingPersons', []);
}

// Kayıp kişileri yükle
function loadMissingPersons() {
    const list = document.getElementById('missingPersonList');
    if (!list) return;

    const missingList = getMissingPersons();

    // Sadece bulunmamışları göster
    const active = missingList.filter(m => !m.found);

    if (active.length === 0) {
        list.innerHTML = '<p style="font-size: 11px; color: var(--text-dim);">Kayıp kişi yok.</p>';
        return;
    }

    list.innerHTML = active.map(m => `
        <div class="missing-card" onclick="viewMissingPerson('${m.id}')">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <span style="font-weight: 600;">${escapeHtml(m.name)}</span>
                ${m.age ? `<span style="font-size: 11px; color: var(--text-muted);">${m.age} yaş</span>` : ''}
            </div>
            <div style="font-size: 11px; color: var(--text-muted); margin-top: 4px;">
                ${getGenderIcon(m.gender)} ${m.gender === 'erkek' ? 'Erkek' : m.gender === 'kadin' ? 'Kadın' : 'Diğer'}
            </div>
            ${m.lastSeen ? `
                <div style="font-size: 10px; color: var(--warning); margin-top: 4px;">
                    📍 Son görülme: ${escapeHtml(m.lastSeen)}
                </div>
            ` : ''}
            ${m.lastSeenTime ? `
                <div style="font-size: 10px; color: var(--text-dim);">
                    🕐 ${formatDate(m.lastSeenTime)}
                </div>
            ` : ''}
            <div style="font-size: 10px; color: var(--text-dim); margin-top: 4px;">
                Bildiren: ${m.reportedBy}
            </div>
            ${STATE.userRole === 'admin' ? `
                <button class="btn btn-success btn-sm" style="margin-top: 8px; padding: 6px;"
                        onclick="markAsFound('${m.id}', event)">
                    ✅ Bulundu İşaretle
                </button>
            ` : ''}
        </div>
    `).join('');
}

// Kayıp kişiyi görüntüle
function viewMissingPerson(id) {
    const missingList = getMissingPersons();
    const person = missingList.find(m => m.id === id);

    if (!person) return;

    // Haritaya git
    if (person.location) {
        flyToLocation(person.location.lat, person.location.lng, 15);
        addMarkerToMap(person.location.lat, person.location.lng, '#ff4757', `Kayıp: ${person.name}`);
    }

    // Detay göster
    alert(`
        Kayıp Kişi Bilgileri
        ───────────────────
        İsim: ${person.name}
        Yaş: ${person.age || 'Bilgi yok'}
        Cinsiyet: ${person.gender === 'erkek' ? 'Erkek' : person.gender === 'kadin' ? 'Kadın' : 'Diğer'}
        Son Görülme: ${person.lastSeen || 'Bilgi yok'}
        Son Görülme Zamanı: ${person.lastSeenTime ? formatDate(person.lastSeenTime) : 'Bilgi yok'}
        Notlar: ${person.notes || 'Yok'}
        Bildiren: ${person.reportedBy}
    `);
}

// Bulundu işaretle
function markAsFound(id, event) {
    event.stopPropagation();

    if (!confirm('Bu kişiyi bulundu olarak işaretlemek istediğinize emin misiniz?')) return;

    let missingList = getMissingPersons();
    const person = missingList.find(m => m.id === id);

    if (person) {
        person.found = true;
        person.foundAt = new Date().toISOString();
        person.foundBy = getCurrentUserEmail();
        saveToStorage('missingPersons', missingList);
        loadMissingPersons();

        showToast(`${person.name} bulundu olarak işaretlendi!`);
        playSound('success');
    }
}

// Cinsiyet ikonu
function getGenderIcon(gender) {
    if (gender === 'erkek') return '👨';
    if (gender === 'kadin') return '👩';
    return '👤';
}

// Kayıp kişiyi haritada göster
function showMissingPersonsOnMap() {
    const missingList = getMissingPersons();
    const active = missingList.filter(m => !m.found);

    active.forEach(m => {
        if (m.location) {
            L.circleMarker([m.location.lat, m.location.lng], {
                radius: 12,
                color: '#ff4757',
                fillColor: '#ff4757',
                fillOpacity: 0.5,
                weight: 2
            }).addTo(window.map).bindPopup(`
                <b style="color: #ff4757">🔴 Kayıp Kişi</b><br>
                <b>${escapeHtml(m.name)}</b><br>
                ${m.age ? `${m.age} yaş` : ''}<br>
                Son görülme: ${escapeHtml(m.lastSeen || '-')}
            `);
        }
    });
}

// Admin: Kayıp kişileri haritada göster
function loadAdminMissingPersons() {
    const list = document.getElementById('missingPersonList');
    if (!list) return;

    const missingList = getMissingPersons();

    if (missingList.length === 0) {
        list.innerHTML = '<p style="font-size: 11px; color: var(--text-dim);">Kayıp kişi yok.</p>';
        return;
    }

    list.innerHTML = missingList.map(m => {
        const statusClass = m.found ? 'background: rgba(46,204,113,0.1);' : '';
        const statusBadge = m.found ? '✅ BULUNDU' : '🔴 KAYIP';

        return `
            <div class="missing-card" style="${statusClass}" onclick="viewMissingPerson('${m.id}')">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <span style="font-weight: 600;">${escapeHtml(m.name)}</span>
                    <span style="font-size: 10px; color: ${m.found ? 'var(--success)' : 'var(--primary)'};">
                        ${statusBadge}
                    </span>
                </div>
                ${m.location ? `
                    <div style="font-size: 10px; color: var(--success); margin-top: 4px;">
                        📍 Konum kaydedildi
                    </div>
                ` : ''}
            </div>
        `;
    }).join('');
}
