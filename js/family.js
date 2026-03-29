// TR-GOZU Aile Üyeleri Modülü

// Aile modalını aç
function openFamilyModal() {
    document.getElementById('familyModal').classList.remove('hidden');
}

// Aile modalını kapat
function closeFamilyModal() {
    document.getElementById('familyModal').classList.add('hidden');
    document.getElementById('familyName').value = '';
    document.getElementById('familyPhone').value = '';
    document.getElementById('familyRelation').value = 'anne';
}

// Aile üyesi ekle
function addFamilyMember() {
    const name = document.getElementById('familyName').value.trim();
    const phone = document.getElementById('familyPhone').value.trim();
    const relation = document.getElementById('familyRelation').value;

    if (!name || !phone) {
        showToast('Ad ve telefon gerekli!');
        return;
    }

    if (!isValidPhone(phone)) {
        showToast('Geçerli bir telefon numarası girin!');
        return;
    }

    const member = {
        id: generateId(),
        name,
        phone,
        relation,
        relationLabel: document.getElementById('familyRelation').options[document.getElementById('familyRelation').selectedIndex].text,
        addedAt: new Date().toISOString(),
        location: null
    };

    // Aile üyelerini kaydet
    const family = getFamilyMembers();
    family.push(member);
    saveToStorage(`family_${getCurrentUserEmail()}`, family);

    closeFamilyModal();
    loadFamilyMembers();

    showToast('Aile üyesi eklendi!');
}

// Aile üyelerini al
function getFamilyMembers() {
    const email = getCurrentUserEmail();
    if (!email) return [];
    return getFromStorage(`family_${email}`, []);
}

// Aile üyelerini yükle
function loadFamilyMembers() {
    const list = document.getElementById('familyList');
    if (!list) return;

    const family = getFamilyMembers();

    if (family.length === 0) {
        list.innerHTML = '<p style="font-size: 11px; color: var(--text-dim);">Aile üyesi yok.</p>';
        return;
    }

    list.innerHTML = family.map(m => `
        <div class="family-card">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <span style="font-weight: 600;">${escapeHtml(m.name)}</span>
                <span style="font-size: 11px; color: var(--text-muted);">${m.relationLabel || m.relation}</span>
            </div>
            <div style="font-size: 11px; color: var(--text-muted); margin-top: 4px;">
                📱 ${formatPhoneNumber(m.phone)}
            </div>
            ${m.location ? `
                <div style="font-size: 10px; color: var(--success); margin-top: 4px;">
                    📍 Son görülme: ${timeSince(m.lastSeen)}
                </div>
            ` : ''}
            <div style="display: flex; gap: 5px; margin-top: 8px;">
                <button class="btn btn-outline btn-sm" style="flex: 1; padding: 6px;"
                        onclick="callFamilyMember('${m.phone}')">
                    Ara
                </button>
                <button class="btn btn-outline btn-sm" style="flex: 1; padding: 6px;"
                        onclick="removeFamilyMember('${m.id}')">
                    Sil
                </button>
            </div>
        </div>
    `).join('');
}

// Aile üyesini ara
function callFamilyMember(phone) {
    window.location.href = `tel:${phone}`;
    showToast('Arama başlatılıyor...');
}

// Aile üyesini sil
function removeFamilyMember(id) {
    if (!confirm('Aile üyesini silmek istediğinize emin misiniz?')) return;

    let family = getFamilyMembers();
    family = family.filter(m => m.id !== id);
    saveToStorage(`family_${getCurrentUserEmail()}`, family);
    loadFamilyMembers();

    showToast('Aile üyesi silindi.');
}

// Aile üyesinin konumunu güncelle
function updateFamilyMemberLocation(memberId, lat, lng) {
    const email = getCurrentUserEmail();
    let family = getFromStorage(`family_${email}`, []);

    const member = family.find(m => m.id === memberId);
    if (member) {
        member.location = { lat, lng };
        member.lastSeen = new Date().toISOString();
        saveToStorage(`family_${email}`, family);
    }
}

// Aile üyelerinin konumlarını haritada göster
function showFamilyOnMap() {
    const family = getFamilyMembers();

    family.forEach(m => {
        if (m.location && m.location.lat) {
            L.circleMarker([m.location.lat, m.location.lng], {
                radius: 10,
                color: '#00d2ff',
                fillColor: '#00d2ff',
                fillOpacity: 0.5
            }).addTo(window.map).bindPopup(`
                <b>👨‍👩‍👧‍👦 ${escapeHtml(m.name)}</b><br>
                ${m.relationLabel || m.relation}<br>
                Son görülme: ${timeSince(m.lastSeen)}
            `);
        }
    });
}
