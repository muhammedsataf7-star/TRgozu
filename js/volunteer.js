// TR-GOZU Gönüllü Modülü

// Gönüllü modalını aç
function openVolunteerModal() {
    document.getElementById('volunteerModal').classList.remove('hidden');
}

// Gönüllü modalını kapat
function closeVolunteerModal() {
    document.getElementById('volunteerModal').classList.add('hidden');
    // Formu temizle
    document.getElementById('volName').value = '';
    document.getElementById('volEmail').value = '';
    document.getElementById('volPhone').value = '';
    document.getElementById('volSkill').value = 'ilkyardim';
}

// Gönüllü kaydet
function submitVolunteer() {
    const name = document.getElementById('volName').value.trim();
    const email = document.getElementById('volEmail').value.trim();
    const phone = document.getElementById('volPhone').value.trim();
    const skill = document.getElementById('volSkill').value;

    if (!name || !email || !phone) {
        showToast('Tüm alanları doldurun!');
        return;
    }

    if (!isValidEmail(email)) {
        showToast('Geçerli bir e-posta girin!');
        return;
    }

    if (!isValidPhone(phone)) {
        showToast('Geçerli bir telefon numarası girin!');
        return;
    }

    const volunteer = {
        id: generateId(),
        name,
        email,
        phone,
        skill,
        skillLabel: CONFIG.VOLUNTEER_SKILLS[skill]?.label || skill,
        registeredAt: new Date().toISOString(),
        location: STATE.currentLocation
    };

    // Gönüllüleri kaydet
    const volunteers = getVolunteers();
    volunteers.push(volunteer);
    saveToStorage('volunteers', volunteers);

    closeVolunteerModal();
    loadVolunteerList();

    showToast('Gönüllü olarak kayıt oldunuz! Teşekkürler.');
    playSound('success');
}

// Gönüllüleri al
function getVolunteers() {
    return getFromStorage('volunteers', []);
}

// Gönüllü listesini yükle
function loadVolunteerList() {
    const list = document.getElementById('volunteerList');
    if (!list) return;

    const volunteers = getVolunteers();
    const email = getCurrentUserEmail();

    if (volunteers.length === 0) {
        list.innerHTML = '<p style="font-size: 11px; color: var(--text-dim);">Henüz gönüllü yok.</p>';
        return;
    }

    list.innerHTML = volunteers.map(v => `
        <div class="volunteer-card">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <span style="font-weight: 600;">${escapeHtml(v.name)}</span>
                <span>${CONFIG.VOLUNTEER_SKILLS[v.skill]?.icon || '📍'}</span>
            </div>
            <div style="font-size: 11px; color: var(--text-muted); margin-top: 4px;">
                ${v.skillLabel || v.skill} • ${v.phone}
            </div>
            ${v.location ? `
                <button class="btn btn-outline btn-sm" style="margin-top: 8px; padding: 6px 10px;"
                        onclick="contactVolunteer('${v.email}', '${escapeHtml(v.name)}')">
                    İletişim
                </button>
            ` : ''}
        </div>
    `).join('');
}

// Gönüllü ile iletişime geç
function contactVolunteer(email, name) {
    // Mesaj modalını aç
    document.getElementById('newMsgRecipient').value = email;
    startNewMessage();
    document.getElementById('newMessageModal').classList.remove('hidden');
}

// Admin gönüllü listesini yükle
function loadAdminVolunteerList() {
    const list = document.getElementById('adminVolunteerList');
    if (!list) return;

    const volunteers = getVolunteers();

    if (volunteers.length === 0) {
        list.innerHTML = '<p style="font-size: 11px; color: var(--text-dim);">Kayıtlı gönüllü yok.</p>';
        return;
    }

    list.innerHTML = volunteers.map(v => `
        <div class="volunteer-card" onclick="flyToLocation(${v.location?.lat || 0}, ${v.location?.lng || 0})">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <strong>${escapeHtml(v.name)}</strong>
                <span style="font-size: 1.2rem;">${CONFIG.VOLUNTEER_SKILLS[v.skill]?.icon || '📍'}</span>
            </div>
            <div style="font-size: 11px; color: var(--text-muted); margin-top: 4px;">
                ${v.skillLabel || v.skill}<br>
                📧 ${v.email}<br>
                📱 ${v.phone}
            </div>
            ${v.location ? `
                <div style="font-size: 10px; color: var(--success); margin-top: 4px;">
                    📍 Konum paylaştı
                </div>
            ` : ''}
        </div>
    `).join('');
}

// Yetenek bazlı gönüllü bul
function findVolunteersBySkill(skill) {
    const volunteers = getVolunteers();
    return volunteers.filter(v => v.skill === skill && v.location);
}

// Yakın gönüllüleri bul
function findNearbyVolunteers(lat, lng, radiusKm = 10) {
    const volunteers = getVolunteers();
    return volunteers.filter(v => {
        if (!v.location) return false;
        const dist = calculateDistance(lat, lng, v.location.lat, v.location.lng);
        return dist <= radiusKm;
    }).map(v => ({
        ...v,
        distance: calculateDistance(lat, lng, v.location.lat, v.location.lng)
    })).sort((a, b) => a.distance - b.distance);
}
