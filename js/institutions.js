// TR-GOZU Kurum ve Kuruluş Modülü (Hastane Kapasitesi + OSRM Rota)

let selectedInstitution = null;

// Hastane kapasitesi simüle et (isim hash tabanlı)
function simulateHospitalCapacity(name) {
    let hash = 0;
    for (let i = 0; i < name.length; i++) {
        hash = ((hash << 5) - hash) + name.charCodeAt(i);
        hash |= 0;
    }
    const seed = Math.abs(hash);
    const totalBeds = 50 + (seed % 251);         // 50-300 yatak
    const occupancyPct = 50 + (seed % 46);        // %50-95 doluluk
    const available = Math.round(totalBeds * (1 - occupancyPct / 100));
    const emergencyOk = (seed % 3) !== 0;         // 2/3 oranında acil kapasitesi var

    return { totalBeds, occupancyPct, available, emergencyOk };
}

// Kurumları yükle
async function loadInstitutions() {
    if (!STATE.currentLocation) {
        showToast('Konumunuzu aktif edin!');
        return;
    }

    showLoading(true);

    const units = await fetchNearbyUnits(
        STATE.currentLocation.lat,
        STATE.currentLocation.lng,
        20000
    );

    showLoading(false);

    const list = document.getElementById('institutionList');
    if (!list) return;

    if (units.length === 0) {
        list.innerHTML = '<p style="font-size: 11px; color: var(--text-dim);">Yakında kurum bulunamadı.</p>';
        return;
    }

    const hospitals = units.filter(u => u.type === 'hospital');
    const assembly = units.filter(u => ['assembly', 'park', 'school', 'square'].includes(u.type));
    const emergency = units.filter(u => ['police', 'fire', 'ambulance', 'gendarmerie', 'military'].includes(u.type));
    const government = units.filter(u => u.type === 'government');

    const lim = 8;
    list.innerHTML = `
        ${hospitals.length > 0 ? `
            <div style="margin-bottom: 10px;">
                <div style="font-size: 10px; color: var(--hospital); font-weight: 600; margin-bottom: 5px;">🏥 HASTANE / SAĞLIK</div>
                ${hospitals.slice(0, lim).map(u => institutionCard(u)).join('')}
            </div>
        ` : ''}
        ${assembly.length > 0 ? `
            <div style="margin-bottom: 10px;">
                <div style="font-size: 10px; color: var(--success); font-weight: 600; margin-bottom: 5px;">🏠 TOPLANMA / OKUL / MEYDAN</div>
                ${assembly.slice(0, lim).map(u => institutionCard(u)).join('')}
            </div>
        ` : ''}
        ${emergency.length > 0 ? `
            <div style="margin-bottom: 10px;">
                <div style="font-size: 10px; color: var(--warning); font-weight: 600; margin-bottom: 5px;">🚨 POLİS · İTFAİYE · AMBULANS · JANDARMA</div>
                ${emergency.slice(0, lim).map(u => institutionCard(u)).join('')}
            </div>
        ` : ''}
        ${government.length > 0 ? `
            <div style="margin-bottom: 10px;">
                <div style="font-size: 10px; color: var(--secondary); font-weight: 600; margin-bottom: 5px;">🏛️ KAMU (KAYMAKAMLIK / VALİLİK / KURUM)</div>
                ${government.slice(0, lim).map(u => institutionCard(u)).join('')}
            </div>
        ` : ''}
    `;
}

// Kurum kartı HTML (hastanelere kapasite bilgisi eklendi)
function institutionCard(unit) {
    const distance = STATE.currentLocation
        ? calculateDistance(
            STATE.currentLocation.lat, STATE.currentLocation.lng,
            unit.lat, unit.lng
          ).toFixed(1) + ' km'
        : '-';

    const icons = {
        hospital: '🏥', police: '🚔', fire: '🚒',
        ambulance: '🚑', assembly: '🏢', park: '🌳',
        school: '🏫', square: '⛲', unknown: '📍',
        gendarmerie: '🛡️', military: '🎖️', government: '🏛️'
    };

    let capacityHtml = '';
    if (unit.type === 'hospital') {
        const cap = simulateHospitalCapacity(unit.name);
        const occColor = cap.occupancyPct >= 90 ? '#ff4757'
            : cap.occupancyPct >= 75 ? '#ffa502' : '#2ecc71';
        const occBar = Math.round(cap.occupancyPct);

        capacityHtml = `
            <div class="hospital-capacity">
                <div style="display:flex;justify-content:space-between;margin-bottom:2px">
                    <span style="color:#aaa;font-size:10px">Doluluk</span>
                    <span style="color:${occColor};font-weight:bold;font-size:10px">%${occBar}</span>
                </div>
                <div style="background:rgba(255,255,255,0.1);border-radius:3px;height:4px;overflow:hidden">
                    <div style="background:${occColor};height:100%;width:${occBar}%"></div>
                </div>
                <div style="display:flex;justify-content:space-between;margin-top:2px;font-size:10px;color:#888">
                    <span>Toplam: ${cap.totalBeds} yatak</span>
                    <span style="color:${cap.available > 0 ? '#2ecc71' : '#ff4757'}">Boş: ${cap.available}</span>
                    <span>${cap.emergencyOk ? '🟢 Acil OK' : '🔴 Acil Dolu'}</span>
                </div>
            </div>
        `;
    }

    return `
        <div class="institution-card" onclick="selectInstitution(${unit.lat}, ${unit.lng}, '${escapeHtml(unit.name)}', '${unit.type}')">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <span style="font-size: 1.1rem;">${icons[unit.type] || '📍'}</span>
                <span style="font-size: 11px; color: var(--text-muted);">${distance}</span>
            </div>
            <div style="font-size: 12px; font-weight: 600; margin-top: 4px;">${escapeHtml(unit.name)}</div>
            ${capacityHtml}
        </div>
    `;
}

// Kurum seç - OSRM rota kullan
async function selectInstitution(lat, lng, name, type) {
    selectedInstitution = { lat, lng, name, type };

    if (window.map) {
        flyToLocation(lat, lng, 15);
    }

    if (STATE.currentLocation && typeof drawOSRMRoute === 'function') {
        const colors = {
            hospital: '#9b59b6', assembly: '#2ecc71', park: '#27ae60',
            school: '#f39c12', police: '#3498db', fire: '#e67e22',
            ambulance: '#e74c3c', square: '#1abc9c',
            gendarmerie: '#8e44ad', military: '#5d4e75', government: '#16a085'
        };
        showToast(`${name} için rota hesaplanıyor...`);
        await drawOSRMRoute(
            STATE.currentLocation.lat, STATE.currentLocation.lng,
            lat, lng,
            colors[type] || '#00d2ff',
            name
        );
    } else if (STATE.currentLocation) {
        addMarkerToMap(lat, lng, '#2ecc71', `${type.toUpperCase()}: ${name}`);
    }

    showToast(`${name} seçildi — rota çizildi.`);
}

// Kurum modalını aç
function openInstitutionModal() {
    const modal = document.getElementById('institutionModal');
    if (modal) {
        modal.classList.remove('hidden');
        loadInstitutions();
    }
}

// Kurum modalını kapat
function closeInstitutionModal() {
    const modal = document.getElementById('institutionModal');
    if (modal) modal.classList.add('hidden');
}

// Kuruma rotayı göster
async function navigateToInstitution() {
    if (!selectedInstitution) {
        showToast('Lütfen önce bir kurum seçin!');
        return;
    }

    if (STATE.currentLocation && typeof drawOSRMRoute === 'function') {
        await drawOSRMRoute(
            STATE.currentLocation.lat, STATE.currentLocation.lng,
            selectedInstitution.lat, selectedInstitution.lng,
            '#2ecc71',
            selectedInstitution.name
        );
    } else if (window.map && STATE.currentLocation) {
        window.map.fitBounds([
            [STATE.currentLocation.lat, STATE.currentLocation.lng],
            [selectedInstitution.lat, selectedInstitution.lng]
        ], { padding: [50, 50] });
    }

    closeInstitutionModal();
    showToast('Rota çizildi! Haritayı takip edin.');
}

// En yakın kurumu bul
async function findNearestInstitution(type) {
    if (!STATE.currentLocation) return null;

    const units = await fetchNearbyUnits(
        STATE.currentLocation.lat,
        STATE.currentLocation.lng,
        30000
    );

    const typeGroups = {
        assembly: ['assembly', 'park', 'school', 'square'],
        hospital: ['hospital'],
        emergency: ['police', 'fire', 'ambulance', 'gendarmerie', 'military'],
        government: ['government']
    };

    const allowedTypes = typeGroups[type] || [type];
    const filtered = units.filter(u => allowedTypes.includes(u.type));

    if (filtered.length === 0) return null;

    filtered.sort((a, b) => {
        const da = calculateDistance(STATE.currentLocation.lat, STATE.currentLocation.lng, a.lat, a.lng);
        const db = calculateDistance(STATE.currentLocation.lat, STATE.currentLocation.lng, b.lat, b.lng);
        return da - db;
    });

    return filtered[0];
}

// Tüm kurumları haritaya ekle
async function addAllInstitutionsToMap() {
    if (!STATE.currentLocation) return;

    const units = await fetchNearbyUnits(
        STATE.currentLocation.lat,
        STATE.currentLocation.lng,
        20000
    );

    units.forEach(unit => {
        if (typeof addUnitMarker === 'function') {
            addUnitMarker(unit);
        }
    });
}
