// TR-GOZU Güvenli Rota Modülü (ana hat: OSRM — map.js drawOSRMRoute)

let routeEnabled = false;
let dangerousZones = [];

// Güvenli rotayı göster
function showSafeRoute() {
    if (!STATE.currentLocation) {
        showToast('Konumunuzu aktif edin!');
        return;
    }

    routeEnabled = !routeEnabled;
    const btn = document.getElementById('btnRoute');

    if (btn) btn.classList.toggle('active', routeEnabled);

    if (routeEnabled) {
        calculateAndDisplayRoute();
    } else {
        clearRoute();
    }
}

// Rotayı temizle
function clearRoute() {
    if (typeof clearMapRouteLayer === 'function') {
        clearMapRouteLayer();
    }
    dangerousZones.forEach((z) => {
        try {
            if (window.map) window.map.removeLayer(z);
        } catch (e) {
            /* ignore */
        }
    });
    dangerousZones = [];
}

const SAFE_ROUTE_MAX_TARGETS = 15;

// Güvenli rotayı OSRM ile çiz — 5 km listesindeki tüm hastane + toplanma hedefleri (mor / yeşil)
async function calculateAndDisplayRoute() {
    clearRoute();

    const { lat: startLat, lng: startLng } = STATE.currentLocation;

    let targets = [];

    (STATE.hospitalsWithin5km || []).forEach((u) => {
        if (u.lat == null || u.lng == null) return;
        targets.push({
            lat: u.lat,
            lng: u.lng,
            color: '#9b59b6',
            popupHtml: `<b>Sağlık kuruluşu</b><br>${escapeHtml(u.name || 'İsimsiz')}<br><small style="color:#94a3b8">Mor çizgi — OSRM yol</small>`
        });
    });
    (STATE.assembliesWithin5km || []).forEach((u) => {
        if (u.lat == null || u.lng == null) return;
        targets.push({
            lat: u.lat,
            lng: u.lng,
            color: '#2ecc71',
            popupHtml: `<b>Toplanma / güvenli alan</b><br>${escapeHtml(u.name || 'İsimsiz')}<br><small style="color:#94a3b8">Yeşil çizgi — OSRM yol</small>`
        });
    });

    const dedup = new Set();
    targets = targets.filter((t) => {
        const k = `${Number(t.lat).toFixed(5)},${Number(t.lng).toFixed(5)}`;
        if (dedup.has(k)) return false;
        dedup.add(k);
        return true;
    });

    let capped = false;
    if (targets.length > SAFE_ROUTE_MAX_TARGETS) {
        targets = targets.slice(0, SAFE_ROUTE_MAX_TARGETS);
        capped = true;
    }

    if (targets.length === 0) {
        const h = await findNearestInstitution('hospital');
        const a = await findNearestInstitution('assembly');
        if (h && h.lat != null && h.lng != null) {
            targets.push({
                lat: h.lat,
                lng: h.lng,
                color: '#9b59b6',
                popupHtml: `<b>Sağlık kuruluşu</b> <small>(geniş arama)</small><br>${escapeHtml(h.name || 'İsimsiz')}`
            });
        }
        if (a && a.lat != null && a.lng != null) {
            targets.push({
                lat: a.lat,
                lng: a.lng,
                color: '#2ecc71',
                popupHtml: `<b>Toplanma alanı</b> <small>(geniş arama)</small><br>${escapeHtml(a.name || 'İsimsiz')}`
            });
        }
        const d2 = new Set();
        targets = targets.filter((t) => {
            const k = `${Number(t.lat).toFixed(5)},${Number(t.lng).toFixed(5)}`;
            if (d2.has(k)) return false;
            d2.add(k);
            return true;
        });
    }

    if (targets.length === 0) {
        showToast('Yakında güvenli nokta bulunamadı. Konumu açıp bir süre bekleyin.');
        routeEnabled = false;
        const btn = document.getElementById('btnRoute');
        if (btn) btn.classList.remove('active');
        return;
    }

    if (typeof drawMultipleOSRMRoutes !== 'function') {
        showToast('Rota modülü yüklenemedi.');
        routeEnabled = false;
        const btn = document.getElementById('btnRoute');
        if (btn) btn.classList.remove('active');
        return;
    }

    if (targets.length > 1) {
        showToast(`${targets.length} rota hesaplanıyor, lütfen bekleyin…`);
    }

    await drawMultipleOSRMRoutes(targets, startLat, startLng);

    const dangers = findDangerousZones();
    dangers.forEach((danger) => {
        const circle = L.circleMarker([danger.lat, danger.lng], {
            radius: 15,
            color: '#ff4757',
            fillColor: '#ff4757',
            fillOpacity: 0.5,
            weight: 2,
            dashArray: '5, 5'
        }).addTo(window.map);

        const reason =
            typeof escapeHtml === 'function' ? escapeHtml(danger.reason) : danger.reason;
        circle.bindPopup(`
            <b style="color: #ff4757">Dikkat gerektiren bölge</b><br>
            ${reason}
        `);

        dangerousZones.push(circle);
    });

    let msg = `${targets.length} hedef için rota çizildi. Mor: sağlık, yeşil: toplanma. Kırmızı işaretler: SOS, kritik vaka veya kapalı yol.`;
    if (capped) {
        msg = `İlk ${SAFE_ROUTE_MAX_TARGETS} hedef gösterildi (performans). ` + msg;
    }
    showToast(msg);
}

// Tehlikeli bölgeleri bul
function findDangerousZones() {
    const dangers = [];
    const sosList = getSOSList();
    const citizens = getCitizens();

    sosList.forEach((s) => {
        if (s.resolved) return;

        if (s.lat && s.lng && s.time) {
            const hoursSince = (Date.now() - new Date(s.time)) / 3600000;
            if (hoursSince < 24) {
                dangers.push({
                    lat: s.lat,
                    lng: s.lng,
                    reason: s.isPanic ? 'Panik sinyali' : 'SOS bildirimi',
                    severity: s.isPanic ? 'high' : 'medium'
                });
            }
        }
    });

    citizens.forEach((c) => {
        if (c.healthStatus === 'kritik' || c.healthStatus === 'enkaz') {
            if (c.lat && c.lng) {
                dangers.push({
                    lat: c.lat,
                    lng: c.lng,
                    reason: c.healthStatus === 'enkaz' ? 'Enkaz altında' : 'Kritik sağlık durumu',
                    severity: 'critical'
                });
            }
        }
    });

    const closedRoads = getFromStorage('closedRoads', []);
    closedRoads.forEach((road) => {
        dangers.push({
            lat: road.lat,
            lng: road.lng,
            reason: `Kapalı yol: ${road.name}`,
            severity: 'medium'
        });
    });

    return dangers;
}

// Yolu kapalı olarak işaretle
function markRoadAsClosed(lat, lng, name) {
    const closedRoads = getFromStorage('closedRoads', []);
    closedRoads.push({ lat, lng, name, time: new Date().toISOString() });
    saveToStorage('closedRoads', closedRoads);

    L.circleMarker([lat, lng], {
        radius: 12,
        color: '#ff4757',
        fillColor: '#ff4757',
        fillOpacity: 0.5,
        weight: 3,
        dashArray: '8, 4'
    })
        .addTo(window.map)
        .bindPopup(`<b>Kapalı yol</b><br>${typeof escapeHtml === 'function' ? escapeHtml(name) : name}`);

    showToast(`Yol kapalı olarak işaretlendi: ${name}`);
}

// Alternatif rota hesapla
function calculateAlternativeRoute(obstacles) {
    if (!STATE.currentLocation || !obstacles || obstacles.length === 0) return null;

    const alternatives = [];
    const { lat, lng } = STATE.currentLocation;

    const angles = [30, 60, 90, 120, 150];

    angles.forEach((angle) => {
        const rad = (angle * Math.PI) / 180;
        const newLat = lat + 0.01 * Math.cos(rad);
        const newLng = lng + 0.01 * Math.sin(rad);
        alternatives.push({ lat: newLat, lng: newLng, angle });
    });

    return alternatives;
}
