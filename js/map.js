// TR-GOZU Harita Modülü

let map;
let userMarker;
let thermalZone;
let thermalLabelMarker;
let earthquakeCircles = [];
let riskZones = [];
let unitMarkers = [];
let teamMarkers = [];
let sosAdminMarkers = {}; // SOS markerları: key -> marker
let heatmapLayer = null;
let routeLayer = null;
let priorityZoneLayers = [];

let darkLayer, satelliteLayer, osmLayer;
let activeBase = 'dark';
let lastNonSatelliteBase = 'dark';
let isSatellite = false;

let firmsLayerGroup = null;
let firmsHotspotsOn = false;
let firmsMoveEndHandler = null;
let lastMapTileErrorToast = 0;

const refreshFirmsDebounced = typeof debounce === 'function'
    ? debounce(() => { if (firmsHotspotsOn) loadFirmsForCurrentBounds(); }, 800)
    : null;

function notifyMapTileError() {
    const now = Date.now();
    if (now - lastMapTileErrorToast < 10000) return;
    lastMapTileErrorToast = now;
    if (typeof showToast === 'function') {
        showToast('Harita karosu yüklenemedi. Biraz uzaklaştırın veya katmanı değiştirin (OSM / koyu).');
    }
}

function bindTileError(layer) {
    if (!layer || !layer.on) return;
    layer.on('tileerror', function () {
        console.warn('Harita tile yüklenemedi');
        notifyMapTileError();
    });
}

// Harita başlat
function initMap() {
    if (map) return;

    map = L.map('map', {
        zoomControl: false,
        attributionControl: true,
        maxZoom: 19,
        minZoom: 2
    }).setView([39.92, 32.85], 6);

    // Koyu tema katmanı - hata yönetimi eklendi
    darkLayer = L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
        attribution: '&copy; TR-GOZU 2026',
        maxZoom: 19,
        maxNativeZoom: 18,
        errorTileUrl: 'data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7'
    }).addTo(map);

    bindTileError(darkLayer);

    // Uydu görüntüsü katmanı
    satelliteLayer = L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}', {
        attribution: '&copy; Esri, Maxar, Earthstar Geographics | Uydu',
        maxZoom: 19,
        maxNativeZoom: 18,
        errorTileUrl: 'data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7'
    });

    bindTileError(satelliteLayer);

    // OpenStreetMap — güncel vektör dünya haritası (OpenStreetMap katkıcıları)
    osmLayer = L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>',
        maxZoom: 19,
        maxNativeZoom: 19,
        subdomains: 'abc',
        errorTileUrl: 'data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7'
    });

    bindTileError(osmLayer);

    window.map = map;
    firmsLayerGroup = L.layerGroup().addTo(map);

    // Harita yüklenince boyutu ayarla
    setTimeout(() => map.invalidateSize(), 300);

    map.on('zoomend', function () {
        map.invalidateSize();
    });
    map.on('moveend', function () {
        map.invalidateSize();
    });

    // Harita tıklama — OpenWeather: sıcaklık, basınç, nem, yağış, AQI (tıklanan koordinat)
    map.on('click', function(e) {
        if (typeof showMapClickWeatherPopup === 'function') {
            showMapClickWeatherPopup(e.latlng.lat, e.latlng.lng);
        } else if (typeof fetchAndShowAirQuality === 'function') {
            fetchAndShowAirQuality(e.latlng.lat, e.latlng.lng);
        }
    });
}

function setBaseLayerMode(mode) {
    if (!map) return;
    const modes = ['dark', 'osm', 'satellite'];
    if (!modes.includes(mode)) return;

    try { map.removeLayer(darkLayer); } catch (e) {}
    try { map.removeLayer(osmLayer); } catch (e) {}
    try { map.removeLayer(satelliteLayer); } catch (e) {}

    if (mode === 'satellite') satelliteLayer.addTo(map);
    else if (mode === 'osm') osmLayer.addTo(map);
    else darkLayer.addTo(map);

    activeBase = mode;
    isSatellite = mode === 'satellite';
    if (mode !== 'satellite') lastNonSatelliteBase = mode;

    const btnSat = document.getElementById('btnSatellite');
    const btnOsm = document.getElementById('btnOsm');
    if (btnSat) btnSat.classList.toggle('active', mode === 'satellite');
    if (btnOsm) btnOsm.classList.toggle('active', mode === 'osm');

    setTimeout(() => map.invalidateSize(), 300);
}

// Uydu görüntüsünü aç/kapat (önceki OSM/koyu temaya dön)
function toggleSatellite() {
    if (isSatellite) {
        setBaseLayerMode(lastNonSatelliteBase || 'dark');
    } else {
        setBaseLayerMode('satellite');
    }
}

async function loadFirmsForCurrentBounds() {
    if (!map || !firmsLayerGroup || typeof fetchFIRMSHotspotsInBBox !== 'function') return;
    const b = map.getBounds();
    firmsLayerGroup.clearLayers();
    const pts = await fetchFIRMSHotspotsInBBox(
        b.getWest(), b.getSouth(), b.getEast(), b.getNorth()
    );
    pts.forEach(h => {
        const r = Math.min(14, 4 + (h.frp || 0) * 2);
        const c = (h.frp || 0) > 5 ? '#ff4757' : '#ffa502';
        const circle = L.circleMarker([h.lat, h.lng], {
            radius: r,
            color: c,
            fillColor: c,
            fillOpacity: 0.55,
            weight: 1
        });
        circle.bindPopup(`
            <b>Uydu sıcak nokta (VIIRS NRT)</b><br>
            NASA FIRMS uyumlu | FRP: ${(h.frp || 0).toFixed(2)} MW<br>
            Parlaklık: ${(h.brightness || 0).toFixed(1)} K<br>
            Güven: ${h.confidence || '-'} · ${h.daynight}<br>
            <small>Endüstriyel ısı / orman yangını olasılığı — yer doğrulaması gerekir</small>
        `);
        circle.addTo(firmsLayerGroup);
    });
}

function toggleFirmsHotspots() {
    firmsHotspotsOn = !firmsHotspotsOn;
    const btn = document.getElementById('btnFirms');
    if (btn) btn.classList.toggle('active', firmsHotspotsOn);

    if (!map) return;

    if (firmsHotspotsOn) {
        loadFirmsForCurrentBounds();
        if (!firmsMoveEndHandler) {
            firmsMoveEndHandler = () => { if (refreshFirmsDebounced) refreshFirmsDebounced(); };
            map.on('moveend', firmsMoveEndHandler);
        }
        showToast('NASA VIIRS sıcak noktaları yüklendi (harita alanına göre güncellenir).');
    } else {
        if (firmsLayerGroup) firmsLayerGroup.clearLayers();
        if (firmsMoveEndHandler) {
            map.off('moveend', firmsMoveEndHandler);
            firmsMoveEndHandler = null;
        }
    }
}

// SOS ikonu oluştur
function createSOSIcon(isPanic = false) {
    const label = isPanic ? 'PANİK' : 'SOS';
    return L.divIcon({
        className: 'sos-icon',
        html: `<div style="
            background: linear-gradient(135deg, #ff4757, #c0392b);
            color: white;
            padding: 6px 12px;
            border-radius: 12px;
            font-weight: bold;
            font-size: 11px;
            white-space: nowrap;
            box-shadow: 0 0 25px rgba(255,71,87,0.7);
            animation: ${isPanic ? 'sosPanic 0.5s infinite' : 'sosPulse 2s infinite'};
            border: 2px solid rgba(255,255,255,0.5);
        ">🆘 ${label}</div>`,
        iconSize: [80, 30],
        iconAnchor: [40, 15]
    });
}

// Normal ikon oluştur
function createNormalIcon(color, opacity) {
    color = color || '#00d2ff';
    opacity = opacity != null ? opacity : 1;
    return L.divIcon({
        className: 'normal-marker',
        html: `<div style="
            width: 16px;
            height: 16px;
            border-radius: 50%;
            background: ${color};
            border: 3px solid white;
            box-shadow: 0 0 15px ${color};
            opacity: ${opacity};
        "></div>`,
        iconSize: [20, 20],
        iconAnchor: [10, 10]
    });
}

// Aktivite zamanına göre renk hesapla
function getMarkerColorByActivity(lastActiveIso) {
    if (!lastActiveIso) return { color: '#95a5a6', opacity: 0.5 };
    const minutes = (Date.now() - new Date(lastActiveIso)) / 60000;
    if (minutes < 1) return { color: '#00d2ff', opacity: 1.0 };
    if (minutes < 5) return { color: '#00d2ff', opacity: 0.85 };
    if (minutes < 30) return { color: '#74b9ff', opacity: 0.7 };
    return { color: '#95a5a6', opacity: 0.5 };
}

// Takım ikonu oluştur
function createTeamIcon(type) {
    const icons = { afad: '🏢', umke: '🏥', police: '🚔', fire: '🚒', volunteer: '❤️' };
    return L.divIcon({
        className: 'team-marker',
        html: `<div style="
            background: linear-gradient(135deg, #2ecc71, #27ae60);
            color: white;
            width: 36px;
            height: 36px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 18px;
            border: 2px solid white;
            box-shadow: 0 0 15px rgba(46,204,113,0.5);
        ">${icons[type] || '📍'}</div>`,
        iconSize: [36, 36],
        iconAnchor: [18, 18]
    });
}

// 4km Termal Daire Çiz (sıcaklık + nem + hissedilen sıcaklık)
function drawThermalZone(lat, lng, temp, humidity) {
    if (thermalZone) { map.removeLayer(thermalZone); thermalZone = null; }
    if (thermalLabelMarker) { map.removeLayer(thermalLabelMarker); thermalLabelMarker = null; }

    const heatIdx = typeof calculateHeatIndex === 'function'
        ? calculateHeatIndex(temp, humidity)
        : temp;

    // Renk skalası
    let zoneColor;
    if (temp < 0) zoneColor = '#8e44ad';
    else if (temp < 10) zoneColor = '#3498db';
    else if (temp < 25) zoneColor = '#2ecc71';
    else if (temp < 35) zoneColor = '#ffa502';
    else zoneColor = '#ff4757';

    // 5 km yarıçap — konumunuza göre sıcaklık / hissedilen sıcaklık özeti
    thermalZone = L.circle([lat, lng], {
        radius: 5000,
        color: zoneColor,
        fillColor: zoneColor,
        fillOpacity: 0.12,
        weight: 2,
        dashArray: '6, 10'
    }).addTo(map);

    thermalZone.bindPopup(`
        <b>5 km Sıcaklık Özeti</b><br>
        Sıcaklık: <b>${temp}°C</b><br>
        Hissedilen: <b style="color:${zoneColor}">${heatIdx}°C</b><br>
        Nem: ${humidity != null ? humidity + '%' : '-'}<br>
        <small style="color:#aaa">OpenWeatherMap verisi</small>
    `);

    // Daire üzerinde yüzen sıcaklık etiketi
    thermalLabelMarker = L.marker([lat, lng], {
        icon: L.divIcon({
            className: 'thermal-label-icon',
            html: `<div class="thermal-badge" style="border-color:${zoneColor}">
                     🌡️ ${temp}°C &nbsp;|&nbsp; His: ${heatIdx}°C
                   </div>`,
            iconSize: [210, 32],
            iconAnchor: [105, -8]
        }),
        interactive: false,
        zIndexOffset: -100
    }).addTo(map);
}

// Risk bölgelerini görselleştir
function visualizeRisks(lat, lng, risks) {
    riskZones.forEach(zone => map.removeLayer(zone));
    riskZones = [];

    if (risks.earthquake > 30) {
        const eqCircle = L.circle([lat, lng], {
            radius: risks.earthquake * 100,
            color: '#ff4757', fillColor: '#ff4757', fillOpacity: 0.2, weight: 3
        }).addTo(map).bindTooltip('Sismik Risk Bölgesi');
        riskZones.push(eqCircle);
    }
    if (risks.flood > 50) {
        const floodArea = L.circle([lat + 0.01, lng + 0.01], {
            radius: 1500, color: '#3498db', fillColor: '#2980b9', fillOpacity: 0.35, weight: 1
        }).addTo(map).bindTooltip('Sel/Taşkın Riski');
        riskZones.push(floodArea);
    }
    if (risks.storm > 50) {
        const stormArea = L.circle([lat - 0.01, lng + 0.01], {
            radius: 1000, color: '#ffa502', fillColor: '#e67e22', fillOpacity: 0.25, weight: 2, dashArray: '10, 5'
        }).addTo(map).bindTooltip('Fırtına Riski');
        riskZones.push(stormArea);
    }
}

// Marker ekle
function addMarkerToMap(lat, lng, color, title) {
    const marker = L.marker([lat, lng], { icon: createNormalIcon(color) })
        .addTo(map)
        .bindPopup(`<b>${title}</b>`);
    return marker;
}

// Birim markerı ekle
function addUnitMarker(unit) {
    const colors = {
        hospital: '#9b59b6', police: '#3498db', fire: '#e67e22',
        ambulance: '#e74c3c', assembly: '#2ecc71', park: '#27ae60',
        school: '#f39c12', square: '#1abc9c',
        gendarmerie: '#8e44ad', military: '#5d4e75', government: '#16a085'
    };

    const marker = L.marker([unit.lat, unit.lng], {
        icon: createNormalIcon(colors[unit.type] || '#00d2ff')
    }).addTo(map);

    const dist = STATE.currentLocation
        ? calculateDistance(STATE.currentLocation.lat, STATE.currentLocation.lng, unit.lat, unit.lng).toFixed(1) + ' km'
        : '-';

    marker.bindPopup(`<b>${unit.name}</b><br><span style="color:${colors[unit.type] || '#00d2ff'}">${unit.type.toUpperCase()}</span><br><small>Mesafe: ${dist}</small>`);
    unitMarkers.push(marker);
}

// Deprem markerı ekle (Kandilli / USGS verisi)
function addEarthquakeMarker(earthquake) {
    const mag = earthquake.magnitude || 0;
    const circle = L.circle([earthquake.lat, earthquake.lng], {
        radius: mag * 8000,
        color: mag >= 5 ? '#c0392b' : '#ff4757',
        fillColor: mag >= 5 ? '#c0392b' : '#ff4757',
        fillOpacity: 0.15,
        weight: 2
    }).addTo(map);

    const srcLabel = earthquake.source === 'afad' ? 'AFAD (ArcGIS)'
        : earthquake.source === 'kandilli' ? 'Kandilli'
        : earthquake.source === 'usgs' ? 'USGS' : (earthquake.source || 'Kaynak');
    circle.bindPopup(`
        <b>Deprem (${srcLabel})</b><br>
        <span style="color: #ff4757; font-weight: bold;">M${mag.toFixed(1)}</span><br>
        ${earthquake.place || 'Bilinmiyor'}<br>
        Derinlik: ${earthquake.depth || '-'} km<br>
        ${earthquake.time ? new Date(earthquake.time).toLocaleString('tr-TR') : ''}
    `);

    earthquakeCircles.push(circle);
}

// OSRM ile gerçek yol rotası çiz
async function drawOSRMRoute(startLat, startLng, endLat, endLng, color, destinationName) {
    if (!map) return null;

    if (routeLayer) { map.removeLayer(routeLayer); routeLayer = null; }
    color = color || '#2ecc71';

    const route = typeof fetchOSRMRoute === 'function'
        ? await fetchOSRMRoute(startLat, startLng, endLat, endLng)
        : null;

    const routeGroup = L.layerGroup();

    if (route && route.coordinates && route.coordinates.length > 1) {
        // Gerçek yol rotası
        const polyline = L.polyline(route.coordinates, {
            color,
            weight: 5,
            opacity: 0.85,
            dashArray: '12, 8'
        }).addTo(routeGroup);

        // Bilgi etiketi - rota ortasında
        const midIdx = Math.floor(route.coordinates.length / 2);
        L.marker(route.coordinates[midIdx], {
            icon: L.divIcon({
                className: 'route-info-icon',
                html: `<div class="route-info-badge">${route.distanceKm} km · yaklaşık ${route.durationMin} dk</div>`,
                iconSize: [130, 24],
                iconAnchor: [65, 12]
            }),
            interactive: false
        }).addTo(routeGroup);
    } else {
        // OSRM başarısız — düz çizgi fallback
        L.polyline([[startLat, startLng], [endLat, endLng]], {
            color,
            weight: 4,
            opacity: 0.7,
            dashArray: '15, 10'
        }).addTo(routeGroup);
    }

    // Başlangıç / bitiş noktaları
    L.circleMarker([startLat, startLng], {
        radius: 8, color: '#00d2ff', fillColor: '#00d2ff', fillOpacity: 1
    }).addTo(routeGroup).bindPopup('<b>Başlangıç</b><br>Bulunduğunuz konum');

    const destLabel =
        typeof escapeHtml === 'function'
            ? escapeHtml(destinationName || 'Seçilen nokta')
            : (destinationName || 'Seçilen nokta');
    L.circleMarker([endLat, endLng], {
        radius: 8, color, fillColor: color, fillOpacity: 1
    }).addTo(routeGroup).bindPopup(`<b>Hedef</b><br>${destLabel}`);

    routeLayer = routeGroup;
    routeLayer.addTo(map);

    // Rotaya odaklan
    try {
        const coords = route ? route.coordinates : [[startLat, startLng], [endLat, endLng]];
        map.fitBounds(L.latLngBounds(coords), { padding: [50, 50] });
    } catch (e) {
        map.fitBounds([[startLat, startLng], [endLat, endLng]], { padding: [50, 50] });
    }

    return routeLayer;
}

/**
 * Konumdan birden çok hedefe aynı anda OSRM rotası (mor: sağlık, yeşil: toplanma).
 * entries: { lat, lng, color, popupHtml }[]
 */
async function drawMultipleOSRMRoutes(entries, startLat, startLng) {
    if (!map || !entries || entries.length === 0) return null;

    if (routeLayer) {
        map.removeLayer(routeLayer);
        routeLayer = null;
    }

    const parent = L.layerGroup();

    L.circleMarker([startLat, startLng], {
        radius: 9,
        color: '#00d2ff',
        fillColor: '#00d2ff',
        fillOpacity: 1,
        weight: 2
    })
        .addTo(parent)
        .bindPopup('<b>Başlangıç</b><br>Bulunduğunuz konum');

    let bounds = L.latLngBounds([startLat, startLng]);

    for (const entry of entries) {
        const endLat = entry.lat;
        const endLng = entry.lng;
        const color = entry.color || '#2ecc71';
        const popupHtml =
            entry.popupHtml ||
            `<b>Hedef</b><br>${typeof escapeHtml === 'function' ? escapeHtml(entry.name || 'Nokta') : entry.name || 'Nokta'}`;

        const route =
            typeof fetchOSRMRoute === 'function'
                ? await fetchOSRMRoute(startLat, startLng, endLat, endLng)
                : null;

        const sub = L.layerGroup();

        if (route && route.coordinates && route.coordinates.length > 1) {
            L.polyline(route.coordinates, {
                color,
                weight: 4,
                opacity: 0.82,
                dashArray: '10, 6'
            }).addTo(sub);

            const midIdx = Math.floor(route.coordinates.length / 2);
            L.marker(route.coordinates[midIdx], {
                icon: L.divIcon({
                    className: 'route-info-icon',
                    html: `<div class="route-info-badge">${route.distanceKm} km · yaklaşık ${route.durationMin} dk</div>`,
                    iconSize: [168, 24],
                    iconAnchor: [84, 12]
                }),
                interactive: false
            }).addTo(sub);

            route.coordinates.forEach((c) => {
                bounds.extend(c);
            });
        } else {
            L.polyline(
                [
                    [startLat, startLng],
                    [endLat, endLng]
                ],
                {
                    color,
                    weight: 3,
                    opacity: 0.65,
                    dashArray: '12, 10'
                }
            ).addTo(sub);
            bounds.extend([endLat, endLng]);
        }

        L.circleMarker([endLat, endLng], {
            radius: 8,
            color,
            fillColor: color,
            fillOpacity: 1,
            weight: 2
        })
            .addTo(sub)
            .bindPopup(popupHtml);

        sub.addTo(parent);
    }

    routeLayer = parent;
    parent.addTo(map);

    try {
        map.fitBounds(bounds, { padding: [58, 58], maxZoom: 15 });
    } catch (e) {
        /* ignore */
    }

    return parent;
}

function clearMapRouteLayer() {
    if (routeLayer && map) {
        try {
            map.removeLayer(routeLayer);
        } catch (e) {
            /* ignore */
        }
        routeLayer = null;
    }
}

// Admin SOS markerını haritaya ekle / güncelle (SOS butonu basınca çağrılır)
function addSOSMarkerToMap(lat, lng, email, isPanic) {
    if (!map) return;

    // Varsa eski markeri güncelle
    const key = `sos_${email}`;
    if (sosAdminMarkers[key]) {
        map.removeLayer(sosAdminMarkers[key]);
    }

    const marker = L.marker([lat, lng], { icon: createSOSIcon(isPanic) }).addTo(map);
    marker.bindPopup(`
        <b style="color:#ff4757">${isPanic ? 'PANİK' : 'SOS'}</b><br>
        ${email}<br>
        ${new Date().toLocaleTimeString('tr-TR')}
    `);
    marker.openPopup();
    sosAdminMarkers[key] = marker;

    // Admin panelini hemen güncelle
    loadCitizensOnMap();
}

// Öncelik bölgelerini güncelle (10+ SOS = kırmızı heatmap bölgesi)
function updatePriorityZones() {
    if (!map) return;

    priorityZoneLayers.forEach(l => map.removeLayer(l));
    priorityZoneLayers = [];

    const sosList = getSOSList();
    const gridSize = 0.08;
    const densityMap = {};

    sosList.forEach(s => {
        if (s.resolved || !s.lat || !s.lng) return;
        const gLat = Math.round(s.lat / gridSize) * gridSize;
        const gLng = Math.round(s.lng / gridSize) * gridSize;
        const key = `${gLat.toFixed(3)},${gLng.toFixed(3)}`;
        if (!densityMap[key]) densityMap[key] = { lat: gLat, lng: gLng, count: 0, panicCount: 0 };
        densityMap[key].count++;
        if (s.isPanic) densityMap[key].panicCount++;
    });

    Object.values(densityMap).forEach(zone => {
        if (zone.count < 3) return;

        let color, opacity, radius;
        if (zone.count >= CONFIG.PRIORITY_THRESHOLDS.CRITICAL) {
            color = '#ff4757'; opacity = 0.35; radius = 6000;
        } else if (zone.count >= CONFIG.PRIORITY_THRESHOLDS.HIGH) {
            color = '#ffa502'; opacity = 0.28; radius = 4500;
        } else {
            color = '#f1c40f'; opacity = 0.2; radius = 3000;
        }

        const circle = L.circle([zone.lat, zone.lng], {
            radius, color, fillColor: color, fillOpacity: opacity, weight: 2
        }).addTo(map);

        circle.bindPopup(`
            <b style="color:${color}">Yoğun SOS Bölgesi</b><br>
            SOS Sayısı: ${zone.count}<br>
            Panik: ${zone.panicCount}
        `);

        priorityZoneLayers.push(circle);
    });
}

// Konum iste
function requestLocation() {
    if (!navigator.geolocation) {
        showToast('Tarayıcı konumu desteklemiyor!');
        return;
    }

    const statusLabel = document.getElementById('locStatus');
    if (statusLabel) statusLabel.innerHTML = '<span style="color: var(--secondary)">Konum alınıyor...</span>';

    navigator.geolocation.getCurrentPosition(
        async (pos) => {
            const { latitude, longitude } = pos.coords;

            STATE.currentLocation = { lat: latitude, lng: longitude };
            STATE.isLocationActive = true;

            map.flyTo([latitude, longitude], 14, { duration: 1.5 });

            if (userMarker) map.removeLayer(userMarker);
            userMarker = L.marker([latitude, longitude], {
                icon: createNormalIcon('#00d2ff')
            }).addTo(map).bindPopup('<b>Konumunuz</b><br>Aktif');

            if (statusLabel) statusLabel.innerHTML = '<span style="color: var(--success)">Konum Aktif</span>';
            const locBtn = document.getElementById('locBtn');
            if (locBtn) locBtn.style.display = 'none';

            const email = getCurrentUserEmail();
            if (email) {
                updateCitizen(email, {
                    lat: latitude,
                    lng: longitude,
                    lastLocation: { lat: latitude, lng: longitude },
                    lastMoveAt: new Date().toISOString()
                });
            }

            if (typeof initBatteryMonitor === 'function') initBatteryMonitor();
            if (typeof startLiveTracking === 'function') startLiveTracking();

            if (typeof performRiskAnalysis === 'function') {
                await performRiskAnalysis(latitude, longitude);
            }

            showToast('Konumunuz aktif edildi!');
        },
        (err) => {
            console.error('Konum hatası:', err);
            if (statusLabel) statusLabel.innerHTML = '<span style="color: var(--primary)">Konum alınamadı</span>';
            showToast('Konum alınamadı. Lütfen izinleri kontrol edin.');
        },
        { enableHighAccuracy: true, timeout: 10000, maximumAge: 0 }
    );
}

// Admin markerlarını temizle
function clearAdminMarkers() {
    unitMarkers.forEach(m => map.removeLayer(m));
    unitMarkers = [];
    teamMarkers.forEach(m => map.removeLayer(m));
    teamMarkers = [];
}

// Acil katmanları temizle
function clearEmergencyLayers() {
    riskZones.forEach(zone => map.removeLayer(zone));
    riskZones = [];
    earthquakeCircles.forEach(c => map.removeLayer(c));
    earthquakeCircles = [];
    if (thermalZone) { map.removeLayer(thermalZone); thermalZone = null; }
    if (thermalLabelMarker) { map.removeLayer(thermalLabelMarker); thermalLabelMarker = null; }
}

// Yetkili görünümünü başlat
function startAdminView() {
    loadCitizensOnMap();
    updatePriorityZones();

    if (window.adminRefreshTimer) clearInterval(window.adminRefreshTimer);
    window.adminRefreshTimer = setInterval(() => {
        loadCitizensOnMap();
        updatePriorityZones();
    }, CONFIG.ADMIN_REFRESH_INTERVAL);
}

// Vatandaşları haritada göster
function loadCitizensOnMap() {
    if (!map) return;
    clearAdminMarkers();

    // Mevcut SOS markerlarını temizle (sadece eski olanlar)
    Object.keys(sosAdminMarkers).forEach(key => {
        if (key.startsWith('sos_')) {
            try { map.removeLayer(sosAdminMarkers[key]); } catch (e) {}
            delete sosAdminMarkers[key];
        }
    });

    const citizens = getCitizens();
    const sosList = getSOSList();

    const listDiv = document.getElementById('citizenTrackList');
    const sosListDiv = document.getElementById('sosSignalList');

    if (listDiv) listDiv.innerHTML = '';
    if (sosListDiv) sosListDiv.innerHTML = '';
    const sosUnverifiedDiv = document.getElementById('sosUnverifiedList');
    if (sosUnverifiedDiv) sosUnverifiedDiv.innerHTML = '';

    const sosForwarded = sosList.filter(s => !s.resolved && s.forwardToAuthority !== false);
    const sosAllActive = sosList.filter(s => !s.resolved);
    const sosEmails = new Set(sosAllActive.map(s => s.user).filter(Boolean));

    citizens.forEach(c => {
        if (!c.lat || !c.lng) return;

        const isSOS = c.isSOS || sosEmails.has(c.email);
        const isPanic = c.isPanic || false;
        const { color: actColor, opacity: actOpacity } = getMarkerColorByActivity(c.lastActive);

        let marker;
        if (isSOS || isPanic) {
            marker = L.marker([c.lat, c.lng], { icon: createSOSIcon(isPanic) }).addTo(map);
        } else {
            marker = L.marker([c.lat, c.lng], { icon: createNormalIcon(actColor, actOpacity) }).addTo(map);
        }

        const healthBadge = c.healthStatus ? CONFIG.HEALTH_STATUS[c.healthStatus]?.icon || '' : '';
        const battStr = c.battery != null ? `%${c.battery}` : '-';

        marker.bindPopup(`
            <b>${c.email}</b><br>
            Durum: ${isSOS ? (isPanic ? '<span style="color:#ff4757">PANİK</span>' : '<span style="color:#ff4757">SOS</span>') : 'Normal'}<br>
            Sağlık: ${healthBadge} ${c.healthStatus ? CONFIG.HEALTH_STATUS[c.healthStatus]?.label || '-' : '-'}<br>
            Batarya: ${battStr}<br>
            Son aktif: ${timeSince(c.lastActive)}<br>
            Son hareket: ${timeSince(c.lastMoveAt)}
        `);

        if (c.healthStatus === 'kritik' || c.healthStatus === 'enkaz') {
            const hMarker = L.circleMarker([c.lat, c.lng], {
                radius: 15,
                color: CONFIG.HEALTH_STATUS[c.healthStatus]?.color || '#ff4757',
                fillOpacity: 0.4,
                weight: 3
            }).addTo(map);
            unitMarkers.push(hMarker);
        }

        unitMarkers.push(marker);

        // Vatandaş takip listesi
        if (listDiv) {
            const statusBadge = isPanic
                ? '<span class="text-danger" style="font-weight:bold">PANİK</span>'
                : isSOS ? '<span class="text-danger">SOS</span>'
                : '<span class="text-success">Aktif</span>';

            const battIcon = c.battery != null
                ? (c.battery <= 10 ? '🔴' : c.battery <= 30 ? '🟡' : '🟢') : '';

            const minsMove = c.lastMoveAt
                ? Math.round((Date.now() - new Date(c.lastMoveAt)) / 60000)
                : null;

            listDiv.innerHTML += `
                <div class="admin-card ${isPanic ? 'panic-card' : isSOS ? 'sos-card' : ''}"
                     onclick="flyToLocation(${c.lat}, ${c.lng})">
                    <div style="display:flex;justify-content:space-between;align-items:center;">
                        <span style="font-size:12px;word-break:break-all;">${c.email}</span>
                        ${statusBadge}
                    </div>
                    <div style="font-size:11px;color:var(--text-muted);margin-top:4px;">
                        Son görülme: ${timeSince(c.lastActive)}
                        ${minsMove !== null ? ` | Hareket: ${minsMove} dk önce` : ''}
                        ${battIcon} ${c.battery != null ? '%' + c.battery : ''} ${healthBadge}
                    </div>
                </div>
            `;
        }
    });

    // SOS listesi ve harita markerları
    sosList.slice().reverse().forEach(s => {
        if (s.resolved || !s.lat || !s.lng) return;

        if (s.forwardToAuthority === false) {
            if (sosUnverifiedDiv) {
                const kd = typeof s.kandilliCheck?.detail === 'string'
                    ? s.kandilliCheck.detail
                    : (s.kandilliCheck?.reason || 'doğrulanmadı');
                sosUnverifiedDiv.innerHTML += `
                <div class="admin-card sos-unverified-card"
                     onclick="flyToLocation(${s.lat}, ${s.lng})">
                    <div style="display:flex;justify-content:space-between;">
                        <span style="font-size:12px;word-break:break-all;">${s.user}</span>
                        <span class="text-warning" style="font-size:10px;">eşleşme yok</span>
                    </div>
                    <div style="font-size:11px;color:var(--text-muted);margin-top:4px;">
                        ${formatTime(s.time)} | ${s.lat.toFixed(4)}, ${s.lng.toFixed(4)}<br>
                        <span style="opacity:0.9">${kd}</span>
                    </div>
                </div>`;
            }
        }

        // Tüm aktif SOS haritada kırmızı (Kandilli ayrımı yalnız panelde)
        const key = `sos_${s.id}`;
        const m = L.marker([s.lat, s.lng], { icon: createSOSIcon(s.isPanic) }).addTo(map);
        const kNote =
            s.forwardToAuthority === false
                ? '<br><small style="color:#f59e0b">Kandilli eşleşmesi yok — yine de konum görünür</small>'
                : '';
        m.bindPopup(`
            <b style="color:#ff4757">${s.isPanic ? 'PANİK' : 'SOS'}</b><br>
            ${s.user}<br>
            ${formatTime(s.time)}${kNote}
        `);
        sosAdminMarkers[key] = m;

        if (sosListDiv && s.forwardToAuthority !== false) {
            sosListDiv.innerHTML += `
                <div class="admin-card ${s.isPanic ? 'panic-card' : 'sos-card'}"
                     onclick="flyToLocation(${s.lat}, ${s.lng})">
                    <div style="display:flex;justify-content:space-between;">
                        <span>SOS ${s.user}</span>
                        ${s.isPanic ? '<span class="text-danger" style="font-weight:bold">PANİK</span>' : ''}
                    </div>
                    <div style="font-size:11px;color:var(--text-muted);">
                        ${formatTime(s.time)} | ${s.lat.toFixed(4)}, ${s.lng.toFixed(4)}
                    </div>
                </div>
            `;
        }
    });
}

// Konuma uç
function flyToLocation(lat, lng, zoom) {
    zoom = zoom || 16;
    if (map) map.flyTo([lat, lng], zoom, { duration: 1 });
}

// Yardım ekibi markerı ekle
function addTeamMarker(lat, lng, type, name) {
    const marker = L.marker([lat, lng], { icon: createTeamIcon(type) }).addTo(map);
    marker.bindPopup(`<b>${name || type.toUpperCase()}</b><br>Ekip Konumu`);
    teamMarkers.push(marker);
    return marker;
}

// Panelde seçilen toplanma / hastane (liste 5 km; rota seçili hedefe)
function onEmergencyTargetSelectChange(kind) {
    const id = kind === 'hospital' ? 'select-hospital-5km' : 'select-assembly-5km';
    const sel = document.getElementById(id);
    if (!sel || sel.disabled) return;

    const idx = parseInt(sel.value, 10);
    if (Number.isNaN(idx)) return;

    if (kind === 'hospital') {
        STATE.selectedHospitalIndex = idx;
        const list = STATE.hospitalsWithin5km || [];
        const u = list[idx];
        STATE.nearestHospital = u || null;
        if (u) {
            const nameEl = document.getElementById('val-hastane');
            const distEl = document.getElementById('val-hastane-mesafe');
            if (nameEl) nameEl.textContent = u.name || 'İsimsiz';
            if (distEl) distEl.textContent = `${u.distance.toFixed(1)} km`;
            if (map && u.lat != null && u.lng != null) map.panTo([u.lat, u.lng]);
        }
    } else {
        STATE.selectedAssemblyIndex = idx;
        const list = STATE.assembliesWithin5km || [];
        const u = list[idx];
        STATE.nearestAssembly = u || null;
        if (u) {
            const nameEl = document.getElementById('val-toplanma-ad');
            const distEl = document.getElementById('val-toplanma-mesafe');
            if (nameEl) nameEl.textContent = u.name || 'İsimsiz';
            if (distEl) distEl.textContent = `${u.distance.toFixed(1)} km`;
            if (map && u.lat != null && u.lng != null) map.panTo([u.lat, u.lng]);
        }
    }
}

// Konumunuza göre seçili toplanma veya sağlık kuruluşuna OSRM rotası
async function drawRouteToNearestSafe(kind) {
    if (!STATE.currentLocation) {
        showToast('Önce konumunuzu açın (Canlı Konum).');
        return;
    }
    const target =
        kind === 'hospital' ? STATE.nearestHospital : STATE.nearestAssembly;
    if (!target || target.lat == null || target.lng == null) {
        showToast('Yakında kayıtlı nokta bulunamadı (OSM).');
        return;
    }
    const color = kind === 'hospital' ? '#9b59b6' : '#2ecc71';
    const name = target.name || (kind === 'hospital' ? 'Sağlık' : 'Toplanma');
    await drawOSRMRoute(
        STATE.currentLocation.lat,
        STATE.currentLocation.lng,
        target.lat,
        target.lng,
        color,
        name
    );
    showToast('Rota çizildi (OpenStreetMap yolları, OSRM).');
}

// Google Haritalar yönlendirme (API anahtarı gerekmez; harici uygulama/tarayıcı)
function openGoogleMapsDirectionsToNearest(kind) {
    if (!STATE.currentLocation) {
        showToast('Önce konumunuzu açın.');
        return;
    }
    const target =
        kind === 'hospital' ? STATE.nearestHospital : STATE.nearestAssembly;
    if (!target || target.lat == null || target.lng == null) {
        showToast('Hedef bulunamadı.');
        return;
    }
    const o = `${STATE.currentLocation.lat},${STATE.currentLocation.lng}`;
    const d = `${target.lat},${target.lng}`;
    const url = `https://www.google.com/maps/dir/?api=1&origin=${encodeURIComponent(o)}&destination=${encodeURIComponent(d)}&travelmode=driving`;
    window.open(url, '_blank', 'noopener,noreferrer');
}

// Harita boyutunu yeniden hesapla
function invalidateMapSize() {
    if (map) setTimeout(() => map.invalidateSize(), 100);
}

window.addEventListener('resize', debounce(invalidateMapSize, 250));
window.addEventListener('orientationchange', () => setTimeout(invalidateMapSize, 300));
