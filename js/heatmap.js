// TR-GOZU Isı Haritası Modülü

let heatmapLayer = null;
let heatmapEnabled = false;

// Isı haritasını aç/kapat
function toggleHeatmap() {
    heatmapEnabled = !heatmapEnabled;
    const btn = document.getElementById('btnHeatmap');

    if (btn) btn.classList.toggle('active', heatmapEnabled);

    if (heatmapEnabled) {
        showHeatmap();
    } else {
        hideHeatmap();
    }
}

// Isı haritasını göster
function showHeatmap() {
    if (!window.map) return;

    // Mevcut katmanı kaldır
    hideHeatmap();

    // SOS verilerini al
    const sosData = getSOSHeatmapData();
    const citizens = getCitizens();

    // Vatandaş verilerini ekle
    citizens.forEach(c => {
        if (c.lat && c.lng) {
            let intensity = 0.3;
            if (c.isPanic) intensity = 1.0;
            else if (c.isSOS) intensity = 0.8;
            else if (c.healthStatus === 'kritik') intensity = 0.9;
            else if (c.healthStatus === 'enkaz') intensity = 1.0;
            else if (c.healthStatus === 'yaraliyim') intensity = 0.6;

            sosData.push({
                lat: c.lat,
                lng: c.lng,
                intensity
            });
        }
    });

    // Isı haritası katmanı oluştur
    heatmapLayer = L.layerGroup();

    sosData.forEach(point => {
        const radius = Math.max(20, point.intensity * 100);
        const opacity = Math.max(0.3, point.intensity * 0.7);
        const color = getHeatmapColor(point.intensity);

        const circle = L.circleMarker([point.lat, point.lng], {
            radius,
            color,
            fillColor: color,
            fillOpacity: opacity,
            weight: 2
        }).addTo(heatmapLayer);

        circle.bindPopup(`
            <b style="color: ${color}">${getHeatmapLabel(point.intensity)}</b>
        `);
    });

    heatmapLayer.addTo(window.map);

    // Harita özelliklerini güncelle
    updateMapOverlay();

    showToast('Isı haritası aktif. Kırmızı = Yoğun, Yeşil = Güvenli');
}

// Isı haritasını gizle
function hideHeatmap() {
    if (heatmapLayer) {
        window.map.removeLayer(heatmapLayer);
        heatmapLayer = null;
    }
}

// Isı haritası rengi
function getHeatmapColor(intensity) {
    if (intensity >= 0.8) return '#ff4757'; // Kırmızı - Kritik
    if (intensity >= 0.6) return '#ffa502'; // Turuncu - Yüksek
    if (intensity >= 0.4) return '#3498db'; // Mavi - Orta
    return '#2ecc71'; // Yeşil - Düşük
}

// Isı haritası etiketi
function getHeatmapLabel(intensity) {
    if (intensity >= 0.8) return '🔴 Kritik Yoğunluk';
    if (intensity >= 0.6) return '🟠 Yüksek Risk';
    if (intensity >= 0.4) return '🔵 Orta Risk';
    return '🟢 Güvenli Bölge';
}

// Harita özelliklerini güncelle
function updateMapOverlay() {
    const panel = document.getElementById('mapOverlayPanel');
    const title = document.getElementById('overlayTitle');
    const content = document.getElementById('overlayContent');

    if (!panel || !title || !content) return;

    const sosList = getSOSList();
    const citizens = getCitizens();

    // İstatistikler
    const activeSOS = sosList.filter(s => !s.resolved).length;
    const criticalHealth = citizens.filter(c =>
        c.healthStatus === 'kritik' || c.healthStatus === 'enkaz'
    ).length;
    const totalActive = citizens.filter(c => c.lat && c.lng).length;

    title.textContent = 'Bölge Durumu';

    content.innerHTML = `
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-bottom: 15px;">
            <div style="background: rgba(255,71,87,0.1); padding: 10px; border-radius: 8px; text-align: center;">
                <div style="font-size: 1.5rem; font-weight: bold; color: var(--primary);">${activeSOS}</div>
                <div style="font-size: 10px; color: var(--text-muted);">Aktif SOS</div>
            </div>
            <div style="background: rgba(255,165,2,0.1); padding: 10px; border-radius: 8px; text-align: center;">
                <div style="font-size: 1.5rem; font-weight: bold; color: var(--warning);">${criticalHealth}</div>
                <div style="font-size: 10px; color: var(--text-muted);">Kritik Vaka</div>
            </div>
        </div>
        <div style="font-size: 11px; color: var(--text-muted);">
            <p><b>Açıklama:</b></p>
            <ul style="margin: 5px 0; padding-left: 15px;">
                <li>🔴 Kırmızı = Kritik yoğunluk (10+ kişi)</li>
                <li>🟠 Turuncu = Yüksek risk (5-10 kişi)</li>
                <li>🔵 Mavi = Orta risk (3-5 kişi)</li>
                <li>🟢 Yeşil = Güvenli bölge</li>
            </ul>
        </div>
    `;

    panel.classList.remove('hidden');
}

// Harita özelliklerini kapat
function closeMapOverlay() {
    const panel = document.getElementById('mapOverlayPanel');
    if (panel) panel.classList.add('hidden');
}

// Bölgesel yoğunluk hesapla
function calculateRegionalDensity() {
    const citizens = getCitizens();
    const sosList = getSOSList();
    const gridSize = 0.5; // 0.5 derece (~55 km)
    const densityMap = {};

    // Tüm vatandaşları grupla
    citizens.forEach(c => {
        if (!c.lat || !c.lng) return;

        const gridLat = Math.floor(c.lat / gridSize) * gridSize;
        const gridLng = Math.floor(c.lng / gridSize) * gridSize;
        const key = `${gridLat},${gridLng}`;

        if (!densityMap[key]) {
            densityMap[key] = {
                lat: gridLat + gridSize / 2,
                lng: gridLng + gridSize / 2,
                count: 0,
                critical: 0
            };
        }

        densityMap[key].count++;

        if (c.isSOS || c.isPanic ||
            c.healthStatus === 'kritik' ||
            c.healthStatus === 'enkaz') {
            densityMap[key].critical++;
        }
    });

    // SOS'leri de ekle
    sosList.forEach(s => {
        if (s.resolved || !s.lat || !s.lng) return;

        const gridLat = Math.floor(s.lat / gridSize) * gridSize;
        const gridLng = Math.floor(s.lng / gridSize) * gridSize;
        const key = `${gridLat},${gridLng}`;

        if (!densityMap[key]) {
            densityMap[key] = {
                lat: gridLat + gridSize / 2,
                lng: gridLng + gridSize / 2,
                count: 0,
                critical: 0
            };
        }

        densityMap[key].count++;
        densityMap[key].critical++;
    });

    return Object.values(densityMap);
}

// Kritik bölgeleri işaretle
function markCriticalRegions() {
    const regions = calculateRegionalDensity();

    regions.forEach(region => {
        if (region.critical >= CONFIG.PRIORITY_THRESHOLDS.CRITICAL) {
            // Kritik bölge
            L.circleMarker([region.lat, region.lng], {
                radius: Math.min(40, region.count * 2),
                color: '#ff4757',
                fillColor: '#ff4757',
                fillOpacity: 0.3,
                weight: 3,
                dashArray: '10, 5'
            }).addTo(window.map).bindPopup(`
                <b style="color: #ff4757">🚨 KRİTİK BÖLGE</b><br>
                Kişi sayısı: ${region.count}<br>
                Kritik vaka: ${region.critical}
            `);
        }
    });
}
