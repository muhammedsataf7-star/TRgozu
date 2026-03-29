// TR-GOZU AI Yönlendirme Modülü

// AI yönlendirmeyi çalıştır
async function runAIRouting() {
    const resultsDiv = document.getElementById('routingResults');
    if (resultsDiv) {
        resultsDiv.innerHTML = '<p style="font-size: 11px; color: var(--text-dim);">🔄 AI analiz yapıyor...</p>';
    }

    showToast('AI ekip yönlendirme başlatıldı...');

    const citizens = getCitizens();
    const sosList = getSOSList();
    const volunteers = getVolunteers();

    // SOS olanları öncelikli grupla
    const urgentCases = citizens.filter(c =>
        c.isSOS || c.isPanic ||
        c.healthStatus === 'kritik' ||
        c.healthStatus === 'enkaz'
    );

    // Bölgesel gruplama
    const regions = groupByRegion(urgentCases);

    // Yönlendirme önerileri
    const routing = [];

    for (const region of regions) {
        const center = calculateRegionCenter(region.cases);
        const teamCount = Math.ceil(region.cases.length / 3); // Her ekip max 3 vaka

        routing.push({
            region,
            center,
            teamCount,
            priority: calculateRegionPriority(region.cases)
        });

        // Haritaya işaretle
        if (window.map && region.cases.length > 0) {
            addRegionMarker(center.lat, center.lng, region.cases.length, region.priority);
        }
    }

    // UI'ı güncelle
    if (resultsDiv) {
        resultsDiv.innerHTML = routing.map(r => `
            <div class="routing-card" style="border-left-color: ${getPriorityColor(r.priority)};">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <strong>Bölge ${r.region.name || 'Merkez'}</strong>
                    <span style="background: ${getPriorityColor(r.priority)}; padding: 2px 8px; border-radius: 8px; font-size: 10px; color: white;">
                        ${r.priority.toUpperCase()}
                    </span>
                </div>
                <div style="font-size: 11px; color: var(--text-muted); margin-top: 4px;">
                    📍 ${r.center.lat.toFixed(3)}, ${r.center.lng.toFixed(3)}<br>
                    👥 ${r.cases.length} acil vaka<br>
                    🚑 ${r.teamCount} ekip gerekli
                </div>
                <button class="btn btn-outline btn-sm" style="margin-top: 8px; padding: 6px 10px;"
                        onclick="flyToLocation(${r.center.lat}, ${r.center.lng})">
                    Haritada Göster
                </button>
            </div>
        `).join('');
    }

    showToast(`AI analiz tamamlandı! ${routing.length} bölge tespit edildi.`);
}

// Bölgeye göre grupla
function groupByRegion(cases) {
    const groups = {};

    cases.forEach(c => {
        if (!c.lat || !c.lng) return;

        // Koordinatları 0.1 dereceye yuvarla (yaklaşık 11 km)
        const gridLat = Math.round(c.lat * 10) / 10;
        const gridLng = Math.round(c.lng * 10) / 10;
        const key = `${gridLat},${gridLng}`;

        if (!groups[key]) {
            groups[key] = {
                name: `Bölge ${Object.keys(groups).length + 1}`,
                lat: gridLat,
                lng: gridLng,
                cases: []
            };
        }
        groups[key].cases.push(c);
    });

    return Object.values(groups);
}

// Bölge merkezini hesapla
function calculateRegionCenter(cases) {
    if (cases.length === 0) {
        return { lat: 0, lng: 0 };
    }

    const totalLat = cases.reduce((sum, c) => sum + (c.lat || 0), 0);
    const totalLng = cases.reduce((sum, c) => sum + (c.lng || 0), 0);

    return {
        lat: totalLat / cases.length,
        lng: totalLng / cases.length
    };
}

// Bölge önceliğini hesapla
function calculateRegionPriority(cases) {
    let score = 0;

    cases.forEach(c => {
        if (c.isPanic) score += 30;
        if (c.isSOS) score += 20;
        if (c.healthStatus === 'enkaz') score += 25;
        if (c.healthStatus === 'kritik') score += 15;
        if (c.healthStatus === 'yaraliyim') score += 10;
    });

    if (score >= 70) return 'critical';
    if (score >= 40) return 'high';
    if (score >= 20) return 'medium';
    return 'low';
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

// Bölge markerı ekle
function addRegionMarker(lat, lng, count, priority) {
    const color = getPriorityColor(priority);

    L.circleMarker([lat, lng], {
        radius: Math.min(30, count * 3),
        color: color,
        fillColor: color,
        fillOpacity: 0.4,
        weight: 3
    }).addTo(window.map).bindPopup(`
        <b style="color: ${color}">${count} Acil Vaka</b><br>
        Öncelik: ${priority.toUpperCase()}
    `);
}

// Ekip yönlendirme önerisi al
function getTeamRecommendation(lat, lng) {
    const volunteers = findNearbyVolunteers(lat, lng, 10);
    const units = []; // fetchNearbyUnits çağrısından gelecek

    return {
        volunteers: volunteers.slice(0, 5),
        nearestUnits: units.slice(0, 3),
        safestRoute: calculateSafestRoute(lat, lng)
    };
}
