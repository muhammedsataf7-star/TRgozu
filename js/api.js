// TR-GOZU API Modülü

/** Sunucu proxy (/api/weather/*) veya doğrudan OpenWeather — anahtar yalnız .env + sunucuda önerilir */
function buildWeatherRequestUrl(endpoint, params) {
    const q = new URLSearchParams();
    Object.keys(params).forEach((k) => {
        if (params[k] != null && params[k] !== '') q.set(k, String(params[k]));
    });
    const base = typeof CONFIG !== 'undefined' && CONFIG.API_BASE_URL;
    if (base) {
        return `${base}/api/weather/${endpoint}?${q.toString()}`;
    }
    const key = CONFIG.WEATHER_API_KEY;
    if (!key) return null;
    q.set('appid', key);
    q.set('units', 'metric');
    q.set('lang', 'tr');
    return `https://api.openweathermap.org/data/2.5/${endpoint}?${q.toString()}`;
}

// Haritada tıklanan nokta: OpenWeather Current Weather + Air Pollution (güncel, tek sağlayıcı)
async function showMapClickWeatherPopup(lat, lng) {
    if (!window.map) return;

    const popup = L.popup({ maxWidth: 300, className: 'map-weather-popup' })
        .setLatLng([lat, lng])
        .setContent('<div style="font-size:12px;color:#94a3b8;padding:4px 0">Yükleniyor…<br><small>OpenWeather API</small></div>')
        .openOn(window.map);

    const weatherP = fetchWeatherData(lat, lng);
    const airUrl = buildWeatherRequestUrl('air_pollution', { lat, lon });
    const airP = airUrl
        ? fetch(airUrl)
            .then((r) => (r.ok ? r.json() : null))
            .catch(() => null)
        : Promise.resolve(null);

    const [w, airJson] = await Promise.all([weatherP, airP]);

    if (!w) {
        popup.setContent('<div style="font-size:12px;color:#fca5a5">Bu konum için hava verisi alınamadı.</div>');
        return;
    }

    const temp = Math.round(w.main.temp);
    const heatIdx = typeof calculateHeatIndex === 'function'
        ? calculateHeatIndex(temp, w.main.humidity)
        : temp;
    const desc = (w.weather && w.weather[0] && w.weather[0].description) || '';
    const icon = typeof getWeatherIcon === 'function' ? getWeatherIcon(w.weather[0].main) : '';
    const p = w.main.pressure;
    const hum = w.main.humidity;
    const wind = (w.wind && w.wind.speed ? w.wind.speed : 0) * 3.6;
    const rain1h = (w.rain && (w.rain['1h'] ?? w.rain['1H'])) != null
        ? Number(w.rain['1h'] ?? w.rain['1H'])
        : (w.rain && w.rain['3h'] != null)
            ? Number(w.rain['3h']) / 3
            : 0;
    const place = w.name || '';

    let aqiRow = '';
    if (airJson && airJson.list && airJson.list[0]) {
        const aqi = airJson.list[0].main.aqi;
        const labels = ['Çok iyi', 'İyi', 'Orta', 'Kötü', 'Çok kötü'];
        const colors = ['#2ecc71', '#a3cb38', '#f1c40f', '#e67e22', '#e74c3c'];
        const idx = Math.min(Math.max(aqi - 1, 0), 4);
        const label = labels[idx];
        const col = colors[idx];
        aqiRow = `<tr><td style="color:#94a3b8;padding:2px 0">Hava kirliliği</td><td><b style="color:${col}">AQI ${aqi}</b> — ${label}</td></tr>`;
        if (typeof updateAQIBar === 'function') {
            updateAQIBar(aqi, { label, color: col, emoji: '' });
        }
    }

    popup.setContent(`
        <div style="font-size:12px;line-height:1.45;min-width:230px;color:#e2e8f0">
            <div style="font-weight:bold;margin-bottom:4px">${icon} <span style="font-size:1.1em">${temp}°C</span>
                <span style="opacity:.85;font-weight:500"> (hissedilen ${heatIdx}°C)</span></div>
            <div style="color:#94a3b8;margin-bottom:8px;text-transform:capitalize">${desc}</div>
            ${place ? `<div style="font-size:10px;color:#64748b;margin-bottom:6px">${place}</div>` : ''}
            <table style="width:100%;font-size:11px;border-collapse:collapse">
                <tr><td style="color:#94a3b8;padding:2px 0">Basınç</td><td><b>${p != null ? Math.round(p) : '—'}</b> mbar (hPa)</td></tr>
                <tr><td style="color:#94a3b8">Nem</td><td><b>%${hum != null ? hum : '—'}</b></td></tr>
                <tr><td style="color:#94a3b8">Rüzgâr</td><td><b>${wind.toFixed(1)}</b> km/s</td></tr>
                <tr><td style="color:#94a3b8">Yağış (≈1 saat)</td><td><b>${rain1h.toFixed(1)}</b> mm/saat</td></tr>
                ${aqiRow}
            </table>
            <div style="font-size:9px;color:#64748b;margin-top:8px">${lat.toFixed(4)}, ${lng.toFixed(4)} · OpenWeatherMap</div>
        </div>
    `);
}

// OpenWeatherMap — anlık hava (Current Weather API, metric + tr)
async function fetchWeatherData(lat, lng) {
    try {
        const url = buildWeatherRequestUrl('weather', { lat, lon });
        if (!url) {
            console.warn('Hava verisi: WEATHER_API_KEY veya sunucu proxy gerekli.');
            return null;
        }
        const response = await fetch(url);
        if (!response.ok) throw new Error('Weather API error');
        const data = await response.json();
        STATE.lastWeatherData = data;
        return data;
    } catch (error) {
        console.error('Hava durumu hatası:', error);
        return null;
    }
}

// OpenWeatherMap 5 günlük tahmin
async function fetchWeatherForecast(lat, lng) {
    try {
        const url = buildWeatherRequestUrl('forecast', { lat, lon, cnt: 16 });
        if (!url) return null;
        const response = await fetch(url);
        if (!response.ok) throw new Error('Forecast API error');
        return await response.json();
    } catch (error) {
        console.error('Hava tahmini hatası:', error);
        return null;
    }
}

// AFAD ArcGIS FeatureServer — deprem noktaları (resmi AFAD altyapısı)
async function fetchAFADArcGISSeismic(limit = 200) {
    try {
        const url = `${CONFIG.AFAD_ARCGIS_EARTHQUAKE}/query?f=geojson&where=mag>=2&outFields=time,latitude,longitude,depth,mag,place&returnGeometry=true&orderByFields=time+DESC&resultRecordCount=${limit}`;
        const response = await fetch(url);
        if (!response.ok) throw new Error(`AFAD ArcGIS ${response.status}`);
        const gj = await response.json();
        if (!gj.features || !Array.isArray(gj.features)) return null;

        return gj.features.map(f => {
            const p = f.properties || {};
            const t = p.time != null ? new Date(p.time).toISOString() : new Date().toISOString();
            return {
                id: p.id || `afad_${p.time}_${p.latitude}`,
                lat: parseFloat(p.latitude ?? f.geometry?.coordinates?.[1]),
                lng: parseFloat(p.longitude ?? f.geometry?.coordinates?.[0]),
                magnitude: parseFloat(p.mag) || 0,
                depth: parseFloat(p.depth) || 0,
                place: p.place || 'Bilinmeyen konum',
                time: t,
                source: 'afad'
            };
        }).filter(eq => !isNaN(eq.lat) && !isNaN(eq.lng));
    } catch (e) {
        console.error('AFAD ArcGIS:', e);
        return null;
    }
}

// NASA VIIRS NRT sıcak noktalar — harita görünüm alanı için
async function fetchFIRMSHotspotsInBBox(west, south, east, north, limit = 600) {
    const pad = 0.15;
    west = Math.max(-180, west - pad);
    east = Math.min(180, east + pad);
    south = Math.max(-85, south - pad);
    north = Math.min(85, north + pad);
    const geom = `${west},${south},${east},${north}`;
    try {
        const url = `${CONFIG.NASA_VIIRS_HOTSPOTS_LAYER}/query?f=geojson&where=1%3D1&geometry=${encodeURIComponent(geom)}&geometryType=esriGeometryEnvelope&inSR=4326&spatialRel=esriSpatialRelIntersects&outFields=latitude,longitude,bright_ti4,frp,confidence,satellite,acq_date,daynight&returnGeometry=true&resultRecordCount=${limit}`;
        const response = await fetch(url);
        if (!response.ok) throw new Error(`VIIRS ${response.status}`);
        const gj = await response.json();
        if (!gj.features) return [];
        return gj.features.map(f => {
            const p = f.properties || {};
            const lat = p.latitude ?? f.geometry?.coordinates?.[1];
            const lng = p.longitude ?? f.geometry?.coordinates?.[0];
            return {
                lat: parseFloat(lat),
                lng: parseFloat(lng),
                frp: parseFloat(p.frp) || 0,
                brightness: parseFloat(p.bright_ti4) || 0,
                confidence: p.confidence || '-',
                satellite: p.satellite || 'VIIRS',
                daynight: p.daynight === 'D' ? 'Gündüz' : 'Gece'
            };
        }).filter(h => !isNaN(h.lat) && !isNaN(h.lng));
    } catch (e) {
        console.error('VIIRS/FIRMS hotspots:', e);
        return [];
    }
}

function dedupeEarthquakes(list) {
    const seen = new Set();
    const out = [];
    const sorted = [...list].sort((a, b) => {
        const ta = new Date(a.time).getTime();
        const tb = new Date(b.time).getTime();
        return tb - ta;
    });
    for (const eq of sorted) {
        if (eq.lat == null || eq.lng == null) continue;
        const k = `${eq.lat.toFixed(2)}|${eq.lng.toFixed(2)}|${String(eq.time).slice(0, 16)}|${eq.magnitude?.toFixed(1)}`;
        if (seen.has(k)) continue;
        seen.add(k);
        out.push(eq);
    }
    return out;
}

async function fetchMergedEarthquakeList() {
    const [afad, kandilli] = await Promise.all([
        fetchAFADArcGISSeismic(250),
        fetchKandilliData()
    ]);
    const raw = [...(afad || []), ...(kandilli || [])];
    if (raw.length) return dedupeEarthquakes(raw);
    return await fetchEarthquakeData(2.5);
}

function parseKandilliEqTime(eq) {
    if (!eq || !eq.time) return 0;
    const ts = String(eq.time);
    if (ts.includes('T')) {
        const x = new Date(ts).getTime();
        return isNaN(x) ? 0 : x;
    }
    const norm = ts.trim().replace(/^(\d{4}-\d{2}-\d{2})\s+/, '$1T');
    const x = new Date(norm).getTime();
    return isNaN(x) ? 0 : x;
}

// SOS öncesi: bölgede Kandilli ile yakın zamanda deprem var mı?
async function verifyKandilliSeismicNear(lat, lng) {
    const maxH = CONFIG.SOS_KANDILLI_MAX_HOURS;
    const maxKm = CONFIG.SOS_KANDILLI_RADIUS_KM;
    const minM = CONFIG.SOS_KANDILLI_MIN_MAG;

    let data;
    try {
        data = await fetchKandilliData();
    } catch (e) {
        data = null;
    }
    if (!data || !data.length) {
        return {
            verified: true,
            reason: 'api_yok',
            detail: 'Kandilli verisi alınamadı; güvenlik için yetkili bildirimi açık kabul edildi.'
        };
    }

    const now = Date.now();
    const windowMs = maxH * 3600000;
    let closest = null;

    for (const eq of data) {
        if (eq.lat == null || eq.lng == null || isNaN(eq.lat) || isNaN(eq.lng)) continue;
        const t = parseKandilliEqTime(eq);
        if (!t || now - t > windowMs) continue;

        const dist = calculateDistance(lat, lng, eq.lat, eq.lng);
        const mag = parseFloat(eq.magnitude) || 0;

        if (dist <= maxKm && mag >= minM) {
            return {
                verified: true,
                reason: 'kandilli_eslesti',
                detail: `M${mag.toFixed(1)} — ${Math.round(dist)} km — ${eq.place || ''}`.trim()
            };
        }
        if (!closest || dist < closest.dist) {
            closest = { dist, mag, place: eq.place, t };
        }
    }

    return {
        verified: false,
        reason: 'eslesme_yok',
        detail: closest
            ? `Son kayıt: M${closest.mag?.toFixed(1)} — ${Math.round(closest.dist)} km (eşik dışı veya süre dışı)`
            : `${maxH} saat / ${maxKm} km içinde eşleşen Kandilli kaydı yok`
    };
}

// USGS son ~24 saat (feed “day”) — Türkiye kutusu + kullanıcıya yakın sayım
async function fetchUSGSTurkeyAndLocalStats(userLat, userLng) {
    const bbox = CONFIG.TURKEY_BBOX;
    const res = {
        turkeyCount: 0,
        within200km: 0,
        lines: [],
        byPlace: {}
    };

    try {
        const response = await fetch(`${CONFIG.EARTHQUAKE_API}2.5_day.geojson`);
        if (!response.ok) throw new Error('USGS');
        const geo = await response.json();
        const features = geo.features || [];
        const dayMs = 24 * 3600000;
        const now = Date.now();

        for (const f of features) {
            const p = f.properties || {};
            const t = p.time;
            if (!t || now - t > dayMs) continue;

            const lng = f.geometry?.coordinates?.[0];
            const la = f.geometry?.coordinates?.[1];
            if (la == null || lng == null) continue;

            const inTurkey = la >= bbox.minLat && la <= bbox.maxLat && lng >= bbox.minLon && lng <= bbox.maxLon;
            if (!inTurkey) continue;

            res.turkeyCount++;
            const dist = calculateDistance(userLat, userLng, la, lng);
            if (dist <= 200) res.within200km++;

            const place = (p.place || 'Bilinmiyor').split(',').map(s => s.trim());
            const regionKey = place.length >= 2 ? place[place.length - 2] : place[0];
            res.byPlace[regionKey] = (res.byPlace[regionKey] || 0) + 1;

            if (res.lines.length < 6) {
                res.lines.push(`M${(p.mag || 0).toFixed(1)} ${p.place || ''} (${new Date(t).toLocaleString('tr-TR', { hour: '2-digit', minute: '2-digit', day: '2-digit', month: '2-digit' })})`);
            }
        }
    } catch (e) {
        console.error('USGS TR özeti:', e);
    }

    return res;
}

// Kandilli Rasathanesi - GERÇEK VERİ (birincil kaynak)
async function fetchKandilliData() {
    try {
        const response = await fetch(CONFIG.KANDILLI_API);
        if (!response.ok) throw new Error(`Kandilli API ${response.status}`);
        const data = await response.json();

        // Kandilli API formatı: {status: true, result: [{earthquake_id, title, date, time, mag, depth, lng, lat}]}
        if (!data.status || !Array.isArray(data.result)) {
            throw new Error('Geçersiz Kandilli yanıtı');
        }

        return data.result.map(eq => ({
            id: eq.earthquake_id || String(Math.random()),
            lat: parseFloat(eq.lat),
            lng: parseFloat(eq.lng),
            magnitude: parseFloat(eq.mag) || 0,
            depth: parseFloat(eq.depth) || 0,
            place: eq.title || 'Bilinmeyen konum',
            time: eq.date && eq.time ? `${eq.date} ${eq.time}` : new Date().toISOString(),
            source: 'kandilli'
        }));
    } catch (error) {
        console.error('Kandilli verisi hatası:', error);
        return null;
    }
}

// USGS Deprem verileri (yedek kaynak)
async function fetchEarthquakeData(minMagnitude = 2.5) {
    try {
        const response = await fetch(
            `${CONFIG.EARTHQUAKE_API}${minMagnitude}_day.geojson`
        );
        if (!response.ok) throw new Error('Earthquake API error');
        const data = await response.json();

        if (!data.features) return [];

        return data.features.map(eq => ({
            id: eq.id,
            lat: eq.geometry.coordinates[1],
            lng: eq.geometry.coordinates[0],
            magnitude: eq.properties.mag || 0,
            depth: eq.geometry.coordinates[2] || 0,
            place: eq.properties.place || 'Bilinmeyen',
            time: new Date(eq.properties.time).toISOString(),
            source: 'usgs'
        }));
    } catch (error) {
        console.error('USGS deprem verisi hatası:', error);
        return null;
    }
}

// OSRM Gerçek Yol Rotası Hesapla
// NOT: OSRM koordinatları lon,lat sırasında alır (Leaflet'in lat,lon sıralamasının aksine)
async function fetchOSRMRoute(startLat, startLng, endLat, endLng) {
    try {
        const url = `${CONFIG.OSRM_API}/${startLng},${startLat};${endLng},${endLat}?overview=full&geometries=geojson`;
        const response = await fetch(url);
        if (!response.ok) throw new Error(`OSRM ${response.status}`);
        const data = await response.json();

        if (data.code !== 'Ok' || !data.routes || data.routes.length === 0) {
            throw new Error('Rota bulunamadı');
        }

        const route = data.routes[0];
        // OSRM'den gelen koordinatlar [lon, lat] -> Leaflet için [lat, lon]'a çevir
        const coordinates = route.geometry.coordinates.map(([lon, lat]) => [lat, lon]);

        return {
            coordinates,
            distance: route.distance,
            duration: route.duration,
            distanceKm: (route.distance / 1000).toFixed(1),
            durationMin: Math.ceil(route.duration / 60)
        };
    } catch (error) {
        console.error('OSRM rota hatası:', error);
        return null;
    }
}

// Isı İndeksi Hesapla (Steadman/Rothfusz formülü)
function calculateHeatIndex(tempC, humidity) {
    if (humidity == null || humidity < 0) return tempC;
    const T = tempC * 9 / 5 + 32; // Celsius -> Fahrenheit
    if (T < 80) return Math.round(tempC); // 27°C altında düzeltme gerekmez

    const RH = humidity;
    const HI_F = -42.379
        + 2.04901523 * T
        + 10.14333127 * RH
        - 0.22475541 * T * RH
        - 0.00683783 * T * T
        - 0.05481717 * RH * RH
        + 0.00122874 * T * T * RH
        + 0.00085282 * T * RH * RH
        - 0.00000199 * T * T * RH * RH;

    return Math.round((HI_F - 32) * 5 / 9);
}

// Overpass API - Yakın birimleri bul
async function fetchNearbyUnits(lat, lng, radius = 10000) {
        const query = `
        [out:json][timeout:40];
        (
            node["amenity"="hospital"](around:${radius},${lat},${lng});
            node["amenity"="clinic"](around:${radius},${lat},${lng});
            node["amenity"="doctors"](around:${radius},${lat},${lng});
            node["amenity"="police"](around:${radius},${lat},${lng});
            node["amenity"="fire_station"](around:${radius},${lat},${lng});
            node["amenity"="emergency_ambulance_station"](around:${radius},${lat},${lng});
            node["social_facility"="assembly_point"](around:${radius},${lat},${lng});
            node["emergency"="assembly_point"](around:${radius},${lat},${lng});
            node["leisure"="park"](around:${radius},${lat},${lng});
            node["amenity"="school"](around:${radius},${lat},${lng});
            node["place"="square"](around:${radius},${lat},${lng});
            node["amenity"="townhall"](around:${radius},${lat},${lng});
            node["office"="government"](around:${radius},${lat},${lng});
            node["military"="office"](around:${radius},${lat},${lng});
            node["military"="barracks"](around:${radius},${lat},${lng});
            way["amenity"="hospital"](around:${radius},${lat},${lng});
            way["amenity"="police"](around:${radius},${lat},${lng});
            way["amenity"="fire_station"](around:${radius},${lat},${lng});
            way["leisure"="park"](around:${radius},${lat},${lng});
            way["amenity"="school"](around:${radius},${lat},${lng});
            way["emergency"="assembly_point"](around:${radius},${lat},${lng});
            way["amenity"="townhall"](around:${radius},${lat},${lng});
            way["office"="government"](around:${radius},${lat},${lng});
            way["military"="office"](around:${radius},${lat},${lng});
            way["military"="barracks"](around:${radius},${lat},${lng});
            relation["amenity"="hospital"](around:${radius},${lat},${lng});
        );
        out center;
    `;

    try {
        const response = await fetch(CONFIG.OVERPASS_API + '?data=' + encodeURIComponent(query));
        if (!response.ok) throw new Error('Overpass API error');
        const data = await response.json();

        const raw = data.elements.map(el => ({
            id: el.id,
            name: el.tags.name || 'İsimsiz Birim',
            type: categorizeUnit(el.tags),
            lat: el.lat || el.center?.lat,
            lng: el.lon || el.center?.lon,
            tags: el.tags
        })).filter(u => u.lat && u.lng);

        const byKey = new Map();
        for (const u of raw) {
            const k = `${u.type}|${u.lat.toFixed(5)}|${u.lng.toFixed(5)}|${u.name.slice(0, 40)}`;
            if (!byKey.has(k)) byKey.set(k, u);
        }
        return Array.from(byKey.values());
    } catch (error) {
        console.error('Overpass API hatası:', error);
        return [];
    }
}

/**
 * OpenStreetMap Overpass — görünür alan (bbox) içindeki şehir / kasaba / büyük yerleşim (place=*).
 * Kaynak: © OpenStreetMap contributors — https://www.openstreetmap.org/copyright
 */
async function fetchPlacesInBBox(south, west, north, east, limit = 55) {
    south = Number(south);
    west = Number(west);
    north = Number(north);
    east = Number(east);
    if ([south, west, north, east].some((n) => Number.isNaN(n))) return [];
    if (south >= north || west === east) return [];
    if (west > east) return [];

    const spanLat = north - south;
    const spanLng = east - west;
    const includeVillage = spanLat < 3.5 && spanLng < 3.5;

    const placeRegex = includeVillage
        ? '^(city|town|large_town|village)$'
        : '^(city|town|large_town)$';

    const outN = Math.min(120, Math.max(20, limit));
    const query = `
[out:json][timeout:28];
(
  node["place"~"${placeRegex}"](${south},${west},${north},${east});
  way["place"~"${placeRegex}"](${south},${west},${north},${east});
);
out center ${outN};
`;

    try {
        const response = await fetch(CONFIG.OVERPASS_API + '?data=' + encodeURIComponent(query));
        if (!response.ok) throw new Error('Overpass places ' + response.status);
        const data = await response.json();
        if (!data.elements || !Array.isArray(data.elements)) return [];

        const raw = data.elements
            .map((el) => {
                const name = el.tags && (el.tags.name || el.tags['name:tr'] || el.tags['name:en']);
                if (!name) return null;
                const lat = el.lat != null ? el.lat : el.center?.lat;
                const lng = el.lon != null ? el.lon : el.center?.lon;
                if (lat == null || lng == null) return null;
                const place = (el.tags && el.tags.place) || 'town';
                return { lat, lng, name: String(name).slice(0, 42), place };
            })
            .filter(Boolean);

        const byKey = new Map();
        for (const p of raw) {
            const k = `${p.lat.toFixed(4)}|${p.lng.toFixed(4)}|${p.name.slice(0, 20)}`;
            if (!byKey.has(k)) byKey.set(k, p);
        }
        return Array.from(byKey.values()).slice(0, limit);
    } catch (e) {
        console.warn('Overpass şehir/yerleşim:', e);
        return [];
    }
}

// Birimi kategorize et
function categorizeUnit(tags) {
    const name = (tags.name || '').toLowerCase();

    if (tags.emergency === 'assembly_point') return 'assembly';
    if (tags.social_facility === 'assembly_point') return 'assembly';

    if (tags.amenity === 'hospital') return 'hospital';
    if (tags.amenity === 'clinic') return 'hospital';
    if (tags.amenity === 'doctors') return 'hospital';

    if (tags.amenity === 'fire_station') return 'fire';
    if (tags.amenity === 'emergency_ambulance_station') return 'ambulance';

    if (tags.amenity === 'police') {
        if (name.includes('jandarma') || name.includes('gendarmerie')) return 'gendarmerie';
        return 'police';
    }

    if (tags.military === 'office' || tags.military === 'barracks') {
        if (name.includes('jandarma') || name.includes('gendarmerie')) return 'gendarmerie';
        return 'military';
    }

    if (tags.amenity === 'townhall' || tags.office === 'government') return 'government';

    if (tags.leisure === 'park') return 'park';
    if (tags.amenity === 'school') return 'school';
    if (tags.place === 'square') return 'square';
    return 'unknown';
}

function applyRiskMeterClasses(risks) {
    const paint = (rowSel, value) => {
        const el = typeof rowSel === 'string' ? document.querySelector(rowSel) : rowSel;
        if (!el) return;
        el.classList.remove('risk-meter-low', 'risk-meter-mid', 'risk-meter-high', 'risk-meter-crit');
        const v = Number(value) || 0;
        if (v < 25) el.classList.add('risk-meter-low');
        else if (v < 50) el.classList.add('risk-meter-mid');
        else if (v < 75) el.classList.add('risk-meter-high');
        else el.classList.add('risk-meter-crit');
    };
    paint('#risk-row-deprem', risks.earthquake);
    paint('#risk-row-sel', risks.flood);
    paint('#risk-row-firtina', risks.storm);
    paint('#risk-row-yangin', risks.fire);
}

function notifyCitizenEnvironmentalRisks(risks, lat, lng, extras) {
    if (STATE.userRole === 'admin') return;
    if (!('Notification' in window) || Notification.permission !== 'granted') return;

    const now = Date.now();
    const minGap = 25 * 60 * 1000;

    if (extras.fireHotspots > 0 && risks.fire >= 55) {
        const k = 'trgozu_last_notify_fire';
        if (now - parseInt(sessionStorage.getItem(k) || '0', 10) > minGap) {
            sessionStorage.setItem(k, String(now));
            sendNotification(
                'TR-GOZU — Yangın riski',
                `Bölgenize yakın uydu (VIIRS) ile ${extras.fireHotspots} sıcak nokta tespit edildi. Dikkatli olun; 110`,
                { tag: 'trgozu-fire', requireInteraction: false }
            );
        }
    }

    if (extras.rain1h >= 10 && risks.flood >= 50) {
        const k = 'trgozu_last_notify_flood';
        if (now - parseInt(sessionStorage.getItem(k) || '0', 10) > minGap) {
            sessionStorage.setItem(k, String(now));
            sendNotification(
                'TR-GOZU — Yoğun yağış',
                `Son saat yağış tahmini yüksek (~${extras.rain1h.toFixed(1)} mm). Sel riskine karşı yüksek zemine çıkın.`,
                { tag: 'trgozu-rain', requireInteraction: false }
            );
        }
    }

    if (risks.earthquake >= 72) {
        const k = 'trgozu_last_notify_eq';
        if (now - parseInt(sessionStorage.getItem(k) || '0', 10) > minGap) {
            sessionStorage.setItem(k, String(now));
            sendNotification(
                'TR-GOZU — Deprem riski',
                'Konumunuza yakın sismik aktivite yüksek. Güvenli alana geçin; çök-kapan-tutun.',
                { tag: 'trgozu-eq', requireInteraction: false }
            );
        }
    }
}

// Risk analizi yap
async function performRiskAnalysis(lat, lng) {
    const risks = { earthquake: 0, flood: 0, storm: 0, fire: 0, overall: 'low' };
    const extras = { rain1h: 0, fireHotspots: 0, pressure: null };

    const usgsStats = await fetchUSGSTurkeyAndLocalStats(lat, lng);
    STATE.usgs24hSummary = usgsStats;

    const usgsEl = document.getElementById('val-usgs-24h');
    if (usgsEl) {
        const topR = Object.entries(usgsStats.byPlace || {}).sort((a, b) => b[1] - a[1]).slice(0, 4);
        const regStr = topR.length ? topR.map(([n, c]) => `${n}: ${c}`).join(' · ') : 'bölge sayımı yok';
        usgsEl.textContent = `USGS 24s TR: ${usgsStats.turkeyCount} olay | ±200 km sizden: ${usgsStats.within200km} | ${regStr}`;
    }

    risks.earthquake = Math.min(45, (usgsStats.within200km || 0) * 9);

    // 1. Hava durumu — yalnız OpenWeather (yağış, basınç mbar, nem, rüzgar)
    const weather = await fetchWeatherData(lat, lng);
    if (weather) {
        const windSpeed = weather.wind.speed * 3.6;
        const humidity = weather.main.humidity;
        const temp = weather.main.temp;
        const weatherMain = weather.weather[0].main.toLowerCase();
        const pressure = weather.main.pressure;
        extras.pressure = pressure;

        const rain1h = (weather.rain && (weather.rain['1h'] ?? weather.rain['1H'])) != null
            ? Number(weather.rain['1h'] ?? weather.rain['1H'])
            : (weather.rain && weather.rain['3h'] != null) ? Number(weather.rain['3h']) / 3 : 0;
        extras.rain1h = rain1h;
        STATE.lastWeatherRainMm = rain1h;

        risks.storm = Math.min(100, Math.round((windSpeed / 100) * 100));
        if (pressure != null && pressure < 1005) {
            risks.storm = Math.min(100, risks.storm + 15);
        }

        risks.flood = Math.round(humidity / 2.5);
        if (weatherMain.includes('rain') || weatherMain.includes('drizzle') || weatherMain.includes('thunderstorm')) {
            risks.flood = Math.min(100, risks.flood + 28 + Math.round(rain1h * 12));
        } else {
            risks.flood = Math.min(100, risks.flood + Math.round(rain1h * 14));
        }

        if (temp > 30 && humidity < 30 && windSpeed > 20) {
            risks.fire = Math.min(100, Math.round(temp * 2 - humidity + windSpeed / 2));
        } else if (temp > 25 && humidity < 40) {
            risks.fire = Math.min(80, Math.round(temp - humidity + 10));
        } else {
            risks.fire = Math.max(0, Math.round((temp - 20) * 2));
        }

        updateWeatherUI(weather, rain1h, pressure);

        if (typeof drawThermalZone === 'function') {
            drawThermalZone(lat, lng, Math.round(temp), humidity);
        }
    }

    // VIIRS sıcak nokta yoğunluğu (yangın görünürlüğü)
    let hotspots = [];
    try {
        const pad = 0.5;
        hotspots = await fetchFIRMSHotspotsInBBox(
            lng - pad, lat - pad, lng + pad, lat + pad, 400
        );
    } catch (e) {
        hotspots = [];
    }
    const localFires = hotspots.filter(h => calculateDistance(lat, lng, h.lat, h.lng) <= 85);
    extras.fireHotspots = localFires.length;
    STATE.lastFireHotspotCount = localFires.length;
    const frpScore = Math.min(55, localFires.reduce((s, h) => s + (h.frp || 0) * 4, 0));
    const countScore = Math.min(45, localFires.length * 12);
    risks.fire = Math.min(100, Math.max(risks.fire, frpScore + countScore));

    // 2. Deprem — yakın olaylar: AFAD+Kandilli; USGS skor yukarıda eklendi
    let earthquakeList = await fetchMergedEarthquakeList();
    let dataSource = 'AFAD + Kandilli';

    if (!earthquakeList || earthquakeList.length === 0) {
        console.warn('Birleşik deprem listesi boş, USGS yedek kullanılıyor...');
        earthquakeList = await fetchEarthquakeData(2.5);
        dataSource = 'USGS';
    }

    if (earthquakeList && earthquakeList.length > 0) {
        let nearestEarthquake = null;
        let minDistance = Infinity;
        let nearbyEarthquakes = [];

        earthquakeList.forEach(eq => {
            if (!eq.lat || !eq.lng || isNaN(eq.lat) || isNaN(eq.lng)) return;
            const distance = calculateDistance(lat, lng, eq.lat, eq.lng);

            if (distance < minDistance) {
                minDistance = distance;
                nearestEarthquake = { ...eq, distance };
            }

            if (distance < 300 && eq.magnitude >= 2.0) {
                nearbyEarthquakes.push({ ...eq, distance });
            }
        });

        if (nearestEarthquake) {
            const nearScore = Math.max(5, Math.min(95,
                Math.round((nearestEarthquake.magnitude * 15) - (nearestEarthquake.distance / 50))
            ));
            risks.earthquake = Math.min(100, Math.max(risks.earthquake, nearScore));
            updateEarthquakeUI(nearestEarthquake, dataSource);
        }

        if (typeof addEarthquakeMarker === 'function') {
            const visibleEqs = nearbyEarthquakes
                .filter(eq => eq.magnitude >= 2.5 && eq.distance < 200)
                .slice(0, 20);
            visibleEqs.forEach(eq => addEarthquakeMarker(eq));
        }

        STATE.nearbyEarthquakes = nearbyEarthquakes;

        const trendEl = document.getElementById('val-deprem-trend');
        if (trendEl) {
            trendEl.textContent = `USGS TR 24s: ${usgsStats.turkeyCount} | ±200 km: ${usgsStats.within200km}`;
        }
    } else {
        STATE.nearbyEarthquakes = [];
    }

    if (weather && typeof loadForecast === 'function') {
        await loadForecast(lat, lng);
    }

    const maxRisk = Math.max(risks.earthquake, risks.flood, risks.storm, risks.fire);
    if (maxRisk >= 70) risks.overall = 'critical';
    else if (maxRisk >= 50) risks.overall = 'high';
    else if (maxRisk >= 30) risks.overall = 'medium';
    else risks.overall = 'low';

    updateRiskUI(risks);
    applyRiskMeterClasses(risks);

    const heurEl = document.getElementById('val-seismic-heuristic');
    if (heurEl) {
        const nNear = Array.isArray(STATE.nearbyEarthquakes)
            ? STATE.nearbyEarthquakes.length
            : 0;
        const nearEq = STATE.nearbyEarthquakes && STATE.nearbyEarthquakes[0];
        const magStr = nearEq && nearEq.magnitude != null
            ? `En yakın kayıt: M${Number(nearEq.magnitude).toFixed(1)} (~${Math.round(nearEq.distance || 0)} km). `
            : '';
        heurEl.textContent =
            'Deprem yüzdeleri bilimsel tahmin değildir; AFAD / Kandilli / USGS akışına dayalı özet skordur. ' +
            magStr +
            `Son taramada yakınınızda (≈300 km) ${nNear} olay listelendi. Resmî uyarılar için Kandilli ve AFAD’ı takip edin.`;
    }

    notifyCitizenEnvironmentalRisks(risks, lat, lng, extras);

    await fetchEmergencyUnits(lat, lng);

    return risks;
}

// Hava durumu UI güncelle (OpenWeather: yağış ve basınç ayrı)
function updateWeatherUI(weather, rain1hOverride, pressureOverride) {
    const belediyeEl = document.getElementById('val-belediye');
    const havaEl = document.getElementById('val-hava');

    if (belediyeEl) belediyeEl.textContent = weather.name || 'Bilinmiyor';

    if (havaEl) {
        const temp = Math.round(weather.main.temp);
        const heatIdx = calculateHeatIndex(temp, weather.main.humidity);
        const desc = weather.weather[0].description;
        const icon = getWeatherIcon(weather.weather[0].main);
        havaEl.textContent = `${icon} ${temp}°C (his: ${heatIdx}°C), ${desc}`;
    }

    const rainMm = rain1hOverride != null ? rain1hOverride : (
        (weather.rain && (weather.rain['1h'] ?? weather.rain['1H'])) != null
            ? Number(weather.rain['1h'] ?? weather.rain['1H'])
            : (weather.rain && weather.rain['3h'] != null) ? Number(weather.rain['3h']) / 3 : 0
    );
    const yagisEl = document.getElementById('val-yagis-mm');
    if (yagisEl) yagisEl.textContent = `${rainMm.toFixed(1)} mm/saat (OpenWeather)`;

    const p = pressureOverride != null ? pressureOverride : weather.main.pressure;
    const basEl = document.getElementById('val-basinç-mbar');
    if (basEl) basEl.textContent = p != null ? `${Math.round(p)} mbar (hPa)` : '-';
}

// Deprem UI güncelle
function updateEarthquakeUI(eq, source) {
    const eqInfoEl = document.getElementById('val-deprem-son');
    if (eqInfoEl) {
        eqInfoEl.textContent = `M${eq.magnitude.toFixed(1)} — ${eq.place || 'Bilinmiyor'} (${Math.round(eq.distance)} km) [${source}]`;
    }
}

// Risk UI güncelle
function updateRiskUI(risks) {
    const depremEl = document.getElementById('val-deprem-risk');
    const selEl = document.getElementById('val-sel-risk');
    const firtinaEl = document.getElementById('val-firtina-risk');
    const yanginEl = document.getElementById('val-yangin-risk');

    if (depremEl) depremEl.textContent = `%${risks.earthquake}`;
    if (selEl) selEl.textContent = `%${risks.flood}`;
    if (firtinaEl) firtinaEl.textContent = `%${risks.storm}`;
    if (yanginEl) yanginEl.textContent = `%${risks.fire}`;

    const locStatusEl = document.getElementById('locStatus');
    if (locStatusEl) {
        if (risks.overall === 'critical') {
            locStatusEl.innerHTML = '<span class="text-danger">KRİTİK RİSK TESPİT EDİLDİ!</span>';
            if (STATE.userRole === 'admin') playSound('alert');
        } else if (risks.overall === 'high') {
            locStatusEl.innerHTML = '<span class="text-warning">YÜKSEK RİSK</span>';
        } else {
            locStatusEl.innerHTML = '<span class="text-success">Bölge Stabil</span>';
        }
    }
}

const EMERGENCY_TYPE_TR = {
    hospital: 'Hastane',
    assembly: 'Toplanma',
    park: 'Park',
    school: 'Okul',
    square: 'Meydan'
};

// Risk paneli: 5 km (CONFIG.INSTITUTION_LIST_RADIUS_KM) içindeki kurumlar için <select> doldur
function fillEmergencyTargetSelects() {
    const rKm = CONFIG.INSTITUTION_LIST_RADIUS_KM != null ? Number(CONFIG.INSTITUTION_LIST_RADIUS_KM) : 5;

    const fillOne = (selectId, list, emptyLabel) => {
        const sel = document.getElementById(selectId);
        if (!sel) return;
        sel.innerHTML = '';
        if (!list || list.length === 0) {
            sel.disabled = true;
            const opt = document.createElement('option');
            opt.value = '';
            opt.textContent = emptyLabel;
            sel.appendChild(opt);
            return;
        }
        sel.disabled = false;
        list.forEach((u, i) => {
            const opt = document.createElement('option');
            opt.value = String(i);
            const tag = EMERGENCY_TYPE_TR[u.type] || u.type || '';
            opt.textContent = `${u.name || 'İsimsiz'} — ${tag} (${u.distance.toFixed(1)} km)`;
            sel.appendChild(opt);
        });
        sel.selectedIndex = 0;
    };

    fillOne(
        'select-hospital-5km',
        STATE.hospitalsWithin5km,
        `${rKm} km içinde sağlık kuruluşu yok (OSM)`
    );
    fillOne(
        'select-assembly-5km',
        STATE.assembliesWithin5km,
        `${rKm} km içinde toplanma / güvenli alan yok (OSM)`
    );
}

// Acil birimleri bul — haritada geniş alan; panelde yalnız yarıçap içi liste + varsayılan en yakın
async function fetchEmergencyUnits(lat, lng) {
    const rKm = CONFIG.INSTITUTION_LIST_RADIUS_KM != null ? Number(CONFIG.INSTITUTION_LIST_RADIUS_KM) : 5;
    const units = await fetchNearbyUnits(lat, lng, 20000);

    const hospitalsAll = units
        .filter((u) => u.type === 'hospital')
        .map((u) => ({
            ...u,
            distance: calculateDistance(lat, lng, u.lat, u.lng)
        }))
        .sort((a, b) => a.distance - b.distance);

    const assembliesAll = units
        .filter((u) =>
            ['assembly', 'park', 'school', 'square'].includes(u.type)
        )
        .map((u) => ({
            ...u,
            distance: calculateDistance(lat, lng, u.lat, u.lng)
        }))
        .sort((a, b) => a.distance - b.distance);

    const hospitals = hospitalsAll.filter((u) => u.distance <= rKm);
    const assemblies = assembliesAll.filter((u) => u.distance <= rKm);

    STATE.hospitalsWithin5km = hospitals;
    STATE.assembliesWithin5km = assemblies;
    STATE.selectedHospitalIndex = 0;
    STATE.selectedAssemblyIndex = 0;

    const hospital = hospitals[0] || null;
    const assembly = assemblies[0] || null;

    STATE.nearestHospital = hospital;
    STATE.nearestAssembly = assembly;

    fillEmergencyTargetSelects();

    if (hospital) {
        updateUI(
            'hospitalBox',
            'val-hastane',
            'val-hastane-mesafe',
            hospital.name,
            hospital.distance.toFixed(1) + ' km'
        );
    } else {
        const hb = document.getElementById('hospitalBox');
        if (hb) {
            hb.classList.remove('hidden');
            const n = document.getElementById('val-hastane');
            const d = document.getElementById('val-hastane-mesafe');
            if (n) n.textContent = `${rKm} km içinde bulunamadı`;
            if (d) d.textContent = '-';
        }
    }

    if (assembly) {
        updateUI(
            'assemblyBox',
            'val-toplanma-ad',
            'val-toplanma-mesafe',
            assembly.name,
            assembly.distance.toFixed(1) + ' km'
        );
    } else {
        const ab = document.getElementById('assemblyBox');
        if (ab) {
            ab.classList.remove('hidden');
            const n = document.getElementById('val-toplanma-ad');
            const d = document.getElementById('val-toplanma-mesafe');
            if (n) n.textContent = `${rKm} km içinde bulunamadı`;
            if (d) d.textContent = '-';
        }
    }

    units.forEach((u) => {
        if (typeof addUnitMarker === 'function') addUnitMarker(u);
    });

    return { assembly, hospital };
}

// UI güncelle
function updateUI(boxId, nameId, distId, name, dist) {
    const box = document.getElementById(boxId);
    if (box) box.classList.remove('hidden');

    const nameEl = document.getElementById(nameId);
    const distEl = document.getElementById(distId);
    if (nameEl) nameEl.textContent = name;
    if (distEl && dist) distEl.textContent = dist;
}

// Konum tabanlı öncelik hesapla
async function calculateLocationPriority(lat, lng) {
    const citizens = getCitizens();
    let nearbyCount = 0;
    let sosCount = 0;

    citizens.forEach(c => {
        if (c.lat && c.lng) {
            const dist = calculateDistance(lat, lng, c.lat, c.lng);
            if (dist <= 1) {
                nearbyCount++;
                if (c.isSOS || c.isPanic) sosCount++;
            }
        }
    });

    let priority = 'low';
    if (sosCount >= CONFIG.PRIORITY_THRESHOLDS.CRITICAL) priority = 'critical';
    else if (sosCount >= CONFIG.PRIORITY_THRESHOLDS.HIGH) priority = 'high';
    else if (sosCount >= CONFIG.PRIORITY_THRESHOLDS.MEDIUM) priority = 'medium';

    return { priority, nearbyCount, sosCount,
        riskLevel: sosCount >= 10 ? 'extreme' : sosCount >= 5 ? 'high' : sosCount >= 3 ? 'medium' : 'low'
    };
}

// Tüm vatandaşları al
function getCitizens() {
    return getFromStorage('citizens', []);
}

// Vatandaş güncelle
function updateCitizen(email, data) {
    const citizens = getCitizens();
    const index = citizens.findIndex(c => c.email === email);

    if (index >= 0) {
        citizens[index] = { ...citizens[index], ...data, lastActive: new Date().toISOString() };
    } else {
        citizens.push({
            email,
            ...data,
            createdAt: new Date().toISOString(),
            lastActive: new Date().toISOString()
        });
    }

    saveToStorage('citizens', citizens);
    return citizens[index >= 0 ? index : citizens.length - 1];
}

// SOS listesini al
function getSOSList() {
    return getFromStorage('sosList', []);
}

// SOS ekle (meta: forwardToAuthority, kandilliCheck — Kandilli doğrulaması)
function addSOS(email, lat, lng, isPanic = false, meta = {}) {
    const forwardToAuthority = meta.forwardToAuthority !== undefined
        ? !!meta.forwardToAuthority
        : true;

    const sosList = getSOSList();
    const sos = {
        id: generateId(),
        user: email,
        lat,
        lng,
        isPanic,
        isVerified: false,
        time: new Date().toISOString(),
        forwardToAuthority,
        kandilliCheck: meta.kandilliCheck || null
    };
    sosList.push(sos);
    saveToStorage('sosList', sosList);

    updateCitizen(email, {
        isSOS: true,
        isPanic: !!isPanic,
        sosTime: sos.time,
        lastSOSForward: forwardToAuthority
    });
    return sos;
}

// SOS kaldır
function removeSOS(email) {
    let sosList = getSOSList();
    sosList = sosList.filter(s => s.user !== email);
    saveToStorage('sosList', sosList);
    updateCitizen(email, { isSOS: false, isPanic: false });
}

// Bildirimleri al
function getAnnouncements() {
    return getFromStorage('announcements', []);
}

// Bildirim ekle
function addAnnouncement(data) {
    const announcements = getAnnouncements();
    const announcement = {
        id: generateId(),
        ...data,
        createdBy: getCurrentUserEmail(),
        createdAt: new Date().toISOString()
    };
    announcements.unshift(announcement);
    saveToStorage('announcements', announcements.slice(0, 50));
    return announcement;
}
