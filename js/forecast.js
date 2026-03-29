// TR-GOZU tahmin (OpenWeather forecast + sismik trend özeti)
let forecastLoaded = false;

async function loadForecast(lat, lng) {
    try {
        const [weatherForecast, earthquakeForecast] = await Promise.all([
            fetchWeatherForecast(lat, lng),
            analyzeEarthquakeTrend(lat, lng)
        ]);

        const floodForecast = analyzeFloodRisk(weatherForecast);
        const fireForecast = analyzeFireRisk(STATE.lastWeatherData);

        STATE.forecastData = {
            earthquake: earthquakeForecast,
            flood: floodForecast,
            fire: fireForecast,
            updatedAt: new Date().toISOString()
        };

        updateForecastUI(STATE.forecastData);
        forecastLoaded = true;
    } catch (err) {
        console.error('Tahmin yüklenemedi:', err);
    }
}

async function analyzeEarthquakeTrend(lat, lng) {
    const nearbyEqs = STATE.nearbyEarthquakes || [];

    if (nearbyEqs.length === 0) {
        return {
            level: 'bilinmiyor',
            label: 'Veri yok',
            color: '#95a5a6',
            detail: 'Deprem listesi boş veya henüz yüklenmedi.'
        };
    }

    const nearby = nearbyEqs.filter(eq => eq.distance < 300);
    const count = nearby.length;
    const maxMag = nearby.reduce((max, eq) => Math.max(max, eq.magnitude), 0);
    const largeCount = nearby.filter(eq => eq.magnitude >= 4.0).length;
    const veryLargeCount = nearby.filter(eq => eq.magnitude >= 5.0).length;

    let level;
    let label;
    let color;
    let detail;

    if (veryLargeCount > 0) {
        level = 'kritik'; label = 'KRİTİK'; color = '#ff4757';
        detail = `${veryLargeCount} adet M5+ deprem (${Math.round(nearby[0]?.distance || 0)} km).`;
    } else if (largeCount > 0 || count >= 10) {
        level = 'yuksek'; label = 'YÜKSEK'; color = '#ffa502';
        detail = `${count} deprem (M${maxMag.toFixed(1)} max, ${Math.round(nearby[0]?.distance || 0)} km).`;
    } else if (count >= 5) {
        level = 'orta'; label = 'ORTA'; color = '#f1c40f';
        detail = `Bölgede ${count} küçük sismik aktivite.`;
    } else if (count > 0) {
        level = 'dusuk'; label = 'DÜŞÜK'; color = '#2ecc71';
        detail = `Bölgede ${count} küçük sismik aktivite.`;
    } else {
        level = 'normal'; label = 'NORMAL'; color = '#00d2ff';
        detail = 'Yakın bölgede kayda değer sismik aktivite yok.';
    }

    return {
        level, label, color, detail, count, maxMag,
        disclaimer: 'Geçmiş aktiviteye dayanır; deprem önceden kesin kestirilemez.'
    };
}

function analyzeFloodRisk(forecast) {
    if (!forecast || !forecast.list) {
        return { level: 'bilinmiyor', label: 'Veri yok', color: '#95a5a6', detail: 'Hava tahmini alınamadı.' };
    }

    const next48h = forecast.list.slice(0, 16);
    const totalRain = next48h.reduce((sum, item) => sum + (item.rain ? item.rain['3h'] || 0 : 0), 0);
    const maxHumidity = Math.max(...next48h.map(i => i.main.humidity));
    const hasThunderstorm = next48h.some(i => i.weather[0].main.toLowerCase().includes('thunderstorm'));

    let level;
    let label;
    let color;
    let detail;

    if (totalRain > 50 || (totalRain > 30 && hasThunderstorm)) {
        level = 'kritik'; label = 'KRİTİK'; color = '#ff4757';
        detail = `48 saatte ~${totalRain.toFixed(0)} mm yağış${hasThunderstorm ? ', gök gürültülü' : ''}.`;
    } else if (totalRain > 20 || (totalRain > 10 && maxHumidity > 85)) {
        level = 'yuksek'; label = 'YÜKSEK'; color = '#ffa502';
        detail = `48 saatte ~${totalRain.toFixed(0)} mm, nem %${maxHumidity}.`;
    } else if (totalRain > 5) {
        level = 'orta'; label = 'ORTA'; color = '#f1c40f';
        detail = `48 saatte ~${totalRain.toFixed(0)} mm yağış.`;
    } else {
        level = 'dusuk'; label = 'DÜŞÜK'; color = '#2ecc71';
        detail = `Önemli yağış beklentisi düşük (~${totalRain.toFixed(0)} mm).`;
    }

    return { level, label, color, detail, totalRain, maxHumidity };
}

function analyzeFireRisk(weather) {
    if (!weather || !weather.main) {
        return { level: 'bilinmiyor', label: 'Veri yok', color: '#95a5a6', detail: 'Hava verisi yok.' };
    }

    const temp = weather.main.temp;
    const humidity = weather.main.humidity;
    const windKmh = (weather.wind?.speed || 0) * 3.6;

    let fwi = 0;
    if (temp > 15) fwi += (temp - 15) * 2;
    if (humidity < 60) fwi += (60 - humidity);
    if (windKmh > 10) fwi += windKmh * 0.5;

    let level;
    let label;
    let color;
    let detail;

    if (fwi >= 80 || (temp > 35 && humidity < 20)) {
        level = 'kritik'; label = 'KRİTİK'; color = '#ff4757';
        detail = `Aşırı yangın hava riski: ${Math.round(temp)}°C, %${humidity}, ${windKmh.toFixed(0)} km/s.`;
    } else if (fwi >= 50 || (temp > 30 && humidity < 30)) {
        level = 'yuksek'; label = 'YÜKSEK'; color = '#ffa502';
        detail = `Yüksek risk. ${Math.round(temp)}°C, %${humidity} nem.`;
    } else if (fwi >= 25 || (temp > 25 && humidity < 40)) {
        level = 'orta'; label = 'ORTA'; color = '#f1c40f';
        detail = 'Orta düzey; sıcak ve kuru.';
    } else {
        level = 'dusuk'; label = 'DÜŞÜK'; color = '#2ecc71';
        detail = 'Koşullar genelde düşük risk.';
    }

    return { level, label, color, detail, fwi: Math.round(fwi), temp, humidity, windKmh };
}

function updateForecastUI(data) {
    if (!data) return;

    const selForecastEl = document.getElementById('val-sel-forecast');
    if (selForecastEl && data.flood) {
        selForecastEl.innerHTML = `<span style="color:${data.flood.color};font-weight:bold">${data.flood.label}</span>`;
        selForecastEl.title = data.flood.detail || '';
    }

    const forecastPanel = document.getElementById('forecastPanel');
    if (forecastPanel) {
        forecastPanel.innerHTML = buildForecastPanel(data);
    }
}

function buildForecastPanel(data) {
    const eq = data.earthquake || {};
    const fl = data.flood || {};
    const fi = data.fire || {};

    return `
        <div style="font-size:11px;line-height:1.7">
            <div style="margin-bottom:8px;padding:6px;background:rgba(255,255,255,0.05);border-radius:6px">
                <div style="font-weight:600;color:#ccc;margin-bottom:3px">Sismik aktivite özeti</div>
                <div style="color:${eq.color || '#aaa'};font-weight:bold">${eq.label || '-'}</div>
                <div style="color:#888;font-size:10px">${eq.detail || ''}</div>
                ${eq.disclaimer ? `<div style="color:#666;font-size:9px;margin-top:2px">${eq.disclaimer}</div>` : ''}
            </div>
            <div style="margin-bottom:8px;padding:6px;background:rgba(255,255,255,0.05);border-radius:6px">
                <div style="font-weight:600;color:#ccc;margin-bottom:3px">Sel / taşkın (48 saat, OpenWeather)</div>
                <div style="color:${fl.color || '#aaa'};font-weight:bold">${fl.label || '-'}</div>
                <div style="color:#888;font-size:10px">${fl.detail || ''}</div>
            </div>
            <div style="padding:6px;background:rgba(255,255,255,0.05);border-radius:6px">
                <div style="font-weight:600;color:#ccc;margin-bottom:3px">Yangın hava indeksi (anlık)</div>
                <div style="color:${fi.color || '#aaa'};font-weight:bold">${fi.label || '-'}</div>
                <div style="color:#888;font-size:10px">${fi.detail || ''}</div>
                ${fi.fwi != null ? `<div style="color:#666;font-size:9px">İndeks: ${fi.fwi}</div>` : ''}
            </div>
        </div>
    `;
}

function openForecastModal() {
    const modal = document.getElementById('forecastModal');
    if (!modal) return;
    modal.classList.remove('hidden');

    if (STATE.forecastData) {
        updateForecastUI(STATE.forecastData);
    } else if (STATE.currentLocation) {
        loadForecast(STATE.currentLocation.lat, STATE.currentLocation.lng);
    } else {
        const panel = document.getElementById('forecastPanel');
        if (panel) panel.innerHTML = '<p style="color:#aaa;font-size:12px">Tahmin için önce konumunuzu aktif edin.</p>';
    }
}

function closeForecastModal() {
    const modal = document.getElementById('forecastModal');
    if (modal) modal.classList.add('hidden');
}
