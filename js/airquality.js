// Hava kalitesi — OpenWeather Air Pollution API
let aqiPopup = null;

const AQI_LEVELS = [
    { max: 1, label: 'Çok iyi', color: '#2ecc71', emoji: '😊', desc: 'Hava kalitesi iyi; açık hava uygundur.' },
    { max: 2, label: 'İyi', color: '#a3cb38', emoji: '🙂', desc: 'Hava kalitesi kabul edilebilir.' },
    { max: 3, label: 'Orta', color: '#f1c40f', emoji: '😐', desc: 'Hassas gruplar için hafif etki olabilir.' },
    { max: 4, label: 'Kötü', color: '#e67e22', emoji: '😷', desc: 'Uzun süre açık havada egzersizden kaçının.' },
    { max: 5, label: 'Çok kötü', color: '#e74c3c', emoji: '🚨', desc: 'Sağlık riski yüksek olabilir; gereksiz dışarı çıkmayın.' }
];

async function fetchAndShowAirQuality(lat, lng) {
    if (aqiPopup && window.map) {
        window.map.closePopup(aqiPopup);
        aqiPopup = null;
    }

    try {
        const airUrl = typeof buildWeatherRequestUrl === 'function'
            ? buildWeatherRequestUrl('air_pollution', { lat, lon: lng })
            : null;
        if (!airUrl) throw new Error('Hava API yapılandırması yok');
        const response = await fetch(airUrl);

        if (!response.ok) throw new Error(`Air quality ${response.status}`);
        const data = await response.json();

        if (!data.list || data.list.length === 0) throw new Error('Veri yok');

        const aqiData = data.list[0];
        const aqi = aqiData.main.aqi;
        const comp = aqiData.components;

        const level = AQI_LEVELS[Math.min(aqi - 1, 4)];

        const popupContent = `
            <div style="min-width:200px;font-size:12px">
                <div style="font-weight:bold;font-size:13px;margin-bottom:6px">
                    ${level.emoji} Hava kalitesi: <span style="color:${level.color}">${level.label}</span>
                </div>
                <div style="color:#888;margin-bottom:8px;font-size:11px">${level.desc}</div>
                <table style="width:100%;font-size:11px;border-collapse:collapse">
                    <tr><td style="color:#aaa">PM2.5</td><td><b>${comp.pm2_5.toFixed(1)}</b> μg/m³</td></tr>
                    <tr><td style="color:#aaa">PM10</td><td><b>${comp.pm10.toFixed(1)}</b> μg/m³</td></tr>
                    <tr><td style="color:#aaa">NO₂</td><td><b>${comp.no2.toFixed(1)}</b> μg/m³</td></tr>
                    <tr><td style="color:#aaa">O₃</td><td><b>${comp.o3.toFixed(1)}</b> μg/m³</td></tr>
                    <tr><td style="color:#aaa">CO</td><td><b>${comp.co.toFixed(0)}</b> μg/m³</td></tr>
                </table>
                <div style="color:#555;font-size:9px;margin-top:6px">OpenWeather Air Pollution</div>
            </div>
        `;

        if (window.map) {
            aqiPopup = L.popup({ maxWidth: 250 })
                .setLatLng([lat, lng])
                .setContent(popupContent)
                .openOn(window.map);
        }

        updateAQIBar(aqi, level);
    } catch (err) {
        console.error('Hava kalitesi:', err);
    }
}

function updateAQIBar(aqi, level) {
    const aqiEl = document.getElementById('val-air-quality');
    if (aqiEl) {
        const em = level.emoji ? `${level.emoji} ` : '';
        aqiEl.innerHTML = `<span style="color:${level.color};font-weight:bold">${em}${level.label}</span>`;
    }
}
