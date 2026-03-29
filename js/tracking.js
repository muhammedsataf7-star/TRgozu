// TR-GOZU Konum Takip Modülü

let trackingWatchId = null;
let trackingTimer = null;
let lastKnownPosition = null;

// Canlı takibi başlat
function startLiveTracking() {
    if (!navigator.geolocation) {
        console.warn('Geolocation desteklenmiyor');
        return;
    }

    // Sürekli konum takibi
    trackingWatchId = navigator.geolocation.watchPosition(
        (position) => {
            const { latitude, longitude } = position.coords;

            STATE.currentLocation = { lat: latitude, lng: longitude };
            lastKnownPosition = { lat: latitude, lng: longitude };

            // Kullanıcı verisini güncelle
            const email = getCurrentUserEmail();
            if (email) {
                updateCitizen(email, {
                    lat: latitude,
                    lng: longitude,
                    lastLocation: { lat: latitude, lng: longitude },
                    lastMoveAt: new Date().toISOString(),
                    accuracy: position.coords.accuracy
                });
            }

            // Haritadaki markerı güncelle
            updateUserMarker(latitude, longitude);
        },
        (error) => {
            console.error('Konum takip hatası:', error);
        },
        {
            enableHighAccuracy: true,
            maximumAge: 10000,
            timeout: 15000
        }
    );

    // Periyodik güncelleme (30 saniye)
    if (trackingTimer) clearInterval(trackingTimer);
    trackingTimer = setInterval(() => {
        updateLocationInterval();
    }, CONFIG.LOCATION_UPDATE_INTERVAL);
}

// Periyodik konum güncelleme
async function updateLocationInterval() {
    if (!navigator.geolocation) return;

    try {
        const position = await new Promise((resolve, reject) => {
            navigator.geolocation.getCurrentPosition(resolve, reject, {
                enableHighAccuracy: true,
                timeout: 10000
            });
        });

        const { latitude, longitude } = position.coords;

        // Hareket kontrolü
        if (lastKnownPosition) {
            const moved = calculateDistance(
                lastKnownPosition.lat, lastKnownPosition.lng,
                latitude, longitude
            ) > 0.05; // 50 metre

            if (moved) {
                STATE.currentLocation = { lat: latitude, lng: longitude };
                lastKnownPosition = { lat: latitude, lng: longitude };

                const email = getCurrentUserEmail();
                if (email) {
                    updateCitizen(email, {
                        lat: latitude,
                        lng: longitude,
                        lastMoveAt: new Date().toISOString()
                    });
                }
            }
        }
    } catch (error) {
        console.error('Interval konum güncelleme hatası:', error);
    }
}

// Kullanıcı markerını güncelle
function updateUserMarker(lat, lng) {
    if (!window.map) return;

    if (typeof createNormalIcon === 'function') {
        if (window.userMarker) {
            window.userMarker.setLatLng([lat, lng]);
        } else {
            window.userMarker = L.marker([lat, lng], {
                icon: createNormalIcon('#00d2ff')
            }).addTo(window.map);
        }
    }
}

// Canlı takibi durdur
function stopLiveTracking() {
    if (trackingWatchId !== null) {
        navigator.geolocation.clearWatch(trackingWatchId);
        trackingWatchId = null;
    }

    if (trackingTimer) {
        clearInterval(trackingTimer);
        trackingTimer = null;
    }
}

// Vatandaş takip listesini güncelle
function updateTrackingList() {
    const listDiv = document.getElementById('citizenTrackList');
    if (!listDiv) return;

    const citizens = getCitizens();
    listDiv.innerHTML = '';

    // Aktif vatandaşları listele
    const activeCitizens = citizens.filter(c => c.lat && c.lng);

    activeCitizens.sort((a, b) => {
        // SOS olanları önce göster
        if (a.isPanic && !b.isPanic) return -1;
        if (!a.isPanic && b.isPanic) return 1;
        if (a.isSOS && !b.isSOS) return -1;
        if (!a.isSOS && b.isSOS) return 1;

        // Son aktifliğe göre
        return new Date(b.lastActive) - new Date(a.lastActive);
    });

    activeCitizens.forEach(c => {
        const priorityScore = calculatePriorityScore({
            healthStatus: c.healthStatus,
            isSOS: c.isSOS,
            isPanic: c.isPanic,
            battery: c.battery,
            timeSinceActive: c.lastActive ?
                (new Date() - new Date(c.lastActive)) / 60000 : 999
        });

        const statusClass = c.isPanic ? 'panic-card' : c.isSOS ? 'sos-card' : '';
        const statusBadge = c.isPanic ? '🚨 PANİK' : c.isSOS ? '🆘 SOS' : '🟢 Aktif';
        const batteryIcon = c.battery != null ?
            (c.battery <= 10 ? '🔴' : c.battery <= 30 ? '🟡' : '🟢') : '';

        listDiv.innerHTML += `
            <div class="admin-card ${statusClass}" onclick="flyToLocation(${c.lat}, ${c.lng})">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <span style="font-size: 12px; word-break: break-all;">
                        ${statusBadge} ${c.email}
                    </span>
                    <span style="font-size: 11px; color: var(--text-muted);">
                        ${priorityScore >= 50 ? '⚠️' : ''}
                    </span>
                </div>
                <div style="font-size: 11px; color: var(--text-muted); margin-top: 4px;">
                    Son: ${timeSince(c.lastActive)} | ${batteryIcon}${c.battery != null ? '%' + c.battery : ''}
                    ${c.healthStatus ? CONFIG.HEALTH_STATUS[c.healthStatus]?.icon || '' : ''}
                </div>
            </div>
        `;
    });

    if (activeCitizens.length === 0) {
        listDiv.innerHTML = '<p style="font-size: 11px; color: var(--text-dim);">Aktif vatandaş yok.</p>';
    }
}

// Son görülme bilgisini al
function getLastSeenInfo(email) {
    const citizens = getCitizens();
    const citizen = citizens.find(c => c.email === email);

    if (!citizen) return null;

    return {
        lastActive: citizen.lastActive,
        lastMoveAt: citizen.lastMoveAt,
        lastLocation: citizen.lastLocation,
        currentLocation: citizen.lat && citizen.lng ?
            { lat: citizen.lat, lng: citizen.lng } : null
    };
}

// Hareket analizi
function analyzeMovement(email) {
    const citizen = getCitizens().find(c => c.email === email);
    if (!citizen || !citizen.lastMoveAt) return null;

    const now = new Date();
    const lastMove = new Date(citizen.lastMoveAt);
    const minutesSinceMove = (now - lastMove) / 60000;

    // Hareket durumu
    let movementStatus = 'unknown';
    if (minutesSinceMove < 5) movementStatus = 'active';
    else if (minutesSinceMove < 30) movementStatus = 'recent';
    else if (minutesSinceMove < 120) movementStatus = 'idle';
    else movementStatus = 'inactive';

    return {
        lastMoveAt: citizen.lastMoveAt,
        minutesSinceMove: Math.round(minutesSinceMove),
        status: movementStatus,
        isPanic: citizen.isPanic,
        isSOS: citizen.isSOS
    };
}
