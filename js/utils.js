// TR-GOZU Yardımcı Fonksiyonlar

// Mesafeyi hesapla (km)
function calculateDistance(lat1, lon1, lat2, lon2) {
    const R = 6371;
    const dLat = (lat2 - lat1) * Math.PI / 180;
    const dLon = (lon2 - lon1) * Math.PI / 180;
    const a = Math.sin(dLat / 2) * Math.sin(dLat / 2) +
              Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) *
              Math.sin(dLon / 2) * Math.sin(dLon / 2);
    return R * (2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a)));
}

// Konumu Türkçe formatla
function formatLocation(lat, lng) {
    return `${lat.toFixed(4)}, ${lng.toFixed(4)}`;
}

// Tarih formatla
function formatDate(date) {
    if (!date) return '-';
    const d = new Date(date);
    return d.toLocaleDateString('tr-TR', {
        day: '2-digit',
        month: '2-digit',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    });
}

// Yaş hesapla
function calculateAge(birthDate) {
    const today = new Date();
    const birth = new Date(birthDate);
    let age = today.getFullYear() - birth.getFullYear();
    const monthDiff = today.getMonth() - birth.getMonth();
    if (monthDiff < 0 || (monthDiff === 0 && today.getDate() < birth.getDate())) {
        age--;
    }
    return age;
}

// Yön hesapla
function calculateBearing(lat1, lon1, lat2, lon2) {
    const dLon = (lon2 - lon1) * Math.PI / 180;
    const lat1Rad = lat1 * Math.PI / 180;
    const lat2Rad = lat2 * Math.PI / 180;
    const y = Math.sin(dLon) * Math.cos(lat2Rad);
    const x = Math.cos(lat1Rad) * Math.sin(lat2Rad) - Math.sin(lat1Rad) * Math.cos(lat2Rad) * Math.cos(dLon);
    let bearing = Math.atan2(y, x) * 180 / Math.PI;
    return (bearing + 360) % 360;
}

// Yön adı
function getDirectionName(bearing) {
    const directions = ['K', 'KD', 'D', 'GD', 'G', 'GB', 'B', 'KB'];
    const index = Math.round(bearing / 45) % 8;
    return directions[index];
}

// HTML'yi temizle
function escapeHtml(text) {
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return text.replace(/[&<>"']/g, m => map[m]);
}

// Local Storage yardımcıları
function saveToStorage(key, data) {
    try {
        localStorage.setItem(key, JSON.stringify(data));
        return true;
    } catch (e) {
        console.error('Storage save error:', e);
        return false;
    }
}

function getFromStorage(key, defaultValue = null) {
    try {
        const data = localStorage.getItem(key);
        return data ? JSON.parse(data) : defaultValue;
    } catch (e) {
        console.error('Storage read error:', e);
        return defaultValue;
    }
}

function removeFromStorage(key) {
    localStorage.removeItem(key);
}

// Debounce fonksiyonu
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// Throttle fonksiyonu
function throttle(func, limit) {
    let inThrottle;
    return function executedFunction(...args) {
        if (!inThrottle) {
            func(...args);
            inThrottle = true;
            setTimeout(() => inThrottle = false, limit);
        }
    };
}

// Ses çal
function playSound(type) {
    try {
        const audioContext = new (window.AudioContext || window.webkitAudioContext)();
        const oscillator = audioContext.createOscillator();
        const gainNode = audioContext.createGain();

        oscillator.connect(gainNode);
        gainNode.connect(audioContext.destination);

        switch(type) {
            case 'sos':
                // SOS pattern: 3 short, 3 long, 3 short
                oscillator.frequency.value = 800;
                gainNode.gain.value = 0.3;
                // Pattern will be handled separately
                break;
            case 'alert':
                oscillator.frequency.value = 1000;
                gainNode.gain.value = 0.5;
                break;
            case 'success':
                oscillator.frequency.value = 600;
                gainNode.gain.value = 0.3;
                break;
            default:
                oscillator.frequency.value = 500;
                gainNode.gain.value = 0.3;
        }

        oscillator.start();
        setTimeout(() => {
            oscillator.stop();
            audioContext.close();
        }, 500);
    } catch (e) {
        console.log('Audio not supported');
    }
}

// Bildirim gönder
function sendNotification(title, body, options = {}) {
    if ('Notification' in window && Notification.permission === 'granted') {
        new Notification(title, {
            body: body,
            icon: options.icon || '/assets/trgozu.jpg',
            badge: options.badge || '/assets/trgozu.jpg',
            tag: options.tag || 'trgozu-notification',
            requireInteraction: options.requireInteraction || false
        });
    }
}

// Bildirim izni iste
async function requestNotificationPermission() {
    if ('Notification' in window && Notification.permission === 'default') {
        const permission = await Notification.requestPermission();
        return permission === 'granted';
    }
    return Notification.permission === 'granted';
}

// Hava durumu ikonu
function getWeatherIcon(weatherMain) {
    const icons = {
        Clear: '☀️',
        Clouds: '☁️',
        Rain: '🌧️',
        Drizzle: '🌧️',
        Thunderstorm: '⛈️',
        Snow: '❄️',
        Mist: '🌫️',
        Fog: '🌫️',
        Haze: '🌫️'
    };
    return icons[weatherMain] || '🌡️';
}

// Risk seviyesi hesapla
function calculateRiskLevel(value, thresholds = { low: 30, medium: 60, high: 80 }) {
    if (value >= thresholds.high) return 'high';
    if (value >= thresholds.medium) return 'medium';
    if (value >= thresholds.low) return 'low';
    return 'none';
}

// Öncelik puanı hesapla
function calculatePriorityScore(factors) {
    let score = 0;
    if (factors.healthStatus === 'kritik') score += 50;
    if (factors.healthStatus === 'enkaz') score += 60;
    if (factors.healthStatus === 'yaraliyim') score += 30;
    if (factors.isSOS) score += 40;
    if (factors.isPanic) score += 30;
    if (factors.battery && factors.battery < 10) score += 20;
    if (factors.timeSinceActive < 5) score += 10; // 5 dakikadan az
    return Math.min(100, score);
}

// Grubu bul (konum bazlı)
function findNearbyGroup(lat, lng, groups, radiusKm = 5) {
    for (const group of groups) {
        const dist = calculateDistance(lat, lng, group.lat, group.lng);
        if (dist <= radiusKm) {
            return group;
        }
    }
    return null;
}

// Konum izni kontrolü
function checkLocationPermission() {
    if ('geolocation' in navigator) {
        return navigator.permissions.query({ name: 'geolocation' })
            .then(result => result.state)
            .catch(() => 'prompt');
    }
    return 'unsupported';
}

// Telefon bilgisi al (Device API varsa)
async function getDeviceInfo() {
    const info = {
        platform: navigator.platform,
        userAgent: navigator.userAgent,
        language: navigator.language,
        online: navigator.onLine
    };

    // Battery API
    if ('getBattery' in navigator) {
        try {
            const battery = await navigator.getBattery();
            info.batteryLevel = Math.round(battery.level * 100);
            info.batteryCharging = battery.charging;
        } catch (e) {
            console.log('Battery API not available');
        }
    }

    // Network API
    if ('connection' in navigator) {
        const conn = navigator.connection;
        info.networkType = conn.effectiveType;
        info.dataSaver = conn.saveData;
    }

    return info;
}

// Emoji'yi SVG'ye dönüştür (placeholder)
function emojiToSvg(emoji, size = 24) {
    return `<span style="font-size:${size}px">${emoji}</span>`;
}

// Hafifletilmiş tarih gösterimi
function timeAgo(date) {
    const seconds = Math.floor((new Date() - new Date(date)) / 1000);
    const intervals = {
        yıl: 31536000,
        ay: 2592000,
        hafta: 604800,
        gün: 86400,
        saat: 3600,
        dakika: 60
    };

    for (const [name, secondsInUnit] of Object.entries(intervals)) {
        const interval = Math.floor(seconds / secondsInUnit);
        if (interval >= 1) {
            return `${interval} ${name} önce`;
        }
    }
    return 'Az önce';
}

// Para birimi formatla (TL)
function formatCurrency(amount) {
    return new Intl.NumberFormat('tr-TR', {
        style: 'currency',
        currency: 'TRY'
    }).format(amount);
}

// Telefon numarası formatla
function formatPhoneNumber(phone) {
    const cleaned = ('' + phone).replace(/\D/g, '');
    const match = cleaned.match(/^(\d{4})(\d{3})(\d{2})(\d{2})$/);
    if (match) {
        return '0' + match[1] + ' ' + match[2] + ' ' + match[3] + ' ' + match[4];
    }
    return phone;
}

// Validate email
function isValidEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

// Validate phone
function isValidPhone(phone) {
    const cleaned = phone.replace(/\D/g, '');
    return cleaned.length >= 10 && cleaned.length <= 13;
}

// Konsola log yaz
function debugLog(...args) {
    if (typeof DEBUG !== 'undefined' && DEBUG) {
        console.log('[TR-GOZU]', ...args);
    }
}
