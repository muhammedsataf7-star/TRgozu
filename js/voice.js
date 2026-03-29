// TR-GOZU Sesli Uyarı Modülü

let voiceAlertOpen = false;
let alertAudio = null;

function isAuthorityUser() {
    return STATE.userRole === 'admin';
}

// Sesli uyarıyı aç/kapat
function toggleVoiceAlert() {
    if (!isAuthorityUser()) {
        showToast('Sesli acil uyarı yalnızca yetkili girişinde kullanılabilir.');
        return;
    }
    voiceAlertOpen = !voiceAlertOpen;
    const panel = document.getElementById('voiceAlertPanel');

    if (voiceAlertOpen) {
        panel.classList.remove('hidden');
    } else {
        panel.classList.add('hidden');
    }
}

// Acil uyarı sesi çal
function playAlertSound() {
    if (!isAuthorityUser()) {
        showToast('Bu siren yalnızca yetkili oturumunda aktif edilebilir.');
        return;
    }
    try {
        // Web Audio API kullanarak siren sesi oluştur
        const audioContext = new (window.AudioContext || window.webkitAudioContext)();

        // İki osilatör ile siren efekti
        const oscillator1 = audioContext.createOscillator();
        const oscillator2 = audioContext.createOscillator();
        const gainNode = audioContext.createGain();

        oscillator1.connect(gainNode);
        oscillator2.connect(gainNode);
        gainNode.connect(audioContext.destination);

        oscillator1.type = 'sawtooth';
        oscillator2.type = 'square';
        gainNode.gain.value = 0.3;

        // Siren deseni: yükselen ve alçalan ton
        const playSiren = () => {
            const now = audioContext.currentTime;

            // Yükselen ton (0-0.5s)
            oscillator1.frequency.setValueAtTime(400, now);
            oscillator1.frequency.linearRampToValueAtTime(800, now + 0.5);
            oscillator2.frequency.setValueAtTime(410, now);
            oscillator2.frequency.linearRampToValueAtTime(810, now + 0.5);

            // Alçalan ton (0.5-1s)
            oscillator1.frequency.linearRampToValueAtTime(400, now + 1);
            oscillator2.frequency.linearRampToValueAtTime(410, now + 1);
        };

        // 3 kez siren çal
        let sirenCount = 0;
        const sirenInterval = setInterval(() => {
            playSiren();
            sirenCount++;
            if (sirenCount >= 3) {
                clearInterval(sirenInterval);
                oscillator1.stop();
                oscillator2.stop();
                audioContext.close();
            }
        }, 1000);

        oscillator1.start();
        oscillator2.start();

        showToast('🔊 Acil uyarı sesi çalınıyor...');

        // Titreşim (mobil cihazlarda)
        if ('vibrate' in navigator) {
            navigator.vibrate([500, 200, 500, 200, 500]);
        }

    } catch (error) {
        console.error('Ses çalma hatası:', error);
        showToast('Ses çalınamadı!');
    }
}

// Kritik durumlarda otomatik uyarı
function checkAutoAlert() {
    if (!isAuthorityUser()) return;
    const autoAlertCheck = document.getElementById('autoAlertCheck');
    if (!autoAlertCheck || !autoAlertCheck.checked) return;

    const citizens = getCitizens();
    const sosList = getSOSList();

    // Kritik vaka var mı kontrol et
    const criticalCount = citizens.filter(c =>
        c.isSOS || c.isPanic ||
        c.healthStatus === 'kritik' ||
        c.healthStatus === 'enkaz'
    ).length;

    if (criticalCount >= 3) {
        // Kritik eşik aşıldı
        playAlertSound();
        sendNotification(
            '🚨 Kritik Durum Uyarısı',
            `${criticalCount} kritik vaka tespit edildi!`,
            { requireInteraction: true }
        );
    }
}

// Mesajlaşma için sesli bildirim
function playMessageSound() {
    try {
        const audioContext = new (window.AudioContext || window.webkitAudioContext)();
        const oscillator = audioContext.createOscillator();
        const gainNode = audioContext.createGain();

        oscillator.connect(gainNode);
        gainNode.connect(audioContext.destination);

        oscillator.type = 'sine';
        oscillator.frequency.value = 800;
        gainNode.gain.value = 0.2;

        oscillator.start();
        gainNode.gain.exponentialRampToValueAtTime(0.01, audioContext.currentTime + 0.2);
        oscillator.stop(audioContext.currentTime + 0.2);

        audioContext.close();
    } catch (error) {
        console.error('Mesaj sesi hatası:', error);
    }
}

// SOS sesi
function playSOSSound() {
    try {
        const audioContext = new (window.AudioContext || window.webkitAudioContext)();

        // SOS: 3 kısa, 3 uzun, 3 kısa
        const pattern = [
            { freq: 800, duration: 0.15 },  // kısa
            { freq: 0, duration: 0.1 },       // boşluk
            { freq: 800, duration: 0.15 },  // kısa
            { freq: 0, duration: 0.1 },       // boşluk
            { freq: 800, duration: 0.15 },  // kısa
            { freq: 0, duration: 0.3 },       // boşluk
            { freq: 800, duration: 0.5 },   // uzun
            { freq: 0, duration: 0.1 },       // boşluk
            { freq: 800, duration: 0.5 },   // uzun
            { freq: 0, duration: 0.1 },       // boşluk
            { freq: 800, duration: 0.5 },   // uzun
            { freq: 0, duration: 0.3 },       // boşluk
            { freq: 800, duration: 0.15 },  // kısa
            { freq: 0, duration: 0.1 },       // boşluk
            { freq: 800, duration: 0.15 },  // kısa
            { freq: 0, duration: 0.1 },       // boşluk
            { freq: 800, duration: 0.15 },  // kısa
        ];

        let time = audioContext.currentTime;
        const gainNode = audioContext.createGain();

        pattern.forEach(({ freq, duration }) => {
            if (freq > 0) {
                const osc = audioContext.createOscillator();
                osc.type = 'sine';
                osc.frequency.value = freq;
                osc.connect(gainNode);
                gainNode.connect(audioContext.destination);
                osc.start(time);
                osc.stop(time + duration);
            }
            time += duration;
        });

        // Titreşim
        if ('vibrate' in navigator) {
            navigator.vibrate([100, 100, 100, 100, 100, 300, 100, 100, 100, 100, 100]);
        }

    } catch (error) {
        console.error('SOS sesi hatası:', error);
    }
}

// Başarı sesi
function playSuccessSound() {
    try {
        const audioContext = new (window.AudioContext || window.webkitAudioContext)();
        const gainNode = audioContext.createGain();
        gainNode.connect(audioContext.destination);
        gainNode.gain.value = 0.2;

        // İki tonlu başarı sesi (C ve E)
        [523.25, 659.25].forEach((freq, i) => {
            const osc = audioContext.createOscillator();
            osc.type = 'sine';
            osc.frequency.value = freq;
            osc.connect(gainNode);
            osc.start(audioContext.currentTime + i * 0.1);
            osc.stop(audioContext.currentTime + i * 0.1 + 0.15);
        });

        audioContext.close();
    } catch (error) {
        console.error('Başarı sesi hatası:', error);
    }
}

// Genel ses çalma fonksiyonu
function playSound(type) {
    if (type === 'alert' && !isAuthorityUser()) return;
    switch(type) {
        case 'sos':
            playSOSSound();
            break;
        case 'alert':
            playAlertSound();
            break;
        case 'success':
            playSuccessSound();
            break;
        case 'message':
            playMessageSound();
            break;
        default:
            console.log('Unknown sound type:', type);
    }
}

// Titreşim deseni
function vibrate(pattern) {
    if ('vibrate' in navigator) {
        navigator.vibrate(pattern);
    }
}
