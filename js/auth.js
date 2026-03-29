// TR-GOZU Kimlik Doğrulama Modülü

const ADMIN_KEYS = {
    "AFAD2026": "AFAD Komuta Merkezi",
    "UMKE911": "UMKE Acil Müdahale",
    "AKUT123": "AKUT Operasyon",
    "ADMIN": "Sistem Yöneticisi"
};

let tempUserData = null;

// Giriş türünü değiştir
function switchAuth(type) {
    document.getElementById('citizenForm').classList.toggle('hidden', type !== 'citizen');
    document.getElementById('adminForm').classList.toggle('hidden', type !== 'admin');
    document.getElementById('tab-c').classList.toggle('active', type === 'citizen');
    document.getElementById('tab-a').classList.toggle('active', type === 'admin');
}

// Şifre görünürlüğünü değiştir
function togglePassVisibility() {
    const passInput = document.getElementById('c_pass');
    const toggleIcon = document.getElementById('toggleTC');

    if (passInput.type === "password") {
        passInput.type = "text";
        toggleIcon.innerHTML = '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>';
    } else {
        passInput.type = "password";
        toggleIcon.innerHTML = '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>';
    }
}

// Kullanım koşulları modalını göster
function showContract() {
    document.getElementById('contractModal').classList.remove('hidden');
}

// Modalı kapat
function closeModal() {
    document.getElementById('contractModal').classList.add('hidden');
    if (!STATE.userRole) tempUserData = null;
}

// Sözleşmeyi onayla ve devam et
function confirmContract() {
    if (!document.getElementById('acceptCheck').checked) {
        showToast('Devam etmek için kullanım koşullarını kabul etmelisiniz!');
        return;
    }

    if (tempUserData) {
        document.getElementById('contractModal').classList.add('hidden');
        document.getElementById('authSection').classList.add('hidden');
        initSystem();
    } else {
        showToast('Lütfen giriş yapın veya kayıt olun.');
        closeModal();
    }
}

// Sistemi başlat
function initSystem() {
    const mainApp = document.getElementById('mainApp');
    const displayUser = document.getElementById('displayUser');
    const roleBadge = document.getElementById('roleBadge');

    mainApp.classList.remove('hidden');
    displayUser.innerText = tempUserData.email || tempUserData.tc || 'Kullanıcı';

    // Haritayı başlat - DOM hazır olana kadar bekle
    setTimeout(() => {
        if (typeof initMap === "function") {
            initMap();
        }
    }, 100);

    const voiceFab = document.querySelector('.voice-fab');
    if (voiceFab) voiceFab.classList.toggle('hidden', STATE.userRole !== 'admin');

    if (STATE.userRole === 'admin') {
        // Yetkili paneli
        document.getElementById('adminPanel').classList.remove('hidden');
        document.getElementById('citizenPanel').classList.add('hidden');
        roleBadge.innerText = tempUserData.unit || "YETKILI";
        roleBadge.style.background = "var(--primary)";

        // Yetkili görünümünü başlat
        setTimeout(() => {
            if (typeof startAdminView === "function") startAdminView();
            if (typeof updateAdminView === "function") updateAdminView();
            if (typeof loadAnnouncements === "function") loadAnnouncements();
            if (typeof loadMissingPersons === "function") loadMissingPersons();
            if (typeof loadVerifications === "function") loadVerifications();
        }, 1000);
    } else {
        // Vatandaş paneli
        document.getElementById('citizenPanel').classList.remove('hidden');
        document.getElementById('adminPanel').classList.add('hidden');
        roleBadge.innerText = "VATANDAŞ";
        roleBadge.style.background = "var(--secondary)";

        // Bildirim izni iste
        requestNotificationPermission();

        // Gönüllü ve sohbet geçmişini yükle
        setTimeout(() => {
            if (typeof loadVolunteerList === 'function') loadVolunteerList();
            if (typeof loadChatHistory === 'function') loadChatHistory();
            if (typeof loadFamilyMembers === 'function') loadFamilyMembers();
            if (typeof loadHelpRequests === 'function') loadHelpRequests();
        }, 1000);
    }

    // Harita boyutını birkaç kez ayarla (DOM hazır olmayabilir)
    setTimeout(() => {
        if (window.map) window.map.invalidateSize();
    }, 300);
    setTimeout(() => {
        if (window.map) window.map.invalidateSize();
    }, 800);
    setTimeout(() => {
        if (window.map) window.map.invalidateSize();
    }, 1500);

    // Bildirim göster
    showToast(`${STATE.userRole === 'admin' ? 'Yetkili' : 'Vatandaş'} olarak hoş geldiniz!`);
}

function passwordPolicyOk(pass) {
    if (typeof pass !== 'string' || pass.length < 8) return false;
    if (!/[a-zA-ZğüşıöçĞÜŞİÖÇ]/.test(pass) || !/[0-9]/.test(pass)) return false;
    return true;
}

async function tryServerRegister(email, pass) {
    if (!CONFIG.USE_SERVER_AUTH || !CONFIG.API_BASE_URL) {
        return { skipped: true, ok: false };
    }
    try {
        const r = await fetch(`${CONFIG.API_BASE_URL}/api/auth/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password: pass })
        });
        const data = await r.json().catch(() => ({}));
        if (r.ok && data.token) {
            setTrgozuSession(data.token, data.role || 'citizen');
            return { ok: true };
        }
        if (data.message) showToast(data.message);
        return { ok: false, blocked: r.status === 400 };
    } catch (e) {
        return { ok: false, blocked: false };
    }
}

async function tryServerLogin(email, pass) {
    if (!CONFIG.USE_SERVER_AUTH || !CONFIG.API_BASE_URL) return null;
    try {
        const r = await fetch(`${CONFIG.API_BASE_URL}/api/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password: pass })
        });
        const data = await r.json().catch(() => ({}));
        if (r.ok && data.token) {
            setTrgozuSession(data.token, data.role || 'citizen');
            return data;
        }
        return null;
    } catch (e) {
        return null;
    }
}

// Kayıt ol
async function valideKayit() {
    const email = document.getElementById('c_user').value.trim().toLowerCase();
    const pass = document.getElementById('c_pass').value;

    if (!email) {
        showToast('E-posta adresi gerekli!');
        return;
    }

    if (!isValidEmail(email)) {
        showToast('Geçerli bir e-posta adresi girin!');
        return;
    }

    if (!email.endsWith('@gmail.com')) {
        showToast('Sadece @gmail.com uzantılı adresler kabul edilir!');
        return;
    }

    if (!passwordPolicyOk(pass)) {
        showToast('Şifre en az 8 karakter; en az bir harf ve bir rakam içermelidir.');
        return;
    }

    const existingPass = localStorage.getItem('user_' + email);
    if (existingPass) {
        showToast('Bu e-posta zaten kayıtlı! Giriş yapın.');
        return;
    }

    showLoading(true);
    const reg = await tryServerRegister(email, pass);
    showLoading(false);
    if (reg.blocked) return;

    const passHash = await derivePasswordHash(pass);
    localStorage.setItem('user_' + email, passHash);

    if (!reg.ok && !reg.skipped && CONFIG.USE_SERVER_AUTH && CONFIG.API_BASE_URL) {
        showToast('Sunucuya bağlanılamadı; kayıt yalnızca bu cihazda güvenli şekilde saklandı.');
    }

    updateCitizen(email, {
        lastActive: new Date().toISOString(),
        registeredAt: new Date().toISOString()
    });

    STATE.userRole = 'citizen';
    tempUserData = { email };
    setCurrentUserEmail(email);

    showContract();
}

// Giriş yap
async function valideGiris() {
    const email = document.getElementById('c_user').value.trim().toLowerCase();
    const pass = document.getElementById('c_pass').value;

    if (!pass || !String(pass).trim()) {
        const pe = document.getElementById('c_pass');
        if (pe) pe.focus();
        showToast('Şifrenizi girin.');
        return;
    }

    if (!email || !isValidEmail(email)) {
        showToast('Geçerli bir e-posta girin!');
        return;
    }

    if (!email.endsWith('@gmail.com')) {
        showToast('Sadece @gmail.com adresi girin!');
        return;
    }

    showLoading(true);
    const srv = await tryServerLogin(email, pass);
    const kayitliSifre = localStorage.getItem('user_' + email);
    let ok = !!srv;

    if (!ok && kayitliSifre) {
        ok = await verifyPasswordHash(pass, kayitliSifre);
        if (ok && !kayitliSifre.startsWith('pbkdf2$')) {
            const upgraded = await derivePasswordHash(pass);
            localStorage.setItem('user_' + email, upgraded);
        }
    }

    showLoading(false);

    if (!ok) {
        showToast(kayitliSifre ? 'Şifre hatalı!' : 'Kayıtlı kullanıcı bulunamadı! Önce kayıt olun.');
        return;
    }

    STATE.userRole = 'citizen';
    tempUserData = { email };
    setCurrentUserEmail(email);

    updateCitizen(email, { lastActive: new Date().toISOString() });

    showContract();
}

// Enter ile giriş / şifre alanına yönlendirme
function initAuthEnterSubmit() {
    document.addEventListener('keydown', onAuthSectionEnter);
}

function onAuthSectionEnter(e) {
    if (e.key !== 'Enter' || e.repeat) return;

    const contractEl = document.getElementById('contractModal');
    if (contractEl && !contractEl.classList.contains('hidden')) {
        e.preventDefault();
        confirmContract();
        return;
    }

    const authEl = document.getElementById('authSection');
    if (!authEl || authEl.classList.contains('hidden')) return;

    const t = e.target;
    if (!t || t.tagName !== 'INPUT') return;

    if (t.id === 'c_user') {
        e.preventDefault();
        const passEl = document.getElementById('c_pass');
        const passVal = passEl ? String(passEl.value).trim() : '';
        if (!passVal) {
            showToast('Şifrenizi girin.');
            if (passEl) passEl.focus();
            return;
        }
        valideGiris();
        return;
    }

    if (t.id === 'c_pass') {
        e.preventDefault();
        if (!String(t.value).trim()) {
            showToast('Şifrenizi girin.');
            t.focus();
            return;
        }
        valideGiris();
        return;
    }

    if (t.id === 'admin_key') {
        e.preventDefault();
        if (!String(t.value).trim()) {
            showToast('Yetkili anahtarını girin.');
            t.focus();
            return;
        }
        handleAdminGirisLocal();
    }
}

document.addEventListener('DOMContentLoaded', initAuthEnterSubmit);

// Yetkili girişi (sunucu veya yerel yedek)
async function handleAdminGirisLocal() {
    const key = document.getElementById('admin_key').value.trim();

    if (CONFIG.USE_SERVER_AUTH && CONFIG.API_BASE_URL) {
        showLoading(true);
        try {
            const r = await fetch(`${CONFIG.API_BASE_URL}/api/auth/admin-login`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ key })
            });
            const data = await r.json().catch(() => ({}));
            showLoading(false);
            if (r.ok && data.token) {
                setTrgozuSession(data.token, 'admin');
                const unitLabel = ADMIN_KEYS[data.unit || key] || data.unit || key;
                STATE.userRole = 'admin';
                tempUserData = {
                    email: 'YETKILI@ADMIN',
                    unit: unitLabel,
                    tc: unitLabel
                };
                showContract();
                return;
            }
        } catch (e) {
            showLoading(false);
        }
    }

    const unit = ADMIN_KEYS[key];
    if (unit) {
        STATE.userRole = 'admin';
        tempUserData = {
            email: 'YETKILI@ADMIN',
            unit: unit,
            tc: unit
        };
        showContract();
    } else {
        showToast('Hatalı Yetkili Anahtarı!');
    }
}

// Yetkili görünümünü güncelle
function updateAdminView() {
    const listContainer = document.getElementById('adminGmailList');
    if (!listContainer) return;

    listContainer.innerHTML = "";
    const citizens = getCitizens();

    if (citizens.length === 0) {
        listContainer.innerHTML = "<p style='font-size: 11px; color: var(--text-dim);'>Henüz kayıtlı vatandaş yok.</p>";
        return;
    }

    citizens.forEach(c => {
        const healthBadge = c.healthStatus ? CONFIG.HEALTH_STATUS[c.healthStatus]?.icon || '' : '';
        const statusColor = c.isSOS ? 'var(--primary)' : c.isPanic ? 'var(--primary)' : 'var(--secondary)';

        listContainer.innerHTML += `
            <div class="admin-card" onclick="flyToLocation(${c.lat || 0}, ${c.lng || 0})">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <span style="font-size: 12px; word-break: break-all; color: ${statusColor};">
                        ${c.isSOS ? '🆘 ' : ''}${c.isPanic ? '🚨 ' : ''}${c.email}
                    </span>
                    ${healthBadge}
                </div>
                ${c.lastActive ? `<div style="font-size: 10px; color: var(--text-dim); margin-top: 4px;">Son: ${timeSince(c.lastActive)}</div>` : ''}
            </div>
        `;
    });
}

// Sidebar'ı aç/kapat (mobilde alt çekmece)
function toggleSidebar() {
    const sidebar = document.getElementById('sidebar');
    const overlay = document.getElementById('sidebarOverlay');

    sidebar.classList.toggle('open');
    overlay.classList.toggle('show');

    // Harita boyutını güncelle - birden fazla kez çünkü animasyon var
    setTimeout(() => {
        if (window.map) window.map.invalidateSize();
    }, 150);
    setTimeout(() => {
        if (window.map) window.map.invalidateSize();
    }, 350);
    setTimeout(() => {
        if (window.map) window.map.invalidateSize();
    }, 600);
}

// Çıkış yap
function logout() {
    if (confirm('Çıkış yapmak istediğinize emin misiniz?')) {
        // Temizlik
        STATE.userRole = null;
        tempUserData = null;
        STATE.userEmail = null;
        STATE.currentLocation = null;
        STATE.isLocationActive = false;

        // UI'ı sıfırla
        document.getElementById('mainApp').classList.add('hidden');
        document.getElementById('authSection').classList.remove('hidden');
        document.getElementById('citizenPanel').classList.add('hidden');
        document.getElementById('adminPanel').classList.add('hidden');

        // Formları temizle
        document.getElementById('c_user').value = '';
        document.getElementById('c_pass').value = '';
        document.getElementById('admin_key').value = '';

        // Timer'ları temizle
        if (window.adminRefreshTimer) {
            clearInterval(window.adminRefreshTimer);
        }
        if (window.trackingTimer) {
            clearInterval(window.trackingTimer);
        }

        const voiceFab = document.querySelector('.voice-fab');
        if (voiceFab) voiceFab.classList.add('hidden');

        clearTrgozuSession();
        showToast('Güvenli çıkış yapıldı.');
    }
}
