// TR-GOZU Mesajlaşma Modülü

let messagingOpen = false;
let currentThread = null;

// Mesajlaşmayı aç/kapat
function toggleMessaging() {
    messagingOpen = !messagingOpen;
    const panel = document.getElementById('messagingPanel');

    if (messagingOpen) {
        panel.classList.remove('hidden');
        loadInbox();
        STATE.unreadMessages = 0;
        updateUnreadBadge();
    } else {
        panel.classList.add('hidden');
    }
}

// Gelen kutusunu yükle
function loadInbox() {
    const list = document.getElementById('inboxList');
    if (!list) return;

    const threads = getMessageThreads();

    if (threads.length === 0) {
        list.innerHTML = '<p style="text-align: center; color: var(--text-dim); font-size: 12px; padding: 20px;">Henüz mesaj yok</p>';
        return;
    }

    list.innerHTML = threads.map(thread => `
        <div class="inbox-item" onclick="openThread('${thread.id}')">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <strong style="font-size: 13px;">${escapeHtml(thread.participant)}</strong>
                <span style="font-size: 10px; color: var(--text-dim);">${timeSince(thread.lastMessageTime)}</span>
            </div>
            <div style="font-size: 12px; color: var(--text-muted); margin-top: 4px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
                ${escapeHtml(thread.lastMessage || '')}
            </div>
        </div>
    `).join('');
}

// Mesaj threadlerini al
function getMessageThreads() {
    const email = getCurrentUserEmail();
    if (!email) return [];
    return getFromStorage(`threads_${email}`, []);
}

// Thread aç
function openThread(threadId) {
    currentThread = threadId;

    const threads = getMessageThreads();
    const thread = threads.find(t => t.id === threadId);

    if (!thread) return;

    document.getElementById('inboxView').classList.add('hidden');
    document.getElementById('threadView').classList.remove('hidden');
    document.getElementById('threadTitle').textContent = thread.participant;

    // Okundu işaretle
    markThreadAsRead(threadId);

    // Mesajları yükle
    loadThreadMessages(threadId);
}

// Thread mesajlarını yükle
function loadThreadMessages(threadId) {
    const container = document.getElementById('threadMessages');
    if (!container) return;

    const messages = getThreadMessages(threadId);
    const email = getCurrentUserEmail();

    container.innerHTML = messages.map(msg => `
        <div class="msg-bubble ${msg.from === email ? 'msg-sent' : 'msg-received'}">
            ${escapeHtml(msg.text)}
            <div style="font-size: 9px; opacity: 0.7; margin-top: 4px;">${formatTime(msg.time)}</div>
        </div>
    `).join('');

    container.scrollTop = container.scrollHeight;
}

// Thread mesajlarını al
function getThreadMessages(threadId) {
    const email = getCurrentUserEmail();
    if (!email) return [];
    return getFromStorage(`messages_${email}_${threadId}`, []);
}

// Geri dön
function backToInbox() {
    currentThread = null;
    document.getElementById('inboxView').classList.remove('hidden');
    document.getElementById('threadView').classList.add('hidden');
}

// Yeni mesaj başlat
function startNewMessage() {
    document.getElementById('newMessageModal').classList.remove('hidden');
}

// Yeni mesaj modalı kapat
function closeNewMessageModal() {
    document.getElementById('newMessageModal').classList.add('hidden');
    document.getElementById('newMsgRecipient').value = '';
    document.getElementById('newMsgContent').value = '';
}

// Yeni mesaj gönder (yeni thread)
function sendNewMessage() {
    const recipient = document.getElementById('newMsgRecipient').value.trim().toLowerCase();
    const text = document.getElementById('newMsgContent').value.trim();
    const email = getCurrentUserEmail();

    if (!recipient || !text) {
        showToast('Alıcı ve mesaj gerekli!');
        return;
    }

    if (!isValidEmail(recipient)) {
        showToast('Geçerli bir e-posta girin!');
        return;
    }

    // Thread oluştur
    const threadId = generateId();
    const thread = {
        id: threadId,
        participant: recipient,
        lastMessage: text,
        lastMessageTime: new Date().toISOString()
    };

    // Gönderen thread'i kaydet
    const senderThreads = getMessageThreads();
    senderThreads.unshift(thread);
    saveToStorage(`threads_${email}`, senderThreads);

    // Alıcı thread'i kaydet (karşı tarafta da görünsün)
    const recipientThreads = getFromStorage(`threads_${recipient}`, []);
    recipientThreads.unshift({
        id: threadId,
        participant: email,
        lastMessage: text,
        lastMessageTime: new Date().toISOString()
    });
    saveToStorage(`threads_${recipient}`, recipientThreads);

    // Mesajı kaydet
    const messages = getThreadMessages(threadId);
    messages.push({
        from: email,
        to: recipient,
        text: text,
        time: new Date().toISOString()
    });
    saveToStorage(`messages_${email}_${threadId}`, messages);
    saveToStorage(`messages_${recipient}_${threadId}`, messages);

    closeNewMessageModal();
    loadInbox();

    showToast('Mesaj gönderildi!');
}

// Doğrudan mesaj gönder
function sendDirectMessage() {
    const input = document.getElementById('dmInput');
    const text = input.value.trim();
    const email = getCurrentUserEmail();

    if (!text || !currentThread) return;

    const threads = getMessageThreads();
    const thread = threads.find(t => t.id === currentThread);
    if (!thread) return;

    // Mesajı kaydet
    const messages = getThreadMessages(currentThread);
    messages.push({
        from: email,
        to: thread.participant,
        text: text,
        time: new Date().toISOString()
    });
    saveToStorage(`messages_${email}_${currentThread}`, messages);
    saveToStorage(`messages_${thread.participant}_${currentThread}`, messages);

    // Thread'i güncelle
    thread.lastMessage = text;
    thread.lastMessageTime = new Date().toISOString();
    saveToStorage(`threads_${email}`, threads);

    input.value = '';
    loadThreadMessages(currentThread);
}

// Enter ile gönder
function handleDMKeydown(event) {
    if (event.key === 'Enter') {
        event.preventDefault();
        sendDirectMessage();
    }
}

// Okundu işaretle
function markThreadAsRead(threadId) {
    const email = getCurrentUserEmail();
    const threads = getMessageThreads();
    const thread = threads.find(t => t.id === threadId);

    if (thread) {
        thread.unread = false;
        saveToStorage(`threads_${email}`, threads);
    }
}

// Okunmamış badge güncelle
function updateUnreadBadge() {
    const badge = document.getElementById('msgUnreadBadge');
    if (!badge) return;

    if (STATE.unreadMessages > 0) {
        badge.textContent = STATE.unreadMessages > 9 ? '9+' : STATE.unreadMessages;
        badge.classList.remove('hidden');
    } else {
        badge.classList.add('hidden');
    }
}

// -------- BÖLGE SOHBET MODÜLÜ --------

// Bölge anahtar kelimesini hesapla (0.05 derece ızgara, ~5 km)
function getRegionKey(lat, lng) {
    const gridLat = (Math.floor(lat / 0.05) * 0.05).toFixed(2);
    const gridLng = (Math.floor(lng / 0.05) * 0.05).toFixed(2);
    return `region_chat_${gridLat}_${gridLng}`;
}

// Bölge mesajlarını yükle
function loadRegionChat() {
    const container = document.getElementById('regionChatMessages');
    if (!container) return;

    if (!STATE.currentLocation) {
        container.innerHTML = '<p style="color:var(--text-dim);font-size:11px;text-align:center;padding:20px">Bölge sohbeti için konumunuzu aktif edin.</p>';
        return;
    }

    const key = getRegionKey(STATE.currentLocation.lat, STATE.currentLocation.lng);
    const messages = getFromStorage(key, []);

    if (messages.length === 0) {
        container.innerHTML = '<p style="color:var(--text-dim);font-size:11px;text-align:center;padding:20px">Bölgenizde henüz mesaj yok. İlk mesajı siz yazın!</p>';
        return;
    }

    const email = getCurrentUserEmail();
    container.innerHTML = messages.slice(-50).map(m => `
        <div class="msg-bubble ${m.from === email ? 'msg-sent' : 'msg-received'}">
            <div style="font-size:9px;opacity:0.6;margin-bottom:2px">${m.from === email ? 'Siz' : m.from.split('@')[0]}</div>
            ${escapeHtml(m.text)}
            <div style="font-size:9px;opacity:0.6;margin-top:3px">${formatTime(m.time)}</div>
        </div>
    `).join('');

    container.scrollTop = container.scrollHeight;
}

// Bölge mesajı gönder
function sendRegionMessage() {
    const input = document.getElementById('regionChatInput');
    if (!input) return;
    const text = input.value.trim();
    if (!text) return;

    if (!STATE.currentLocation) {
        showToast('Bölge sohbeti için konumunuzu aktif edin!');
        return;
    }

    const email = getCurrentUserEmail();
    if (!email) {
        showToast('Mesaj göndermek için giriş yapın!');
        return;
    }

    const key = getRegionKey(STATE.currentLocation.lat, STATE.currentLocation.lng);
    const messages = getFromStorage(key, []);

    messages.push({
        from: email,
        text,
        time: new Date().toISOString(),
        lat: STATE.currentLocation.lat,
        lng: STATE.currentLocation.lng
    });

    // Son 100 mesajı sakla
    saveToStorage(key, messages.slice(-100));

    input.value = '';
    loadRegionChat();
}

// Bölge sohbet enter tuşu
function handleRegionChatKeydown(event) {
    if (event.key === 'Enter' && !event.shiftKey) {
        event.preventDefault();
        sendRegionMessage();
    }
}

// Bölge mesajlaşması (yakın kullanıcılar arası)
function getNearbyUsersMessageGroup() {
    if (!STATE.currentLocation) return null;

    const citizens = getCitizens();
    const nearby = citizens.filter(c => {
        if (!c.lat || !c.lng || c.email === getCurrentUserEmail()) return false;
        const dist = calculateDistance(
            STATE.currentLocation.lat, STATE.currentLocation.lng,
            c.lat, c.lng
        );
        return dist <= 5;
    });

    return { location: STATE.currentLocation, users: nearby };
}

// DM / Bölge sekme değiştir
function switchMessagingTab(tab) {
    const dmTab = document.getElementById('dmTab');
    const regionTab = document.getElementById('regionTab');
    const dmView = document.getElementById('dmView');
    const regionView = document.getElementById('regionView');

    if (!dmTab || !regionTab || !dmView || !regionView) return;

    if (tab === 'dm') {
        dmTab.classList.add('active');
        regionTab.classList.remove('active');
        dmView.classList.remove('hidden');
        regionView.classList.add('hidden');
        loadInbox();
    } else {
        regionTab.classList.add('active');
        dmTab.classList.remove('active');
        regionView.classList.remove('hidden');
        dmView.classList.add('hidden');
        loadRegionChat();
    }
}
