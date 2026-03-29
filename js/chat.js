// TR-GOZU AI Sohbet Modülü (Gelişmiş - Bağlam Destekli)

let chatOpen = false;

// Sohbeti aç/kapat
function toggleChat() {
    chatOpen = !chatOpen;
    const panel = document.getElementById('chatPanel');

    if (chatOpen) {
        panel.classList.remove('hidden');
        document.getElementById('chatInput').focus();

        if (!getChatHistory().length) {
            const welcome = getAIRandomResponse('greetings');
            addChatMessage(welcome, 'bot');
            addChatMessage('Deprem, sel, yangın, ilk yardım, toplanma alanı, SOS kullanımı gibi konularda soru sorabilirsiniz.', 'bot');
        } else {
            loadChatHistory();
        }
    } else {
        panel.classList.add('hidden');
    }
}

// Sohbet geçmişini al
function getChatHistory() {
    const email = getCurrentUserEmail();
    if (!email) return [];
    return getFromStorage(`chat_${email}`, []);
}

// Sohbet geçmişini kaydet
function saveChatHistory(messages) {
    const email = getCurrentUserEmail();
    if (email) saveToStorage(`chat_${email}`, messages.slice(-50));
}

// Geçmişi yükle
function loadChatHistory() {
    const messages = getChatHistory();
    const container = document.getElementById('chatMessages');
    if (!container) return;

    container.innerHTML = '';
    messages.forEach(msg => appendChatMessage(container, msg.text, msg.type));
    container.scrollTop = container.scrollHeight;
}

// Sohbet mesajı ekle
function addChatMessage(text, type) {
    const container = document.getElementById('chatMessages');
    if (!container) return;

    appendChatMessage(container, text, type);

    const history = getChatHistory();
    history.push({ text, type, time: Date.now() });
    saveChatHistory(history);

    container.scrollTop = container.scrollHeight;
}

// Mesajı DOM'a ekle
function appendChatMessage(container, text, type) {
    const div = document.createElement('div');
    div.className = `chat-bubble chat-${type}`;
    // Satır sonlarını destekle
    div.style.whiteSpace = 'pre-wrap';
    div.textContent = text;
    container.appendChild(div);
}

// Mesaj gönder
async function sendChatMessage() {
    const input = document.getElementById('chatInput');
    const text = input.value.trim();
    if (!text) return;

    addChatMessage(text, 'user');
    input.value = '';

    const typingEl = document.getElementById('chatTyping');
    if (typingEl) typingEl.classList.remove('hidden');

    const proxyUrl =
        typeof CONFIG !== 'undefined' && CONFIG.AI_CHAT_PROXY_URL
            ? String(CONFIG.AI_CHAT_PROXY_URL).trim()
            : '';

    if (proxyUrl) {
        try {
            const history = getChatHistory()
                .filter((m) => m.type === 'user' || m.type === 'bot')
                .slice(-12)
                .map((m) => ({
                    role: m.type === 'user' ? 'user' : 'assistant',
                    content: m.text
                }));
            const res = await fetch(proxyUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ message: text, messages: history })
            });
            const data = res.ok ? await res.json().catch(() => null) : null;
            const reply =
                data &&
                (data.reply || data.message || data.content || data.text);
            if (reply && String(reply).trim()) {
                if (typingEl) typingEl.classList.add('hidden');
                addChatMessage(String(reply).trim(), 'bot');
                return;
            }
        } catch (e) {
            console.warn('AI proxy:', e);
        }
    }

    const delay = 600 + Math.random() * 800;
    setTimeout(() => {
        if (typingEl) typingEl.classList.add('hidden');
        const response = generateAIResponse(text);
        addChatMessage(response, 'bot');
    }, delay);
}

// Enter tuşu ile gönder
function handleChatKeydown(event) {
    if (event.key === 'Enter' && !event.shiftKey) {
        event.preventDefault();
        sendChatMessage();
    }
}

// Anahtar kelime puanlama sistemi
function scoreKeywords(msg, keywords) {
    let score = 0;
    keywords.forEach(kw => { if (msg.includes(kw)) score++; });
    return score;
}

function isDisallowedTopic(userMessage) {
    const m = userMessage.toLowerCase();
    const blocked = [
        'porno', 'porn', 'sex', 'seks', 'cinsel', 'masturb', 'escort', '+18',
        'yetiskin icerik', 'nude', 'çıplak', 'amcık', 'sikiş', 'penis', 'vajina'
    ];
    return blocked.some(k => m.includes(k));
}

// AI Yanıt üreteci (gelişmiş, bağlam destekli — yalnızca afet/acil; +18 yok)
function generateAIResponse(userMessage) {
    if (isDisallowedTopic(userMessage)) {
        return 'Bu konularda yardımcı olamam. TR-GOZU yalnızca afet, acil durum ve güvenlik bilgisi sunar. Deprem, yangın, rota veya SOS hakkında sorabilirsiniz.';
    }

    const msg = userMessage.toLowerCase()
        .replace(/[çÇ]/g, 'c').replace(/[şŞ]/g, 's').replace(/[ğĞ]/g, 'g')
        .replace(/[üÜ]/g, 'u').replace(/[öÖ]/g, 'o').replace(/[ıİ]/g, 'i');

    // Selamlaşma
    if (scoreKeywords(msg, ['merhaba', 'selam', 'hello', 'hi', 'hosgeldin', 'iyi gunler']) >= 1) {
        return getAIRandomResponse('greetings');
    }

    // Teşekkür
    if (scoreKeywords(msg, ['tesekkur', 'tessekur', 'sagol', 'sagolun', 'eyvallah', 'thank']) >= 1) {
        return 'Rica ederiz. Güvende kalmanız için buradayız. Başka bir sorunuz varsa sormaktan çekinmeyin.';
    }

    // AFAD / canlı veri / uydu harita
    if (scoreKeywords(msg, ['afad', 'afad harita', 'deprem afad', 'afad veri']) >= 1) {
        return 'Deprem olayları AFAD’un ArcGIS yayını ile ve Kandilli verisiyle birleştirilerek güncellenir; haritada kırmızı daireler büyüklüğe göre son sarsıntıları gösterir. Uydu için haritada uydu düğmesine, dünya haritası için OSM düğmesine basabilirsiniz. Resmî bilgi: deprem.afad.gov.tr';
    }
    if (scoreKeywords(msg, ['firms', 'nasa', 'uydu yangin', 'sicak nokta', 'thermal', 'viirs']) >= 1) {
        return 'Haritada 🔥 (NASA VIIRS / FIRMS uyumlu NRT) düğmesine basın; görünen alandaki uydu sıcak noktaları yüklenir. Her nokta otomatik olarak gerçek yangın demek değildir — fabrika ve sıcak zemin de olabilir. Kesin teyit için yerel AFAD/orman veya 110 hattını kullanın.';
    }

    // Deprem
    const depremScore = scoreKeywords(msg, ['deprem', 'sarsinit', 'earthquake', 'quake', 'artci', 'enkaz', 'yikil', 'bina yikil', 'kandilli', 'sarsinti']);
    if (depremScore >= 1) {
        let resp = CONFIG.AI_RESPONSES.disasters.deprem;
        // Bağlam: Kandilli veri varsa ekle
        if (STATE.nearbyEarthquakes && STATE.nearbyEarthquakes.length > 0) {
            const nearest = STATE.nearbyEarthquakes[0];
            resp += `\n\nBölgenizdeki son deprem: M${nearest.magnitude.toFixed(1)} — ${nearest.place || 'Bilinmiyor'} (${Math.round(nearest.distance)} km).`;
        }
        return resp;
    }

    // Sel / Taşkın
    if (scoreKeywords(msg, ['sel', 'taskin', 'su baskini', 'flood', 'yagmur', 'nehir', 'dere']) >= 1) {
        let resp = CONFIG.AI_RESPONSES.disasters.sel;
        if (STATE.forecastData?.flood) {
            resp += `\n\nSel tahmini: ${STATE.forecastData.flood.label} — ${STATE.forecastData.flood.detail}`;
        }
        return resp;
    }

    // Yangın
    if (scoreKeywords(msg, ['yangin', 'ates', 'duman', 'alev', 'fire', 'tup', 'gaz']) >= 1) {
        let resp = CONFIG.AI_RESPONSES.disasters.yangin;
        if (STATE.forecastData?.fire) {
            resp += `\n\nYangın risk indeksi: ${STATE.forecastData.fire.label} — ${STATE.forecastData.fire.detail}`;
        }
        return resp;
    }

    // Fırtına
    if (scoreKeywords(msg, ['firtina', 'kasirga', 'storm', 'tayfun', 'hurricane', 'tornado']) >= 1) {
        return CONFIG.AI_RESPONSES.disasters.firtina;
    }

    // Heyelan
    if (scoreKeywords(msg, ['heyelan', 'toprak kayma', 'landslide', 'cig', 'avalanche']) >= 1) {
        return CONFIG.AI_RESPONSES.disasters.heyelan;
    }

    // Kar fırtınası
    if (scoreKeywords(msg, ['kar', 'kar firtina', 'tipi', 'blizzard', 'hipotermi', 'donma']) >= 1) {
        return CONFIG.AI_RESPONSES.disasters.kar;
    }

    // İlk yardım
    if (scoreKeywords(msg, ['ilk yardim', 'cpr', 'kalp masaji', 'kanama', 'kirik', 'yanik', 'bilinc kaybı', 'bayildi', 'sok', 'first aid']) >= 1) {
        return CONFIG.AI_RESPONSES.first_aid;
    }

    // SOS
    if (scoreKeywords(msg, ['sos', 'acil', 'yardim et', 'sikistim', 'kurtar', 'emergency', 'kurtarim']) >= 1) {
        return CONFIG.AI_RESPONSES.sos_help;
    }

    // Karakol / polis
    if (scoreKeywords(msg, ['karakol', 'polis merkezi', 'polis', '155', 'jandarma', '156']) >= 1) {
        return 'En yakın karakol ve polis birimleri OpenStreetMap verisiyle haritada mavi işaretlerle listelenir. Konumu açtıktan sonra yetkili panelinde kurum listesinden seçim yapın veya haritada polis işaretlerine dokunun. Acil: 155 (Polis), 156 (Jandarma), 112.';
    }

    // Konum / Harita
    if (scoreKeywords(msg, ['konum', 'nerede', 'nerde', 'location', 'harita', 'gps', 'takip']) >= 1) {
        return CONFIG.AI_RESPONSES.location;
    }

    // Toplanma alanı
    if (scoreKeywords(msg, ['toplanma', 'toplanma alani', 'assembly', 'guvenli yer', 'nereye gideyim', 'nereye gidecegim']) >= 1) {
        let resp = CONFIG.AI_RESPONSES.assembly;
        if (STATE.currentLocation) {
            const toplanma = document.getElementById('val-toplanma-ad');
            if (toplanma && toplanma.textContent && toplanma.textContent !== '-') {
                resp += `\n\nEn yakın toplanma alanı: ${toplanma.textContent}`;
                const mesafe = document.getElementById('val-toplanma-mesafe');
                if (mesafe && mesafe.textContent !== '-') resp += ` (${mesafe.textContent})`;
            }
        }
        return resp;
    }

    // Hastane / Sağlık
    if (scoreKeywords(msg, ['hastane', 'saglik', 'doktor', 'klinik', 'acil servis', 'hospital', 'tibbi', 'yarali']) >= 1) {
        let resp = CONFIG.AI_RESPONSES.hospital;
        if (STATE.currentLocation) {
            const hast = document.getElementById('val-hastane');
            if (hast && hast.textContent && hast.textContent !== '-') {
                resp += `\n\nEn yakın hastane: ${hast.textContent}`;
                const hMesafe = document.getElementById('val-hastane-mesafe');
                if (hMesafe && hMesafe.textContent !== '-') resp += ` (${hMesafe.textContent})`;
            }
        }
        return resp;
    }

    // Yardım genel
    if (scoreKeywords(msg, ['yardim', 'yardimci', 'help', 'destek', 'ne yapmaliyim', 'ne yapayim']) >= 1) {
        return CONFIG.AI_RESPONSES.help;
    }

    // Gönüllü
    if (scoreKeywords(msg, ['gonullu', 'volunteer', 'gonulluluk', 'gonullu ol']) >= 1) {
        return CONFIG.AI_RESPONSES.volunteer;
    }

    // Aile / Yakınlar
    if (scoreKeywords(msg, ['aile', 'anne', 'baba', 'cocuk', 'family', 'yakin', 'akraba']) >= 1) {
        return 'Aile üyelerinizi sistemde kayıt ederek takip edebilirsiniz. Sol panelden "Aile Üyesi Ekle" seçeneğini kullanın. Kayıp aile üyeleri için "Kayıp Kişi Bildir" butonunu kullanın.';
    }

    // Batarya
    if (scoreKeywords(msg, ['batarya', 'pil', 'battery', 'sarj', 'sepetle', 'powerbank']) >= 1) {
        return CONFIG.AI_RESPONSES.battery;
    }

    // Kayıp kişi
    if (scoreKeywords(msg, ['kayip', 'kayboldu', 'missing', 'bulamiyorum', 'bulamadim', 'son gorus']) >= 1) {
        return CONFIG.AI_RESPONSES.missing;
    }

    // Hava / Sıcaklık
    if (scoreKeywords(msg, ['hava', 'sicaklik', 'nem', 'weather', 'temperature', 'hava durumu']) >= 1) {
        if (STATE.lastWeatherData) {
            const w = STATE.lastWeatherData;
            const temp = Math.round(w.main.temp);
            const heatIdx = typeof calculateHeatIndex === 'function'
                ? calculateHeatIndex(temp, w.main.humidity) : temp;
            return `Bulunduğunuz bölgedeki anlık hava durumu:\n${w.weather[0].description}, ${temp}°C (hissedilen: ${heatIdx}°C), nem: %${w.main.humidity}, rüzgar: ${(w.wind.speed * 3.6).toFixed(0)} km/s.`;
        }
        return CONFIG.AI_RESPONSES.weather || 'Sol panelde anlık hava durumu bilgisini görebilirsiniz.';
    }

    // Deprem tahmini / trend
    if (scoreKeywords(msg, ['deprem tahmini', 'deprem trendi', 'sismik', 'magnitude', 'buyukluk', 'kandilli', 'usgs']) >= 1) {
        if (STATE.forecastData?.earthquake) {
            const eq = STATE.forecastData.earthquake;
            return `Sismik aktivite trendi: ${eq.label}\n${eq.detail}\n${eq.disclaimer || ''}`;
        }
        return CONFIG.AI_RESPONSES.earthquake_info;
    }

    // Güvenli rota
    if (scoreKeywords(msg, ['rota', 'yol', 'nasil gideyim', 'nereden gideyim', 'route', 'yol haritasi']) >= 1) {
        return 'Güvenli rota için haritanın altındaki "Güvenli Rota" butonuna basın. Sistem, OSRM verilerini kullanarak gerçek yolları takip eden, tehlikeli bölgelerden kaçınan bir rota hesaplar.';
    }

    // Raporlama / ihbar
    if (scoreKeywords(msg, ['ihbar', 'bildir', 'rapor', 'report', 'sahte ihbar', 'dogru mu']) >= 1) {
        return 'Sahte ihbar engelleme sistemimiz aktif. Aynı bölgeden 2+ SOS gelirse sistem doğrulama yapar. Lütfen gerçek acil durumlarda SOS butonunu kullanın; yanlışlıkla basıldıysa "VAZGEÇ" ile iptal edin.';
    }

    // Acil numaralar
    if (scoreKeywords(msg, ['numara', 'telefon', 'ara', 'call', '112', 'afad', 'itfaiye', 'polis']) >= 1) {
        return 'Türkiye Acil Numaraları:\n\n112 — İmdat / Ambulans / AFAD\n110 — İtfaiye\n155 — Polis\n156 — Jandarma\n122 — AFAD Doğal Afet\n182 — Zehir Danışma\n\nSisteme bağlı olduğunuzda SOS butonu da yetkililer ile anında iletişim sağlar.';
    }

    // Kısa / doğal sorular ("ne", "nasil", "neden" tek başına)
    if (msg.length < 4 || scoreKeywords(msg, ['ne yapayim', 'ne yapmali', 'yardim et bana', 'acil ne']) >= 1) {
        return 'Afet anında özet: 1) Sakin kalın. 2) 112 / 110 / 155 arayın. 3) Mümkünse konumu açın. 4) SOS veya sağlık durumunu güncelleyin. 5) Tahliye varsa toplanma alanına gidin. Spesifik soru yazarsanız (ör. “depremde çök-kapan-tutun”) size göre yanıtlarım.';
    }

    // Varsayılan
    return CONFIG.AI_RESPONSES.default;
}

// AI'dan rastgele yanıt al
function getAIRandomResponse(type) {
    const responses = CONFIG.AI_RESPONSES[type];
    if (Array.isArray(responses)) {
        return responses[Math.floor(Math.random() * responses.length)];
    }
    return responses || CONFIG.AI_RESPONSES.default;
}

// Sohbeti temizle
function clearChat() {
    const email = getCurrentUserEmail();
    if (email) removeFromStorage(`chat_${email}`);
    const container = document.getElementById('chatMessages');
    if (container) container.innerHTML = '';
    showToast('Sohbet temizlendi.');
}
