// TR-GOZU Konfigürasyon
const CONFIG = {
    /**
     * Sunucu ile aynı kökenden açıldığında (npm start) hava API anahtarı .env üzerinden proxy ile gelir.
     * Doğrudan file:// veya statik hostta hava için: .env WEATHER_API_KEY + node js/server.js kullanın
     * veya geçici olarak aşağıdaki alana anahtar koymayın — anahtar istemcide kalır (önerilmez).
     */
    WEATHER_API_KEY: '',

    /** Boş = otomatik window.location.origin (http sunucuda proxy kullanılır) */
    API_BASE_URL:
        typeof window !== 'undefined' && window.location && window.location.protocol !== 'file:'
            ? window.location.origin
            : '',

    /** Sunucu üzerinden kayıt/giriş + JWT (npm start ile aynı origin) */
    USE_SERVER_AUTH: true,

    // Eşik Değerleri
    BATTERY_THRESHOLD: 10,
    SOS_COUNTDOWN: 5,
    PANIC_PRESS_INTERVAL: 2000,
    PANIC_PRESS_COUNT: 3,

    // Yenileme Aralıkları
    ADMIN_REFRESH_INTERVAL: 5000,
    CITIZEN_REFRESH_INTERVAL: 10000,
    LOCATION_UPDATE_INTERVAL: 30000,

    // Türkiye yaklaşık sınır (USGS filtre / istatistik)
    TURKEY_BBOX: { minLat: 35.5, maxLat: 42.5, minLon: 25.5, maxLon: 45.5 },

    // SOS: Kandilli ile sismik doğrulama (normal SOS yetkiliye yalnız eşleşmede)
    SOS_KANDILLI_RADIUS_KM: 175,
    SOS_KANDILLI_MAX_HOURS: 72,
    SOS_KANDILLI_MIN_MAG: 2.0,

    // Deprem API
    EARTHQUAKE_API: 'https://earthquake.usgs.gov/earthquakes/feed/v1.0/summary/',
    KANDILLI_API: 'https://api.orhanaydogdu.com.tr/deprem/kandilli/live',
    // AFAD resmi ArcGIS deprem katmanı (anlık, dünya geneli yayın + Türkiye olayları)
    AFAD_ARCGIS_EARTHQUAKE: 'https://services-ap1.arcgis.com/V658FuwgeH1dACcz/ArcGIS/rest/services/EARTHQUAKE/FeatureServer/0',
    // NASA VIIRS sıcak noktalar (FIRMS ile uyumlu NRT; yakın zamanda uydu geçişi)
    NASA_VIIRS_HOTSPOTS_LAYER: 'https://services9.arcgis.com/RHVPKKiFTONKtxq3/arcgis/rest/services/Satellite_VIIRS_Thermal_Hotspots_and_Fire_Activity/FeatureServer/0',

    // Overpass API
    OVERPASS_API: 'https://overpass-api.de/api/interpreter',

    /** Risk paneli: konumunuza göre listelenen hastane / toplanma yarıçapı (km) */
    INSTITUTION_LIST_RADIUS_KM: 5,

    // OSRM Yol Rota API (ücretsiz, açık kaynak)
    OSRM_API: 'https://router.project-osrm.org/route/v1/driving',

    // Google Directions: tarayıcıdan CORS yok; üretimde kendi backend proxy kullanın. Boş = yalnız OSRM.
    GOOGLE_DIRECTIONS_API_KEY: '',

    // Gerçek LLM: API anahtarını tarayıcıya koymayın. Kendi sunucunuzda POST proxy (ör. OpenAI uyumlu) tanımlayın.
    // İstek gövdesi: { "messages": [...], "message": "son kullanıcı metni" } — yanıt: { "reply": "..." }
    AI_CHAT_PROXY_URL: '',

    // Öncelik Eşikleri
    PRIORITY_THRESHOLDS: {
        CRITICAL: 10,
        HIGH: 5,
        MEDIUM: 3
    },

    // Doğrulama Eşikleri
    VERIFICATION_THRESHOLD: 2,

    // Önbellek
    CACHE_DURATION: 5 * 60 * 1000,

    // Yardım Türleri
    HELP_TYPES: {
        su: { icon: '💧', label: 'Su', priority: 'high' },
        yiyecek: { icon: '🍞', label: 'Yiyecek', priority: 'high' },
        ilkyardim: { icon: '🏥', label: 'İlk Yardım', priority: 'critical' },
        barinak: { icon: '🏠', label: 'Barınak', priority: 'high' },
        giyim: { icon: '👕', label: 'Giyim', priority: 'medium' },
        diger: { icon: '📦', label: 'Diğer', priority: 'low' }
    },

    // Afet Türleri
    DISASTER_TYPES: [
        { id: 'deprem', label: 'Deprem', icon: '🌍' },
        { id: 'sel', label: 'Sel/Taşkın', icon: '🌊' },
        { id: 'firtina', label: 'Fırtına', icon: '🌪️' },
        { id: 'yangin', label: 'Yangın', icon: '🔥' },
        { id: 'heyelan', label: 'Heyelan', icon: '⛰️' },
        { id: 'kar', label: 'Kar Fırtınası', icon: '❄️' },
        { id: 'diger', label: 'Diğer', icon: '⚠️' }
    ],

    // Sağlık Durumları
    HEALTH_STATUS: {
        iyiyim: { icon: '🟢', label: 'İyiyim', color: '#2ecc71' },
        yaraliyim: { icon: '🟠', label: 'Yaralıyım', color: '#ffa502' },
        kritik: { icon: '🔴', label: 'Kritik', color: '#ff4757' },
        enkaz: { icon: '🟣', label: 'Enkaz Altında', color: '#9b59b6' }
    },

    // Gönüllü Yetenekleri
    VOLUNTEER_SKILLS: {
        ilkyardim: { label: 'İlk Yardım', icon: '🏥' },
        arama: { label: 'Arama-Kurtarma', icon: '🔍' },
        lojistik: { label: 'Lojistik', icon: '🚚' },
        psikolojik: { label: 'Psikolojik Destek', icon: '🧠' }
    },

    // Gelişmiş AI Yanıt Veritabanı
    AI_RESPONSES: {
        greetings: [
            'Merhaba! TR-GOZU Acil Destek Sistemi olarak size yardımcı olmaya hazırım.',
            'Hoş geldiniz. Afet ve acil durum konularında sorularınızı yanıtlayabilirim.',
            'TR-GOZU AI destek hattına bağlandınız. Nasıl yardımcı olabilirim?'
        ],
        disasters: {
            deprem: 'Deprem sırasında yapmanız gerekenler:\n\n1. SAKIN KALIN — çökme üçgeni oluşturun.\n2. Sağlam bir mobilyanın YANINA (masanın altına değil yanına) diz çökün ve başınızı koruyun.\n3. Pencere, cam ve dış duvarlardan uzaklaşın.\n4. Asansör kullanmayın, sarsıntı bitene kadar bekleyin.\n5. Sarsıntı bitince gaz/su/elektrik vanalarını kapatın.\n6. Artçı sarsıntılara karşı açık alanlarda bekleyin.\n7. SOS butonuna basarak konumunuzu yetkililere bildirin.\n\nACİL: 112 (AFAD), 110 (İtfaiye), 155 (Polis)',
            sel: 'Sel/Taşkın durumunda yapmanız gerekenler:\n\n1. Hemen yüksek bir kata çıkın, bodrum ve zemin kattan uzaklaşın.\n2. Elektrik panolarına ve prizlere DOKUNMAYIN.\n3. Akan suya girmeyin — 15 cm derinlik sizi devirebilir.\n4. Araçla sel bölgesinden geçmeyin, araç sürüklenir.\n5. Tahliye uyarısı gelirse eşya almadan hemen çıkın.\n6. Kirli suyla temas sonrası ellerinizi yıkayın.\n\nACİL: 112 (AFAD)',
            firtina: 'Fırtına sırasında yapmanız gerekenler:\n\n1. Kapalı alanda, penceresiz bir odada kalın.\n2. Pencere ve camlardan uzaklaşın — bantlamak tehlikeli cam parçası oluşturur.\n3. Yüksek profilli araçlarla seyahat etmeyin.\n4. Kopuk elektrik hatlarına kesinlikle yaklaşmayın.\n5. Fırtına geçene kadar dışarı çıkmayın.\n6. Dışarıda kalırsanız alçak bir çukura yatıp başınızı koruyun.\n\nACİL: 112',
            yangin: 'Yangın durumunda yapmanız gerekenler:\n\n1. Binayı HEMEN terk edin — eşya almayın.\n2. Duman varsa alçak pozisyonda, yerde sürünerek ilerleyin.\n3. Kapı sıcaksa AÇMAYIN — arkasında alev olabilir.\n4. Asansör kullanmayın, merdiveni kullanın.\n5. Çıkamazsanız: pencereye gidin, yardım çağırın, kapı altını bez ile tıkayın.\n6. Toplanma alanına gidin, sayım yapılacaktır.\n\nACİL: 110 (İtfaiye), 112',
            heyelan: 'Heyelan durumunda yapmanız gerekenler:\n\n1. Yamaçlardan ve vadilerden uzaklaşın.\n2. Akış yönünün dışına, yüksek ve sağlam zemine çıkın.\n3. Araçta iseniz: ani gürültü veya sallantıda hemen araçtan çıkın.\n4. Toz bulutu ve gürültü heyelan habercisidir.\n\nACİL: 112',
            kar: 'Kar Fırtınası sırasında yapmanız gerekenler:\n\n1. Mümkünse evden çıkmayın.\n2. Araç kullanmak zorundaysanız yavaş gidin, kış lastiği takılı olsun.\n3. Araç mahsur kalırsa motoru çalıştırın, egzozu karın tıkamadığından emin olun.\n4. Hipotermi belirtileri (şiddetli titreme, uyuşukluk): ısıtın ve 112 arayın.\n5. Çığ riski varsa yüksek kesimlerden uzak durun.\n\nACİL: 112',
            genel: 'Genel acil durum protokolü:\n\n1. Sakin kalın ve durumu değerlendirin.\n2. 112 (AFAD/Ambulans), 155 (Polis), 110 (İtfaiye).\n3. TR-GOZU SOS butonuna basarak konumunuzu paylaşın.\n4. Sağlık durumunuzu güncelleyin (sol panel).\n5. En yakın toplanma alanına gidin.\n6. Aile üyelerinizi haberdar edin.'
        },
        help: 'Yardım almak için:\n\n- SOS butonu (ekran sağ alt): Anında yetkililere konum bildirimi\n- Sağlık durumu (sol panel): Durumunuzu ekiplere bildirin\n- Akıllı Yardım (sol panel): Su, yiyecek, barınak ihtiyaçlarınızı listeleyin\n- Gönüllü Listesi: Yakınınızdaki gönüllüleri görün\n\nACİL: 112 — AFAD: 122',
        location: 'Konumunuzu paylaşmak için:\n\n1. Sol panelde "Konumu Aktif Et" butonuna basın.\n2. Tarayıcının konum iznini "İzin Ver" olarak ayarlayın.\n3. Konum aktif olunca yetkililer sizi haritada görebilir.\n4. Batarya %10 altına düşünce konum otomatik paylaşılır.\n\nNot: Konum verisi yalnızca yetkili ekiplerle paylaşılır.',
        sos_help: 'SOS butonu hakkında:\n\n- Tek basma: 5 saniyelik geri sayım başlar, yetkililere konumunuz iletilir.\n- Hızlı 3 kez basma: PANİK modu — öncelikli müdahale tetiklenir.\n- VAZGEÇ: Yanlışlıkla bastıysanız iptal edebilirsiniz.\n\nKonumunuz paylaşılmamışsa önce konumu aktif edin.',
        assembly: 'Toplanma alanları hakkında:\n\n- Haritada yeşil işaretli noktalar toplanma alanlarıdır.\n- En yakın alan sol panelde "Toplanma Alanı" bölümünde gösterilir.\n- Rota için "Güvenli Rota" butonuna basın — gerçek yol rotası çizilir.\n- Doluluk fazlaysa bir sonraki toplanma alanını tercih edin.',
        hospital: 'Hastane ve sağlık tesisleri:\n\n- Haritada mor işaretli noktalar hastanelerdir.\n- En yakın sağlık merkezi sol panelde gösterilir.\n- Yatak doluluk bilgisi kurum listesinde mevcuttur.\n- Rota için "Güvenli Rota" butonunu kullanın.\n\nACİL: 112',
        first_aid: 'Temel ilk yardım:\n\n- CPR: 30 bası + 2 nefes, dakikada 100-120 hız, 5 cm derinlik.\n- Kanama: Baskı uygulayın, yarayı yüksekte tutun.\n- Kırık: Hareket ettirmeyin, sabitleyin.\n- Yanık: Soğuk su — en az 20 dakika. BUZ KULLANMAYIN.\n- Bilinç kaybı: Yan yatırın, hava yolunu açık tutun, 112 arayın.',
        volunteer: 'Gönüllü olmak için:\n\nSol panelden "Gönüllü Ol" butonuna basarak kayıt olabilirsiniz.\nAlanlar: İlk yardım, arama-kurtarma, lojistik, psikolojik destek.\nGmail ve telefon numaranız diğer gönüllüler ve yetkililerle paylaşılır.',
        missing: 'Kayıp kişi bildirimi:\n\nSol panelden "Kayıp Kişi Ekle" butonuna basın.\nGerekli bilgiler: Ad soyad, yaş, cinsiyet, son görülme yeri ve zamanı.\nKayıp kişinin son konumu haritada gösterilir.',
        battery: 'Batarya yönetimi:\n\n- Batarya %10 düşünce konum otomatik paylaşılır.\n- Şarj tasarrufu için ekran parlaklığını azaltın.\n- Arka plan uygulamalarını kapatın.\n- Powerbank ile şarj önerilir.',
        earthquake_info: 'Deprem bilgileri:\n\nSol panelde Kandilli Rasathanesi verilerine göre bölgenizdeki deprem risk yüzdesi ve sismik aktivite trendi gösterilmektedir.\nHaritada kırmızı daireler son depremleri gösterir.',
        default: 'Sorunuzu anlayamadım. Şunları deneyebilirsiniz:\n\n- "Depremde ne yapmalıyım?" gibi spesifik bir soru sorun.\n- "Toplanma alanı nerede?", "SOS nasıl kullanılır?" diyebilirsiniz.\n- Acil için SOS butonunu kullanın veya 112\'yi arayın.'
    }
};

// Global State
const STATE = {
    userRole: null,
    tempUserData: null,
    userEmail: null,
    currentLocation: null,
    isLocationActive: false,
    sosCount: 0,
    lastSosTime: 0,
    isPanic: false,
    batteryLevel: null,
    healthStatus: null,
    unreadMessages: 0,
    map: null,
    heatmapEnabled: false,
    routeEnabled: false,
    lastWeatherData: null,
    forecastData: null,
    usgs24hSummary: null,
    lastWeatherRainMm: 0,
    lastFireHotspotCount: 0,
    nearestHospital: null,
    nearestAssembly: null,
    /** Konumunuza göre CONFIG.INSTITUTION_LIST_RADIUS_KM içindeki OSM kurumları — mesafeye göre sıralı */
    hospitalsWithin5km: [],
    assembliesWithin5km: [],
    selectedHospitalIndex: 0,
    selectedAssemblyIndex: 0
};

// Yardımcı fonksiyonlar
function generateId() {
    return Date.now().toString(36) + Math.random().toString(36).substr(2);
}

function formatTime(date) {
    if (!date) return '-';
    const d = new Date(date);
    return d.toLocaleTimeString('tr-TR', { hour: '2-digit', minute: '2-digit' });
}

function timeSince(date) {
    if (!date) return 'Bilinmiyor';
    const seconds = Math.floor((new Date() - new Date(date)) / 1000);
    if (seconds < 60) return 'Az önce';
    const minutes = Math.floor(seconds / 60);
    if (minutes < 60) return `${minutes} dk önce`;
    const hours = Math.floor(minutes / 60);
    if (hours < 24) return `${hours} saat önce`;
    const days = Math.floor(hours / 24);
    return `${days} gün önce`;
}

function showToast(message, duration = 3000) {
    const toast = document.getElementById('toast');
    const toastMsg = document.getElementById('toastMessage');
    if (toast && toastMsg) {
        toastMsg.textContent = message;
        toast.classList.remove('hidden');
        setTimeout(() => toast.classList.add('hidden'), duration);
    }
}

function showLoading(show = true) {
    const overlay = document.getElementById('loadingOverlay');
    if (overlay) {
        overlay.classList.toggle('hidden', !show);
    }
}

function getCurrentUserEmail() {
    return STATE.userEmail || localStorage.getItem('currentUserEmail');
}

function setCurrentUserEmail(email) {
    STATE.userEmail = email;
    localStorage.setItem('currentUserEmail', email);
}

