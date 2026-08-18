// G4MEOVER Heltec ukfe_rf Empfaenger (USB Army Penetrator)
// Heltec WiFi LoRa 32 V3 (ESP32-S3 + SX1262). Empfaengt 868.35-MHz-2FSK-Frames
// vom Flipper-RF-Console, verifiziert (MAC+CRC+Rolling-Counter) und fuehrt Befehle aus.
#include <Arduino.h>
#include <RadioLib.h>
#include <U8g2lib.h>
#include <SPI.h>
#include <WiFi.h>
#include <esp_now.h>
#include <esp_wifi.h>
#include "USB.h"
#include "USBHIDKeyboard.h"

// ESP-NOW-Kanal — MUSS mit dem WROOM-Relay (g4meover-wifi-relay) uebereinstimmen.
#define ESPNOW_CHANNEL 1

extern "C" {
#include "ukfe_rf.h"
}
#include "wifi_attack.h"   // native WiFi-Angriffe (Deauth/Beacon/Scan), nicht-blockierend
#include "evil_portal.h"   // Captive Portal (SoftAP + DNS + Login-Harvest)
#include "wifi_recon.h"    // Promiscuous-Recon (Handshake/Probe/PacketMon/Pwnagotchi/Wardrive)

// Natives USB (ESP32-S3, GPIO19/20) als HID-Tastatur -> BadUSB auf Zielrechner.
// Nur autorisierte Tests/eigene Geraete. Zielrechner an das native USB (nicht COM26/CP210x).
USBHIDKeyboard Keyboard;

// ---- Heltec WiFi LoRa 32 V3 Pinbelegung ----
#define PIN_LORA_NSS   8
#define PIN_LORA_DIO1  14
#define PIN_LORA_RST   12
#define PIN_LORA_BUSY  13
#define PIN_LORA_SCK   9
#define PIN_LORA_MISO  11
#define PIN_LORA_MOSI  10
#define PIN_OLED_SDA   17
#define PIN_OLED_SCL   18
#define PIN_OLED_RST   21
#define PIN_VEXT       36  // LOW = OLED-Versorgung an
#define PIN_LED        35

static const uint8_t BROADCAST_MAC[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

// Gemeinsames Geheimnis fuer den keyed MAC — IDENTISCH mit RF_SECRET in
// lora-ukfe/rf/rf_comm.c (out-of-band pairen, Pairing-Bytes ersetzen!).
static const uint8_t UKFE_SECRET[UKFE_RF_SECRET_LEN] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,   // "G4MEOVER"
    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,   // Pairing-Bytes
};

SPIClass loraSpi(HSPI);
SX1262 radio = new Module(PIN_LORA_NSS, PIN_LORA_DIO1, PIN_LORA_RST, PIN_LORA_BUSY, loraSpi);
U8G2_SSD1306_128X64_NONAME_F_HW_I2C oled(U8G2_R0, PIN_OLED_RST, PIN_OLED_SCL, PIN_OLED_SDA);

static volatile bool rxFlag = false;
static uint32_t lastCounter = 0;     // Anti-Replay-Fenster (868-Funk)
static uint32_t rxCount = 0, okCount = 0;

// ---- ESP-NOW-Transport (WiFi 2.4G, vom WROOM-Relay) — additiv neben 868 ----
static volatile bool enowFlag = false;
static uint8_t  enowBuf[UKFE_RF_MAX_FRAME];
static volatile int enowLen = 0;
static uint32_t enowCounter = 0;     // SEPARATES Anti-Replay-Fenster (WiFi)
static uint32_t enowRx = 0, enowOk = 0;
static uint8_t  enowSenderMac[6] = {0};   // MAC des WROOM-Relays (fuer ACK-Rueckweg)
static uint32_t respCounter = 0;          // eigener Counter fuer Antwort-Frames

ICACHE_RAM_ATTR void onDio1() {
    rxFlag = true;
}

// ESP-NOW-Empfang: nur Bytes puffern + Flag setzen (schnell, kein HID/Delay hier).
void onEspNowRecv(const uint8_t* mac, const uint8_t* data, int len) {
    if(enowFlag) return;             // vorheriger Frame noch nicht verarbeitet
    if(len <= 0 || len > (int)UKFE_RF_MAX_FRAME) return;
    memcpy(enowSenderMac, mac, 6);   // Absender fuer den ACK merken
    memcpy(enowBuf, data, len);
    enowLen = len;
    enowFlag = true;
}

// Signierten ACK per ESP-NOW an den Absender (WROOM) zurueck -> Deck sieht das Ergebnis.
void send_espnow_ack(const uint8_t* mac, uint8_t orig_cmd, uint8_t result) {
    UkfeRfMessage m;
    m.cmd = UkfeRfRespAck; m.arg_len = 2;
    m.args[0] = orig_cmd; m.args[1] = result;
    m.counter = ++respCounter;
    uint8_t frame[UKFE_RF_MAX_FRAME];
    size_t n = ukfe_rf_build_frame(UKFE_SECRET, &m, frame, sizeof(frame));
    if(!n) return;
    if(!esp_now_is_peer_exist(mac)) {
        esp_now_peer_info_t p = {};
        memcpy(p.peer_addr, mac, 6);
        p.channel = ESPNOW_CHANNEL; p.encrypt = false;
        esp_now_add_peer(&p);
    }
    esp_now_send(mac, frame, n);
}

void oledMsg(const char* l1, const char* l2 = "", const char* l3 = "") {
    oled.clearBuffer();
    oled.setFont(u8g2_font_6x10_tf);
    oled.drawStr(0, 10, "G4MEOVER UKFE-RX");
    oled.drawStr(0, 26, l1);
    oled.drawStr(0, 40, l2);
    oled.drawStr(0, 54, l3);
    char st[28];
    snprintf(st, sizeof(st), "rx:%lu ok:%lu en:%lu",
             (unsigned long)rxCount, (unsigned long)okCount, (unsigned long)enowOk);
    oled.drawStr(0, 64, st);
    oled.sendBuffer();
}

// ---- HID-Payload-Bibliothek (benannt, erweiterbar). Nur autorisierte Tests. ----
static void win_r(const char* cmd) {  // Ausfuehren-Dialog + Kommando
    Keyboard.press(KEY_LEFT_GUI);
    Keyboard.press('r');
    delay(120);
    Keyboard.releaseAll();
    delay(400);
    Keyboard.println(cmd);
}
static void pl_marker()      { Keyboard.println("G4MEOVER-HID online"); }
static void pl_notepad()     { win_r("notepad"); }
static void pl_powershell()  { win_r("powershell"); }
static void pl_cmd_marker()  { win_r("cmd /k echo G4MEOVER pentest marker"); }
static void pl_lock()        { Keyboard.press(KEY_LEFT_GUI); Keyboard.press('l');
                               delay(80); Keyboard.releaseAll(); }

typedef struct { const char* name; void (*run)(); } HidPayload;
static const HidPayload PAYLOADS[] = {
    {"Marker",     pl_marker},
    {"Notepad",    pl_notepad},
    {"PowerShell", pl_powershell},
    {"CMD Marker", pl_cmd_marker},
    {"Lock",       pl_lock},
};
#define PAYLOAD_COUNT (sizeof(PAYLOADS) / sizeof(PAYLOADS[0]))

// Fuehrt Payload idx aus, liefert den Namen (fuer OLED) zurueck.
static const char* hid_payload(uint8_t idx) {
    delay(300);  // Host-Enumeration abwarten
    if(idx >= PAYLOAD_COUNT) return "?";
    PAYLOADS[idx].run();
    return PAYLOADS[idx].name;
}

void act(const UkfeRfMessage* m) {
    char buf[24];
    // LED-Quittung
    digitalWrite(PIN_LED, HIGH); delay(60); digitalWrite(PIN_LED, LOW);
    switch(m->cmd) {
    case UkfeRfCmdTrigger: {
        uint8_t id = m->arg_len ? m->args[0] : 0;
        const char* pn = hid_payload(id);
        snprintf(buf, sizeof(buf), "id=%u: %s", id, pn);
        oledMsg("CMD: TRIGGER", buf, "-> HID getippt");
        break;
    }
    case UkfeRfCmdPayloadRun: {
        uint8_t idx = m->arg_len ? m->args[0] : 0;
        const char* pn = hid_payload(idx);
        snprintf(buf, sizeof(buf), "idx=%u: %s", idx, pn);
        oledMsg("CMD: PAYLOAD", buf, "-> HID getippt");
        break;
    }
    case UkfeRfCmdWifiScan: {
        oledMsg("CMD: WIFI SCAN", "scanne...");
        uint8_t n = wifi_attack_scan();           // blockierend ~2 s, danach ESP-NOW-Kanal zurueck
        snprintf(buf, sizeof(buf), "%u APs gefunden", n);
        oledMsg("CMD: WIFI SCAN", buf, "-> siehe Serial");
        break;
    }
    case UkfeRfCmdWifiDeauth: {
        // args: uint8 bssid[6], uint8 channel (0=alle/hoppen)
        if(m->arg_len >= 6) {
            uint8_t ch = (m->arg_len >= 7) ? m->args[6] : 0;
            wifi_attack_deauth(m->args, ch, 0);
            snprintf(buf, sizeof(buf), "ch=%u %02X:%02X:%02X..", ch,
                     m->args[0], m->args[1], m->args[2]);
            oledMsg("CMD: WIFI DEAUTH", buf, "laeuft (868=stop)");
        } else {
            oledMsg("CMD: WIFI DEAUTH", "arg fehlt (bssid)");
        }
        break;
    }
    case UkfeRfCmdWifiStop:
        wifi_attack_stop();
        evil_portal_stop();                       // beendet auch ein laufendes Portal
        wifi_recon_stop();                        // beendet auch laufenden Recon-Sniffer
        oledMsg("CMD: WIFI STOP", "Angriff beendet");
        break;
    case UkfeRfCmdBeaconSpam: {
        uint8_t mode = m->arg_len ? m->args[0] : 0;
        wifi_attack_beacon(mode, 0);
        oledMsg("CMD: BEACON SPAM", "laeuft (868=stop)");
        break;
    }
    case UkfeRfCmdEvilPortal: {
        uint8_t pid = m->arg_len ? m->args[0] : 0;
        evil_portal_start(pid, ESPNOW_CHANNEL);   // uebernimmt WiFi; ESP-NOW pausiert, 868 steuert
        snprintf(buf, sizeof(buf), "SSID:%s", evil_portal_ssid());
        oledMsg("CMD: EVIL PORTAL", buf, "868=stop, Logins@Serial");
        break;
    }
    case UkfeRfCmdHandshake: {
        // args: uint8 bssid[6], uint8 channel — EAPOL sniffen + Deauth-Stoesse
        if(m->arg_len >= 7) {
            wifi_recon_handshake(m->args, m->args[6], 0);
            snprintf(buf, sizeof(buf), "ch=%u %02X:%02X:%02X..", m->args[6],
                     m->args[0], m->args[1], m->args[2]);
            oledMsg("CMD: HANDSHAKE", buf, "868=stop, EAPOL@Serial");
        } else {
            oledMsg("CMD: HANDSHAKE", "arg fehlt (bssid+ch)");
        }
        break;
    }
    case UkfeRfCmdWardrive: {
        oledMsg("CMD: WARDRIVE", "scanne...");
        uint8_t n = wifi_recon_wardrive();        // Scan -> WiGLE-CSV ueber Serial
        snprintf(buf, sizeof(buf), "%u APs", n);
        oledMsg("CMD: WARDRIVE", buf, "WiGLE-CSV@Serial");
        break;
    }
    case UkfeRfCmdProbeSniff:
        wifi_recon_probe(0);
        oledMsg("CMD: PROBE SNIFF", "laeuft (868=stop)", "SSID/MAC@Serial");
        break;
    case UkfeRfCmdPacketMon:
        wifi_recon_packetmon(0);
        oledMsg("CMD: PACKET MON", "laeuft (868=stop)", "Stats@Serial");
        break;
    case UkfeRfCmdPwnagotchi:
        wifi_recon_pwnagotchi(0);
        oledMsg("CMD: PWNAGOTCHI", "Detektor laeuft", "868=stop");
        break;
    case UkfeRfCmdKarma:
        // TODO: Probe sniffen + passende Fake-APs beacon-en (Probe->Response-Loop)
        oledMsg("CMD: KARMA", "noch nicht impl.");
        break;
    default:
        snprintf(buf, sizeof(buf), "0x%02X alen=%u", m->cmd, m->arg_len);
        oledMsg("CMD:", buf);
        break;
    }
}

void startRx() {
    // Fester Paketrahmen (Flipper padded auf UKFE_RF_MAX_FRAME) -> deterministisch.
    radio.startReceive();
}

void setup() {
    Serial.begin(115200);
    Keyboard.begin();   // natives USB-HID-Keyboard
    USB.begin();
    pinMode(PIN_LED, OUTPUT);
    pinMode(PIN_VEXT, OUTPUT);
    digitalWrite(PIN_VEXT, LOW);  // OLED-Versorgung an
    delay(50);
    oled.begin();
    oledMsg("Init...");

    loraSpi.begin(PIN_LORA_SCK, PIN_LORA_MISO, PIN_LORA_MOSI, PIN_LORA_NSS);

    // FSK exakt auf die ukfe_rf-Konstanten: 868.35 MHz, 9.6 kbps, 25 kHz Dev.
    int st = radio.beginFSK(
        UKFE_RF_FREQUENCY_HZ / 1e6f,   // MHz
        UKFE_RF_BITRATE / 1000.0f,     // kbps (9.6)
        47.6f,                         // kHz Dev — MUSS zum Flipper-Preset 2FSKDev476 passen
        117.3f,                        // RX-Bandbreite kHz (deckt 2*(Dev+br/2))
        10,                            // TX-Power (fuer spaetere Antworten)
        16);                           // Praeambel-Bits
    radio.setTCXO(1.8);                // Heltec V3: TCXO 1.8 V
    radio.setDio2AsRfSwitch(true);

    uint8_t sync[2] = {(UKFE_RF_SYNC_WORD >> 8) & 0xFF, UKFE_RF_SYNC_WORD & 0xFF};
    radio.setSyncWord(sync, 2);
    radio.fixedPacketLengthMode(UKFE_RF_MAX_FRAME);
    radio.setCRC(0);                   // CRC macht ukfe_rf selbst (CRC16 im Frame)

    if(st != RADIOLIB_ERR_NONE) {
        char e[24]; snprintf(e, sizeof(e), "FSK err %d", st);
        oledMsg("RADIO FEHLER", e);
        while(true) delay(1000);
    }

    radio.setDio1Action(onDio1);
    startRx();

    // ---- ESP-NOW-Empfang initialisieren (WiFi 2.4G, parallel zum 868-RX) ----
    // SX1262 (externes SPI) und WiFi (interner 2.4G-Radio) koexistieren konfliktfrei.
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    esp_wifi_set_channel(ESPNOW_CHANNEL, WIFI_SECOND_CHAN_NONE);
    bool enow_ok = (esp_now_init() == ESP_OK);
    if(enow_ok) {
        esp_now_register_recv_cb(onEspNowRecv);
        // Broadcast-Peer, damit der Hub 868-Frames an ALLE Satelliten weiterfunken kann.
        esp_now_peer_info_t bpeer = {};
        memcpy(bpeer.peer_addr, BROADCAST_MAC, 6);
        bpeer.channel = ESPNOW_CHANNEL; bpeer.encrypt = false;
        esp_now_add_peer(&bpeer);
    } else Serial.println("ESP-NOW init FEHLGESCHLAGEN (868-RX laeuft weiter)");

    // WiFi-Module kennen den ESP-NOW-Kanal, um ihn nach Angriffen/Recon wiederherzustellen.
    wifi_attack_init(ESPNOW_CHANNEL);
    wifi_recon_init(ESPNOW_CHANNEL);

    Serial.printf("\nG4MEOVER UKFE-RX bereit. 868.35MHz-2FSK + ESP-NOW(Kanal %d, %s).\n",
                  ESPNOW_CHANNEL, enow_ok ? "an" : "AUS");
    Serial.printf("STA-MAC %s\n", WiFi.macAddress().c_str());
    oledMsg("Bereit.", "868 2FSK + ESPNOW", "warte auf Frame");
}

void loop() {
    // Laufenden WiFi-Angriff bedienen (nicht-blockierend, ein Burst pro Iteration).
    wifi_attack_tick();
    evil_portal_tick();   // falls Portal aktiv: DNS + HTTP bedienen
    wifi_recon_tick();    // falls Recon aktiv: Kanal-Hop / Deauth-Stoss / Statistik

    // --- ESP-NOW-Frame (WiFi vom WROOM-Relay) zuerst verarbeiten ---
    if(enowFlag) {
        int len = enowLen;
        uint8_t frame[UKFE_RF_MAX_FRAME];
        memcpy(frame, enowBuf, len);
        enowFlag = false;            // Puffer wieder freigeben
        enowRx++;
        size_t real_len = (size_t)frame[0] + 1;
        if(real_len > (size_t)len) real_len = len;
        UkfeRfMessage msg;
        if(ukfe_rf_parse_frame(UKFE_SECRET, frame, real_len, &msg, &enowCounter)) {
            enowOk++;
            Serial.printf("ESPNOW OK cmd=0x%02X counter=%lu\n",
                          msg.cmd, (unsigned long)msg.counter);
            act(&msg);
            send_espnow_ack(enowSenderMac, msg.cmd, 0);   // ACK an den WROOM/Deck zurueck
        } else {
            Serial.println("ESPNOW PARSE FAIL (MAC/CRC/Counter)");
        }
    }

    if(!rxFlag) return;
    rxFlag = false;

    uint8_t frame[UKFE_RF_MAX_FRAME];
    int len = radio.readData(frame, UKFE_RF_MAX_FRAME);
    rxCount++;

    // --- Diagnose: rohe Bytes + RSSI ueber Serial ---
    Serial.printf("RX len=%d rssi=%.1f : ", len, radio.getRSSI());
    for(int i = 0; i < UKFE_RF_MAX_FRAME; i++) Serial.printf("%02X ", frame[i]);
    Serial.println();

    if(len == RADIOLIB_ERR_NONE) {
        UkfeRfMessage msg;
        // Echte Framelaenge steht in frame[0] (LEN); der Rest ist Padding.
        size_t real_len = (size_t)frame[0] + 1;
        if(real_len > UKFE_RF_MAX_FRAME) real_len = UKFE_RF_MAX_FRAME;
        if(ukfe_rf_parse_frame(UKFE_SECRET, frame, real_len, &msg, &lastCounter)) {
            okCount++;
            Serial.printf("PARSE OK cmd=0x%02X counter=%lu\n", msg.cmd, (unsigned long)msg.counter);
            act(&msg);
            // HUB: den vom Flipper per 868 empfangenen Frame per ESP-NOW an ALLE
            // Satelliten weiterfunken (LilyGo/WROOM/S3). Der Heltec = 868->ESP-NOW-Bridge.
            esp_err_t br = esp_now_send(BROADCAST_MAC, frame, real_len);
            Serial.printf("HUB -> ESP-NOW broadcast %s\n", br == ESP_OK ? "OK" : "FAIL");
        } else {
            Serial.println("PARSE FAIL (MAC/CRC/Counter)");
            // Diagnose direkt aufs OLED: erste 8 empfangene Bytes (erwartet: [LEN][47][01]...)
            char h1[24], h2[24];
            snprintf(h1, sizeof(h1), "%02X %02X %02X %02X",
                     frame[0], frame[1], frame[2], frame[3]);
            snprintf(h2, sizeof(h2), "%02X %02X %02X %02X",
                     frame[4], frame[5], frame[6], frame[7]);
            oledMsg(h1, h2, "erwartet: LL 47 01");
        }
    }
    startRx();  // wieder in Empfang gehen
}
