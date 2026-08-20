#include "lorawan_link.h"

#include <Arduino.h>
#include <RadioLib.h>
#include <stdlib.h>
#include <string.h>

#include "secret.h"

// Aus main.cpp: der gemeinsame SX1262 + der FSK-Restore (ukfe_rf-Empfang wiederherstellen).
extern SX1262 radio;
extern void ukfe_fsk_restore();

// Hex-String -> uint64 (MSB-first, wie DevEUI/JoinEUI notiert).
static uint64_t hex_u64(const char* s) { return strtoull(s, nullptr, 16); }

// Hex-String -> n Bytes.
static void hex_bytes(const char* s, uint8_t* out, size_t n) {
    for (size_t i = 0; i < n; i++) {
        char b[3] = { s[i * 2], s[i * 2 + 1], 0 };
        out[i] = (uint8_t)strtoul(b, nullptr, 16);
    }
}

bool lorawan_join_and_uplink(const char* status) {
    // SX1262 in LoRa-Grundzustand bringen (war zuvor im FSK-Modus fuer ukfe_rf).
    radio.begin();
    radio.setTCXO(1.8);
    radio.setDio2AsRfSwitch(true);
    radio.setRxBoostedGainMode(true);  // hoehere RX-Empfindlichkeit -> faengt den JoinAccept
                                       // (ohne dies: rc=-1116, RX-Fenster leer). Wie heltec-tag.

    static LoRaWANNode node(&radio, &EU868);
    uint8_t appkey[16];
    hex_bytes(LORAWAN_APP_KEY, appkey, 16);
    node.beginOTAA(hex_u64(LORAWAN_JOIN_EUI), hex_u64(LORAWAN_DEV_EUI), appkey, appkey);
    // Duty-Cycle-/Dwell-Sperre aus: sonst blockiert RadioLib nach mehreren Joins den TX
    // (EU868 1%) -> JoinRequest geht gar nicht raus -> -1116/keine TTN-Events. On-demand ok.
    node.setDutyCycle(false);
    node.setDwellTime(false);

    Serial.printf("[LORAWAN] OTAA join devEUI=%s ...\n", LORAWAN_DEV_EUI);
    int rc = node.activateOTAA(0);
    bool joined = (rc == RADIOLIB_LORAWAN_NEW_SESSION ||
                   rc == RADIOLIB_LORAWAN_SESSION_RESTORED ||
                   rc == RADIOLIB_ERR_NONE);
    Serial.printf("[LORAWAN] join rc=%d joined=%d\n", rc, joined ? 1 : 0);

    if (joined) {
        // Status-Uplink (fPort 1). Downlink -> ukfe_rf-Aktion folgt (TODO: Kommandokanal).
        int up = node.sendReceive((uint8_t*)status, strlen(status), 1);
        Serial.printf("[LORAWAN] uplink rc=%d payload='%s'\n", up, status);
    }

    // WICHTIG: SX1262 zurueck in den FSK-Modus, damit ukfe_rf weiterlaeuft.
    ukfe_fsk_restore();
    return joined;
}
