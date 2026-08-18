// G4MEOVER — BLE-Angriffsmodul (ESP32-S3, NimBLE). Advertising-Spam + Scan.
// Spam: gefaelschte Pairing-/Proximity-Advertisements (Apple/Windows/Android) mit
// pro Paket wechselnder Zufalls-MAC. Nicht-blockierend: ble_spam_tick() rotiert.
//
// NUR fuer autorisierte Security-Tests / eigene Hardware / CTF.
#pragma once
#include <stdint.h>

// mode: 0=alle rotierend, 1=Apple, 2=Windows(SwiftPair), 3=Android(FastPair)
void    ble_spam_start(uint8_t mode);
void    ble_spam_stop();
void    ble_spam_tick();            // in loop() aufrufen (sendet naechstes Advertisement)
bool    ble_spam_active();

// Einmaliger aktiver BLE-Scan (blockierend dur_ms). Gibt Anzahl gefundener Geraete zurueck.
uint8_t ble_scan(uint32_t dur_ms);
