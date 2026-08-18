// G4MEOVER — WiFi-Angriffsmodul (ESP32-S3, natives esp_wifi Raw-802.11)
// Nicht-blockierende State-Machine: pro loop()-Tick ein Frame-Burst, damit die
// 868-FSK-Steuerung und ESP-NOW zwischen den Bursts jederzeit responsiv bleiben.
//
// NUR fuer autorisierte Security-Tests / eigene Hardware / CTF.
#pragma once
#include <stdint.h>

// espnow_channel: der Kanal, auf dem ESP-NOW-Befehle empfangen werden — wird nach
// jedem Angriff wiederhergestellt (Angriffe koennen den Kanal wechseln/hoppen).
void        wifi_attack_init(uint8_t espnow_channel);

// Einmaliger AP-Scan (blockierend ~2 s). Ergebnis via wifi_attack_last_scan_count().
uint8_t     wifi_attack_scan();
uint8_t     wifi_attack_last_scan_count();

// Deauth: broadcast-Deauth gegen die Clients von bssid. channel 0 => Kanal-Hopping 1..13.
// Laeuft bis wifi_attack_stop() oder dur_ms (0 => Default-Timeout).
void        wifi_attack_deauth(const uint8_t bssid[6], uint8_t channel, uint32_t dur_ms);

// Beacon-Spam: gefaelschte APs. mode 0=Themen-Liste, 1=Zufallsnamen. Kanal-Hopping.
void        wifi_attack_beacon(uint8_t mode, uint32_t dur_ms);

// Laufenden Angriff stoppen + ESP-NOW-Kanal wiederherstellen.
void        wifi_attack_stop();

// In jeder loop()-Iteration aufrufen (sendet den naechsten Burst, prueft Timeout).
void        wifi_attack_tick();

bool        wifi_attack_busy();
const char* wifi_attack_state_str();
