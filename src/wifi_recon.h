// G4MEOVER — WiFi-Recon (ESP32-S3, Promiscuous-Sniffer). Handshake/Probe/PacketMon/
// Pwnagotchi + Wardrive. Nicht-blockierende State-Machine mit Kanal-Hopping; der
// 868-SX1262 bleibt Steuerkanal (ESP-NOW pausiert waehrend des Sniffens).
//
// NUR fuer autorisierte Security-Tests / eigene Hardware / CTF.
#pragma once
#include <stdint.h>

void     wifi_recon_init(uint8_t espnow_channel);

// WPA-Handshake-Capture fuer bssid auf channel: sniff EAPOL + periodische Deauth-Stoesse.
void     wifi_recon_handshake(const uint8_t bssid[6], uint8_t channel, uint32_t dur_ms);
void     wifi_recon_probe(uint32_t dur_ms);        // Probe-Requests -> SSID/Client-MAC
void     wifi_recon_packetmon(uint32_t dur_ms);    // Paketstatistik (mgmt/data/ctrl)
void     wifi_recon_pwnagotchi(uint32_t dur_ms);   // Pwnagotchi-Beacon-Detektor

uint8_t  wifi_recon_wardrive();   // einmaliger Scan -> WiGLE-CSV ueber Serial, gibt AP-Zahl zurueck

void     wifi_recon_stop();
void     wifi_recon_tick();
bool     wifi_recon_busy();
uint32_t wifi_recon_hits();       // je nach Modus: EAPOL / Probes / Pakete / Pwnagotchis
const char* wifi_recon_state_str();
