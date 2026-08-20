// G4MEOVER V3 — On-Demand-LoRaWAN (TTN, EU868) auf demselben SX1262 wie ukfe_rf-FSK.
// Auf Kommando (UkfeRfCmdLoraJoin 0x60): SX1262 kurz auf LoRaWAN schalten, OTAA joinen,
// einen Status-Uplink senden, dann FSK-Modus wiederherstellen (ukfe_rf laeuft weiter).
// Gibt dem Flipper-Oekosystem Weitverkehr ueber die LORIX/TTN — Grundlage fuer
// Downlink->ukfe_rf-Aktion (globaler Kommandokanal). Nur autorisierte Nutzung.
#pragma once
#include <stdint.h>

// Joint OTAA + sendet `status` als Uplink (fPort 1). Liefert true bei erfolgreichem Join.
// Stellt danach IMMER den FSK-ukfe_rf-Empfang wieder her.
bool lorawan_join_and_uplink(const char* status);
