// G4MEOVER RF Console — 868-FSK Command Protocol v1
// Gemeinsamer Header: Flipper (CC1101) <-> Heltec LoRa v3 (SX1262)
#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// ---- Physical Layer ----
#define UKFE_RF_FREQUENCY_HZ   868350000u
#define UKFE_RF_BITRATE        9600u
#define UKFE_RF_DEVIATION_HZ   25000u
#define UKFE_RF_SYNC_WORD      0x4737u   // "G7"
#define UKFE_RF_MAGIC          0x47u     // 'G'
#define UKFE_RF_VERSION        0x01u
#define UKFE_RF_MAX_ARGS       40u
#define UKFE_RF_SECRET_LEN     16u

// ---- Commands (Flipper -> Heltec) ----
typedef enum {
    UkfeRfCmdStatus      = 0x01,
    UkfeRfCmdTrigger     = 0x02,  // args: uint8 id, uint32 delay_ms (LE)
    UkfeRfCmdAbort       = 0x03,
    UkfeRfCmdPayloadList = 0x04,
    UkfeRfCmdPayloadRun  = 0x05,  // args: uint8 idx
    UkfeRfCmdLoraScan    = 0x10,  // args: uint32 start_khz, uint32 end_khz, uint16 dwell_ms
    UkfeRfCmdWifiScan    = 0x20,
    UkfeRfCmdWifiDeauth  = 0x21,  // args: uint8 bssid[6], uint8 channel
    UkfeRfCmdWifiStop    = 0x22,
    UkfeRfCmdEvilPortal  = 0x23,  // args: uint8 portal_id
    UkfeRfCmdBeaconSpam  = 0x24,  // args: uint8 mode
} UkfeRfCmd;

// ---- Responses (Heltec -> Flipper), Bit7 gesetzt ----
typedef enum {
    UkfeRfRespAck        = 0x80,  // args: uint8 orig_cmd, uint8 result(0=ok)
    UkfeRfRespStatus     = 0x81,  // args: uint8 mode, busy, batt, rssi
    UkfeRfRespPayload    = 0x84,  // args: uint8 idx, char name[]
    UkfeRfRespScanHit    = 0x90,  // args: uint32 freq_or_ch, uint8 rssi
} UkfeRfResp;

// ---- Frame (nach Sync-Word). Feldreihenfolge = Wire-Format. ----
// [LEN][MAGIC][VER][COUNTER(4 LE)][CMD][ALEN][ARGS..][MAC(4)][CRC16(2)]
#define UKFE_RF_HDR_OVERHEAD  (1+1+1+4+1+1+4+2)  // ohne ARGS
#define UKFE_RF_MAX_FRAME     (UKFE_RF_HDR_OVERHEAD + UKFE_RF_MAX_ARGS)

typedef struct {
    uint32_t counter;                 // Rolling-Counter (Anti-Replay)
    uint8_t  cmd;                     // UkfeRfCmd / UkfeRfResp
    uint8_t  arg_len;                 // 0..UKFE_RF_MAX_ARGS
    uint8_t  args[UKFE_RF_MAX_ARGS];
} UkfeRfMessage;

// ---- API (in ukfe_rf.c auf beiden Seiten identisch implementieren) ----

// CRC16-CCITT ueber buf[0..len-1]
uint16_t ukfe_rf_crc16(const uint8_t* buf, size_t len);

// 4-Byte truncated keyed MAC ueber VER|COUNTER|CMD|ALEN|ARGS
void ukfe_rf_mac(const uint8_t secret[UKFE_RF_SECRET_LEN],
                 const UkfeRfMessage* msg, uint8_t out_mac[4]);

// Baut Wire-Frame in out (>= UKFE_RF_MAX_FRAME). Gibt Gesamtlaenge zurueck (0=Fehler).
size_t ukfe_rf_build_frame(const uint8_t secret[UKFE_RF_SECRET_LEN],
                           const UkfeRfMessage* msg,
                           uint8_t* out, size_t out_cap);

// Parst + verifiziert (MAC, CRC). last_counter: Anti-Replay-Fenster (wird bei Erfolg aktualisiert).
// Rueckgabe: true wenn gueltig UND counter akzeptiert. NULL fuer last_counter = ohne Replay-Check (Flipper-RX).
bool ukfe_rf_parse_frame(const uint8_t secret[UKFE_RF_SECRET_LEN],
                         const uint8_t* in, size_t in_len,
                         UkfeRfMessage* out_msg, uint32_t* last_counter);

// Bequeme Builder fuer haeufige Befehle (fuellen msg->cmd/args/arg_len)
void ukfe_rf_make_trigger(UkfeRfMessage* m, uint8_t id, uint32_t delay_ms);
void ukfe_rf_make_lora_scan(UkfeRfMessage* m, uint32_t start_khz, uint32_t end_khz, uint16_t dwell_ms);
void ukfe_rf_make_wifi_deauth(UkfeRfMessage* m, const uint8_t bssid[6], uint8_t channel);
void ukfe_rf_make_simple(UkfeRfMessage* m, UkfeRfCmd cmd);
