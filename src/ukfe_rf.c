// G4MEOVER RF Console — Protokoll-Logik (plattformunabhaengig, ohne HW-Abhaengigkeit)
#include "ukfe_rf.h"
#include <string.h>

// ---- CRC16-CCITT (0x1021, init 0xFFFF) ----
uint16_t ukfe_rf_crc16(const uint8_t* buf, size_t len) {
    uint16_t crc = 0xFFFF;
    for(size_t i = 0; i < len; i++) {
        crc ^= (uint16_t)buf[i] << 8;
        for(int b = 0; b < 8; b++)
            crc = (crc & 0x8000) ? (uint16_t)((crc << 1) ^ 0x1021) : (uint16_t)(crc << 1);
    }
    return crc;
}

// ---- Lightweight keyed MAC (secret-gesandwichter 32-bit Mixer, 4 B trunc) ----
// Bewusst self-contained (kompiliert auf Flipper UND Heltec ohne Krypto-Lib).
// Fuer hoehere Sicherheit spaeter HMAC-SHA256 (mbedtls im Flipper-SDK verfuegbar).
static uint32_t mix32(uint32_t h, const uint8_t* d, size_t n) {
    for(size_t i = 0; i < n; i++) {
        h ^= d[i];
        h *= 0x01000193u;          // FNV-Prime
        h ^= h >> 15;
        h *= 0x2545F491u;
    }
    return h;
}

void ukfe_rf_mac(const uint8_t secret[UKFE_RF_SECRET_LEN],
                 const UkfeRfMessage* msg, uint8_t out_mac[4]) {
    uint8_t hdr[6];
    hdr[0] = UKFE_RF_VERSION;
    hdr[1] = (uint8_t)(msg->counter & 0xFF);
    hdr[2] = (uint8_t)((msg->counter >> 8) & 0xFF);
    hdr[3] = (uint8_t)((msg->counter >> 16) & 0xFF);
    hdr[4] = (uint8_t)((msg->counter >> 24) & 0xFF);
    hdr[5] = msg->cmd;
    uint32_t h = 0x811C9DC5u;                  // FNV-offset
    h = mix32(h, secret, UKFE_RF_SECRET_LEN);  // key vorne
    h = mix32(h, hdr, sizeof(hdr));
    h = mix32(h, &msg->arg_len, 1);
    h = mix32(h, msg->args, msg->arg_len);
    h = mix32(h, secret, UKFE_RF_SECRET_LEN);  // key hinten (Sandwich)
    out_mac[0] = (uint8_t)(h & 0xFF);
    out_mac[1] = (uint8_t)((h >> 8) & 0xFF);
    out_mac[2] = (uint8_t)((h >> 16) & 0xFF);
    out_mac[3] = (uint8_t)((h >> 24) & 0xFF);
}

// ---- Build ----
size_t ukfe_rf_build_frame(const uint8_t secret[UKFE_RF_SECRET_LEN],
                           const UkfeRfMessage* msg, uint8_t* out, size_t out_cap) {
    if(!secret || !msg || !out || msg->arg_len > UKFE_RF_MAX_ARGS) return 0;
    size_t body = 1 + 1 + 4 + 1 + 1 + msg->arg_len + 4; // MAGIC..MAC
    size_t total = 1 + body + 2;                        // LEN + body + CRC
    if(out_cap < total) return 0;

    uint8_t mac[4];
    ukfe_rf_mac(secret, msg, mac);

    size_t p = 0;
    out[p++] = (uint8_t)(body + 2);        // LEN = alles nach LEN (body + CRC)
    out[p++] = UKFE_RF_MAGIC;
    out[p++] = UKFE_RF_VERSION;
    out[p++] = (uint8_t)(msg->counter & 0xFF);
    out[p++] = (uint8_t)((msg->counter >> 8) & 0xFF);
    out[p++] = (uint8_t)((msg->counter >> 16) & 0xFF);
    out[p++] = (uint8_t)((msg->counter >> 24) & 0xFF);
    out[p++] = msg->cmd;
    out[p++] = msg->arg_len;
    memcpy(&out[p], msg->args, msg->arg_len); p += msg->arg_len;
    memcpy(&out[p], mac, 4); p += 4;
    uint16_t crc = ukfe_rf_crc16(out, p);  // LEN..MAC
    out[p++] = (uint8_t)(crc & 0xFF);
    out[p++] = (uint8_t)((crc >> 8) & 0xFF);
    return p;
}

// ---- Parse + verify ----
bool ukfe_rf_parse_frame(const uint8_t secret[UKFE_RF_SECRET_LEN],
                         const uint8_t* in, size_t in_len,
                         UkfeRfMessage* out_msg, uint32_t* last_counter) {
    if(!secret || !in || !out_msg || in_len < UKFE_RF_HDR_OVERHEAD) return false;
    uint8_t len = in[0];
    if((size_t)len + 1 != in_len) return false;
    if(in[1] != UKFE_RF_MAGIC || in[2] != UKFE_RF_VERSION) return false;
    uint8_t alen = in[8];
    if(alen > UKFE_RF_MAX_ARGS) return false;
    size_t expect = 1 + (1 + 1 + 4 + 1 + 1 + alen + 4 + 2);
    if(in_len != expect) return false;

    size_t mac_off = 9 + alen;
    size_t crc_off = mac_off + 4;
    uint16_t crc_calc = ukfe_rf_crc16(in, crc_off);       // LEN..MAC
    uint16_t crc_recv = (uint16_t)(in[crc_off] | ((uint16_t)in[crc_off + 1] << 8));
    if(crc_calc != crc_recv) return false;

    UkfeRfMessage m;
    m.counter = (uint32_t)in[3] | ((uint32_t)in[4] << 8) |
                ((uint32_t)in[5] << 16) | ((uint32_t)in[6] << 24);
    m.cmd = in[7];
    m.arg_len = alen;
    memcpy(m.args, &in[9], alen);

    uint8_t mac_calc[4];
    ukfe_rf_mac(secret, &m, mac_calc);
    if(memcmp(mac_calc, &in[mac_off], 4) != 0) return false;  // Fälschung

    if(last_counter) {                                        // Anti-Replay
        if(m.counter <= *last_counter) return false;          // verbraucht/replay
        *last_counter = m.counter;
    }
    *out_msg = m;
    return true;
}

// ---- Bequeme Builder ----
static void put_u32(uint8_t* d, uint32_t v) {
    d[0] = (uint8_t)(v & 0xFF); d[1] = (uint8_t)((v >> 8) & 0xFF);
    d[2] = (uint8_t)((v >> 16) & 0xFF); d[3] = (uint8_t)((v >> 24) & 0xFF);
}
void ukfe_rf_make_simple(UkfeRfMessage* m, UkfeRfCmd cmd) {
    m->cmd = (uint8_t)cmd; m->arg_len = 0;
}
void ukfe_rf_make_trigger(UkfeRfMessage* m, uint8_t id, uint32_t delay_ms) {
    m->cmd = UkfeRfCmdTrigger; m->arg_len = 5; m->args[0] = id; put_u32(&m->args[1], delay_ms);
}
void ukfe_rf_make_lora_scan(UkfeRfMessage* m, uint32_t start_khz, uint32_t end_khz, uint16_t dwell_ms) {
    m->cmd = UkfeRfCmdLoraScan; m->arg_len = 10;
    put_u32(&m->args[0], start_khz); put_u32(&m->args[4], end_khz);
    m->args[8] = (uint8_t)(dwell_ms & 0xFF); m->args[9] = (uint8_t)((dwell_ms >> 8) & 0xFF);
}
void ukfe_rf_make_wifi_deauth(UkfeRfMessage* m, const uint8_t bssid[6], uint8_t channel) {
    m->cmd = UkfeRfCmdWifiDeauth; m->arg_len = 7; memcpy(m->args, bssid, 6); m->args[6] = channel;
}
