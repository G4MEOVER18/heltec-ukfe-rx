// G4MEOVER Heltec ukfe_rf Empfaenger (USB Army Penetrator)
// Heltec WiFi LoRa 32 V3 (ESP32-S3 + SX1262). Empfaengt 868.35-MHz-2FSK-Frames
// vom Flipper-RF-Console, verifiziert (MAC+CRC+Rolling-Counter) und fuehrt Befehle aus.
#include <Arduino.h>
#include <RadioLib.h>
#include <U8g2lib.h>
#include <SPI.h>

extern "C" {
#include "ukfe_rf.h"
}

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
static uint32_t lastCounter = 0;     // Anti-Replay-Fenster
static uint32_t rxCount = 0, okCount = 0;

ICACHE_RAM_ATTR void onDio1() {
    rxFlag = true;
}

void oledMsg(const char* l1, const char* l2 = "", const char* l3 = "") {
    oled.clearBuffer();
    oled.setFont(u8g2_font_6x10_tf);
    oled.drawStr(0, 10, "G4MEOVER UKFE-RX");
    oled.drawStr(0, 26, l1);
    oled.drawStr(0, 40, l2);
    oled.drawStr(0, 54, l3);
    char st[24];
    snprintf(st, sizeof(st), "rx:%lu ok:%lu", (unsigned long)rxCount, (unsigned long)okCount);
    oled.drawStr(0, 64, st);
    oled.sendBuffer();
}

void act(const UkfeRfMessage* m) {
    char buf[24];
    // LED-Quittung
    digitalWrite(PIN_LED, HIGH); delay(60); digitalWrite(PIN_LED, LOW);
    switch(m->cmd) {
    case UkfeRfCmdTrigger:
        snprintf(buf, sizeof(buf), "id=%u", m->arg_len ? m->args[0] : 0);
        oledMsg("CMD: TRIGGER", buf);
        // TODO(HW): GPIO/USB-HID-Payload ausloesen
        break;
    case UkfeRfCmdPayloadRun:
        snprintf(buf, sizeof(buf), "idx=%u", m->arg_len ? m->args[0] : 0);
        oledMsg("CMD: PAYLOAD", buf);
        break;
    case UkfeRfCmdWifiDeauth:
        oledMsg("CMD: WIFI DEAUTH");
        // TODO(HW): an ESP32-WiFi-Satellit weiterreichen
        break;
    case UkfeRfCmdEvilPortal:
        oledMsg("CMD: EVIL PORTAL");
        break;
    case UkfeRfCmdBeaconSpam:
        oledMsg("CMD: BEACON SPAM");
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
    oledMsg("Bereit.", "868.35 MHz 2FSK", "warte auf Frame");
}

void loop() {
    if(!rxFlag) return;
    rxFlag = false;

    uint8_t frame[UKFE_RF_MAX_FRAME];
    int len = radio.readData(frame, UKFE_RF_MAX_FRAME);
    rxCount++;

    if(len == RADIOLIB_ERR_NONE) {
        UkfeRfMessage msg;
        if(ukfe_rf_parse_frame(UKFE_SECRET, frame, UKFE_RF_MAX_FRAME, &msg, &lastCounter)) {
            okCount++;
            act(&msg);
        } else {
            oledMsg("Frame verworfen", "(MAC/CRC/Replay)");
        }
    }
    startRx();  // wieder in Empfang gehen
}
