# Heltec ukfe_rf Empfänger (USB Army Penetrator)

Firmware für den **Heltec WiFi LoRa 32 V3** (ESP32-S3 + SX1262). Empfängt die `ukfe_rf`-Befehle des Flipper-RF-Console über Funk, verifiziert sie (keyed MAC + CRC16 + Rolling-Counter) und führt Aktionen aus. Die noch fehlende **Satelliten-Ebene** des G4MEOVER-Ökosystems.

## RF-Konfiguration (beide Seiten MÜSSEN übereinstimmen)
| Parameter | Wert |
|---|---|
| Frequenz | 868.35 MHz |
| Modulation | **2-FSK** |
| Bitrate | 9600 bps |
| Deviation | 25 kHz |
| Sync-Wort | 0x4737 („G7") |
| Frame | `[LEN][MAGIC][VER][COUNTER(4)][CMD][ALEN][ARGS..][MAC(4)][CRC16(2)]` |
| Secret (MAC) | 16 Byte, identisch auf beiden Seiten (siehe `main.cpp`) |

## Wichtig: Flipper-Seite muss auf 2-FSK
Der Flipper-Transport (`lora-ukfe/rf/rf_comm.c`) nutzt aktuell **OOK** (`Ook650Async`) mit Manchester-Bitbanging bei ~2 kbps (Platzhalter, passt nicht zu den deklarierten Konstanten). Der SX1262 empfängt rohes OOK nicht zuverlässig. **Umbau (konkret):**
1. Preset `Ook650Async` → **`FuriHalSubGhzPreset2FSKDev476Async`** (47.6 kHz Dev, stock — kein custom Register-Array nötig). SX1262 dann auf `freqDev=47.6` statt 25 setzen.
2. `encode_frame`: statt Manchester **NRZ**-Bits bei fixem Bitperiod (1/9600 ≈ 104 µs) — high=f+dev, low=f−dev via LevelDuration; davor **Präambel** (0xAA…) + **Sync 0x4737**, dann die `UKFE_RF_MAX_FRAME` Frame-Bytes (fixed length).
3. Secret `RF_SECRET` (rf_comm.c) == `UKFE_SECRET` (main.cpp) — **stimmt bereits überein**; Pairing-Bytes vor Produktivnutzung ersetzen.

Das Protokoll (`ukfe_rf.c/.h`) bleibt unverändert — nur die physikalische Schicht ändert sich. Feintuning (Präambellänge, Sync-Erkennung, Bit-Timing) am lebenden Link.

## Pinbelegung (Heltec V3, in `main.cpp`)
SX1262: NSS 8 · DIO1 14 · RST 12 · BUSY 13 · SCK 9 · MISO 11 · MOSI 10
OLED (SSD1306): SDA 17 · SCL 18 · RST 21 · Vext 36 (LOW=an) · LED 35

## Bauen & Flashen
```
pio run                       # bauen
pio run -t upload -e heltec_wifi_lora_32_V3 --upload-port COM26
pio device monitor -p COM26 -b 115200
```

## Befehle (ukfe_rf, in `act()`)
Trigger · PayloadRun · WifiDeauth · EvilPortal · BeaconSpam — v1 quittiert per OLED + LED.
**Stretch:** USB-HID-Payload (ESP32-S3 native USB), WiFi-Angriffe an einen ESP-Satelliten weiterreichen.

## Offene Hardware-Iteration
- Paket-Format-Alignment SX1262 ↔ CC1101 (fixed length, Sync, Präambel) am lebenden Link feintunen.
- Flipper-Seite 2-FSK-Preset (custom CC1101-Register).
- Secret aus einer geteilten Config statt Hardcode.

## USB-HID (Penetrator)
Bei `TRIGGER`/`PAYLOAD` tippt der ESP32-S3 eine HID-Payload ueber **natives USB**.
- Build-Flags: `ARDUINO_USB_MODE=0` (OTG/TinyUSB) + `ARDUINO_USB_CDC_ON_BOOT=0` (Serial->UART0).
- **Verdrahtung:** Die USB-C-Buchse des Heltec haengt am CP210x (COM26, nur Flash/Serial). Fuer HID die **nativen USB-Pins des S3 (GPIO19=D-, GPIO20=D+)** an den Ziel-USB fuehren.
- Payloads in `hid_payload()` (idx aus dem Funkbefehl). Default: benigne Demos (Marker / Win+R->notepad). Eigene autorisierte Payloads dort ergaenzen.
- **Rahmen:** nur eigene Geraete / autorisierte Tests.
