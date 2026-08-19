// G4MEOVER — DuckyScript-Interpreter (Untermenge) fuer USB-HID (BadUSB).
// Wiederverwendbar (V3/LilyGo/V4). ducky_run(Keyboard, script) tippt das Skript.
// NUR fuer autorisierte Security-Tests / eigene Hardware / CTF.
#pragma once
#include <Arduino.h>
#include <USBHIDKeyboard.h>

// Tastenname -> HID-Keycode (USBHIDKeyboard KEY_*). 0 = unbekannt.
static uint8_t ducky_keyname(const String& k) {
    String u = k; u.toUpperCase();
    if(u == "ENTER" || u == "RETURN")     return KEY_RETURN;
    if(u == "TAB")                        return KEY_TAB;
    if(u == "SPACE")                      return ' ';
    if(u == "ESC" || u == "ESCAPE")       return KEY_ESC;
    if(u == "BACKSPACE")                  return KEY_BACKSPACE;
    if(u == "DELETE" || u == "DEL")       return KEY_DELETE;
    if(u == "INSERT")                     return KEY_INSERT;
    if(u == "HOME")                       return KEY_HOME;
    if(u == "END")                        return KEY_END;
    if(u == "PAGEUP" || u == "PAGE_UP")   return KEY_PAGE_UP;
    if(u == "PAGEDOWN" || u == "PAGE_DOWN") return KEY_PAGE_DOWN;
    if(u == "UP" || u == "UPARROW")       return KEY_UP_ARROW;
    if(u == "DOWN" || u == "DOWNARROW")   return KEY_DOWN_ARROW;
    if(u == "LEFT" || u == "LEFTARROW")   return KEY_LEFT_ARROW;
    if(u == "RIGHT" || u == "RIGHTARROW") return KEY_RIGHT_ARROW;
    if(u == "CAPSLOCK")                   return KEY_CAPS_LOCK;
    if(u.length() >= 2 && u[0] == 'F') {  // F1..F12
        int n = u.substring(1).toInt();
        if(n >= 1 && n <= 12) return KEY_F1 + (n - 1);
    }
    if(u.length() == 1) return (uint8_t)tolower((int)u[0]);  // Einzelzeichen
    return 0;
}

// Modifier-Name -> Keycode. 0 = kein Modifier.
static uint8_t ducky_modkey(const String& t) {
    String u = t; u.toUpperCase();
    if(u == "GUI" || u == "WINDOWS" || u == "WIN" || u == "COMMAND") return KEY_LEFT_GUI;
    if(u == "CTRL" || u == "CONTROL") return KEY_LEFT_CTRL;
    if(u == "ALT")   return KEY_LEFT_ALT;
    if(u == "SHIFT") return KEY_LEFT_SHIFT;
    return 0;
}

// Presst alle Bindestrich-getrennten Modifier eines Tokens (z.B. "CTRL-ALT"). true wenn Modifier.
static bool ducky_press_mods(USBHIDKeyboard& kb, const String& tok) {
    String first = tok; int h = tok.indexOf('-'); if(h >= 0) first = tok.substring(0, h);
    if(!ducky_modkey(first)) return false;
    String c = tok;
    while(c.length()) {
        int i = c.indexOf('-'); String part = (i < 0) ? c : c.substring(0, i);
        c = (i < 0) ? String("") : c.substring(i + 1);
        uint8_t m = ducky_modkey(part);
        if(m) kb.press(m);
        else { uint8_t k = ducky_keyname(part); if(k) kb.press(k); }
    }
    return true;
}

// Fuehrt ein (mehrzeiliges) DuckyScript aus.
static void ducky_run(USBHIDKeyboard& kb, const char* script) {
    uint32_t defDelay = 0;
    const char* p = script;
    char line[220];
    while(*p) {
        int li = 0;
        while(*p && *p != '\n' && li < (int)sizeof(line) - 1) { if(*p != '\r') line[li++] = *p; p++; }
        if(*p == '\n') p++;
        line[li] = 0;
        char* s = line; while(*s == ' ' || *s == '\t') s++;
        if(!*s) continue;

        char* sp = strchr(s, ' ');
        String cmd  = sp ? String(s).substring(0, (int)(sp - s)) : String(s);
        String rest = sp ? String(sp + 1) : String("");
        String C = cmd; C.toUpperCase();

        if(C == "REM") { /* Kommentar */ }
        else if(C == "DELAY")            { delay((uint32_t)rest.toInt()); }
        else if(C == "DEFAULT_DELAY" || C == "DEFAULTDELAY") { defDelay = (uint32_t)rest.toInt(); }
        else if(C == "STRING")           { kb.print(rest); }
        else if(C == "STRINGLN")         { kb.print(rest); kb.write(KEY_RETURN); }
        else if(C == "REPEAT")           { /* optional: hier ignoriert */ }
        else if(ducky_press_mods(kb, cmd)) {          // Modifier-Kombo (evtl. + Tasten in rest)
            String r = rest;
            while(r.length()) {
                int i = r.indexOf(' '); String tok = (i < 0) ? r : r.substring(0, i);
                r = (i < 0) ? String("") : r.substring(i + 1);
                if(!ducky_press_mods(kb, tok)) { uint8_t k = ducky_keyname(tok); if(k) kb.press(k); }
            }
            delay(20); kb.releaseAll();
        }
        else {                                        // benannte Einzeltaste
            uint8_t k = ducky_keyname(cmd);
            if(k) kb.write(k);
        }
        if(defDelay) delay(defDelay);
    }
}
