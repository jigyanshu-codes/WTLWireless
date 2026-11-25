// <wtl> project: wtlwireless | file: src/core/MtkScan.cpp | author: watchthelight </wtl>
// SPDX-License-Identifier: ISC AND BSD-3-Clause-Clear
// W4: firmware commands after the firmware runs (hwInit), then firmware scans, listed as Mtk* properties.
// Command layouts are ported from Linux mt76 v6.18 (Copyright (C) 2023 MediaTek Inc., ISC):
//   mt7925/mcu.c fill_message (UNI txd), get_nic_capability, set_eeprom, set_channel_domain, hw_scan;
//   mt76_connac_mcu.c uni_add_dev; mt7925/init.c mac_init (MDP RX length, de-AMSDU); mt7925/mac.c fill_rx
//   (RXD group layout, P-RXV RCPI).
// The minimal post-firmware sequence (NIC capability, DEV_INFO, BSS_INFO, domain, scan, skipping the
// rest of init_hardware) and the beacon locator fallback in mtkParseFrame follow itlmt7925
// (github.com/thanhnndev/ga403wm-hackintosh, kexts/itlmt7925/itlmt7925_m2.cpp and _m3.cpp,
// Copyright (c) 2026 thanhnndev and contributors, BSD-3-Clause-Clear). Its values were checked against
// Linux. Where they differ we follow Linux: EFUSE format WHOLE (1), MAX_RX_LEN shifted into bits 15:3.
// The scan includes the DFS channels 52-144, marked passive (NO_IR | RADAR).
// 0.9.0 (W1): the one-shot scanStage became hwInit (hardware ready) plus a scan machine driven from the tick
// (scanStart / scanService) that fills a BSS cache (bssNote) with each network's security from its RSN or WPA
// element (mtk_rsn_parse in MtkSupp.c). The connection manager in MtkJoin.cpp picks from that cache.

#include "WTLWireless.hpp"

namespace {
constexpr uint32_t MCU_UNI_TXD_LEN = 48;   // struct mt76_connac2_mcu_uni_txd
constexpr uint8_t UNI_DEV_INFO_UPDATE = 0x01, UNI_BSS_INFO_UPDATE = 0x02, UNI_CHIP_CONFIG = 0x0e,
                  UNI_SET_DOMAIN_INFO = 0x15, UNI_SCAN_REQ = 0x16, UNI_SET_DBDC_PARMS = 0x28, UNI_EFUSE_CTRL = 0x2d;
constexpr uint8_t MCU_CMD_ACK = 1u << 0, MCU_CMD_UNI = 1u << 1, MCU_CMD_SET = 1u << 2;
constexpr uint8_t EVENT_SCAN_DONE = 0x0e;      // MCU_UNI_EVENT_SCAN_DONE (connac3)
constexpr uint8_t EVENT_CONNAC2_SCAN_DONE = 0x0d; // MCU_EVENT_SCAN_DONE (connac2)
constexpr uint8_t MCU_CE_CMD_START_HW_SCAN = 0x03, MCU_CE_CMD_SET_CHAN_DOMAIN = 0x0f;

struct MtkConnac2ScanSsid {
    uint32_t ssid_len;
    uint8_t ssid[32];
} __attribute__((packed));

struct MtkConnac2ScanChannel {
    uint8_t band;
    uint8_t channel_num;
} __attribute__((packed));

struct MtkConnac2ScanReq {
    uint8_t seq_num;
    uint8_t bss_idx;
    uint8_t scan_type;        // 0: passive, 1: active
    uint8_t ssid_type;        // BIT(0) wildcard SSID
    uint8_t ssids_num;
    uint8_t probe_req_num;    // 2
    uint8_t scan_func;        // BIT(5) SCAN_FUNC_SPLIT_SCAN
    uint8_t version;          // 1
    MtkConnac2ScanSsid ssids[4];
    uint16_t probe_delay_time;
    uint16_t channel_dwell_time;
    uint16_t timeout_value;
    uint8_t channel_type;     // 4: specified channels
    uint8_t channels_num;     // valid when channel_type is 4
    MtkConnac2ScanChannel channels[32];
    uint16_t ies_len;
    uint8_t ies[600];
    uint8_t ext_channels_num;
    uint8_t ext_ssids_num;
    uint16_t channel_min_dwell_time;
    MtkConnac2ScanChannel ext_channels[32];
    MtkConnac2ScanSsid ext_ssids[6];
    uint8_t bssid[6];
    uint8_t random_mac[6];
    uint8_t pad[63];
    uint8_t ssid_type_ext;
} __attribute__((packed));
static_assert(sizeof(MtkConnac2ScanReq) == 1186, "MtkConnac2ScanReq must be 1186 bytes");
inline uint32_t mdpDcr0(const MtkChip *c) { return ((c && c->id == 0x7902) ? 0x820cd000 : 0x820cc800) + 0x000; }
inline uint32_t mdpDcr1(const MtkChip *c) { return ((c && c->id == 0x7902) ? 0x820cd000 : 0x820cc800) + 0x004; }
constexpr uint8_t UNI_BAND_CONFIG = 0x08;
// mt792x_regs.h, per band
inline uint32_t tmacCtcr0(int b) { return (b ? 0x820f4000 : 0x820e4000) + 0x0f4; }
inline uint32_t mibScr1(int b) { return (b ? 0x820fd000 : 0x820ed000) + 0x004; }
inline uint32_t dmaDcr0(int b) { return b ? 0x820f7000 : 0x820e7000; }
inline uint32_t wtbloffRscr(int b) { return (b ? 0x820f9000 : 0x820e9000) + 0x008; }
constexpr uint32_t CHAN_NO_IR = 1u << 1, CHAN_RADAR = 1u << 3;   // cfg80211 ieee80211_channel_flags
constexpr uint32_t SCAN_SETTLE_TICKS = 500, SCAN_TIMEOUT_TICKS = 20000, BSS_AGE_TICKS = 60000;
constexpr int UNICMD_DEAD_AFTER = 3;           // consecutive command timeouts before the firmware counts as dead

inline uint32_t le32(const uint8_t *p) { return (uint32_t)p[3] << 24 | (uint32_t)p[2] << 16 | (uint32_t)p[1] << 8 | p[0]; }
inline uint16_t le16(const uint8_t *p) { return (uint16_t)(p[1] << 8 | p[0]); }
inline void put16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
inline void put32(uint8_t *p, uint32_t v) { for (int i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (8 * i)); }

const uint8_t kCh2[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 };
const uint8_t kCh5[] = { 36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
                         149, 153, 157, 161, 165 };
inline bool isDfs(uint8_t ch) { return ch >= 52 && ch <= 144; }
// FCC countries keep the US set. Elsewhere the core adds 12-13 and makes 149-165 passive: listening is legal
// everywhere, and an AP heard there lets the firmware transmit (mt76 beacon hint), so no table can make it louder.
const uint8_t kCh2Extra[] = { 12, 13 };
bool fccCountry(const char *cc) {
    static const char *const fcc[] = { "US", "CA", "PR", "GU", "VI", "AS", "MP", "UM" };
    for (const char *f : fcc) if (cc[0] == f[0] && cc[1] == f[1]) return true;
    return false;
}

// mt7925_queue_rx_skb (mt7925/mac.c): RXD0 PKT_TYPE bits 31:27, PKT_FLAG bits 19:16, SW_PKT_TYPE bits 31:16.
// A frame is PKT_TYPE_NORMAL (2), or SW_PKT_TYPE FRAME (0x3801 under mask 0x380F), or RX_EVENT (7) with
// PKT_FLAG 1 (PKT_TYPE_NORMAL_MCU). a test boot showed scan results arrive on the MCU ring as the latter.
enum RxKind { RX_FRAME, RX_EVENT, RX_TXFREE, RX_TXS, RX_OTHER };
inline RxKind rxKind(const uint8_t *p, uint32_t len) {
    if (len < 4) return RX_OTHER;
    uint32_t w = le32(p), type = w >> 27, flag = (w >> 16) & 0xf, sw = (w >> 16) & 0xffff;
    if (type != 2 && (sw & 0x380f) == 0x3801) type = 2;
    if (type == 7 && flag == 1) type = 8;
    if (type == 2 || type == 8) return RX_FRAME;
    if (type == 6) return RX_TXFREE;               // PKT_TYPE_TXRX_NOTIFY
    if (type == 0) return RX_TXS;                  // PKT_TYPE_TXS
    return type == 7 ? RX_EVENT : RX_OTHER;
}

// A beacon (FC 0x80, broadcast DA) or probe response (0x50) with TA == BSSID (unicast) at offset o of the RX buffer
inline bool isBeaconAt(const uint8_t *p, uint32_t len, uint32_t o) {
    if (o + 38 > len) return false;
    uint8_t fc = p[o];
    if ((fc != 0x80 && fc != 0x50) || (p[o + 1] & 0x03) != 0) return false;
    if (memcmp(p + o + 10, p + o + 16, 6) != 0 || (p[o + 10] & 1)) return false;
    if (fc == 0x80 && (p[o + 4] & p[o + 5] & p[o + 6] & p[o + 7] & p[o + 8] & p[o + 9]) != 0xff) return false;
    return true;
}
} // namespace

// UNI command (mt7925_mcu_fill_message, __MCU_CMD_FIELD_UNI branch) on TX ring 15; waits for the reply
// with the same sequence number on RX ring 0 and copies it to ev (up to evMax bytes). It drains both RX rings
// while waiting, so it must never run from inside dispatchRx (the slot being dispatched would be dispatched
// again): that case returns -13 and is counted. After UNICMD_DEAD_AFTER timeouts in a row the firmware counts
// as dead and every later command returns -14 at once, so the tick does not sleep 3 s per command forever.
int WTLWireless::uniCmd(uint8_t cid, const void *payload, uint32_t plen, bool query, uint8_t *ev, uint32_t evMax, uint32_t *evLen) {
    static uint8_t msg[2048];
    if (evLen) *evLen = 0;
    if (inDispatch) { uniCmdInDispatch++; return -13; }
    if (fwDead) { uniCmdFails++; return -14; }
    if (MCU_UNI_TXD_LEN + plen > sizeof(msg)) return -10;
    bzero(msg, MCU_UNI_TXD_LEN);
    uint8_t seq = nextSeq();
    uint32_t total = MCU_UNI_TXD_LEN + plen;
    put32(msg + 0, (total & 0xffff) | (2u << 23) | (0x20u << 25));   // TX_BYTES, PKT_FMT CMD, Q_IDX MCU_PORT_RX_Q0
    uint32_t txd1 = chip ? chip->txdHdrFormat : (1u << 14);
    put32(msg + 4, txd1);                                             // HDR_FORMAT CMD
    put16(msg + 32, (uint16_t)(total - 32));                          // uni_txd->len
    put16(msg + 34, cid);                                             // uni_txd->cid
    msg[37] = 0xa0;                                                   // MCU_PKT_ID
    msg[39] = seq;
    uint8_t opt = query ? (MCU_CMD_ACK | MCU_CMD_UNI) : (MCU_CMD_ACK | MCU_CMD_UNI | MCU_CMD_SET);
    msg[42] = 0;                                                      // s2d_index H2N
    msg[43] = opt;
    memcpy(msg + MCU_UNI_TXD_LEN, payload, plen);
    int sent = txSend(txMcu, msg, total);
    bzero(msg + MCU_UNI_TXD_LEN, plen);                               // key material does not stay in the static buffer
    if (sent < 0) { uniCmdFails++; return -11; }

    static uint8_t evTmp[128];
    uint32_t tmpLen = 0;
    uint8_t *dstEv = (ev && evMax) ? ev : evTmp;
    uint32_t dstMax = (ev && evMax) ? evMax : (uint32_t)sizeof(evTmp);
    uint32_t *dstLen = (ev && evMax) ? evLen : &tmpLen;
    int wrc = waitMcuResp(seq, dstEv, dstMax, dstLen);
    if (wrc == 0) {
        uint32_t tlvOff = (chip && chip->id == 0x7902) ? 36 : 44;
        uint8_t eidOff = chip ? (chip->mcuRxdSeq - 1) : 36;
        if (*dstLen >= tlvOff + 8 && dstEv[eidOff] == 0x01 && dstEv[tlvOff] == (uint8_t)cid) {
            uint32_t st = le32(dstEv + tlvOff + 4);
            if (st != 0) {
                uniCmdErrCid = cid;
                uniCmdErrStatus = st;
                char errBuf[48];
                snprintf(errBuf, sizeof(errBuf), "cid 0x%02x st 0x%08x", cid, st);
                setProperty("MtkUniLastErr", errBuf);
            }
        }
    }
    return wrc;
}

int WTLWireless::waitMcuResp(uint8_t seq, uint8_t *ev, uint32_t evMax, uint32_t *evLen) {
    uint8_t seqOff = chip ? chip->mcuRxdSeq : 37;
    uint32_t minHdr = (chip && chip->id == 0x7902) ? 36 : 44;

    for (int t = 0; t < 3000; t++) {
        pollRx();
        uint32_t len = 0;
        const uint8_t *p = rxPoll(rxMcu, &len);
        if (!p) { IOSleep(1); continue; }
        if (rxKind(p, len) != RX_EVENT) { dispatchRx(p, len); rxRelease(rxMcu); continue; }
        noteEvent(p, len);
        bool match = len >= minHdr && p[seqOff] == seq;
        if (match && ev && evMax) {
            uint32_t c = len < evMax ? len : evMax;
            memcpy(ev, p, c);
            if (evLen) *evLen = c;
        }
        rxRelease(rxMcu);
        if (match) { uniCmdTimeouts = 0; return 0; }
        rxUnmatched++;
    }
    uniCmdFails++;
    if (++uniCmdTimeouts >= UNICMD_DEAD_AFTER && !fwDead) {
        fwDead = true;
        step("fail: firmware unresponsive (3 command timeouts), machines stopped");
    }
    return -12;
}

// ConNaC2 MCU CE / EXT command (struct mt76_connac2_mcu_txd, 64 bytes + payload)
int WTLWireless::ceCmd(uint8_t cid, uint8_t extCid, const void *payload, uint32_t plen, bool query,
                       bool wait, uint8_t *ev, uint32_t evMax, uint32_t *evLen) {
    static uint8_t msg[64 + 1600];
    if (plen > sizeof(msg) - 64) { uniCmdFails++; return -10; }
    if (inDispatch) { uniCmdInDispatch++; return -13; }
    if (fwDead) { uniCmdFails++; return -14; }
    bzero(msg, 64);
    uint32_t total = 64 + plen;
    uint8_t seq = nextSeq();
    uint32_t txd1 = (chip && chip->txdHdrFormat) ? chip->txdHdrFormat : ((1u << 31) | (1u << 16));
    put32(msg + 0, (total & 0xffff) | (2u << 23) | (0x20u << 25)); // TX_BYTES | PKT_FMT_CMD | MCU_PORT_RX_Q0
    put32(msg + 4, txd1);
    put16(msg + 32, (uint16_t)(total - 32));                          // len
    put16(msg + 34, 0x8000);                                          // pq_id: MCU_PQ_ID(MCU, RX_Q0)
    msg[36] = cid;
    msg[37] = 0xa0;                                                   // MCU_PKT_ID
    msg[38] = query ? 0 : 1;                                          // MCU_Q_QUERY / MCU_Q_SET
    msg[39] = seq;
    msg[41] = extCid;
    msg[42] = 0;                                                      // s2d_index: MCU_S2D_H2N
    msg[43] = extCid ? 1 : 0;                                         // ext_cid_ack
    if (payload && plen) memcpy(msg + 64, payload, plen);
    int sent = txSend(txMcu, msg, total);
    bzero(msg + 64, plen);
    if (sent < 0) { uniCmdFails++; return -11; }
    if (!wait) return 0;
    return waitMcuResp(seq, ev, evMax, evLen);
}

// Count an MCU event by id and keep hex of the first few (diagnostics)
void WTLWireless::noteEvent(const uint8_t *p, uint32_t len) {
    rxEvents++;
    uint32_t minHdr = (chip && chip->id == 0x7902) ? 36 : 44;
    if (len < minHdr) { evShort++; return; }
    uint8_t eidOff = chip ? (chip->mcuRxdSeq - 1) : 36;
    uint8_t eid = p[eidOff];
    evCount[eid]++;
    if (eid == EVENT_SCAN_DONE || eid == EVENT_CONNAC2_SCAN_DONE || eid == 0x23) scanDone = true;
    if (eid == 0x27 && len >= (minHdr + 11)) {         // MCU_UNI_EVENT_ROC grant
        rocTok = p[minHdr + 9];
        rocStatus = p[minHdr + 10];
        rocGrant = true;
    }
    if (evDumps < 4 && eid != 0x01) {       // 0x01 = command results, already counted
        char key[24], hex[3 * 64 + 1];
        uint32_t n = len < 64 ? len : 64, k = 0;
        for (uint32_t i = 0; i < n; i++) k += snprintf(hex + k, sizeof(hex) - k, "%02x", p[i]);
        snprintf(key, sizeof(key), "MtkEvDump%u", evDumps++);
        setProperty(key, hex);
    }
}

void WTLWireless::rxFilterPromisc() {
    wr(rmacBase(0), (1u << 1) | (1u << 3));
    wr(rmacBase(1), (1u << 1) | (1u << 3));
    wr(rmacBase(0) + 4, 0);
    wr(rmacBase(1) + 4, 0);
    rmw(mdpBnrcfr0(chip, 0), 0x3f0, 0);
    rmw(mdpBnrcfr0(chip, 1), 0x3f0, 0);
    rmw(mdpBnrcfr1(chip, 0), (3u << 27) | (3u << 29), 0);
    rmw(mdpBnrcfr1(chip, 1), (3u << 27) | (3u << 29), 0);
}

// mt792x_mac_init_band (mt792x_mac.c), called for band 0 and 1
void WTLWireless::macInitBand(int b) {
    rmw(tmacCtcr0(b), 0x3f, 0x3f);                                 // INS_DDLMT_REFTIME
    rmw(tmacCtcr0(b), (1u << 18) | (1u << 17), (1u << 18) | (1u << 17));
    rmw(rmacBase(b) + 0x3c4, 1u << 30, 1u << 30);                  // RMAC_MIB_TIME0 RXTIME_EN
    rmw(rmacBase(b) + 0x380, 1u << 30, 1u << 30);                  // RMAC_MIB_AIRTIME0 RXTIME_EN
    rmw(mibScr1(b), (1u << 8) | (1u << 9), (1u << 8) | (1u << 9)); // TXDUR / RXDUR
    rmw(dmaDcr0(b), 0xfff8, 1536u << 3);                           // MAX_RX_LEN
    rmw(dmaDcr0(b), 1u << 23, 0);                                  // RXD_G5 off
    rmw(wtbloffRscr(b), (3u << 30) | (3u << 24), 3u << 24);        // RCPI mode 0, param 3
    wr(rmacBase(b), (1u << 1) | (1u << 3));                  // RFCR: accept all beacons, probe responses, other BSS (only drop FCSFAIL, bad version)
    wr(rmacBase(b) + 4, 0);                                  // RFCR1: clear drops
    rmw(mdpBnrcfr0(chip, b), 0x3f0, 0);                      // route MCU_RX_MGMT, MCU_RX_CTL to HIF (0)
}

// One RX packet from either ring (mt7925_queue_rx_skb classification). Frames go to the data path from the
// association on (joinState 3 = association request sent), so a message 1 or a deauthentication arriving while
// the post-association commands run is not lost; before that only the beacon locator sees them.
void WTLWireless::dispatchRx(const uint8_t *p, uint32_t len) {
    if (len >= 4) rxTypes[le32(p) >> 27]++;
    bool was = inDispatch;
    inDispatch = true;
    if (joinState >= 1 && len >= 4) {
        char hex[65] = {};
        uint32_t dumpLen = len < 32 ? len : 32;
        for (uint32_t i = 0; i < dumpLen; i++) snprintf(hex + i * 2, 3, "%02x", p[i]);
        setProperty("MtkLastJoinRxAny", hex);
        setNum("MtkLastJoinRxKind", (uint32_t)rxKind(p, len));
    }
    switch (rxKind(p, len)) {
    case RX_FRAME:
        rxFrames++;
        if (joinState >= 1) {
            char hex[65] = {};
            uint32_t dumpLen = len < 32 ? len : 32;
            for (uint32_t i = 0; i < dumpLen; i++) snprintf(hex + i * 2, 3, "%02x", p[i]);
            setProperty("MtkLastJoinRxHex", hex);
            if (len > 32) {
                char hex32[65] = {};
                uint32_t dLen32 = len - 32 < 32 ? len - 32 : 32;
                for (uint32_t i = 0; i < dLen32; i++) snprintf(hex32 + i * 2, 3, "%02x", p[32 + i]);
                setProperty("MtkLastJoinRx32", hex32);
            }
        }
        noteMgmt(p, len);
        if (linkUp || joinState >= 3) rxFrame(p, len);
        else mtkParseFrame(p, len);
        break;
    case RX_TXS:
        txStatus(p, len);
        break;
    case RX_TXFREE:
        txFree(p, len);
        break;
    case RX_EVENT:
        noteEvent(p, len);
        break;
    default:
        rxOther++;
        break;
    }
    inDispatch = was;
}

// Drain the band0 data ring (scan results arrive there as beacons / probe responses)
void WTLWireless::pollRx() {
    if (stallFreezeRx) return;                  // supervisor test: the data ring goes unread until the reload
    if (chip && chip->id == 0x7902 && (scanRunning || joinState >= 1)) {
        if (rr(rmacBase(0)) != ((1u << 1) | (1u << 3))) {
            wr(rmacBase(0), (1u << 1) | (1u << 3));
            wr(rmacBase(1), (1u << 1) | (1u << 3));
            wr(rmacBase(0) + 4, 0);
            wr(rmacBase(1) + 4, 0);
        }
    }
    for (int guard = 0; guard < 256; guard++) {
        uint32_t len = 0;
        const uint8_t *p = rxPoll(rxData, &len);
        if (!p) break;
        dispatchRx(p, len);
        rxRelease(rxData);
    }
    // MT7927 has a second RX ring (7) for firmware events and TX-done notices; it is classified like the others, and
    // draining it matters more than what it holds: an unread ring stalls the firmware
    if (chip && chip->rxqWa && rxWa.desc.va) {
        for (int guard = 0; guard < 128; guard++) {
            uint32_t len = 0;
            const uint8_t *p = rxPoll(rxWa, &len);
            if (!p) break;
            dispatchRx(p, len);
            rxRelease(rxWa);
        }
    }
}

// Where the 802.11 frame starts in an RX buffer (mt7925_mac_fill_rx / mt7921_mac_fill_rx):
// Connac2 (MT7902 / MT7921): base RXD 24 bytes (6 DWs), group 4 (16 bytes: 4 DWs), group 1 (16 bytes: 4 DWs),
// group 2 (8 bytes: 2 DWs), group 3 (8 bytes: 2 DWs P-RXV), group 5 (72 bytes: 18 DWs C-RXV),
// then HDR_OFFSET units of 2 bytes in rxd2 bits 15:14.
// Connac3 (MT7925 / MT7927): base RXD 32 bytes (8 DWs), groups 4, 1, 2, 3 (16 bytes each), group 5 (96 bytes),
// then HDR_OFFSET units of 2 bytes in rxd2 bits 15:13.
uint32_t WTLWireless::rxFrameOffset(uint32_t rxd1, uint32_t rxd2) {
    if (chip && chip->id == 0x7902) {
        uint32_t off = 24;                                                // base RXD 24 bytes (6 DWs)
        if (rxd1 & (1u << 14)) off += 16;                                 // group 4 (4 DWs = 16 bytes)
        if (rxd1 & (1u << 11)) off += 16;                                 // group 1 (4 DWs = 16 bytes)
        if (rxd1 & (1u << 12)) off += 8;                                  // group 2 (2 DWs = 8 bytes)
        if (rxd1 & (1u << 13)) {                                          // group 3 (P-RXV: 2 DWs = 8 bytes)
            off += 8;
            if (rxd1 & (1u << 15)) off += 72;                             // group 5 (C-RXV: 18 DWs = 72 bytes)
        }
        return off + 2 * ((rxd2 >> 14) & 3);                              // remove_pad (HDR_OFFSET)
    } else {
        uint32_t off = 32;
        if (rxd1 & (1u << 19)) off += 16;                                 // group 4
        if (rxd1 & (1u << 16)) off += 16;                                 // group 1
        if (rxd1 & (1u << 17)) off += 16;                                 // group 2
        if (rxd1 & (1u << 18)) {                                          // group 3 (P-RXV), group 5 (C-RXV)
            off += 16;
            if (rxd1 & (1u << 20)) off += 96;
        }
        return off + 2 * ((rxd2 >> 13) & 7);
    }
}

// RSSI in dBm from the P-RXV group (word 1 bits 7:0 = RCPI of chain 0 in connac2, to_rssi: (rcpi - 220) / 2), or -127
int8_t WTLWireless::rxRssi(const uint8_t *p, uint32_t len, uint32_t rxd1) {
    bool is7902 = (chip && chip->id == 0x7902);
    uint32_t grp3Bit = is7902 ? (1u << 13) : (1u << 18);
    if (!(rxd1 & grp3Bit)) return -127;
    uint32_t off = is7902 ? 24 : 32;
    if (is7902) {
        if (rxd1 & (1u << 14)) off += 16;                                 // group 4
        if (rxd1 & (1u << 11)) off += 16;                                 // group 1
        if (rxd1 & (1u << 12)) off += 8;                                  // group 2 (8 bytes)
        if (off + 8 > len) return -127;
        uint32_t rcpi = le32(p + off + 4) & 0xff;                         // DW1 bits 7:0 = RCPI0
        if (rcpi == 0 || rcpi == 0xff) return -127;
        int v = ((int)rcpi - 220) / 2;
        if (v < -127) v = -127;
        if (v > 0) v = 0;
        return (int8_t)v;
    } else {
        if (rxd1 & (1u << 19)) off += 16;
        if (rxd1 & (1u << 16)) off += 16;
        if (rxd1 & (1u << 17)) off += 16;
        if (off + 16 > len) return -127;
        uint32_t rcpi = le32(p + off + 12) & 0xff;
        if (rcpi == 0 || rcpi == 0xff) return -127;
        int v = ((int)rcpi - 220) / 2;
        if (v < -127) v = -127;
        if (v > 0) v = 0;
        return (int8_t)v;
    }
}

// Find the beacon / probe response in an RX buffer: at the offset the RXD groups give, else (the itlmt7925
// rxParseFrame approach, kept as a fallback) by scanning for FC 0x80/0x50 with TA == BSSID
void WTLWireless::mtkParseFrame(const uint8_t *p, uint32_t len) {
    if (len < 24 + 36) return;
    uint32_t rxd1 = le32(p + 4), rxd2 = le32(p + 8);
    uint32_t off = rxFrameOffset(rxd1, rxd2);
    if (!isBeaconAt(p, len, off)) {
        bool found = false;
        uint32_t startOff = (chip && chip->id == 0x7902) ? 24 : 32;
        for (off = startOff; off + 38 <= len && off < 224; off++)
            if (isBeaconAt(p, len, off)) { found = true; break; }
        if (!found) { rxOther++; return; }
    }
    bssNoteFrame(p + off, len - off, rxRssi(p, len, rxd1));
}

// An 802.11 beacon / probe response (f = frame control): SSID and channel from its elements, then the cache
void WTLWireless::bssNoteFrame(const uint8_t *f, uint32_t flen, int8_t rssi) {
    if (flen < 36) return;
    const uint8_t *ie = f + 36, *end = f + flen;
    char ssid[33] = {};
    uint8_t ssidLen = 0, ch = 0;
    while (ie + 2 <= end && ie + 2 + ie[1] <= end) {
        if (ie[0] == 0 && ie[1] <= 32) { memcpy(ssid, ie + 2, ie[1]); ssidLen = ie[1]; ssid[ie[1]] = 0; }
        else if (ie[0] == 3 && ie[1] >= 1) ch = ie[2];
        else if (ie[0] == 61 && ie[1] >= 1 && !ch) ch = ie[2];
        ie += 2 + ie[1];
    }
    rxBeacons++;
    bssNote(f, flen, ssid, ssidLen, ch, rssi);
    for (int i = 0; i < nBss; i++)
        if (!memcmp(bss[i].bssid, f + 16, 6)) { bss[i].probe = (f[0] & 0xf0) == 0x50; break; }
}

// The primary 20 MHz channels of the domain the firmware scans (kCh2 + kCh5): what the native front end reports as
// supported channels. Any thread: the arrays are constants.
uint32_t WTLWireless::coreChannels(uint8_t *list, uint32_t max) {
    uint8_t ch[sizeof(kCh2) + sizeof(kCh2Extra) + sizeof(kCh5)];
    uint32_t n2, n = domainChannels(ch, nullptr, &n2);
    if (n > max) n = max;
    memcpy(list, ch, n);
    return n;
}

// The same list with band and flags (ops v6). No 6 GHz entries: the core does not scan or join there yet.
uint32_t WTLWireless::coreChannels2(mtk_chan *list, uint32_t max) {
    uint8_t ch[sizeof(kCh2) + sizeof(kCh2Extra) + sizeof(kCh5)];
    uint32_t fl[sizeof(ch)], n2, n = domainChannels(ch, fl, &n2);
    if (n > max) n = max;
    for (uint32_t i = 0; i < n; i++) {
        list[i].band = i < n2 ? MTK_CHAN_2G : MTK_CHAN_5G;
        list[i].bw = MTK_BW_20;
        list[i].chan = list[i].center = ch[i];
        list[i].flags = (uint16_t)((fl[i] & CHAN_NO_IR ? MTK_CHAN_F_PASSIVE : 0) | (fl[i] & CHAN_RADAR ? MTK_CHAN_F_DFS : 0));
    }
    return n;
}

// The channels of the current country: 2.4 GHz first (*n2 of them), flags (CHAN_*) per channel when asked
uint32_t WTLWireless::domainChannels(uint8_t *ch, uint32_t *flags, uint32_t *n2) {
    bool fcc = fccCountry(country);
    uint32_t n = 0;
    for (uint32_t i = 0; i < sizeof(kCh2); i++, n++) { ch[n] = kCh2[i]; if (flags) flags[n] = 0; }
    if (!fcc)
        for (uint32_t i = 0; i < sizeof(kCh2Extra); i++, n++) { ch[n] = kCh2Extra[i]; if (flags) flags[n] = CHAN_NO_IR; }
    *n2 = n;
    for (uint32_t i = 0; i < sizeof(kCh5); i++, n++) {
        ch[n] = kCh5[i];
        if (flags) flags[n] = isDfs(kCh5[i]) ? CHAN_NO_IR | CHAN_RADAR : (!fcc && kCh5[i] >= 149) ? CHAN_NO_IR : 0;
    }
    return n;
}

// Upsert one BSS by BSSID: the newest beacon's fixed fields and elements, its security, when it was last seen.
// The oldest entry goes when the cache is full (never the one being joined).
void WTLWireless::bssNote(const uint8_t *frame, uint32_t len, const char *ssid, uint8_t ssidLen, uint8_t ch, int8_t rssi) {
    if (len < 36) return;
    const uint8_t *bssid = frame + 16;
    int idx = -1;
    for (int i = 0; i < nBss; i++)
        if (!memcmp(bss[i].bssid, bssid, 6)) { idx = i; break; }
    if (idx < 0) {
        if (nBss < MTK_BSS_CACHE) {
            idx = nBss++;
        } else {
            // full: drop the oldest entry this scan has not heard; 2.4 GHz finds would otherwise lose to the 5 GHz
            // channels scanned after them
            uint32_t oldest = 0;
            bool stale = false;
            for (int i = 0; i < nBss; i++) {
                if (joinState && !memcmp(bss[i].bssid, tgtBssid, 6)) continue;
                bool s = bss[i].seenGen != bssGen;
                if (idx < 0 || (s != stale ? s : ticks - bss[i].lastSeen > oldest)) {
                    idx = i; oldest = ticks - bss[i].lastSeen; stale = s;
                }
            }
            if (idx < 0) return;
        }
        bzero(&bss[idx], sizeof(bss[idx]));
        memcpy(bss[idx].bssid, bssid, 6);
        bss[idx].rssi = -127;
    }
    MtkBss &b = bss[idx];
    if (ssidLen > 0 || b.ssidLen == 0) {
        memcpy(b.ssid, ssid, 33);
        b.ssidLen = ssidLen;
    }
    if (ch) b.ch = ch;
    if (rssi != -127) b.rssi = rssi;
    b.bcnInt = le16(frame + 32);
    b.cap = le16(frame + 34);
    uint32_t n = len - 36;
    if (n > sizeof(b.ie)) n = sizeof(b.ie);
    memcpy(b.ie, frame + 36, n);
    b.ieLen = (uint16_t)n;
    b.lastSeen = ticks;
    b.seenGen = bssGen;
    b.seen++;
    bssParseSec(b);
    b.flags &= (uint8_t)~(MTK_BSS_JOINABLE | MTK_BSS_CURRENT);
    if (bssJoinable(b, false) || bssJoinable(b, true)) b.flags |= MTK_BSS_JOINABLE;
    if (joinState && !memcmp(b.bssid, tgtBssid, 6)) b.flags |= MTK_BSS_CURRENT;
}

// Security of a cached BSS from its RSN element (48), WPA vendor element (dd 00 50 f2 01) or Privacy bit
void WTLWireless::bssParseSec(MtkBss &b) {
    b.sec = (b.cap & 0x10) ? MTK_SEC_WEP : MTK_SEC_OPEN;
    b.akm = b.pairwise = b.group = 0;
    b.rsnCaps = 0;
    b.flags &= (uint8_t)~(MTK_BSS_MFPC | MTK_BSS_MFPR);
    const uint8_t *wpa = nullptr;
    size_t wpaLen = 0;
    for (const uint8_t *ie = b.ie, *end = b.ie + b.ieLen; ie + 2 <= end && ie + 2 + ie[1] <= end; ie += 2 + ie[1]) {
        mtk_rsn_info r;
        if (ie[0] == 48) {
            if (mtk_rsn_parse(ie, (size_t)(end - ie), &r) == 0) {
                b.sec = MTK_SEC_RSN;
                b.akm = r.akm;
                b.pairwise = r.pairwise;
                b.group = r.group;
                b.rsnCaps = r.caps;
                if (r.caps & MTK_RSN_CAP_MFPC) b.flags |= MTK_BSS_MFPC;
                if (r.caps & MTK_RSN_CAP_MFPR) b.flags |= MTK_BSS_MFPR;
                return;                                              // RSN wins over a WPA1 element
            }
        } else if (ie[0] == 0xdd && ie[1] >= 4 && ie[2] == 0x00 && ie[3] == 0x50 && ie[4] == 0xf2 && ie[5] == 0x01) {
            wpa = ie;
            wpaLen = (size_t)(end - ie);
        }
    }
    if (wpa) {
        mtk_rsn_info r;
        if (mtk_rsn_parse(wpa, wpaLen, &r) == 0) {
            b.sec = MTK_SEC_WPA1;
            b.akm = r.akm;
            b.pairwise = r.pairwise;
            b.group = r.group;
        }
    }
}

// What we can join: an open network without a key; with a PMK a WPA2 network that offers AKM PSK with pairwise
// CCMP (EAPOL descriptor version 2) and a CCMP or TKIP group key, and does not require management frame protection
bool WTLWireless::bssJoinable(const MtkBss &b, bool withKey) const {
    if (!b.ssidLen) return false;
    if (!withKey) return b.sec == MTK_SEC_OPEN;
    if (b.sec != MTK_SEC_RSN) return false;
    if (!(b.akm & MTK_AKM_PSK) || !(b.pairwise & MTK_CIPHER_CCMP)) return false;
    if (b.group != 4 && b.group != 2) return false;
    if (b.flags & MTK_BSS_MFPR) return false;
    return true;
}

// Higher is better: signal, 5 GHz preferred, something we can join preferred
int WTLWireless::bssScore(const MtkBss &b) const {
    int s = b.rssi;
    if (b.ch > 14) s += 10;
    if (!(b.flags & MTK_BSS_JOINABLE)) s -= 100;
    return s;
}

// Forget networks not seen for a minute (never the one being joined)
void WTLWireless::bssAge() {
    for (int i = 0; i < nBss;) {
        if (ticks - bss[i].lastSeen > BSS_AGE_TICKS && !(joinState && !memcmp(bss[i].bssid, tgtBssid, 6)) &&
            !(wantActive && bss[i].ssidLen == wantSsidLen && !memcmp(bss[i].ssid, wantSsid, wantSsidLen))) {
            if (i != nBss - 1) bss[i] = bss[nBss - 1];
            nBss--;
            continue;
        }
        i++;
    }
}

// MtkScan property: ssid/channel/rssi/security per network (no BSSIDs, so ioreg dumps need no redaction)
void WTLWireless::publishScan() {
    static const char *secName[] = {"open", "wep", "wpa", "wpa2"};
    static char list[1536];
    size_t n = 0;
    list[0] = 0;
    for (int i = 0; i < nBss && n + 64 < sizeof(list); i++) {
        const MtkBss &b = bss[i];
        char ssid[33];
        memcpy(ssid, b.ssid, 33);
        for (int k = 0; ssid[k]; k++)
            if (ssid[k] < 0x20 || ssid[k] > 0x7e || ssid[k] == ';' || ssid[k] == '/') ssid[k] = '?';
        n += snprintf(list + n, sizeof(list) - n, "%s%s/%u/%d/%s%s", i ? "; " : "", b.ssidLen ? ssid : "(hidden)", b.ch,
                      b.rssi, secName[b.sec & 3], (b.flags & MTK_BSS_JOINABLE) ? "" : "!");
    }
    setProperty("MtkScan", list[0] ? list : "(no networks)");
    setNum("MtkW1Bss", (uint32_t)nBss);
}

// The station interface (mt76_connac_mcu_uni_add_dev, NL80211_IFTYPE_STATION): DEV_INFO with our own MAC, then the
// idle BSS_INFO basic record. The firmware accepts unicast only for this address, so a station address change
// (coreSetMac) removes the interface and adds it again with the new one, the way Linux re-adds the vif.
int WTLWireless::devInfo(bool enable) {
    uint8_t dev[16] = {};
    dev[0] = 0;                 // omac_idx
    dev[1] = (chip && chip->id == 0x7902) ? 0 : 0xff; // band_idx (mt7925 uses 0xff)
    put16(dev + 4, 0);          // DEV_INFO_ACTIVE
    put16(dev + 6, 12);
    dev[8] = enable ? 1 : 0;    // active
    dev[9] = 0;                 // link_idx
    memcpy(dev + 10, mac, 6);
    int rc = uniCmd(UNI_DEV_INFO_UPDATE, dev, sizeof(dev), false, nullptr, 0, nullptr);

    uint8_t bssb[36] = {};
    uint8_t *b = bssb + 4;      // hdr: bss_idx 0, pad[3]
    put16(b + 0, 0);            // UNI_BSS_INFO_BASIC
    put16(b + 2, 32);
    b[4] = enable ? 1 : 0;      // active
    b[7] = ((chip && (chip->quirks & MTK_Q_BAND_IDX)) || (chip && chip->id == 0x7902)) ? 0 : 0xff;   // band_idx
    put32(b + 8, 0x10001);      // CONNECTION_INFRA_STA
    b[12] = 1;                  // conn_state
    put16(b + 20, 19);          // bmc_tx_wlan_idx (itlmt7925 value, WTBL reserved)
    put16(b + 26, 19);          // sta_idx
    setNum("MtkW4BssInfo", (uint32_t)uniCmd(UNI_BSS_INFO_UPDATE, bssb, sizeof(bssb), false, nullptr, 0, nullptr));
    return rc;
}

// Everything after the firmware runs and before the first scan: NIC capability (MAC), EFUSE mode, MDP and band
// init, the station interface, the US domain and power tables, RTS threshold and RX filter
int WTLWireless::hwInit(bool keepMac) {
    static uint8_t ev[512];
    uint32_t evl = 0;

    // drain anything the firmware sent after FW_START
    for (int i = 0; i < 200; i++) {
        pollRx();
        uint32_t len;
        const uint8_t *q = rxPoll(rxMcu, &len);
        if (q) { dispatchRx(q, len); rxRelease(rxMcu); continue; }
        IOSleep(1);
    }

    // 1. NIC capability -> MAC address, nss, chip_cap (mt7921_mcu_get_nic_capability 0x8a / mt7925 UNI_CHIP_CONFIG)
    nicNss = (chip && chip->nss) ? chip->nss : 1;
    nicChipCap = 0;
    bool gotMac = false;
    if (chip && chip->id == 0x7902) {
        uint8_t noPay[1] = {};
        static uint8_t ncEv[1024];
        uint32_t ncEvl = 0;
        int ncRc = ceCmd(0x8a /* MCU_CE_CMD_GET_NIC_CAPAB */, 0, noPay, 0, false, true, ncEv, sizeof(ncEv), &ncEvl);
        setNum("MtkW4NicCap", (uint32_t)ncRc);
        setNum("MtkW4NicCap8a", (uint32_t)ncRc);
        if (ncEvl >= 36) {
            char dump[70] = {};
            uint32_t dlen = (ncEvl - 36 < 32) ? (ncEvl - 36) : 32;
            for (uint32_t i = 0; i < dlen; i++) snprintf(dump + i * 2, 3, "%02x", ncEv[36 + i]);
            setProperty("MtkNicCapDump", dump);
        }
        if (ncRc == 0 && ncEvl >= 40) {
            uint16_t nElem = (uint16_t)(ncEv[36] | ((uint16_t)ncEv[37] << 8));
            setNum("MtkW4NicCapElements", nElem);
            uint32_t pos = 40;
            for (uint16_t ei = 0; ei < nElem && pos + 8 <= ncEvl; ei++) {
                uint32_t tType = le32(ncEv + pos);
                uint32_t tLen = le32(ncEv + pos + 4);
                pos += 8;
                if (tLen > ncEvl - pos) break;
                const uint8_t *td = ncEv + pos;
                if (tType == 7 /* MT_NIC_CAP_MAC_ADDR */ && tLen >= 6) {
                    if (!keepMac && (td[0] & 1) == 0 && (td[0] | td[1] | td[2] | td[3] | td[4] | td[5]) != 0) {
                        memcpy(mac, td, 6);
                        gotMac = true;
                    }
                    char macStr[24] = {};
                    snprintf(macStr, sizeof(macStr), "%02x:%02x:%02x:%02x:%02x:%02x",
                             td[0], td[1], td[2], td[3], td[4], td[5]);
                    setProperty("MtkW4NicCapMac", macStr);
                } else if (tType == 8 /* MT_NIC_CAP_PHY */ && tLen >= 12) {
                    if (td[4] >= 1 && td[4] <= 4) nicNss = td[4];
                    setNum("MtkChipNss", nicNss);
                    char phyStr[64] = {};
                    snprintf(phyStr, sizeof(phyStr), "nss %u bw %u path 0x%02x 5g %u he %u vht %u",
                             td[4], td[3], td[10], td[2], td[11], td[1]);
                    setProperty("MtkW4NicCapPhy", phyStr);
                } else if (tType == 24 /* MT_NIC_CAP_6G */ && tLen >= 1) {
                    setNum("MtkW4NicCap6g", td[0]);
                } else if (tType == 32 /* MT_NIC_CAP_CHIP_CAP */ && tLen >= 8) {
                    nicChipCap = (uint64_t)le32(td) | ((uint64_t)le32(td + 4) << 32);
                    char ccStr[24] = {};
                    snprintf(ccStr, sizeof(ccStr), "0x%016llx", (unsigned long long)nicChipCap);
                    setProperty("MtkChipCap", ccStr);
                }
                pos += tLen;
            }
        }
    } else {
        uint8_t cap[8] = {0, 0, 0, 0, 3, 0, 4, 0};   // rsv[4], tag UNI_CHIP_CONFIG_NIC_CAPA, len sizeof - 4
        int rc = uniCmd(UNI_CHIP_CONFIG, cap, sizeof(cap), false, ev, sizeof(ev), &evl);
        setNum("MtkW4NicCap", (uint32_t)rc);
        uint32_t tlvOff = 44;
        if (evl >= tlvOff) {
            char dump[70] = {};
            uint32_t dlen = (evl - tlvOff < 32) ? (evl - tlvOff) : 32;
            for (uint32_t i = 0; i < dlen; i++) snprintf(dump + i * 2, 3, "%02x", ev[tlvOff + i]);
            setProperty("MtkNicCapDump", dump);
        }
        if (!rc && evl > (tlvOff + 4)) {
            const uint8_t *q = ev + tlvOff, *end = ev + evl;
            uint16_t n = le16(q);
            q += 4;
            for (uint16_t i = 0; i < n && q + 4 <= end; i++) {
                uint16_t tag16 = le16(q), tl16 = le16(q + 2);
                if (tag16 == 7 && tl16 >= 10 && q + tl16 <= end && !keepMac) {
                    memcpy(mac, q + 4, 6);
                    if ((mac[0] & 1) == 0 && (mac[0] | mac[1] | mac[2] | mac[3] | mac[4] | mac[5]) != 0)
                        gotMac = true;
                }
                if (tl16 < 4 || q + tl16 > end) break;
                q += tl16;
            }
            setNum("MtkW4NicCapElements", n);
        }
    }
    if (keepMac) {
        // a reload keeps the address macOS may have set (I-058): the firmware gets it again in DEV_INFO below
    } else if (gotMac) {
        char s[18];
        snprintf(s, sizeof(s), "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        setProperty("MtkMacAddr", s);
    } else {
        static const uint8_t fallback_laa[6] = {0x02, 0x00, 0x79, 0x02, 0x00, 0x01};   // locally administered
        static const uint8_t fallback_7902[6] = {0xf8, 0x54, 0xf6, 0x7b, 0x1a, 0x16};  // AzureWave Vivobook 15
        const uint8_t *fb = (chip && chip->id == 0x7902) ? fallback_7902 : fallback_laa;
        memcpy(mac, fb, 6);
        if (chip && chip->id == 0x7902) setProperty("MtkMacAddr", "f8:54:f6:7b:1a:16 (hardware fallback)");
        else setProperty("MtkMacAddr", "none (using 02:00:79:02:00:01)");
    }

    // 2. EFUSE buffer mode = efuse, whole (mt7921_mcu_set_eeprom / mt7925_mcu_set_eeprom)
    if (chip && chip->id == 0x7902) {
        uint8_t eeBuf[4] = {0, 1, 0, 0}; // EE_MODE_EFUSE, EE_FORMAT_WHOLE
        setNum("MtkW4Eeprom", (uint32_t)ceCmd(0xed, 0x21 /* EFUSE_BUFFER_MODE */, eeBuf, sizeof(eeBuf), false, true));
        bool eeMacOk = true;
        for (int i = 0; i < 6; i++)
            if (readEeprom(0x004u + (uint32_t)i, &eepromMac[i])) { eeMacOk = false; break; }
        if (eeMacOk) {
            char ms[24];
            snprintf(ms, sizeof(ms), "%02x:%02x:%02x:%02x:%02x:%02x",
                     eepromMac[0], eepromMac[1], eepromMac[2], eepromMac[3], eepromMac[4], eepromMac[5]);
            setProperty("MtkW9EepromMac", ms);
        }
    } else {
        uint8_t ee[12] = {0, 0, 0, 0, 2, 0, 8, 0, 0, 1, 0, 0};
        setNum("MtkW4Eeprom", (uint32_t)uniCmd(UNI_EFUSE_CTRL, ee, sizeof(ee), false, nullptr, 0, nullptr));
    }

    // Reset timeouts so optional queries do not count as fatal strikes against station setup
    uniCmdTimeouts = 0;

    // 3. MDP: max RX length 1536 (bits 15:3), hardware de-AMSDU, hardware RX header translation
    rmw(mdpDcr1(chip), 0xfff8, 1536u << 3);
    rmw(mdpDcr0(chip), (1u << 15) | (1u << 19), (1u << 15) | (1u << 19));
    setNum("MtkW4MdpDcr0", rr(mdpDcr0(chip)));
    setNum("MtkW4DmaDcr0Before", rr(dmaDcr0(0)));
    if (chip && chip->id == 0x7902) {
        // mt7921_mac_init: clear ADM counters across all 20 WTBL entries
        for (uint32_t i = 0; i < 20; i++) {
            rmw(0x820d4230, 0x3ffu | (1u << 12), i | (1u << 12));
            pollMsec(0x820d4230, 1u << 31, 0, 50, 1);
        }
    }
    macInitBand(0);
    macInitBand(1);
    setNum("MtkW4DmaDcr0", rr(dmaDcr0(0)));
    setNum("MtkW4Rfcr", rr(rmacBase(0)));
    setNum("MtkW4Rfcr1", rr(rmacBase(0) + 4));
    setNum("MtkW4MdpBnrcfr0", rr(mdpBnrcfr0(chip, 0)));

    // 3b. MT7927: dual-band concurrency on (mt7925_mcu_set_dbdc: UNI_MBMC_SETTING under SET_DBDC_PARMS). Linux logs a
    // failure and carries on, so this only publishes the result.
    if (chip->quirks & MTK_Q_DBDC) {
        uint8_t dbdc[12] = {0, 0, 0, 0, 0, 0, 8, 0, 1, 0, 0, 0};   // pad[4], tag 0, len 8, mbmc_en 1, band 0
        setNum("MtkW4Dbdc", (uint32_t)uniCmd(UNI_SET_DBDC_PARMS, dbdc, sizeof(dbdc), false, nullptr, 0, nullptr));
    }

    // 4. ConNaC2: finish mt7921_mac_init (PROTECT_CTRL), then __mt7921_start (MAC_INIT_CTRL, domain + CLC + TX power, SET_RX_PATH), then add_dev
    if (chip && chip->id == 0x7902) {
        uint8_t rts7902[12] = {};
        rts7902[0] = 1;              // prot_idx = 1
        rts7902[1] = 0;              // band = 0
        put32(rts7902 + 4, 0x92bu);  // len_thresh
        put32(rts7902 + 8, 2u);      // pkt_thresh
        setNum("MtkW4Rts", (uint32_t)ceCmd(0xed, 0x3e /* PROTECT_CTRL */, rts7902, sizeof(rts7902), false, true));
        IOSleep(20);
        setNum("MtkW4PostRtsAlive", (uint32_t)mcuRegRead(0x820c8000u));

        uint8_t macEn[4] = {1, 0, 0, 0}; // enable = 1, band = 0
        setNum("MtkW4MacEnable", (uint32_t)ceCmd(0xed, 0x46 /* MAC_INIT_CTRL */, macEn, sizeof(macEn), false, true));
    }

    // 5. channel domain of the country (US until macOS sets one), DFS channels passive
    domainStage();

    if (chip && chip->id == 0x7902) {
        uint8_t rxp[76] = {};
        rxp[0] = 1;                  // control_ch
        rxp[1] = 1;                  // center_ch
        rxp[2] = 0;                  // bw: 20 MHz
        rxp[3] = nicNss;             // tx_streams_num (from GET_NIC_CAPAB MT_NIC_CAP_PHY)
        rxp[4] = (uint8_t)((1u << nicNss) - 1); // rx_streams: antenna_mask (SET_RX_PATH expects mask)
        rxp[5] = 0;                  // CH_SWITCH_NORMAL
        rxp[6] = 0;                  // band_idx
        rxp[10] = 0;                 // channel_band: 2.4 GHz
        setNum("MtkW4RxPath", (uint32_t)ceCmd(0xed, 0x4e /* SET_RX_PATH */, rxp, sizeof(rxp), false, true));

        setNum("MtkW4DevInfo", (uint32_t)devInfo(true));
    } else {
        setNum("MtkW4DevInfo", (uint32_t)devInfo(true));
        // __mt7925_start: RTS threshold 0x92b (mt7925_mcu_set_rts_thresh)
        uint8_t rts[16] = {0, 0, 0, 0, 0x08, 0, 12, 0, 0x2b, 0x09, 0, 0, 2, 0, 0, 0};
        setNum("MtkW4Rts", (uint32_t)uniCmd(UNI_BAND_CONFIG, rts, sizeof(rts), false, nullptr, 0, nullptr));
    }
    // configure_filter: FILTER_ENABLE | FILTER_OTHER_BSS
    if (chip && chip->id == 0x7902) {
        // FIF mode filter only (mt7921_configure_filter calls mt7921_mcu_set_rxfilter(dev, flags, 0, 0))
        uint8_t d1[68] = {};
        d1[4] = 1; // mode = 1 (fif mode)
        put32(d1 + 8, (1u << 31) | (1u << 6)); // MT7921_FILTER_ENABLE | MT7921_FILTER_OTHER_BSS
        ceCmd(0x0a /* MCU_CE_CMD_SET_RX_FILTER */, 0, d1, sizeof(d1), false, false);
        setNum("MtkW4PostFilterAlive", (uint32_t)mcuRegRead(0x820c8000u));

        wr(rmacBase(0), (1u << 1) | (1u << 3));
        wr(rmacBase(1), (1u << 1) | (1u << 3));
        wr(rmacBase(0) + 4, 0);
        wr(rmacBase(1) + 4, 0);
        setNum("MtkW4RxFilter", 0);
    } else {
        uint8_t flt[72] = {};
        put16(flt + 4, 0x0c);                       // UNI_BAND_CONFIG_SET_MAC80211_RX_FILTER
        put16(flt + 6, 68);
        put32(flt + 12, (1u << 31) | (1u << 6));    // fif
        setNum("MtkW4RxFilter", (uint32_t)uniCmd(UNI_BAND_CONFIG, flt, sizeof(flt), false, nullptr, 0, nullptr));
    }
    setNum("MtkW4RfcrAfterFilter", rr(rmacBase(0)));
    if (fwDead) { step("W4 fail: firmware stopped answering during hardware init"); return -1; }
    step("W4 pass: station ready (MAC, domain, power), scanning from the tick");
    return 0;
}

// mt7925_regd_update order: CLC country tables, the channel domain (mt7925_mcu_set_channel_domain), the per-rate limits
int WTLWireless::domainStage() {
    static uint8_t dom[16 + 8 * 48];
    bzero(dom, sizeof(dom));
    uint8_t ch[48];
    uint32_t fl[48], n2, n = domainChannels(ch, fl, &n2);
    dom[0] = (uint8_t)country[0]; dom[1] = (uint8_t)country[1];
    dom[4] = 0; dom[5] = 3; dom[6] = 3;           // bw_2g 20/40, bw_5g/6g up to 160
    uint8_t *w;
    bool connac2 = (chip && chip->id == 0x7902);
    if (connac2) {
        dom[8] = (uint8_t)n2; dom[9] = (uint8_t)(n - n2); dom[10] = 0; dom[11] = 0;
        w = dom + 12;
    } else {
        put16(dom + 8, 2);
        put16(dom + 10, (uint16_t)(8 + n * 8));
        dom[12] = (uint8_t)n2; dom[13] = (uint8_t)(n - n2); dom[14] = 0;
        w = dom + 16;
    }
    for (uint32_t i = 0; i < n; i++, w += 8) { put16(w, ch[i]); put32(w + 4, fl[i]); }
    powerStage(false);
    if (connac2) setNum("MtkW4AliveClc", (uint32_t)mcuRegRead(0x820c8000u));
    int rc = connac2
        ? ceCmd(MCU_CE_CMD_SET_CHAN_DOMAIN, 0, dom, (uint32_t)(w - dom), false, false)
        : uniCmd(UNI_SET_DOMAIN_INFO, dom, (uint32_t)(w - dom), false, nullptr, 0, nullptr);
    setNum("MtkW4Domain", (uint32_t)rc);
    if (connac2) setNum("MtkW4AliveDom", (uint32_t)mcuRegRead(0x820c8000u));
    powerStage(true);
    if (connac2) setNum("MtkW4AlivePwr", (uint32_t)mcuRegRead(0x820c8000u));
    char t[48];
    snprintf(t, sizeof(t), "%c%c, %u channels (%u at 2.4 GHz), rc %d", country[0], country[1], n, n2, rc);
    setProperty("MtkCountry", t);
    return rc;
}

// One firmware scan of every channel in the domain (mt7925_mcu_hw_scan): wildcard SSID, active where allowed.
// Results arrive as beacons / probe responses on the data ring (bssNote), the end as event SCAN_DONE.
int WTLWireless::scanStart() {
    scanSeq = (uint8_t)((scanSeq % 0x7f) + 1);
    bssGen++;
    scanDone = false;
    scanDoneAt = 0;
    scanStartedAt = ticks;
    cmLastScanAt = ticks;

    if (chip && chip->id == 0x7902) {
        static uint8_t msg[64 + sizeof(MtkConnac2ScanReq)];
        bzero(msg, sizeof(msg));
        uint32_t total = (uint32_t)sizeof(msg);
        put32(msg + 0, (total & 0xffff) | (2u << 23) | (0x20u << 25)); // TX_BYTES, PKT_FMT CMD, Q_IDX MCU_PORT_RX_Q0
        uint32_t txd1 = chip->txdHdrFormat ? chip->txdHdrFormat : ((1u << 31) | (1u << 16));
        put32(msg + 4, txd1);
        put16(msg + 32, (uint16_t)(total - 32));
        put16(msg + 34, 0x8000); // pq_id: MCU_PQ_ID(MT_TX_PORT_IDX_MCU, RX_Q0)
        msg[36] = MCU_CE_CMD_START_HW_SCAN; // 0x03
        msg[37] = 0xa0;          // MCU_PKT_ID
        msg[38] = 1;             // set_query: MCU_Q_SET
        msg[39] = scanSeq;
        msg[40] = 0;
        msg[41] = 0;             // ext_cid
        msg[42] = 0;             // s2d_index: MCU_S2D_H2N
        msg[43] = 0;             // ext_cid_ack

        MtkConnac2ScanReq *req = (MtkConnac2ScanReq *)(msg + 64);
        req->seq_num = scanSeq;
        req->bss_idx = 0;
        req->scan_type = 1;        // Always active scan with probe requests
        if (wantActive && wantSsidLen > 0 && wantSsidLen <= 32) {
            req->ssids_num = 1;
            req->ssid_type = (1u << 2) | (1u << 0); // specified SSID + wildcard SSID
            req->ssid_type_ext = 0;
            req->ssids[0].ssid_len = wantSsidLen;
            memcpy(req->ssids[0].ssid, wantSsid, wantSsidLen);
        } else {
            req->ssids_num = 0;
            req->ssid_type = 1;        // BIT(0) wildcard SSID
            req->ssid_type_ext = 0;
        }
        req->probe_req_num = 2;
        req->scan_func = 1u << 5;  // SCAN_FUNC_SPLIT_SCAN
        req->version = 1;

        uint8_t ch[48];
        uint32_t n2, n = domainChannels(ch, nullptr, &n2);
        req->channel_min_dwell_time = 60;
        req->channel_dwell_time = 120;
        req->timeout_value = (uint16_t)(n * 120);
        req->channel_type = 4;     // specified channels
        req->channels_num = (n > 32) ? 32 : (uint8_t)n;
        req->ext_channels_num = (n > 32) ? (uint8_t)(n - 32) : 0;
        for (uint32_t i = 0; i < n; i++) {
            uint8_t band = (i < n2) ? 1 : 2; // 1: 2.4GHz, 2: 5GHz
            if (i < 32) {
                req->channels[i].band = band;
                req->channels[i].channel_num = ch[i];
            } else {
                req->ext_channels[i - 32].band = band;
                req->ext_channels[i - 32].channel_num = ch[i];
            }
        }
        bzero(req->bssid, 6);

        rxFilterPromisc();

        int sent = txSend(txMcu, msg, total);
        setNum("MtkW4ScanReq", (uint32_t)sent);
        if (sent < 0) {
            scanFails++;
            if (userScanPending) { userScanPending = false; userScanDoneAt = ticks; }
            return sent;
        }
        scanRunning = true;
        scans++;
        return 0;
    }

    static uint8_t sc[4 + 20 + 368 + 16 + 136 + 12];
    bzero(sc, sizeof(sc));
    uint8_t ch[48];
    uint32_t n2, n = domainChannels(ch, nullptr, &n2);
    uint8_t *w = sc;
    uint8_t bandIdx = 1;
    w[0] = (uint8_t)((bandIdx << 7) | scanSeq);             // seq_num | band_idx << 7
    w += 4;
    put16(w, 1); put16(w + 2, 20);                // UNI_SCAN_REQ
    w[4] = 1;                                     // active (the firmware stays passive on NO_IR channels)
    w[5] = 2;                                     // probe_req_num
    w[6] = 1u << 5;                               // SCAN_FUNC_SPLIT_SCAN
    put16(w + 8, 60);                             // channel_min_dwell_time
    put16(w + 10, 120);                           // channel_dwell_time
    w += 20;
    put16(w, 10); put16(w + 2, 368);              // UNI_SCAN_SSID
    w[4] = 1;                                     // wildcard
    w += 368;
    put16(w, 11); put16(w + 2, 16);               // UNI_SCAN_BSSID
    memset(w + 4, 0xff, 6);
    w += 16;
    put16(w, 12); put16(w + 2, 136);              // UNI_SCAN_CHANNEL
    w[4] = 4;                                     // specified channels
    w[5] = (uint8_t)n;
    for (uint32_t k = 0; k < n; k++) { w[8 + 2 * k] = k < n2 ? 1 : 2; w[9 + 2 * k] = ch[k]; }
    w += 136;
    put16(w, 14); put16(w + 2, 12);               // UNI_SCAN_MISC
    int rc = uniCmd(UNI_SCAN_REQ, sc, sizeof(sc), false, nullptr, 0, nullptr);
    setNum("MtkW4ScanReq", (uint32_t)rc);
    if (rc) {
        scanFails++;
        if (userScanPending) { userScanPending = false; userScanDoneAt = ticks; }   // the fallback must not wait forever
        return rc;
    }
    scanRunning = true;
    scans++;
    return 0;
}

// Tick: finish a running scan half a second after SCAN_DONE (or at the 20 s limit), start a wanted one when
// the radio is free (idle, or associated: the firmware scans around the association)
void WTLWireless::scanService() {
    if (scanRunning) {
        if (scanDone && !scanDoneAt) scanDoneAt = ticks;
        bool finish = (scanDoneAt && ticks - scanDoneAt >= SCAN_SETTLE_TICKS) || ticks - scanStartedAt >= SCAN_TIMEOUT_TICKS;
        if (!finish) return;
        scanRunning = false;
        scanFinishedAt = ticks;
        scanEverDone = true;
        if (!firstScanDoneAt) firstScanDoneAt = ticks;
        if (!scanDoneAt) scanFails++;
        setNum("MtkW4ScanDone", scanDoneAt ? scanDoneAt - scanStartedAt : 0xffffffff);
        setNum("MtkW4RfcrInScan", rr(rmacBase(0)));
        setNum("MtkW6RxDataDmaIdx", rawRead(rxData.regs + 12));
        setNum("MtkW6RxDataCpuIdx", rawRead(rxData.regs + 8));
        setNum("MtkW6RxFrames", rxFrames);
        setNum("MtkW6RxBeacons", rxBeacons);
        setNum("MtkW6RxOther", rxOther);
        publishScan();
        if (userScanPending) { userScanPending = false; userScanDoneAt = ticks; }
        if (feScanDone && fe.ctx) feScanDone(fe.ctx, scanDoneAt ? 0 : -1, (uint32_t)nBss);
        cmKick = true;
        return;
    }
    if (scanWanted && !fwDead && (joinState == 0 || joinState == 5)) {
        scanWanted = false;
        scanStart();
    }
}
