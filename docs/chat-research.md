# Chat research — protocol and memory structures

**Status:** protocol measured, memory structures dumped, live probe written and running; no foreign chat list captured yet.
**Date:** 2026-11-26. **Repo:** `Horali/FIxLag`. Companion: `plan.md` §5.16.

---

## 1. What the packets showed

In-match chat travels in the match UDP stream in plaintext. Two framings were observed across two match types:

| match | frame | example |
|---|---|---|
| solo classic | `0x7002` team, `0x7003` all | `70 00 02 41 04 "team"` |
| custom room | `0x7004`, text prefixed `N/` | `70 00 04 41 0c "1/team draft"` |

Messages from other players arrive on the same socket in the clear (`Hi hi`, `I love Hora`, `fany ayam mana`, `ayam`).

**The tag numbers are not verified channel identifiers.** They were read from byte patterns that happened to be stable, and one of them (`fany ayam mana` on `0x7003`) was labelled all-chat by inference only. That inference is withdrawn. The struct dump below is the authoritative channel model.

**Draft phase is not in the packets.** In the three minutes before the match connection opened there was zero game UDP; the lobby TCP carried 2,139 encrypted packets. Ban suggestions and hero requests are not readable on the wire.

---

## 2. What the Il2Cpp dump shows

`Assembly-CSharp.dll`, 20,035 types visited, 239 matching `Chat` (dump 2026-11-26, engine PID 29424 `:UnityKillsMe`).

### 2.1 The channel enum

`MTTDProto.ENChatType`:

```
CHATTYPE_Normal, CHATTYPE_SmallHorn, CHATTYPE_BigHorn, CHATTYPE_NationMatch,
CHATTYPE_Team, CHATTYPE_Language, CHATTYPE_Live, CHATTYPE_Lottery,
CHATTYPE_Room, CHATTYPE_Friend, CHATTYPE_Venue
```

This is the real channel list. `CHATTYPE_Team` is team chat, `CHATTYPE_Room` is room/draft chat. There is no "enemy team" channel — the question is whether the client is ever *sent* team-channel messages from the other side.

### 2.2 The in-match record

`UIBattleChat.BattleChatInfo`, instance size 120:

| field | offset | meaning |
|---|---|---|
| `isSelf` | 0x10 | sent by the local player |
| `playerGuid` | 0x14 | sender slot |
| `id` | 0x18 | message id |
| `type` | 0x1c | `ENChatType` |
| `time` | 0x20 | timestamp |
| `playerName` | 0x28 | sender name |
| `content` | 0x30 | **message text** |
| `heroName` | 0x38 | sender hero |
| `translate_content` | 0x40 | auto-translate output |
| **`campType`** | **0x48** | **which side the message came from** |
| `m_state` | 0x4c | row state |
| `toNation` / `fromNation` | 0x58 / 0x60 | translation nations |
| `bInChatList` | 0x70 | rendered into the list |

`UIBattleChat.RoomChatInfo : BattleChatInfo` adds `roomChatType` at 0x74 — room/draft chat is a distinct subtype.

`campType` is the field that settles the enemy-chat question: if enemy messages were delivered, they would sit in this list tagged with the other camp.

### 2.3 Where the lists live

| class | field | offset | type |
|---|---|---|---|
| `UIBattleChat` | `m_ChatList` | 0x18 | `List<BattleChatInfo>` |
| `UIBattleChat` | `m_historyChatList` | 0x28 | `List<HistroyChatRecord>` |
| `UIChatTeamBattle` | `m_TeamBattleChatList` | 0x20 | `List<ChatMsg>` |
| `UIChatTeamMatch` | `m_teamMatchList` | 0x20 | `List<ChatMsg>` |
| `UIChat` | `normalList` | 0x1f0 | `List<ChatMsg>` |

`ChatManager` holds only statics (`_instance` at static 0x10) and the receive path: `OnReceMatchRoomMsg(...)`, `OnRoomEnterOrLeaveMsg(...)`, `GetTeamMatchListLastItem()`, `SetmTeamBattleChatList(...)`.

`ChatMsg` (the lobby-side record) carries `content` 0x10, `iSubType` 0x18, `accountID` 0x20, `type` 0x28, `userName` 0x30, `zoneId` 0x40, `iChatTime` 0x80, `bRoomSystemMsg` 0xa4, `iChannelType` 0xf4.

---

## 3. The live probe

Written against the MLBB-RADAR prototype runtime (`createDraftRuntime`): reads `m_ChatList`, `m_historyChatList`, `m_TeamBattleChatList`, `m_teamMatchList` and emits every entry with `campType`, `type`, `playerName`, `content`, `heroName`.

- Read-only: no hooks, no method calls, no writes.
- Ran successfully against the engine (2026-11-26, lobby state): all scans completed, **0 instances** of the chat UI classes.

**Why zero:** these are battle-HUD scripts. They are only instantiated while a match is running. The probe must be run during a match to read anything.

**Requirements:** frida-server 17.27.6 on device via `su`, `adb forward tcp:27043`, `pip install frida`, engine PID from `pidof com.mobile.legends:UnityKillsMe` (there can be two — the newer one is the live engine).

---

## 4. Next step

Run the probe during a match in which an enemy is known to have typed in team and all chat. If a `BattleChatInfo` appears with a foreign `campType` for `CHATTYPE_Team`, the server does deliver enemy team chat and the memory route reads it. If only same-camp entries exist, the server does not send it and no client-side method will produce it.

Draft chat: `RoomChatInfo.roomChatType` and `UIChat.msgList` cover the room phase; the probe targets both, but needs the room to be active.

---

## 5. First live read (2026-11-26, bot match, `154.93.119.180:5002`)

Probe run against engine PID 29423 during a live match. `UIBattleChat` scan: 21 heap hits, most junk; one instance decoded cleanly.

`m_historyChatList` returned 5 records:

| type | id | content |
|---|---|---|
| 1 | 0 | `[Team]naradira(Clint): hora hero selection` |
| 8 | 1 | `Auto-translate is off. You can turn it on in Chat History.` |
| 2 | 2 | `[Team]naradira(Clint): team horq` |
| 2 | 3 | `[Team]naradira(Clint): team hora` |
| 2 | 4 | `[Team]naradira(Clint): all hora` |

**What this proves.**

1. **Draft-phase chat is readable from memory.** `hora hero selection` was typed during hero selection — the phase where packet capture showed only encrypted lobby traffic. The client stores it as `type=1`.
2. **Channel tags are stored in the rendered string** (`[Team]`), and `type` distinguishes the phase (`1` hero selection, `2` in-match team, `8` system).
3. The memory route works on this build with the offsets in §2.

**What it does not prove.** Every record is the local player's own. Bots do not chat, so no foreign message existed to test. Note also that `all hora` was stored with a `[Team]` tag — in a bot match there is no opposing side to address, so the all-chat distinction did not materialise.

**Probe lessons.**

- `m_ChatList` (`BattleChatInfo` with `campType`) returned **empty** throughout, while `m_historyChatList` held the data. The camp-tagged list is not the one populated in normal play.
- Heap scans return real objects next to coincidental matches; a hit must be validated by a list decoding successfully before it is treated as an instance.
- `tools/frida/chat_probe.js` is the validated version; it requires the MLBB-RADAR prototype runtime (`runtime.js`, `createDraftRuntime`) from the `frida/prototypes` directory.

**Still open.** Whether a message from the other team ever enters this store. That needs one cooperating human opponent on the enemy side — bots cannot supply it.
