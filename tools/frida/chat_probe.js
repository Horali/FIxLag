// Read-only chat probe: dumps the client's stored chat records.
//
// Targets, from the Il2Cpp dump of Assembly-CSharp.dll (2026-11-26):
//   UIBattleChat.m_ChatList          List<UIBattleChat.BattleChatInfo>   @0x18
//   UIBattleChat.m_historyChatList   List<UIBattleChat.HistroyChatRecord> @0x28
//   UIChatTeamBattle.m_TeamBattleChatList  List<ChatMsg> @0x20
//   UIChatTeamMatch.m_teamMatchList        List<ChatMsg> @0x20
//
// BattleChatInfo carries campType (0x48) -- the side a message came from -- and
// the history records carry the rendered string, which embeds the channel tag
// ("[Team]", "[All]").
//
// Heap scans return junk hits as well as real objects, so each hit is filtered:
// a hit is only reported when one of its lists decodes. No hooks, no method
// calls, no writes.
(() => {
    const config = Object.assign({ mode: 'chat', scan: true, phase: 'live' },
        typeof PROTOTYPE_OPTIONS === 'undefined' ? {} : PROTOTYPE_OPTIONS);
    const R = createDraftRuntime(config);
    const emit = (e, d) => R.emit(e, Object.assign({ mode: 'chat', phase: config.phase }, d));

    function battleEntry(obj) {
        const out = { klass: R.className(R.objectClass(obj)) };
        for (const f of ['isSelf', 'campType', 'type', 'id', 'time', 'm_state', 'roomChatType']) {
            try {
                const v = R.scalar(obj, f, true);
                if (v !== null && v !== undefined) out[f] = String(v);
            } catch (e) { /* field absent on this type */ }
        }
        for (const f of ['playerName', 'content', 'heroName', 'translate_content']) {
            try {
                const p = R.ref(obj, f, true);
                if (p && !p.isNull()) out[f] = R.string(p);
            } catch (e) { /* field absent */ }
        }
        return out;
    }

    function historyEntry(obj) {
        const out = { klass: R.className(R.objectClass(obj)) };
        for (const f of ['type', 'id', 'campType', 'time']) {
            try {
                const v = R.scalar(obj, f, true);
                if (v !== null && v !== undefined) out[f] = String(v);
            } catch (e) { /* field absent */ }
        }
        for (const f of ['content', 'translate_content', 'playerName']) {
            try {
                const p = R.ref(obj, f, true);
                if (p && !p.isNull()) out[f] = R.string(p);
            } catch (e) { /* field absent */ }
        }
        return out;
    }

    function msgEntry(obj) {
        const out = { klass: R.className(R.objectClass(obj)) };
        for (const f of ['type', 'iSubType', 'iChannelType', 'iChatTime', 'accountID', 'level', 'zoneId']) {
            try {
                const v = R.scalar(obj, f, true);
                if (v !== null && v !== undefined) out[f] = String(v);
            } catch (e) { /* field absent */ }
        }
        for (const f of ['content', 'userName']) {
            try {
                const p = R.ref(obj, f, true);
                if (p && !p.isNull()) out[f] = R.string(p);
            } catch (e) { /* field absent */ }
        }
        return out;
    }

    // Read one list and return {ok, list}; a THROW here means this hit is not a
    // real instance of the class, so the caller skips it silently.
    function readList(obj, listField) {
        const p = R.ref(obj, listField, true);
        if (!p || p.isNull()) return null;
        return R.list(p);
    }

    async function dump(className, fields, reader) {
        const k = R.tryFind(className, '');
        if (!k || k.isNull()) { emit('class_missing', { className }); return; }
        const hits = await R.scan([k]);
        emit('instances', { className, count: hits.length });
        let valid = 0;
        for (const hit of hits) {
            let any = false;
            for (const listField of fields) {
                let l = null;
                try { l = readList(hit.pointer, listField); } catch (e) { continue; }
                if (!l) continue;
                any = true;
                valid++;
                emit('list', { className, listField, status: l.status, count: l.count,
                    elementType: l.elementType, pointer: hit.pointer.toString() });
                for (const p of l.values) {
                    if (!R.valid(p)) continue;
                    try { emit('item', Object.assign({ className, listField }, reader(p))); }
                    catch (e) { /* skip unreadable entry */ }
                }
            }
            if (!any) emit('skip', { className, pointer: hit.pointer.toString(),
                reason: 'no list decoded; not a live instance' });
        }
        emit('valid_instances', { className, valid });
    }

    (async () => {
        try {
            R.init();
            await R.buildIndex();
            await dump('UIBattleChat', ['m_ChatList', 'm_historyChatList'], battleEntry);
            await dump('UIBattleChat', ['m_historyChatList'], historyEntry);
            await dump('UIChatTeamBattle', ['m_TeamBattleChatList'], msgEntry);
            await dump('UIChatTeamMatch', ['m_teamMatchList'], msgEntry);
            emit('summary', { status: 'complete' });
        } catch (e) {
            emit('probe_error', { error: String(e), stack: e.stack });
        }
    })();
})();
