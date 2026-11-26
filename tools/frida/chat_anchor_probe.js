// Read-only, anchor-only read of the in-match chat lists.
//
// No heap scanning. UIBattleChat exposes a private static:
//   private static UIBattleChat instance;   // static offset 0x0
// and the lists:
//   m_PreTransChatList  0x10   List<BattleChatInfo>
//   m_ChatList          0x18   List<BattleChatInfo>   <- carries campType (0x48)
//   m_SurKillTipList    0x20
//   m_historyChatList   0x28   List<HistroyChatRecord> (rendered strings)
//
// BattleChatInfo: isSelf 0x10, playerGuid 0x14, id 0x18, type 0x1c, time 0x20,
// playerName 0x28, content 0x30, heroName 0x38, translate_content 0x40,
// campType 0x48, m_state 0x4c, bInChatList 0x70.
// RoomChatInfo adds roomChatType at 0x74.
//
// The instance is null outside a match, which is a valid answer, not a failure.
(() => {
    const config = Object.assign({ mode: 'chat', phase: 'any', maxRows: 500 },
        typeof PROTOTYPE_OPTIONS === 'undefined' ? {} : PROTOTYPE_OPTIONS);
    const R = createDraftRuntime(config);
    const emit = (e, d) => R.emit(e, Object.assign({ mode: 'chat' }, d));

    function readStatic(k, name) {
        const f = R.field(k, name, true);
        if (!f) { emit('field_missing', { name }); return null; }
        const slot = Memory.alloc(8);
        slot.writePointer(ptr(0));
        R.api.staticValue(f.field, slot);
        return slot.readPointer();
    }

    function scalarOf(obj, name) {
        try { const v = R.scalar(obj, name, true); return v === null ? null : String(v); }
        catch (e) { return null; }
    }

    function stringOf(obj, name) {
        try {
            const p = R.ref(obj, name, true);
            return (p && !p.isNull()) ? R.string(p) : null;
        } catch (e) { return null; }
    }

    function battleEntry(obj) {
        const out = { klass: R.className(R.objectClass(obj)) };
        for (const f of ['isSelf', 'campType', 'type', 'id', 'time', 'm_state', 'roomChatType']) {
            const v = scalarOf(obj, f);
            if (v !== null) out[f] = v;
        }
        for (const f of ['playerName', 'content', 'heroName', 'translate_content']) {
            const v = stringOf(obj, f);
            if (v !== null) out[f] = v;
        }
        return out;
    }

    function historyEntry(obj) {
        const out = { klass: R.className(R.objectClass(obj)) };
        for (const f of ['type', 'id', 'campType', 'time']) {
            const v = scalarOf(obj, f);
            if (v !== null) out[f] = v;
        }
        for (const f of ['content', 'translate_content']) {
            const v = stringOf(obj, f);
            if (v !== null) out[f] = v;
        }
        return out;
    }

    function dumpList(owner, field, reader) {
        let list;
        try { list = R.list(R.ref(owner, field, true), config.maxRows); }
        catch (e) { emit('list_error', { field, error: String(e) }); return; }
        if (!list) { emit('list_missing', { field }); return; }
        emit('list', { field, status: list.status, count: list.count,
            elementType: list.elementType });
        for (const p of list.values) {
            if (!R.valid(p)) continue;
            try { emit('item', Object.assign({ field }, reader(p))); }
            catch (e) { emit('item_error', { field, error: String(e) }); }
        }
    }

    (async () => {
        try {
            R.init();
            await R.buildIndex();
            const k = R.tryFind('UIBattleChat', '');
            if (!k || k.isNull()) { emit('class_missing', { className: 'UIBattleChat' }); return; }

            const inst = readStatic(k, 'instance');
            emit('instance', { pointer: inst ? inst.toString() : null });
            if (!inst || inst.isNull()) {
                emit('summary', { status: 'no_instance_outside_match' });
                return;
            }
            if (!R.isA(inst, k)) emit('warn', { reason: 'static is not a UIBattleChat' });

            dumpList(inst, 'm_PreTransChatList', battleEntry);
            dumpList(inst, 'm_ChatList', battleEntry);
            dumpList(inst, 'm_SurKillTipList', battleEntry);
            dumpList(inst, 'm_historyChatList', historyEntry);
            emit('summary', { status: 'complete' });
        } catch (e) {
            emit('probe_error', { error: String(e), stack: e.stack });
        }
    })();
})();
