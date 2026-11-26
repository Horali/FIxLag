// Read-only, anchor-only dump of the chat-intent vocabulary.
//
// No heap scanning at all. The chain, from the full metadata dump:
//   SystemData.m_SystemConfigInfo   static field, offset 0x0, type SystemConfig
//   SystemConfig._ChatConvertInt    instance offset 0x6d8
//   ChatConvertInt.m_mapChatConvertItem   Dictionary<int, ChatConvertItem>
//   ChatConvertItem { m_iChatMsgId 0x28, m_iChatInt 0x2c, m_sMsg 0x30 }
//
// This is the cheap path: a handful of pointer reads instead of gigabytes of
// scanning, so it cannot stall the game.
(() => {
    const config = Object.assign({ mode: 'chatcfg', phase: 'any' },
        typeof PROTOTYPE_OPTIONS === 'undefined' ? {} : PROTOTYPE_OPTIONS);
    const R = createDraftRuntime(config);
    const emit = (e, d) => R.emit(e, Object.assign({ mode: 'chatcfg', phase: config.phase }, d));

    function readStatic(objClass, name) {
        const f = R.field(objClass, name, true);
        if (!f) { emit('field_missing', { name }); return null; }
        const slot = Memory.alloc(8);
        slot.writePointer(ptr(0));
        R.api.staticValue(f.field, slot);
        return slot.readPointer();
    }

    function itemFields(obj) {
        const out = {};
        for (const f of ['m_iChatMsgId', 'm_iChatInt']) {
            try { const v = R.scalar(obj, f, true); if (v !== null) out[f] = String(v); } catch (e) { /* absent */ }
        }
        try {
            const p = R.ref(obj, 'm_sMsg', true);
            if (p && !p.isNull()) out.m_sMsg = R.string(p);
        } catch (e) { /* absent */ }
        return out;
    }

    (async () => {
        try {
            R.init();
            await R.buildIndex();
            const sysData = R.tryFind('SystemData', '');
            if (!sysData || sysData.isNull()) { emit('class_missing', { className: 'SystemData' }); return; }

            const cfgPtr = readStatic(sysData, 'm_SystemConfigInfo');
            emit('system_config', { pointer: cfgPtr ? cfgPtr.toString() : null });
            if (!cfgPtr || cfgPtr.isNull()) { emit('summary', { status: 'config_not_loaded' }); return; }
            if (!R.isA(cfgPtr, R.tryFind('SystemConfig', ''))) emit('warn', { reason: 'pointer is not a SystemConfig' });

            const conv = R.ref(cfgPtr, '_ChatConvertInt', true);
            emit('chat_convert', { pointer: conv ? conv.toString() : null });
            if (!conv || conv.isNull()) { emit('summary', { status: 'chat_convert_null' }); return; }

            const map = R.ref(conv, 'm_mapChatConvertItem', true);
            const d = R.dictionary(map);
            emit('table', { status: d.status, count: d.count, truncated: d.truncated || false });
            for (const entry of d.entries) {
                const v = entry.value && entry.value.value;
                if (!v || !R.valid(v)) continue;
                try { emit('convert', Object.assign({ key: String(entry.key.value) }, itemFields(v))); }
                catch (e) { emit('entry_error', { error: String(e) }); }
            }
            emit('summary', { status: 'complete' });
        } catch (e) {
            emit('probe_error', { error: String(e), stack: e.stack });
        }
    })();
})();
