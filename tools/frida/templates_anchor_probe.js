// Read-only, static-anchored template & hero table probe.
//
// Zero heap scanning and zero method invocation.
// Static anchors -> TableStreamBase<...>.m_Data -> SharedDictionary.m_dic:
//   - CData_Hero.m_Instance            (m_ID, m_mName, m_Sort[])
//   - CData_BattleAniEmoji.m_Instance  (m_ID, m_mName)
//   - CData_Emoji.m_Instance           (m_EmojiID, m_mEmojiName)
//   - CData_BattleFastChatMessage.m_Instance (m_ID, m_mMessage)
// Targeted locale lookup (no full 114k dump):
//   - CData_AllLanguageTemplete.m_Instance -> m_DataCache / datas / PKHash
//     computed via 32-bit base-31 hash("<Table>_<Column>_<ID>") for wantedIds.
(() => {
    const config = Object.assign(
        {
            mode: 'templates',
            phase: 'any',
            maxRows: 4000,
            wantedShowMessageIds: [10498, 11010, 11011, 11012, 12154, 15338, 15339, 17254, 31471, 31684, 31685, 31686, 33187, 36420, 36421, 48273, 154830],
        },
        typeof PROTOTYPE_OPTIONS === 'undefined' ? {} : PROTOTYPE_OPTIONS
    );
    const R = createDraftRuntime(config);
    const emit = (e, d) => R.emit(e, Object.assign({ mode: 'templates' }, d));

    const ROLE_NAMES = { 1: 'Tank', 2: 'Fighter', 3: 'Assassin', 4: 'Mage', 5: 'Marksman', 6: 'Support' };

    function pkHash(str) {
        let h = 0;
        for (let i = 0; i < str.length; i++) {
            h = (Math.imul(h, 31) + str.charCodeAt(i)) >>> 0;
        }
        return h;
    }

    function readStatic(k, name) {
        const f = R.field(k, name, true);
        if (!f) return null;
        const slot = Memory.alloc(8);
        slot.writePointer(ptr(0));
        R.api.staticValue(f.field, slot);
        const p = slot.readPointer();
        return p && R.valid(p) ? p : null;
    }

    function resolveSharedDic(inst) {
        const data = R.ref(inst, 'm_Data', true);
        if (!data || !R.valid(data)) return null;
        try {
            const d = R.dictionary(data, config.maxRows);
            if (d && d.status === 'ok') return d;
        } catch (_) {}
        const inner = R.ref(data, 'm_dic', true);
        if (inner && R.valid(inner)) {
            return R.dictionary(inner, config.maxRows);
        }
        return null;
    }

    function readInt32Array(arrPtr) {
        if (!arrPtr || !R.valid(arrPtr)) return [];
        const len = arrPtr.add(24).readU64().toNumber();
        if (len < 0 || len > 32) return [];
        const out = [];
        for (let i = 0; i < len; i++) out.push(arrPtr.add(32 + i * 4).readS32());
        return out;
    }

    function readByteArray(arrPtr) {
        if (!arrPtr || !R.valid(arrPtr)) return null;
        const len = arrPtr.add(24).readU64().toNumber();
        if (len <= 0 || len > 16 * 1024 * 1024) return null;
        return new Uint8Array(arrPtr.add(32).readByteArray(len));
    }

    function readTableString(buf, off) {
        let ln = 0, shift = 0, p = off;
        while (p < buf.length) {
            const b = buf[p++];
            ln |= (b & 0x7f) << shift;
            if (!(b & 0x80)) break;
            shift += 7;
        }
        if (p + ln > buf.length) return '';
        let out = '';
        for (let i = 0; i < ln; i++) out += String.fromCharCode(buf[p + i]);
        try {
            return decodeURIComponent(escape(out));
        } catch (_) {
            return out;
        }
    }

    function indexMulongTable(buf) {
        if (!buf || buf.length < 40) return null;
        const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
        const dicOff = view.getUint32(29, true);
        if (dicOff + 8 > buf.length) return null;
        const dicCnt = view.getUint32(dicOff + 4, true);
        const map = new Map();
        let p = dicOff + 8;
        for (let i = 0; i < dicCnt && p + 8 <= buf.length; i++, p += 8) {
            map.set(view.getUint32(p, true), view.getUint32(p + 4, true));
        }
        return map;
    }

    function dumpTableSummary(className, reader) {
        const k = R.tryFind(className, '');
        if (!k || k.isNull()) { emit('table_missing', { className }); return; }
        const inst = readStatic(k, 'm_Instance');
        if (!inst) { emit('table_null', { className }); return; }
        const d = resolveSharedDic(inst);
        if (!d) { emit('table_no_dic', { className }); return; }
        emit('table_ok', { className, count: d.count });
        for (const e of d.entries) {
            const el = e.value && e.value.value;
            if (!el || !R.valid(el)) continue;
            try { reader(e.key.value, el); } catch (_) {}
        }
    }

    (async () => {
        try {
            R.init();
            await R.buildIndex();

            // 1. Heroes: id, name, roles
            dumpTableSummary('CData_Hero', (key, el) => {
                if (key > 200) return;
                const name = R.scalar(el, 'm_mName', true);
                const sortPtr = R.ref(el, 'm_Sort', true);
                const sorts = readInt32Array(sortPtr).map(v => ROLE_NAMES[v] || String(v));
                emit('hero', { id: key, name, role: sorts.join('/') });
            });

            // 2. BattleAniEmoji (12/<id>) & Emoji (2/<id>)
            dumpTableSummary('CData_BattleAniEmoji', (key, el) => {
                emit('ani_emoji', { id: key, name: R.scalar(el, 'm_mName', true) });
            });
            dumpTableSummary('CData_Emoji', (key, el) => {
                emit('emoji', { id: key, name: R.scalar(el, 'm_mEmojiName', true) });
            });

            // 3. BattleFastChatMessage (in-match quick-chat)
            dumpTableSummary('CData_BattleFastChatMessage', (key, el) => {
                emit('fastchat', { id: key, text: R.scalar(el, 'm_mMessage', true) });
            });

            // 4. Targeted ShowMessage lookup via CData_AllLanguageTemplete raw bytes (no full locale dump)
            const langK = R.tryFind('CData_AllLanguageTemplete', '');
            const langInst = langK && !langK.isNull() ? readStatic(langK, 'm_Instance') : null;
            if (langInst) {
                const rawPtr = R.ref(langInst, 'datas', true) || R.ref(langInst, 'cacheBytes', true);
                const buf = readByteArray(rawPtr);
                const idx = indexMulongTable(buf);
                if (idx) {
                    const resolved = {};
                    for (const sid of config.wantedShowMessageIds) {
                        const off = idx.get(pkHash('ShowMessage_mMessage_' + sid));
                        if (off !== undefined) resolved[String(sid)] = readTableString(buf, off);
                    }
                    emit('targeted_strings', { count: Object.keys(resolved).length, resolved });
                } else {
                    emit('lang_note', { status: 'cache_only_or_lazy', instance: langInst.toString() });
                }
            }

            emit('summary', { status: 'complete' });
        } catch (e) {
            emit('probe_error', { error: String(e), stack: e.stack });
            emit('summary', { status: 'error' });
        }
    })();
})();
