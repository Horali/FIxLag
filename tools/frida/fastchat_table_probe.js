// Read-only, anchor-only read of the quick-chat table (CData_BattleFastChatMessage).
//
// No heap scan and no method calls. The chain:
//   CData_BattleFastChatMessage.m_Instance   static field
//   -> walk the runtime parent chain and print every resolved instance field.
//      The closed generic base (TableStreamBase<int,...>) has real offsets here,
//      even though the metadata dump shows 0x0 for the open definition.
//   -> m_Data (SharedDictionary<int, Element>) and m_keyDic (IDictionary<int,int>)
//   -> enumerate rows, check each row's class and m_ID against its key.
(() => {
    const config = Object.assign({ mode: 'fastchat', phase: 'any', maxRows: 2000 },
        typeof PROTOTYPE_OPTIONS === 'undefined' ? {} : PROTOTYPE_OPTIONS);
    const R = createDraftRuntime(config);
    const emit = (e, d) => R.emit(e, Object.assign({ mode: 'fastchat' }, d));

    function readStatic(k, name) {
        const f = R.field(k, name, true);
        if (!f) { emit('field_missing', { name }); return null; }
        const slot = Memory.alloc(8);
        slot.writePointer(ptr(0));
        R.api.staticValue(f.field, slot);
        return slot.readPointer();
    }

    // Print the class chain with every instance field and its resolved offset.
    function layout(k, label) {
        const chain = [];
        let c = k;
        for (let d = 0; !c.isNull() && d < 16; d++, c = R.api.parent(c)) {
            const all = R.fields(c);
            const inst = Object.values(all).filter(f => !(f.flags & 16))
                .map(f => ({ name: f.name, offset: '0x' + f.offset.toString(16), type: f.type }));
            const size = R.api.instanceSize ? R.api.instanceSize(c) : null;
            chain.push({ cls: R.displayClassName(c), instanceSize: size === null ? null : '0x' + size.toString(16), fields: inst });
        }
        emit('layout', { label, chain });
    }

    function tryDict(obj, label) {
        try {
            const d = R.dictionary(obj, config.maxRows);
            emit('dict', { label, status: d.status, count: d.count, allocated: d.allocatedCount,
                keyType: d.keyType, valueType: d.valueType, stride: d.stride });
            return d;
        } catch (e) {
            emit('dict_error', { label, error: String(e) });
            return null;
        }
    }

    function readRow(el) {
        const out = {};
        for (const f of Object.values(R.fields(R.objectClass(el)))) {
            if (f.flags & 16) continue;
            try {
                if (f.type === 'System.String') { const p = R.pointer(el, f.offset); out[f.name] = p.isNull() ? null : R.string(p, 512); }
                else out[f.name] = R.scalar(el, f.name, true);
            } catch (e) { /* non-scalar: skip */ }
        }
        // Base-class scalars too (TableElementBase).
        try { out.m_ID = R.scalar(el, 'm_ID', true); } catch (e) { /* absent */ }
        return out;
    }

    (async () => {
        try {
            R.init();
            await R.buildIndex();
            const k = R.tryFind('CData_BattleFastChatMessage', '');
            const elK = R.tryFind('CData_BattleFastChatMessage_Element', '');
            if (!k || k.isNull()) { emit('summary', { status: 'class_missing' }); return; }

            const inst = readStatic(k, 'm_Instance');
            emit('instance', { pointer: inst ? inst.toString() : null });
            if (!inst || inst.isNull()) { emit('summary', { status: 'instance_null' }); return; }
            emit('instance_check', { isA: R.isA(inst, k), runtimeClass: R.displayClassName(R.objectClass(inst)) });

            layout(R.objectClass(inst), 'instance');

            const fData = R.field(R.objectClass(inst), 'm_Data', true);
            const fKey = R.field(R.objectClass(inst), 'm_keyDic', true);
            emit('resolved', {
                m_Data: fData ? { offset: '0x' + fData.offset.toString(16), type: fData.type } : null,
                m_keyDic: fKey ? { offset: '0x' + fKey.offset.toString(16), type: fKey.type } : null,
            });

            // Load state. m_keyDic can be emptied after rows load, so its count is
            // not a safe completeness test; dataRowNum (header row total) is.
            const state = {};
            for (const n of ['m_bHasInited', 'isOpenLazyInit', 'm_Data_IsFullLoaded', 'dataRowNum']) {
                try { state[n] = R.scalar(inst, n, true); } catch (e) { state[n] = null; }
            }
            emit('load_state', state);

            let keyCount = null;
            if (fKey) {
                const kd = R.pointer(inst, fKey.offset);
                emit('keydic', { pointer: kd.toString(), runtimeClass: kd.isNull() ? null : R.displayClassName(R.objectClass(kd)) });
                if (!kd.isNull()) { const d = tryDict(kd, 'm_keyDic'); if (d) keyCount = d.count; }
            }

            if (!fData) { emit('summary', { status: 'm_Data_missing' }); return; }
            const data = R.pointer(inst, fData.offset);
            emit('data', { pointer: data.toString(), runtimeClass: data.isNull() ? null : R.displayClassName(R.objectClass(data)) });
            if (data.isNull()) { emit('summary', { status: 'm_Data_null', keyCount }); return; }
            layout(R.objectClass(data), 'm_Data');

            // SharedDictionary may be a Dictionary itself, or wrap one.
            let d = tryDict(data, 'm_Data');
            if (!d) {
                for (const f of Object.values(R.fields(R.objectClass(data)))) {
                    if (f.flags & 16 || !/Dictionary/.test(f.type)) continue;
                    const inner = R.pointer(data, f.offset);
                    emit('inner_candidate', { name: f.name, type: f.type, pointer: inner.toString() });
                    if (!inner.isNull()) { d = tryDict(inner, 'm_Data.' + f.name); if (d) break; }
                }
            }
            if (!d) { emit('summary', { status: 'no_dictionary_decoded', keyCount }); return; }

            let ok = 0, bad = 0;
            for (const e of d.entries) {
                const key = e.key.value, el = e.value.value;
                if (!el || !R.valid(el)) { bad++; emit('row_bad', { key, reason: 'null value' }); continue; }
                const classOk = elK && !elK.isNull() ? R.isA(el, elK) : null;
                const row = readRow(el);
                const idOk = row.m_ID === key;
                if (classOk !== false && idOk) ok++; else bad++;
                emit('row', { key, classOk, idOk, row });
            }
            emit('summary', { status: 'complete', dataCount: d.count, keyCount, rowsOk: ok, rowsBad: bad,
                dataRowNum: state.dataRowNum, fullLoadedFlag: state.m_Data_IsFullLoaded,
                // Live result: the flag stayed false and m_keyDic was empty while all
                // rows were present, so compare against the header row total instead.
                partial: typeof state.dataRowNum === 'number' ? d.count < state.dataRowNum : null });
        } catch (e) {
            emit('probe_error', { error: String(e), stack: e.stack });
            emit('summary', { status: 'error' });
        }
    })();
})();
