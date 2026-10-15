"""JNI (Java Native Interface) modeling for Android native libraries.

Native methods receive a `JNIEnv *` as their first argument. `env` points at a `JNINativeInterface`
dispatch table, so a JNI call compiles to a double indirect load — `(*env)->Fn(env, …)` — which the
lifter renders as `*(int64_t *)(*(int64_t *)env + 0xOFF)(env, …)`. The slot offset identifies the
function; this module maps it back to the name (JEB/IDA ship this; it is the single biggest
readability win for Android native code) and reads `RegisterNatives` tables.

`ORDER` is the exact field order of `JNINativeInterface_` from the JNI spec (OpenJDK jni.h), so
offset / pointer-size = index into `ORDER`. The first four slots are reserved.
"""
import re

ORDER = [
    "reserved0", "reserved1", "reserved2", "reserved3",
    "GetVersion", "DefineClass", "FindClass",
    "FromReflectedMethod", "FromReflectedField", "ToReflectedMethod",
    "GetSuperclass", "IsAssignableFrom", "ToReflectedField",
    "Throw", "ThrowNew", "ExceptionOccurred", "ExceptionDescribe", "ExceptionClear",
    "FatalError", "PushLocalFrame", "PopLocalFrame",
    "NewGlobalRef", "DeleteGlobalRef", "DeleteLocalRef", "IsSameObject",
    "NewLocalRef", "EnsureLocalCapacity",
    "AllocObject", "NewObject", "NewObjectV", "NewObjectA",
    "GetObjectClass", "IsInstanceOf", "GetMethodID",
    "CallObjectMethod", "CallObjectMethodV", "CallObjectMethodA",
    "CallBooleanMethod", "CallBooleanMethodV", "CallBooleanMethodA",
    "CallByteMethod", "CallByteMethodV", "CallByteMethodA",
    "CallCharMethod", "CallCharMethodV", "CallCharMethodA",
    "CallShortMethod", "CallShortMethodV", "CallShortMethodA",
    "CallIntMethod", "CallIntMethodV", "CallIntMethodA",
    "CallLongMethod", "CallLongMethodV", "CallLongMethodA",
    "CallFloatMethod", "CallFloatMethodV", "CallFloatMethodA",
    "CallDoubleMethod", "CallDoubleMethodV", "CallDoubleMethodA",
    "CallVoidMethod", "CallVoidMethodV", "CallVoidMethodA",
    "CallNonvirtualObjectMethod", "CallNonvirtualObjectMethodV", "CallNonvirtualObjectMethodA",
    "CallNonvirtualBooleanMethod", "CallNonvirtualBooleanMethodV", "CallNonvirtualBooleanMethodA",
    "CallNonvirtualByteMethod", "CallNonvirtualByteMethodV", "CallNonvirtualByteMethodA",
    "CallNonvirtualCharMethod", "CallNonvirtualCharMethodV", "CallNonvirtualCharMethodA",
    "CallNonvirtualShortMethod", "CallNonvirtualShortMethodV", "CallNonvirtualShortMethodA",
    "CallNonvirtualIntMethod", "CallNonvirtualIntMethodV", "CallNonvirtualIntMethodA",
    "CallNonvirtualLongMethod", "CallNonvirtualLongMethodV", "CallNonvirtualLongMethodA",
    "CallNonvirtualFloatMethod", "CallNonvirtualFloatMethodV", "CallNonvirtualFloatMethodA",
    "CallNonvirtualDoubleMethod", "CallNonvirtualDoubleMethodV", "CallNonvirtualDoubleMethodA",
    "CallNonvirtualVoidMethod", "CallNonvirtualVoidMethodV", "CallNonvirtualVoidMethodA",
    "GetFieldID",
    "GetObjectField", "GetBooleanField", "GetByteField", "GetCharField", "GetShortField",
    "GetIntField", "GetLongField", "GetFloatField", "GetDoubleField",
    "SetObjectField", "SetBooleanField", "SetByteField", "SetCharField", "SetShortField",
    "SetIntField", "SetLongField", "SetFloatField", "SetDoubleField",
    "GetStaticMethodID",
    "CallStaticObjectMethod", "CallStaticObjectMethodV", "CallStaticObjectMethodA",
    "CallStaticBooleanMethod", "CallStaticBooleanMethodV", "CallStaticBooleanMethodA",
    "CallStaticByteMethod", "CallStaticByteMethodV", "CallStaticByteMethodA",
    "CallStaticCharMethod", "CallStaticCharMethodV", "CallStaticCharMethodA",
    "CallStaticShortMethod", "CallStaticShortMethodV", "CallStaticShortMethodA",
    "CallStaticIntMethod", "CallStaticIntMethodV", "CallStaticIntMethodA",
    "CallStaticLongMethod", "CallStaticLongMethodV", "CallStaticLongMethodA",
    "CallStaticFloatMethod", "CallStaticFloatMethodV", "CallStaticFloatMethodA",
    "CallStaticDoubleMethod", "CallStaticDoubleMethodV", "CallStaticDoubleMethodA",
    "CallStaticVoidMethod", "CallStaticVoidMethodV", "CallStaticVoidMethodA",
    "GetStaticFieldID",
    "GetStaticObjectField", "GetStaticBooleanField", "GetStaticByteField", "GetStaticCharField",
    "GetStaticShortField", "GetStaticIntField", "GetStaticLongField", "GetStaticFloatField",
    "GetStaticDoubleField",
    "SetStaticObjectField", "SetStaticBooleanField", "SetStaticByteField", "SetStaticCharField",
    "SetStaticShortField", "SetStaticIntField", "SetStaticLongField", "SetStaticFloatField",
    "SetStaticDoubleField",
    "NewString", "GetStringLength", "GetStringChars", "ReleaseStringChars",
    "NewStringUTF", "GetStringUTFLength", "GetStringUTFChars", "ReleaseStringUTFChars",
    "GetArrayLength", "NewObjectArray", "GetObjectArrayElement", "SetObjectArrayElement",
    "NewBooleanArray", "NewByteArray", "NewCharArray", "NewShortArray",
    "NewIntArray", "NewLongArray", "NewFloatArray", "NewDoubleArray",
    "GetBooleanArrayElements", "GetByteArrayElements", "GetCharArrayElements",
    "GetShortArrayElements", "GetIntArrayElements", "GetLongArrayElements",
    "GetFloatArrayElements", "GetDoubleArrayElements",
    "ReleaseBooleanArrayElements", "ReleaseByteArrayElements", "ReleaseCharArrayElements",
    "ReleaseShortArrayElements", "ReleaseIntArrayElements", "ReleaseLongArrayElements",
    "ReleaseFloatArrayElements", "ReleaseDoubleArrayElements",
    "GetBooleanArrayRegion", "GetByteArrayRegion", "GetCharArrayRegion", "GetShortArrayRegion",
    "GetIntArrayRegion", "GetLongArrayRegion", "GetFloatArrayRegion", "GetDoubleArrayRegion",
    "SetBooleanArrayRegion", "SetByteArrayRegion", "SetCharArrayRegion", "SetShortArrayRegion",
    "SetIntArrayRegion", "SetLongArrayRegion", "SetFloatArrayRegion", "SetDoubleArrayRegion",
    "RegisterNatives", "UnregisterNatives",
    "MonitorEnter", "MonitorExit", "GetJavaVM",
    "GetStringRegion", "GetStringUTFRegion",
    "GetPrimitiveArrayCritical", "ReleasePrimitiveArrayCritical",
    "GetStringCritical", "ReleaseStringCritical",
    "NewWeakGlobalRef", "DeleteWeakGlobalRef", "ExceptionCheck",
    "NewDirectByteBuffer", "GetDirectBufferAddress", "GetDirectBufferCapacity",
    "GetObjectRefType",
]


def slot_name(offset, ptr):
    """Name of the JNINativeInterface function at byte `offset` for a `ptr`-byte pointer, or None."""
    if ptr not in (4, 8) or offset < 0 or offset % ptr:
        return None
    i = offset // ptr
    return ORDER[i] if 4 <= i < len(ORDER) else None


# `t = *(int64_t *)(*(int64_t *)ENV + 0xOFF)(ENV, args…)`  →  a JNIEnv dispatch. The cast width
# (int64_t / int32_t) also tells us the pointer size, so no architecture argument is needed.
_CALL = re.compile(
    r"\*\(u?int(?P<w>64|32)_t \*\)\(\*\(u?int(?:64|32)_t \*\)(?P<base>[A-Za-z_]\w*)"
    r"\s*\+\s*(?P<off>0x[0-9a-fA-F]+)\)\((?P<args>[^;()]*)\)")


def name_calls(text):
    """Rewrite JNIEnv dispatch calls in decompiled C to `env->FunctionName(args)`."""
    def sub(m):
        name = slot_name(int(m.group("off"), 16), 8 if m.group("w") == "64" else 4)
        if not name:
            return m.group(0)
        base, args = m.group("base"), m.group("args").strip()
        if args == base:                       # env was the only (receiver) argument
            args = ""
        elif args.startswith(base + ","):      # drop the implicit receiver
            args = args[len(base) + 1:].lstrip()
        return f"{base}->{name}({args})"
    return _CALL.sub(sub, text)


_SIG = re.compile(r"\((?:\[*(?:[ZBCSIJFD]|L[^;()\[]+;))*\)\[*(?:[ZBCSIJFDV]|L[^;()\[]+;)")
_IDENT = re.compile(r"[A-Za-z_$][\w$]*")


def _cstr(im, va, limit=256):
    s = im.read(va, limit).split(b"\0", 1)[0]
    try:
        return s.decode("ascii")
    except UnicodeDecodeError:
        return None


def _data(im):
    return [(s, im.read(s.va, s.size)) for s in im.sections
            if not s.code and s.offset and s.name not in (".bss", ".tbss")]


def native_tables(im):
    """Statically-registered natives: find `JNINativeMethod {char *name; char *sig; void *fn;}`
    records in data (what JNI_OnLoad hands to RegisterNatives) by their shape — a pointer to a JNI
    signature string, preceded by a pointer to an identifier and followed by a pointer to code.
    No call-site dataflow needed: the table itself is self-describing.
    Returns {fn_addr: (java_name, signature, thumb)}; `thumb` is the ARM mode bit of the pointer."""
    ptr = im.arch.bits // 8
    data = _data(im)
    sigs = {}                                   # va -> signature string
    for s, raw in data:
        for m in re.finditer(rb"\(([\x21-\x7e]*?)\)[\x21-\x7e]+\0", raw):
            txt = m.group()[:-1].decode()
            if _SIG.fullmatch(txt):
                sigs[s.va + m.start()] = txt
    if not sigs:
        return {}
    # PIC libraries keep their pointers in relocations (the file word is 0): consult fixups first.
    by_val = {}
    for slot, v in im.fixups.items():
        by_val.setdefault(v, []).append(slot)

    def at(va):
        return im.fixups.get(va) or int.from_bytes(im.read(va, ptr), "little")

    out = {}
    for sva, sig in sigs.items():
        slots = list(by_val.get(sva, ()))
        needle = sva.to_bytes(ptr, "little")
        for s, raw in data:                     # non-PIC / REL: the pointer is in the file bytes
            o = raw.find(needle)
            while o != -1:
                if (s.va + o) % ptr == 0:
                    slots.append(s.va + o)
                o = raw.find(needle, o + 1)
        for slot in slots:
            name, fn = _cstr(im, at(slot - ptr)), at(slot + ptr)
            if fn and name and _IDENT.fullmatch(name) and im.is_code(fn & ~1):
                out[fn & ~1] = (name, sig, bool(fn & 1) and im.arch.name == "arm")
    return out
