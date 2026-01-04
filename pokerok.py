#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
анализ pokerok.apk
"""

from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import os
import struct
import sys
import zipfile
from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional, Tuple


def human_size(n: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    x = float(n)
    for u in units:
        if x < 1024 or u == units[-1]:
            return f"{x:.2f} {u}"
        x /= 1024.0
    return f"{n} B"


def file_hashes(path: str, chunk_size: int = 1024 * 1024) -> Dict[str, str]:
    h_md5 = hashlib.md5()
    h_sha1 = hashlib.sha1()
    h_sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            h_md5.update(chunk)
            h_sha1.update(chunk)
            h_sha256.update(chunk)
    return {"md5": h_md5.hexdigest(), "sha1": h_sha1.hexdigest(), "sha256": h_sha256.hexdigest()}


def is_zip(path: str) -> bool:
    try:
        return zipfile.is_zipfile(path)
    except Exception:
        return False


def read_zip_inventory(apk_path: str, max_list: int = 50) -> Dict[str, Any]:
    inv: Dict[str, Any] = {}
    with zipfile.ZipFile(apk_path, "r") as z:
        infos = z.infolist()
        names = [i.filename for i in infos]

        inv["file_count"] = len(infos)
        inv["total_uncompressed_bytes"] = sum(i.file_size for i in infos)
        inv["total_compressed_bytes"] = sum(i.compress_size for i in infos)

        # ключевые файлы
        key_files = [
            "AndroidManifest.xml",
            "classes.dex",
            "resources.arsc",
            "META-INF/MANIFEST.MF",
        ]
        inv["key_files_present"] = {k: (k in names) for k in key_files}

        # multidex
        dex_files = [n for n in names if n.startswith("classes") and n.endswith(".dex")]
        inv["dex_files"] = sorted(dex_files)
        inv["multidex"] = len(dex_files) > 1

        # нативные библиотеки
        so_files = [n for n in names if n.startswith("lib/") and n.endswith(".so")]
        abi_counter = Counter()
        for n in so_files:
            parts = n.split("/")
            if len(parts) >= 3:
                abi_counter[parts[1]] += 1
        inv["native_libs"] = {
            "count": len(so_files),
            "abis": dict(sorted(abi_counter.items(), key=lambda x: (-x[1], x[0]))),
        }

        # признаки v1-подписи
        meta_inf = [n for n in names if n.startswith("META-INF/")]
        sig_files = [n for n in meta_inf if n.upper().endswith((".RSA", ".DSA", ".EC"))]
        inv["v1_signature_files"] = sorted(sig_files)
        inv["has_meta_inf_manifest_mf"] = "META-INF/MANIFEST.MF" in names

        # частотность каталогов верхнего уровня
        top_level = []
        for n in names:
            p = n.split("/", 1)[0]
            top_level.append(p)
        inv["top_level_entries"] = dict(Counter(top_level).most_common(20))

        # список самых больших файлов (по распакованному размеру)
        biggest = sorted(infos, key=lambda i: i.file_size, reverse=True)[: min(max_list, len(infos))]
        inv["largest_files"] = [
            {"name": i.filename, "bytes": i.file_size, "human": human_size(i.file_size)} for i in biggest
        ]

        # несколько первых файлов (для общей картины)
        sample = sorted(infos, key=lambda i: i.filename)[: min(max_list, len(infos))]
        inv["sample_files"] = [i.filename for i in sample]

    return inv


# ---- APK Signing Block (v2/v3) detection (best-effort) ----

EOCD_SIG = b"PK\x05\x06"
EOCD_MIN_LEN = 22
EOCD_MAX_COMMENT = 0xFFFF  # 65535


def find_eocd(f) -> Optional[int]:
    """
    Находит смещение EOCD (End of Central Directory).
    EOCD находится в конце файла: последние 22..(22+65535) байт.
    """
    f.seek(0, os.SEEK_END)
    size = f.tell()
    read_size = min(size, EOCD_MIN_LEN + EOCD_MAX_COMMENT)
    f.seek(size - read_size, os.SEEK_SET)
    data = f.read(read_size)

    # ищем последнюю сигнатуру EOCD
    idx = data.rfind(EOCD_SIG)
    if idx < 0:
        return None
    return (size - read_size) + idx


def parse_eocd(data: bytes) -> Optional[Dict[str, int]]:
    """
    Разбор EOCD: важно получить offset начала Central Directory.
    Формат EOCD (22 bytes + comment):
      0  4  signature
      4  2  disk_no
      6  2  cd_start_disk
      8  2  entries_this_disk
      10 2  entries_total
      12 4  cd_size
      16 4  cd_offset
      20 2  comment_len
    """
    if len(data) < EOCD_MIN_LEN or data[:4] != EOCD_SIG:
        return None
    fields = struct.unpack_from("<4sHHHHIIH", data, 0)
    _, disk_no, cd_start_disk, ent_disk, ent_total, cd_size, cd_offset, comment_len = fields
    return {
        "disk_no": disk_no,
        "cd_start_disk": cd_start_disk,
        "entries_this_disk": ent_disk,
        "entries_total": ent_total,
        "cd_size": cd_size,
        "cd_offset": cd_offset,
        "comment_len": comment_len,
    }


APK_SIG_MAGIC = b"APK Sig Block 42"  # 16 bytes


def detect_apk_signing_block(apk_path: str) -> Dict[str, Any]:
    """
    Best-effort определение APK Signing Block (v2/v3).
    Алгоритм:
    - находим EOCD -> берём cd_offset (offset Central Directory)
    - APK Signing Block (если есть) расположен непосредственно перед Central Directory
      и заканчивается magic "APK Sig Block 42"
    - внутри блока есть пары (len, id+value). По ID можно понять v2/v3.
    """
    out: Dict[str, Any] = {
        "has_apk_signing_block": False,
        "v2_signature": False,
        "v3_signature": False,
        "details": {},
    }

    try:
        with open(apk_path, "rb") as f:
            eocd_off = find_eocd(f)
            if eocd_off is None:
                out["details"]["error"] = "EOCD not found"
                return out

            f.seek(eocd_off)
            eocd_data = f.read(EOCD_MIN_LEN)
            e = parse_eocd(eocd_data)
            if not e:
                out["details"]["error"] = "EOCD parse failed"
                return out

            cd_offset = e["cd_offset"]
            out["details"]["central_directory_offset"] = cd_offset

            # magic расположен в конце Signing Block; проверим наличие magic прямо перед CD:
            magic_pos = cd_offset - len(APK_SIG_MAGIC)
            if magic_pos < 0:
                return out

            f.seek(magic_pos, os.SEEK_SET)
            magic = f.read(len(APK_SIG_MAGIC))
            if magic != APK_SIG_MAGIC:
                return out  # signing block не найден (или zipalign/неподдерживаемый формат)

            # если magic на месте, читаем "size" в конце блока (8 байт перед magic)
            size_end_pos = cd_offset - len(APK_SIG_MAGIC) - 8
            if size_end_pos < 0:
                return out
            f.seek(size_end_pos, os.SEEK_SET)
            (block_size,) = struct.unpack("<Q", f.read(8))

            # block_size — размер блока без первых 8 байт (по формату). Проверим разумность.
            block_total = block_size + 8  # включая первое поле size
            block_start = cd_offset - block_total
            if block_start < 0:
                out["details"]["error"] = "Signing block start < 0"
                return out

            # читаем весь блок и проверяем согласованность с первым size
            f.seek(block_start, os.SEEK_SET)
            blob = f.read(block_total)
            if len(blob) != block_total:
                out["details"]["error"] = "Short read signing block"
                return out

            (first_size,) = struct.unpack_from("<Q", blob, 0)
            if first_size != block_size:
                out["details"]["warning"] = "Size mismatch in signing block"

            out["has_apk_signing_block"] = True
            out["details"]["signing_block_start"] = block_start
            out["details"]["signing_block_size"] = int(block_size)

            # парсим последовательность ID-value (после первых 8 байт, до последних 24 байт [size+magic])
            # структура: uint64 len; then len bytes: uint32 id; (len-4) value
            # будем безопасно и поверхностно проходить, не декодируя value
            cursor = 8
            end = len(blob) - 24  # последние 8(size)+16(magic)
            ids = set()
            pair_count = 0

            while cursor + 8 <= end:
                (pair_len,) = struct.unpack_from("<Q", blob, cursor)
                cursor += 8
                if pair_len < 4 or cursor + pair_len > end:
                    break
                (pair_id,) = struct.unpack_from("<I", blob, cursor)
                ids.add(pair_id)
                pair_count += 1
                cursor += pair_len

            out["details"]["signing_block_pair_count"] = pair_count
            out["details"]["signing_block_ids_hex"] = sorted([f"0x{v:08x}" for v in ids])

            # известные ID:
            # v2: 0x7109871a, v3: 0xf05368c0
            if 0x7109871A in ids:
                out["v2_signature"] = True
            if 0xF05368C0 in ids:
                out["v3_signature"] = True

    except Exception as ex:
        out["details"]["error"] = f"{type(ex).__name__}: {ex}"

    return out


# ---- Optional: androguard extraction ----

def try_androguard(apk_path: str) -> Optional[Dict[str, Any]]:
    """
    Пытается использовать androguard, если установлен.
    Возвращает словарь с метаданными или None.
    """
    try:
        from androguard.core.apk import APK  # type: ignore
    except Exception:
        return None

    try:
        a = APK(apk_path)
        info: Dict[str, Any] = {}

        info["package"] = a.get_package()
        info["app_name"] = a.get_app_name()
        info["version_name"] = a.get_androidversion_name()
        info["version_code"] = a.get_androidversion_code()
        info["min_sdk"] = a.get_min_sdk_version()
        info["target_sdk"] = a.get_target_sdk_version()

        perms = sorted(a.get_permissions() or [])
        info["permissions"] = perms
        info["permissions_count"] = len(perms)

        # Компоненты — могут быть None
        def _safe_list(x):
            return sorted(x) if x else []

        info["activities"] = _safe_list(a.get_activities())
        info["services"] = _safe_list(a.get_services())
        info["receivers"] = _safe_list(a.get_receivers())
        info["providers"] = _safe_list(a.get_providers())

        # Сертификаты (androguard может вытащить инфу, но зависит от версии)
        try:
            certs = a.get_certificates()
            if certs:
                info["certificates_count"] = len(certs)
        except Exception:
            pass

        return info
    except Exception as ex:
        return {"error": f"{type(ex).__name__}: {ex}", "note": "androguard available but failed to parse"}


def analyze_apk(apk_path: str) -> Dict[str, Any]:
    if not os.path.isfile(apk_path):
        raise FileNotFoundError(apk_path)

    st = os.stat(apk_path)
    base: Dict[str, Any] = {
        "path": os.path.abspath(apk_path),
        "filename": os.path.basename(apk_path),
        "size_bytes": st.st_size,
        "size_human": human_size(st.st_size),
        "mtime": _dt.datetime.fromtimestamp(st.st_mtime).isoformat(sep=" ", timespec="seconds"),
    }

    base["hashes"] = file_hashes(apk_path)

    base["is_zip"] = is_zip(apk_path)
    if base["is_zip"]:
        base["zip_inventory"] = read_zip_inventory(apk_path)
    else:
        base["zip_inventory"] = None

    # подписи
    base["signing"] = detect_apk_signing_block(apk_path)

    # v1 (по содержимому zip) — добавим агрегатный флаг
    if base["zip_inventory"]:
        v1_files = base["zip_inventory"].get("v1_signature_files") or []
        has_mf = bool(base["zip_inventory"].get("has_meta_inf_manifest_mf"))
        base["signing"]["v1_signature_likely"] = bool(v1_files and has_mf)
        base["signing"]["v1_signature_files"] = v1_files

        # "v4" часто лежит отдельно как .idsig рядом с apk — проверим рядом
        idsig_path = apk_path + ".idsig"
        base["signing"]["v4_idsig_present_next_to_apk"] = os.path.isfile(idsig_path)

    # опционально androguard
    base["androguard"] = try_androguard(apk_path)

    return base


def print_human(report: Dict[str, Any]) -> None:
    print("== ФАЙЛ ==")
    print("Путь:", report["path"])
    print("Размер:", report["size_human"], f"({report['size_bytes']} bytes)")
    print("Изменён:", report["mtime"])
    print("\n== ХЭШИ ==")
    for k, v in report["hashes"].items():
        print(f"{k.upper():7} {v}")

    print("\n== APK/ZIP ==")
    print("ZIP:", "да" if report["is_zip"] else "нет")
    inv = report.get("zip_inventory")
    if inv:
        print("Файлов внутри:", inv["file_count"])
        print("Сжато:", human_size(inv["total_compressed_bytes"]), " / Распаковано:", human_size(inv["total_uncompressed_bytes"]))
        print("Ключевые файлы:")
        for k, ok in inv["key_files_present"].items():
            print(f"  - {k}: {'есть' if ok else 'нет'}")
        print("DEX:", ", ".join(inv["dex_files"]) if inv["dex_files"] else "нет")
        print("Multidex:", "да" if inv["multidex"] else "нет")
        nl = inv["native_libs"]
        print("Native libs (.so):", nl["count"])
        if nl["abis"]:
            print("ABI:", ", ".join([f"{abi}({cnt})" for abi, cnt in nl["abis"].items()]))

        print("\nТоп верхних элементов (частота):")
        for name, cnt in inv["top_level_entries"].items():
            print(f"  {name}: {cnt}")

        print("\nСамые большие файлы:")
        for lf in inv["largest_files"][:10]:
            print(f"  {lf['human']:>10}  {lf['name']}")

    print("\n== ПОДПИСЬ (best-effort) ==")
    s = report["signing"]
    v1 = s.get("v1_signature_likely", False)
    print("v1 (META-INF):", "похоже да" if v1 else "нет/неизвестно")
    if s.get("v1_signature_files"):
        for n in s["v1_signature_files"]:
            print("  -", n)

    print("APK Signing Block:", "да" if s.get("has_apk_signing_block") else "нет/неизвестно")
    print("v2:", "да" if s.get("v2_signature") else "нет/неизвестно")
    print("v3:", "да" if s.get("v3_signature") else "нет/неизвестно")
    print("v4 .idsig рядом:", "да" if s.get("v4_idsig_present_next_to_apk") else "нет")

    details = s.get("details") or {}
    if details.get("error"):
        print("Signing details error:", details["error"])
    elif details.get("warning"):
        print("Signing details warning:", details["warning"])

    ag = report.get("androguard")
    if ag:
        print("\n== ANDROGUARD (опционально) ==")
        if "error" in ag:
            print("Ошибка:", ag["error"])
            if "note" in ag:
                print("Примечание:", ag["note"])
        else:
            print("Package:", ag.get("package"))
            print("App name:", ag.get("app_name"))
            print("Version:", ag.get("version_name"), f"(code {ag.get('version_code')})")
            print("SDK:", f"min {ag.get('min_sdk')} / target {ag.get('target_sdk')}")
            print("Permissions:", ag.get("permissions_count", 0))
            # чтобы не печатать километры — покажем первые 20
            perms = ag.get("permissions") or []
            if perms:
                for p in perms[:20]:
                    print("  -", p)
                if len(perms) > 20:
                    print(f"  ... и ещё {len(perms) - 20}")

            def _print_comp(title: str, items: List[str], limit: int = 20):
                if not items:
                    return
                print(f"{title}:", len(items))
                for it in items[:limit]:
                    print("  -", it)
                if len(items) > limit:
                    print(f"  ... и ещё {len(items) - limit}")

            _print_comp("Activities", ag.get("activities") or [])
            _print_comp("Services", ag.get("services") or [])
            _print_comp("Receivers", ag.get("receivers") or [])
            _print_comp("Providers", ag.get("providers") or [])


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Базовый офлайн-анализ APK (pokerok.apk по умолчанию)")
    p.add_argument("--apk", default="pokerok.apk", help="Путь к APK (по умолчанию: pokerok.apk)")
    p.add_argument("--json", action="store_true", help="Вывести отчёт в JSON")
    p.add_argument("--out", default="", help="Путь для сохранения JSON отчёта (если задан)")
    args = p.parse_args(argv)

    try:
        report = analyze_apk(args.apk)
    except FileNotFoundError:
        print(f"Файл не найден: {args.apk}", file=sys.stderr)
        return 2
    except Exception as ex:
        print(f"Ошибка анализа: {type(ex).__name__}: {ex}", file=sys.stderr)
        return 1

    if args.json or args.out:
        j = json.dumps(report, ensure_ascii=False, indent=2)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as f:
                f.write(j)
            print(f"JSON отчёт сохранён: {args.out}")
        else:
            print(j)
    else:
        print_human(report)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())