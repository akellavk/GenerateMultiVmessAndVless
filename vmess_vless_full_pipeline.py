#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
vmess_vless_full_pipeline.py

Usage:
    python vmess_vless_full_pipeline.py

Порядок работы:
1. decode  — читает file1.txt, снимает "vmess://" или "vless://", декодирует base64 → JSON для vmess, парсит URL для vless, нормализует (добавляет недостающие поля) и перезаписывает file1.txt.
2. encode  — использует file1.txt как шаблон и SNI.txt как список подстановок, затем пишет результат в file3.txt.

Файлы по умолчанию:
    file1.txt  — шаблон (и вход для decode)
    SNI.txt    — список SNI (по строке на каждый)
    file3.txt  — итоговый файл с vmess:// или vless:// ссылками
"""

import argparse
import base64
import json
import sys
from pathlib import Path
import tempfile
import os
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

# --- параметры для decode ---

WANTED_ORDER_VMESS = [
    "add", "aid", "allowInsecure", "alpn", "fp", "host", "id", "net", "path",
    "port", "ps", "scy", "sni", "tls", "type", "v"
]

WANTED_ORDER_VLESS = [
    "add", "port", "id", "ps", "type", "encryption", "security",
    "sni", "host", "path", "seed", "fp", "alpn", "allowInsecure",
    "mode", "pbk", "sid", "spx", "pqv", "ech", "flow"
]

DEFAULTS_IF_MISSING_VMESS = {
    "aid": "0",
    "alpn": "",
    "type": "",
    "allowInsecure": 1,
}

DEFAULTS_IF_MISSING_VLESS = {
    "encryption": "none",
    "security": "none",
    "type": "tcp",
    "allowInsecure": 1,
}


def truthy_to_int(v):
    if isinstance(v, bool):
        return 1 if v else 0
    if isinstance(v, (int, float)):
        return 1 if v != 0 else 0
    if isinstance(v, str):
        s = v.strip().lower()
        return 1 if s in {"1", "true", "yes", "y", "on"} else 0
    return 0


def parse_vless_url(url: str) -> dict:
    """Парсит vless URL и возвращает словарь с параметрами"""
    parsed = urlparse(url)

    result = {
        "id": parsed.username,
        "add": parsed.hostname,
        "port": str(parsed.port),
        "ps": parsed.fragment or "",
    }

    # Парсим query параметры
    query_params = parse_qs(parsed.query)
    for key, value in query_params.items():
        result[key] = value[0] if len(value) == 1 else value

    return result


def encode_vless_url(config: dict) -> str:
    """Создает vless URL из конфигурации"""
    netloc = f"{config['id']}@{config['add']}:{config['port']}"

    # Формируем query параметры
    query_params = {}
    NON_QUERY_FIELDS = {"add", "port", "id", "ps"}
    VLESS_QUERY_PARAMS = [field for field in WANTED_ORDER_VLESS if field not in NON_QUERY_FIELDS]
    for key in VLESS_QUERY_PARAMS:
        if key in config and config[key] and config[key] != "":
            query_params[key] = config[key]

    query_string = urlencode(query_params)
    fragment = config.get("ps", "")

    return urlunparse(("vless", netloc, "", "", query_string, fragment))


def decode_vmess_or_vless_line(line: str) -> dict:
    s = line.strip()
    if not s:
        raise ValueError("Пустая строка")

    if s.startswith("vmess://"):
        s = s[len("vmess://"):]
        pad = (-len(s)) % 4
        if pad:
            s += "=" * pad
        raw = base64.b64decode(s.encode("ascii"))
        obj = json.loads(raw.decode("utf-8"))
        obj["_type"] = "vmess"
        return obj

    elif s.startswith("vless://"):
        obj = parse_vless_url(s)
        obj["_type"] = "vless"
        return obj

    elif s.startswith("{") and s.endswith("}"):
        obj = json.loads(s)
        obj["_type"] = obj.get("_type", "vmess")  # по умолчанию vmess для JSON
        return obj

    else:
        raise ValueError("Строка не vmess://, не vless:// и не JSON")


def normalize_vmess_entry(d: dict) -> dict:
    out = dict(d)

    if "port" in out:
        out["port"] = str(out["port"])
    if "allowInsecure" in out:
        out["allowInsecure"] = truthy_to_int(out["allowInsecure"])

    for k, v in DEFAULTS_IF_MISSING_VMESS.items():
        if k not in out:
            out[k] = v

    for k in WANTED_ORDER_VMESS:
        if k not in out:
            out[k] = ""

    ordered = {k: out.get(k, "") for k in WANTED_ORDER_VMESS}
    ordered["_type"] = "vmess"
    return ordered


def normalize_vless_entry(d: dict) -> dict:
    out = dict(d)

    if "port" in out:
        out["port"] = str(out["port"])
    if "allowInsecure" in out:
        out["allowInsecure"] = truthy_to_int(out["allowInsecure"])

    for k, v in DEFAULTS_IF_MISSING_VLESS.items():
        if k not in out:
            out[k] = v

    for k in WANTED_ORDER_VLESS:
        if k not in out:
            out[k] = ""

    ordered = {k: out.get(k, "") for k in WANTED_ORDER_VLESS}
    ordered["_type"] = "vless"
    return ordered


def normalize_entry(d: dict) -> dict:
    if d.get("_type") == "vless":
        return normalize_vless_entry(d)
    else:
        return normalize_vmess_entry(d)


def decode_file_inplace(path: Path):
    if not path.exists():
        print(f"Ошибка: входной файл не найден: {path}", file=sys.stderr)
        sys.exit(1)

    out_dir = path.parent if path.parent.exists() else Path(".")
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False, dir=str(out_dir)) as tmp:
        tmp_name = tmp.name
        written = 0
        vmess_count = 0
        vless_count = 0

        with path.open("r", encoding="utf-8") as f:
            for idx, line in enumerate(f, 1):
                s = line.strip()
                if not s:
                    continue
                try:
                    obj = decode_vmess_or_vless_line(s)
                    norm = normalize_entry(obj)

                    if norm["_type"] == "vmess":
                        compact = json.dumps(
                            norm, ensure_ascii=False, separators=(",", ":"))
                        vmess_count += 1
                    else:
                        compact = json.dumps(
                            norm, ensure_ascii=False, separators=(",", ":"))
                        vless_count += 1

                    tmp.write(compact + "\n")
                    written += 1
                except Exception as e:
                    print(
                        f"[decode] Строка {idx} пропущена: {e}", file=sys.stderr)

    os.replace(tmp_name, path)
    print(
        f"[decode] Готово: записано {written} строк в {path} (vmess: {vmess_count}, vless: {vless_count})")

# --- encode ---


def read_first_nonempty_line(path: Path) -> str:
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            s = line.rstrip("\n\r")
            if s.strip() != "":
                return s
    return ""


def read_lines(path: Path):
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if s != "":
                yield s


def make_proxy_lines(template: str, replacements):
    """Создает строки proxy в зависимости от типа шаблона"""
    try:
        template_obj = json.loads(template)
        proxy_type = template_obj.get("_type", "vmess")
    except:
        # Если не JSON, пытаемся определить по префиксу
        if template.startswith("vless://"):
            proxy_type = "vless"
        else:
            proxy_type = "vmess"

    if proxy_type == "vmess":
        return make_vmess_lines(template, replacements)
    else:
        return make_vless_lines(template, replacements)


def make_vmess_lines(template: str, replacements):
    out = []
    for rep in replacements:
        # Заменяем в JSON
        try:
            template_obj = json.loads(template)
            if "sni" in template_obj:
                template_obj["sni"] = rep
            if "host" in template_obj:
                template_obj["host"] = rep
            if "ps" in template_obj:
                template_obj["ps"] = f'{template_obj["ps"]} ({rep})'
            replaced_json = json.dumps(
                template_obj, ensure_ascii=False, separators=(",", ":"))
            b64 = base64.b64encode(
                replaced_json.encode("utf-8")).decode("ascii")
            out.append("vmess://" + b64)
        except:
            # Fallback: простая замена в строке
            replaced = template.replace("vk.com", rep)
            b64 = base64.b64encode(replaced.encode("utf-8")).decode("ascii")
            out.append("vmess://" + b64)
    return out


def make_vless_lines(template: str, replacements):
    out = []
    for rep in replacements:
        try:
            template_obj = json.loads(template)
            if "sni" in template_obj:
                template_obj["sni"] = rep
            if "host" in template_obj and template_obj['type'] not in ("xhttp", "ws"):
                template_obj["host"] = rep
            if "ps" in template_obj:
                template_obj["ps"] = f'{template_obj["ps"]} ({rep})'

            vless_url = encode_vless_url(template_obj)
            out.append(vless_url)
        except Exception as e:
            print(f"Ошибка при создании vless ссылки: {e}", file=sys.stderr)
    return out


def encode_files(tmpl_path: Path, sni_path: Path, out_path: Path):
    if not tmpl_path.exists():
        print(f"Ошибка: шаблон не найден {tmpl_path}", file=sys.stderr)
        sys.exit(1)
    if not sni_path.exists():
        print(f"Ошибка: файл SNI не найден {sni_path}", file=sys.stderr)
        sys.exit(1)

    template = read_first_nonempty_line(tmpl_path)
    if template == "":
        print(f"Ошибка: шаблон {tmpl_path} пуст.", file=sys.stderr)
        sys.exit(1)

    replacements = list(read_lines(sni_path))
    if not replacements:
        print(
            f"Предупреждение: файл SNI {sni_path} пуст. Ничего не записано.", file=sys.stderr)
        out_path.write_text("", encoding="utf-8")
        return

    proxy_lines = make_proxy_lines(template, replacements)

    with out_path.open("w", encoding="utf-8") as f:
        for line in proxy_lines:
            f.write(line + "\n")

    print(f"[encode] Готово: записано {len(proxy_lines)} строк в {out_path}")

# --- main ---


def main():
    parser = argparse.ArgumentParser(
        description="Сначала decode file1.txt (in-place) → затем encode (file1.txt + SNI.txt → file3.txt)"
    )
    parser.add_argument("--template", "-t", default="file1.txt",
                        help="шаблон И вход для decode (default: file1.txt)")
    parser.add_argument("--sni", "-s", default="SNI.txt",
                        help="файл SNI для encode (default: SNI.txt)")
    parser.add_argument("--out", "-o", default="file3.txt",
                        help="выходной файл для encode (default: file3.txt)")
    args = parser.parse_args()

    tmpl = Path(args.template)
    sni = Path(args.sni)
    outp = Path(args.out)

    # 1) decode (in-place)
    decode_file_inplace(tmpl)

    # 2) encode
    encode_files(tmpl, sni, outp)


if __name__ == "__main__":
    main()
