import argparse
import configparser
import re
import sys
from dataclasses import dataclass
from pathlib import Path

import pefile
from capstone import CS_ARCH_X86, CS_MODE_64, Cs



MODULE_NAME = "weixin.dll"
MUTEX_NAME = "XWeChat_App_Instance_Identity_Mutex_Name"

HOOK_PATTERN = (
    "0F 10 05 ?? ?? ?? ?? 0F 11 00 "
    "0F 10 05 ?? ?? ?? ?? 0F 11 40 10 "
    "0F 10 05 ?? ?? ?? ?? 0F 11 40 20 "
    "0F 10 05 ?? ?? ?? ?? 0F 11 40 30 "
    "0F 10 05 ?? ?? ?? ?? 0F 11 40 40 "
    "66 C7 40 50 00 00 31 C9 31 D2 49 89 C0 "
    "FF 15 ?? ?? ?? ?? 48 85 C0"
)

GLOBAL_CONFIG_PATTERN = (
    "48 C7 05 ?? ?? ?? ?? 00 00 00 00 "
    "48 C7 05 ?? ?? ?? ?? 0D 00 00 00 "
    "48 C7 05 ?? ?? ?? ?? 0F 00 00 00 "
    "48 B8 67 6C 6F 62 61 6C 5F 63 "
    "48 89 05 ?? ?? ?? ?? "
    "48 B8 6C 5F 63 6F 6E 66 69 67 "
    "48 89 05 ?? ?? ?? ?? "
    "48 8D 0D ?? ?? ?? ?? E9 ?? ?? ?? ??"
)

L_CONFIG_MOV = bytes.fromhex("48 B8 6C 5F 63 6F 6E 66 69 67")
HOST_REDIRECT = b"/host-redirect.xml"
HOST_REDIRECT_NO_SLASH = b"host-redirect.xml"


@dataclass
class LoadedImage:
    data: bytes
    image_base: int
    path: Path


@dataclass
class Offsets:
    version: str
    mutex_name_offset: int
    global_config_offset: int
    host_redirect_xml_offset: int
    hook_offset: int


def parse_args():
    parser = argparse.ArgumentParser(
        description="Find MutiWeixinTools offsets by scanning Weixin.dll on disk."
    )
    parser.add_argument(
        "--config",
        default="config.ini",
        help="Path to config.ini. Defaults to ./config.ini.",
    )
    parser.add_argument(
        "--dll",
        help="Path to Weixin.dll. This is the most direct input.",
    )
    parser.add_argument(
        "--wechat-exe",
        help="Path to Weixin.exe/WeChat.exe. Used to infer the matching Weixin.dll path.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print detected offsets without writing config.ini.",
    )
    return parser.parse_args()


def compile_hex_pattern(pattern: str) -> re.Pattern:
    regex = bytearray()
    for part in pattern.split():
        if part == "??":
            regex.extend(b".")
        else:
            regex.extend(re.escape(bytes.fromhex(part)))
    return re.compile(bytes(regex), re.DOTALL)


def get_file_version(file_path: Path) -> str:
    try:
        pe = pefile.PE(str(file_path), fast_load=True)
        if getattr(pe, "VS_FIXEDFILEINFO", None):
            info = pe.VS_FIXEDFILEINFO[0]
            return (
                f"{info.FileVersionMS >> 16}."
                f"{info.FileVersionMS & 0xFFFF}."
                f"{info.FileVersionLS >> 16}."
                f"{info.FileVersionLS & 0xFFFF}"
            )
    except Exception:
        pass

    match = re.search(r"[\\/](\d+\.\d+\.\d+\.\d+)[\\/]", str(file_path))
    if match:
        return match.group(1)
    return "unknown"


def load_config_wechat_path(config_path: Path) -> str | None:
    if not config_path.exists():
        return None

    config = configparser.ConfigParser()
    config.read(config_path, encoding="utf-8")
    value = config.get("weixin", "path", fallback="").strip().strip('"')
    return value or None


def version_key(path: Path) -> tuple[int, ...]:
    version = get_file_version(path)
    if version == "unknown":
        return ()
    try:
        return tuple(int(part) for part in version.split("."))
    except ValueError:
        return ()


def find_weixin_dll_from_path(path_text: str | None) -> Path | None:
    if not path_text:
        return None

    path = Path(path_text.strip().strip('"'))
    if path.is_file() and path.name.lower() == MODULE_NAME:
        return path

    base_dir = path if path.is_dir() else path.parent
    candidates = []

    direct = base_dir / MODULE_NAME
    if direct.exists():
        candidates.append(direct)

    candidates.extend(base_dir.glob(f"*/{MODULE_NAME}"))

    if not candidates:
        return None

    return sorted(
        candidates,
        key=lambda item: (version_key(item), item.stat().st_mtime),
        reverse=True,
    )[0]


def resolve_dll_path(args, config_path: Path) -> Path:
    dll_path = find_weixin_dll_from_path(args.dll)
    if dll_path:
        return dll_path.resolve()

    dll_path = find_weixin_dll_from_path(args.wechat_exe)
    if dll_path:
        return dll_path.resolve()

    dll_path = find_weixin_dll_from_path(load_config_wechat_path(config_path))
    if dll_path:
        return dll_path.resolve()

    raise RuntimeError(
        "Could not locate Weixin.dll. Pass --dll <path>, pass --wechat-exe <path>, "
        "or set [weixin] path in config.ini."
    )


def load_pe_image(dll_path: Path) -> LoadedImage:
    if not dll_path.exists():
        raise FileNotFoundError(f"Weixin.dll does not exist: {dll_path}")

    pe = pefile.PE(str(dll_path), fast_load=False)
    image_size = pe.OPTIONAL_HEADER.SizeOfImage
    image = bytearray(image_size)

    raw = dll_path.read_bytes()
    header_size = min(pe.OPTIONAL_HEADER.SizeOfHeaders, len(raw), image_size)
    image[:header_size] = raw[:header_size]

    for section in pe.sections:
        rva = int(section.VirtualAddress)
        raw_offset = int(section.PointerToRawData)
        raw_size = int(section.SizeOfRawData)
        virtual_size = int(section.Misc_VirtualSize or raw_size)
        if rva >= image_size or raw_size <= 0:
            continue

        chunk = raw[raw_offset : raw_offset + raw_size]
        copy_size = min(len(chunk), virtual_size, image_size - rva)
        image[rva : rva + copy_size] = chunk[:copy_size]

    return LoadedImage(
        data=bytes(image),
        image_base=int(pe.OPTIONAL_HEADER.ImageBase),
        path=dll_path,
    )


def find_mutex_offset(data: bytes) -> int:
    offset = data.find(MUTEX_NAME.encode("utf-16le"))
    if offset == -1:
        raise RuntimeError("Could not find mutex_name string.")
    return offset


def find_host_redirect_offset(data: bytes) -> int:
    offset = data.find(HOST_REDIRECT)
    if offset != -1:
        return offset

    offset = data.find(HOST_REDIRECT_NO_SLASH)
    if offset != -1 and offset > 0 and data[offset - 1] == 0x2F:
        return offset - 1

    raise RuntimeError("Could not find /host-redirect.xml string.")


def find_global_config_offset(data: bytes) -> int:
    pattern = compile_hex_pattern(GLOBAL_CONFIG_PATTERN)
    match = pattern.search(data)
    if not match:
        raise RuntimeError("Could not find global_config pattern.")

    mov_offset = data.find(L_CONFIG_MOV, match.start(), match.end())
    if mov_offset == -1:
        raise RuntimeError("Found global_config pattern, but could not locate l_config mov instruction.")

    return mov_offset + 8


def hook_pattern_references_mutex(data: bytes, image_base: int, hook_rva: int, mutex_rva: int) -> bool:
    # First instruction is: 0F 10 05 <disp32> => movups xmm0, xmmword ptr [rip+disp32]
    if hook_rva + 7 > len(data):
        return False
    displacement = int.from_bytes(data[hook_rva + 3 : hook_rva + 7], "little", signed=True)
    target = image_base + hook_rva + 7 + displacement
    return target - image_base == mutex_rva


def find_hook_offset(data: bytes, image_base: int, mutex_rva: int) -> int:
    pattern = compile_hex_pattern(HOOK_PATTERN)
    matches = list(pattern.finditer(data))
    if not matches:
        raise RuntimeError("Could not find hook pattern.")

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = False

    for match in matches:
        start = match.start()
        if not hook_pattern_references_mutex(data, image_base, start, mutex_rva):
            continue

        last_call = None
        code = data[start : start + 0x3000]
        for instruction in md.disasm(code, image_base + start):
            if instruction.mnemonic == "call":
                last_call = instruction.address
            elif instruction.mnemonic == "ret":
                if last_call is None:
                    break
                return last_call - image_base

    raise RuntimeError("Found hook pattern, but could not find the call before ret.")


def find_offsets(image: LoadedImage) -> Offsets:
    mutex_name_offset = find_mutex_offset(image.data)
    return Offsets(
        version=get_file_version(image.path),
        mutex_name_offset=mutex_name_offset,
        global_config_offset=find_global_config_offset(image.data),
        host_redirect_xml_offset=find_host_redirect_offset(image.data),
        hook_offset=find_hook_offset(image.data, image.image_base, mutex_name_offset),
    )


def format_offsets(offsets: Offsets) -> str:
    return (
        f"[{offsets.version}]\n"
        f"mutex_name_offset = 0x{offsets.mutex_name_offset:X}\n"
        f"global_config_offset = 0x{offsets.global_config_offset:X}\n"
        f"host_redirect_xml_offset = 0x{offsets.host_redirect_xml_offset:X}\n"
        f"hook_offset = 0x{offsets.hook_offset:X}\n"
    )


def update_config(config_path: Path, offsets: Offsets) -> None:
    section_text = format_offsets(offsets).rstrip()

    if config_path.exists():
        text = config_path.read_text(encoding="utf-8")
    else:
        text = "[weixin]\npath = \n"

    line_ending = "\r\n" if "\r\n" in text else "\n"
    normalized = text.replace("\r\n", "\n")
    pattern = re.compile(rf"(?ms)^\[{re.escape(offsets.version)}\]\n.*?(?=^\[|\Z)")

    if pattern.search(normalized):
        normalized = pattern.sub(section_text + "\n\n", normalized).rstrip() + "\n"
    else:
        normalized = normalized.rstrip() + "\n\n" + section_text + "\n"

    config_path.write_text(normalized.replace("\n", line_ending), encoding="utf-8")


def main() -> int:
    args = parse_args()
    config_path = Path(args.config).resolve()
    dll_path = resolve_dll_path(args, config_path)

    print(f"Scanning file: {dll_path}")
    image = load_pe_image(dll_path)

    print(f"Version: {get_file_version(image.path)}")
    print(f"ImageBase: 0x{image.image_base:X}")

    offsets = find_offsets(image)
    print(format_offsets(offsets), end="")

    if args.dry_run:
        print("Dry run: config.ini was not changed.")
        return 0

    update_config(config_path, offsets)
    print(f"Saved offsets to: {config_path}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        raise SystemExit(1)
