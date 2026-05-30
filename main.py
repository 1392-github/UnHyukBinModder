import argparse
import tempfile
import os
import zipfile
import re
import json
import subprocess

import lief
import capstone
import keystone

def sanitize(name):
    name = re.sub(r"_+", "_", re.sub(r"[^A-Za-z0-9_]", "_", name)).strip("_")
    if name[0].isdigit(): name = "_" + name
    return name

parser = argparse.ArgumentParser()
parser.add_argument("--input", "-i", help = "모드를 적용하려는 바이너리 파일 경로")
parser.add_argument("--output", "-o", help = "모드 적용이 된 파일이 생성될 경로")
parser.add_argument("--mods", "-m", help = "적용할 모드를 ,로 구분해 적용 순서대로 입력")
parser.add_argument("--extsymbols", "-es", help = "외부 심볼 파일들을 ,로 구분해 우선 순위대로 입력 (중복 시 뒤쪽 것이 우선)")
args = parser.parse_args()
if args.input is None:
    input_file = input("모드를 적용하려는 바이너리 파일 경로: ")
else:
    input_file = args.input
if args.output is None:
    output_file = input("모드 적용이 된 파일이 생성될 경로: ")
else:
    output_file = args.output
if args.mods is None:
    print("적용할 모드들 입력, [Enter]로 입력 멈춤")
    mods = []
    while True:
        mod = input()
        if mod == "":
            break
        mods.append(mod)
else:
    mods = args.mods.split(",")
if args.extsymbols is None:
    print("외부 심볼 파일들 입력, [Enter]로 입력 멈춤")
    ext_symbols = []
    while True:
        sym = input()
        if sym == "":
            break
        ext_symbols.append(sym)
    ext_symbols = []
else:
    ext_symbols = args.extsymbols.split(",")
del args

tempdir = tempfile.mkdtemp()
print(tempdir)
os.mkdir(os.path.join(tempdir, "zip"))
for i,v in enumerate(mods):
    if not os.path.exists(v):
        raise FileNotFoundError(f"{v}는 없는 파일 또는 폴더입니다.")
    if os.path.isfile(v):
        with zipfile.ZipFile(v) as z:
            path = os.path.join(tempdir, "zip", os.path.basename(v))
            z.extractall(path)
            files = os.listdir(path)
            files0_joined = os.path.join(path, files[0])
            if len(files) == 1 and os.path.isdir(files0_joined):
                mods[i] = files0_joined
            else:
                mods[i] = path

info = []
for mod in mods:
    with open(os.path.join(mod, "info.json"), "r", encoding = "utf-8") as f:
        info.append(json.load(f))
arch = info[0]["architecture"]
if arch not in ("x86", "x86_64", "arm64"):
    raise Exception(f"{arch}는 올바르지 않은 아키텍처입니다. x86, x86_64, arm64만 지원합니다. (arm32는 추후 지원 예정)")
bin_format = info[0]["format"]
if bin_format not in ("pe", "elf"):
    raise Exception(f"{bin_format}는 올바르지 않은 타입입니다. pe, elf만 지원합니다.")
for i in info[1:]:
    arch2 = i["architecture"]
    bin_format2 = i["format"]
    if arch2 not in ("x86", "x86_64", "arm64"):
        raise Exception(f"{arch2}는 올바르지 않은 아키텍처입니다. x86, x86_64, arm64만 지원합니다. (arm32는 추후 지원 예정)")
    if bin_format2 not in ("pe", "elf"):
        raise Exception(f"{bin_format2}는 올바르지 않은 타입입니다. pe, elf만 지원합니다.")
    if arch2 != arch:
        raise Exception("서로 다른 아키텍처의 모드가 섞여 있습니다.")
    if bin_format2 != bin_format:
        raise Exception("서로 다른 타입의 모드가 섞여 있습니다.")
if arch in ("arm32", "arm64") and bin_format == "pe":
    raise Exception("ARM 아키텍처 PE는 현재 지원하지 않습니다.")
input_bin = lief.parse(input_file)
if input_bin is None:
    raise Exception("원본 파일이 올바른 바이너리 파일이 아닙니다.")
if input_bin.format not in (lief.Binary.FORMATS.PE, lief.Binary.FORMATS.ELF):
    raise Exception(f"{input_bin.format.name}은 지원하는 형식이 아닙니다. PE, ELF만 지원합니다.")

linker_script_symbols = []
found_symbols = set()
for func in input_bin.functions:
    if not func.name:
        continue
    name = sanitize(func.name)
    if name in found_symbols:
        raise Exception(f"심볼 이름 {name}이 중복되었습니다.")
    found_symbols.add(name)
    linker_script_symbols.append(f"{name} = {hex(func.address)};")
for mod in mods:
    for r, d, f in os.walk(os.path.join(mod, "symbols")):
        for i in f:
            with open(os.path.join(r, i), "r", encoding = "utf-8") as fi:
                j = json.load(fi)
            for n, v in j.items():
                name = sanitize(n)
                if name in found_symbols:
                    raise Exception(f"심볼 이름 {name}이 중복되었습니다.")
                found_symbols.add(name)
                linker_script_symbols.append(f"{name} = {v};")
for symf in ext_symbols:
    with open(symf, "r", encoding = "utf-8") as fi:
        j = json.load(fi)
    for n, v in j.items():
        name = sanitize(n)
        if name in found_symbols:
            raise Exception(f"심볼 이름 {name}이 중복되었습니다.")
        found_symbols.add(name)
        linker_script_symbols.append(f"{name} = {v};")

objects = []
for mod in mods:
    for r, d, f in os.walk(mod):
        for i in f:
            path = os.path.join(r, i)
            if os.path.splitext(path)[1] in (".o", ".obj"):
                objects.append(os.path.normpath(path))
if input_bin.format == lief.Binary.FORMATS.PE:
    align = input_bin.optional_header.section_alignment
else:
    align = 0x1000
    for seg in input_bin.segments:
        if seg.type == lief.ELF.Segment.TYPE.LOAD:
            if seg.alignment > align:
                align = seg.alignment
last = 0
for sec in input_bin.sections:
    end = sec.virtual_address + sec.size
    if end > last:
        last = end
last = (last + align - 1) & ~(align - 1)
print(hex(last + input_bin.imagebase))
linker_script = os.path.join(tempdir, "link.ld")
with open(linker_script, "w", encoding = "utf-8") as f:
    f.write("""{0}
SECTIONS
{{
    . = {1};
    .modrx : 
    {{
        *(.text)
        *(.text.*)
        *(.rdata)
        *(.rdata$*)
        *(.rdata.*)
        *(.rodata)
        *(.rodata.*)
        *(.init) *(.fini)
        . = ALIGN({2});
    }}
    . = ALIGN({2});
    .modrw : 
    {{
        *(.data)
        *(.data.*)
        *(.bss)
        *(.bss.*)
        *(COMMON)
        . = ALIGN({2});
    }}
    .edata :
    {{
        *(.edata)
    }}
    .reloc :
    {{
        *(.reloc)
    }}
    /DISCARD/ :
    {{
        *(*)
    }}
}}""".format("\n".join(linker_script_symbols), hex(last + input_bin.imagebase), align))
linked = os.path.join(tempdir, "linked")
cmd = [None, "-m", None, "--export-all-symbols", "-g", "-T", linker_script, "-o", linked] + objects
if arch == "x86":
    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_32)
    if bin_format == "pe":
        cmd[0] = r".\ld\x86_pe.exe"
        cmd[2] = "i386pe"
    else:
        cmd[0] = r".\ld\x86_elf.exe"
        cmd[2] = "elf_i386"
elif arch == "x86_64":
    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
    if bin_format == "pe":
        cmd[0] = r".\ld\x86_pe.exe"
        cmd[2] = "i386pep"
    else:
        cmd[0] = r".\ld\x86_elf.exe"
        cmd[2] = "elf_x86_64"
elif arch == "arm64":
    cmd[0] = r".\ld\arm.exe"
    cmd[2] = "aarch64elf"
cs.detail = True
subprocess.run(cmd)
linked_bin = lief.parse(linked)
if input_bin.format == lief.Binary.FORMATS.PE:
    section1 = linked_bin.get_section(".modrx")
    section2 = lief.PE.Section(".modrx")
    section2.content = section1.content
    section2.characteristics = 0x60000020
    section2 = input_bin.add_section(section2)
    section1 = linked_bin.get_section(".modrw")
    section2 = lief.PE.Section(".modrw")
    if section1.sizeof_raw_data == 0 or section1.pointerto_raw_data == 0 or section1.has_characteristic(lief.PE.Section.CHARACTERISTICS.CNT_UNINITIALIZED_DATA):
        section2.characteristics = 0xc0000080
        section2.virtual_size = section1.virtual_size
    else:
        section2.content = section1.content
        section2.characteristics = 0xc0000040
    section2 = input_bin.add_section(section2)
modrx2 = input_bin.add_section(lief.PE.Section(".modrx2"))
modrx2.characteristics = 0x60000020
modrx2_address = modrx2.virtual_address + input_bin.imagebase
modrx2_content = []
def add_modrx2_content(new):
    global modrx2_address
    for i in new:
        modrx2_content.append(i)
    modrx2_address += len(new)
x86_operands_size = {
    1: "byte ptr",
    2: "word ptr",
    4: "dword ptr",
    8: "qword ptr",
    16: "xmmword ptr"
}
for mod in mods:
    with open(os.path.join(mod, "hook.json"), "r", encoding = "utf-8") as f:
        hooks = json.load(f)
    for hook in hooks:
        if hook["target"]["type"] == "absolute":
            if isinstance(hook["target"]["address"], int):
                location = hook["target"]["address"]
            elif isinstance(hook["target"]["address"], str):
                location = int(hook["target"]["address"], 16)
            else:
                raise Exception("target의 address는 정수나 문자열이어야 합니다.")
        section = input_bin.section_from_rva(location - input_bin.imagebase)
        if section is None:
            raise Exception(f"{hex(location)}은 없는 주소이거나 초기화되지 않은 데이터가 있는 섹션의 주소입니다.")
        content = list(section.content)
        original_command : list[tuple[int, capstone.CsInsn]] = []
        size_sum = 0
        st = location - input_bin.imagebase - section.virtual_address
        for c in cs.disasm(bytes(content[st:st+15]), location):
            original_command.append((location + size_sum, c))
            size_sum += c.size
            if size_sum >= 5:
                break
        content[st:st+5] = ks.asm(f"jmp {hex(modrx2_address)}", location)[0]
        section.content = content
        add_modrx2_content(ks.asm(f"call {hex(linked_bin.get_function_address(hook['function']) + input_bin.imagebase)}", modrx2_address)[0])
        for addr, org in original_command:
            if capstone.CS_GRP_BRANCH_RELATIVE in org.groups:
                add_modrx2_content(ks.asm(f"{org.mnemonic} {org.op_str}", modrx2_address)[0])
            else:
                changed = False
                for op in org.operands:
                    if op.type == capstone.CS_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP:
                        op.mem.disp -= modrx2_address - addr
                        changed = True
                if changed:
                    cmd = org.mnemonic + " "
                    for op in org.operands:
                        if op.type == capstone.CS_OP_REG:
                            cmd += org.reg_name(op.reg)
                        elif op.type == capstone.CS_OP_IMM:
                            cmd += hex(op.imm)
                        elif op.type == capstone.CS_OP_MEM:
                            if org.mnemonic != "lea":
                                cmd += x86_operands_size[op.size] + " "
                            cmd += "[" + org.reg_name(op.mem.base)
                            if op.mem.index:
                                cmd += " + " + org.reg_name(op.mem.index)
                                if op.mem.scale != 1:
                                    cmd += "*" + str(op.mem.scale)
                            if op.mem.disp:
                                cmd += " + " + hex(op.mem.disp)
                            cmd += "]"
                        cmd += ", "
                    add_modrx2_content(ks.asm(cmd[:-2], modrx2_address)[0])
                else:
                    add_modrx2_content(org.bytes)
        add_modrx2_content(ks.asm(f"jmp {hex(location + size_sum)}", modrx2_address)[0])
modrx2.content = modrx2_content
modrx2.sizeof_raw_data = (len(modrx2_content) + input_bin.optional_header.file_alignment - 1) & ~(input_bin.optional_header.file_alignment - 1)
modrx2.virtual_size = (len(modrx2_content) + align - 1) & ~(align - 1)
input_bin.write(output_file)