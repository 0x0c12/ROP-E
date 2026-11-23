import r2pipe as r2p
import json
from pwn import ELF

def sym_anal(sym_list, symbols) -> type(()):
    functions = {}
    objects = {}
    for tgt_func in sym_list:
        target = next(
            ((sym["vaddr"], sym["type"]) for sym in symbols if tgt_func in sym.get("name", "")),
            None
        )
        if target:
            target_addr = target[0]
            if target[1] == "FUNC":
                print(f"[+] Found function {tgt_func} at {hex(target_addr)}")
                p.cmd(f"af {namespace}.{tgt_func} @ {target_addr}")
                functions[f"{namespace}.{tgt_func}"] = hex(target_addr)
            elif target[1] == "OBJ":
                print(f"[+] Found object {tgt_func} at {hex(target_addr)}")
                p.cmd(f"f {namespace}.{tgt_func} @ {target_addr}")
                objects[f"{namespace}.{tgt_func}"] = hex(target_addr)
            else:
                print(f"[=] Found symbol {tgt_func} of type {target[1]}, ignoring...")
        else:
            print(f"[-] Couldn't find {tgt_func} in the library {lib_name}")
    return (functions, objects)

def dbg_start(start_sym, functions):
    tgt_key = next((k for k in functions if f"{namespace}.{start_sym}" in k),None)

    if not tgt_key:
        print(f"[-] Failed to find {start_sym}")
        return

    tgt_fn_addr = functions[tgt_key]
    disasm = p.cmdj(f"pdfj @ {tgt_fn_addr}") or {}

    ret_op = next(
       (op for op in reversed(disasm.get("ops", [])) if op.get("type") == "ret" or op.get("opcode") == "ret"),
        None
    )

    if ret_op:
        offset = ret_op["addr"] - int(tgt_fn_addr, 16)
        p.cmd(f"dcu {tgt_key}+{offset}")
        print(f"[+] Left you at ret instruction of {tgt_key} [address: {hex(int(tgt_fn_addr, 16)+offset)}]")
    else:
        print(f"[-] SOMEHOW, awkwardly enough, the ret instruction couldn't be found... are you sure this is a standard function?")

# def xrefs_anal(functions, objects, symbols):
    # TODO: do PLT and GOT analysis and loop over the symbols to do afr
    # additionally, also map the library .text and .fini mappings to catch any strays

p = r2p.open()

lib_name = "libbadchars32.so"
lib = ELF(lib_name)

symbol_list = lib.symbols
namespace = "twil"
dbg_start_sym = "pwnme"

# start dbg mode by stopping at main
p.cmd("dcu main")
symbols = p.cmdj(f"dmij {lib_name}") or []

functions, objects = sym_anal(symbol_list, symbols)

print("Functions\n", json.dumps(functions, indent=4))
print("Objects\n", json.dumps(objects, indent=4))

dbg_start(dbg_start_sym, functions)
