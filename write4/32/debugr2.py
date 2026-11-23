import r2pipe as r2p

p = r2p.open()

lib_name = "libwrite432.so"
tgt_func = "pwnme"

# start dbg by stopping at main

p.cmd("dcu main")

symbols = p.cmdj(f"dmij {lib_name}") or []
target_addr = next(
    (sym["vaddr"] for sym in symbols if tgt_func in sym.get("name", "")),
    None
)

if target_addr:
    print(f"[+] Found {tgt_func} at {hex(target_addr)}")

    p.cmd(f"af twil.{tgt_func} @ {target_addr}")

    p.cmd(f"dcu {target_addr}")

    # uwu
    p.cmd(f"s {target_addr}")
else:
    print(f"[-] Couldn't find {tgt_func} in the library {lib_name}")
