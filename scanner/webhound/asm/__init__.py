# WebHound — webhound/asm/__init__.py
# Attack-Surface Management (ASM) primitives. Each module is a
# standalone callable so scan profiles, scheduled monitoring, or admin
# endpoints can decide when to invoke. Default scan pipeline does NOT
# run ASM today — it's an opt-in surface to avoid slowing every scan.
