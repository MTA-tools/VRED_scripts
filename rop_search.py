def add(gadget_list, src_register, dst_register):
    gadgets = []
    r = re.compile(r'^0x[0-9a-fA-F]{8}:.*(add|adc) ' + dst_register + r', ' + src_register + r'.*ret')
    long_gadgets = list(filter(r.match, gadget_list))
    gadgets += sorted(long_gadgets, key=len)

    return gadgets
