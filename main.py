import angr
import sys

def get_default_targets(cfg, ins_type):
    if ins_type == 'jmp':
        return []
    if ins_type == 'call':
        return []
    if ins_type == 'ret':
        return []

def get_allowed_targets(cfg, indir_node):
    succ = cfg.get_successors(indir_node)
    for target in succ:
        if target.block is None:
            # unresolved target
            return get_default_targets(cfg, indir_node.block.capstone.insns[-1].insn.mnemonic)
    return succ

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('Usage: python %s <executable-file>' % (sys.argv[0]))
    filename = sys.argv[1]
    p = angr.Project(filename, auto_load_libs=False) # shared libs not handled
    cfg = p.analyses.CFGFast() # static version
    indir_nodes = []
    for addr in cfg.indirect_jumps:
        ns = cfg.model.get_all_nodes(addr)
        #assert len(ns) == 1, f'At {addr}, {len(ns)} nodes exist!'
        indir_nodes.extend(ns)
    for node in cfg.model.nodes():
        if node.block is not None and node.block.capstone.insns[-1].insn.mnemonic == 'ret':
            indir_nodes.append(node)

    all_targets = {}
    for node in indir_nodes:
        if node.addr not in all_targets:
            all_targets[node.addr] = []
        all_targets[node.addr].extend(get_allowed_targets(cfg, node))
    print(all_targets)
    print(len([a for a in all_targets.values() if not a]))
    print(len(all_targets))

    target_types = {'ret': {}, 'jmp': {}, 'call': {}}
    for node in indir_nodes:
        mnem = node.block.capstone.insns[-1].insn.mnemonic
        if mnem not in target_types:
            print(mnem)
            continue
        targset = target_types[node.block.capstone.insns[-1].insn.mnemonic]
        if node.addr not in targset:
            targset[node.addr] = []
        targset[node.addr].extend(get_allowed_targets(cfg, node))
    for typ, targset in target_types.items():
        nfull = len([1 for a in targset.values() if not a])
        print(f'{typ}: {nfull} / {len(targset)}')
