import random
from copy import copy 

class OCFI:
    def __init__(self, cfg):
        resolved_indir = get_resolved_indirect_branches(cfg)
        indir_targets = {addr: get_target_addrs(cfg, addr) for addr in resolved_indir}
        self.cfg = cfg
        self.tset = indir_targets
        self.do_clustering()

    def make_portals(self):
        ''' make portals by ordering targets and adding furthest ones'''
        for cluster in self.clusters:
            cluster.fill_nexus()

    def do_clustering(self):
        ''' perform clustering algorithm. Roughly:
        for each indirect branch: 
            for each branch target:
                If it is not already targeted, add it to the cluster.
                If it is already targeted:
                    If there is space in our nexus, add it to the nexus.
                    Otherwise, do nothing (expand bounds).
            while there is space in our nexus, find the furthest target in our
            cluster not already in the nexus and add it to the nexus.
        '''
        clusters = []
        used_targets = {}
        for indir_addr in sorted(self.tset.keys()):
            targets = self.tset[indir_addr]
            clusterid = len(clusters)
            cluster = OCFICluster(indir_addr, clusterid)
            for target_addr in targets:
                if target_addr in used_targets:
                    cluster.add_fartarget(used_targets[target_addr])
                else:
                    ref = cluster.add_target(target_addr)
                    used_targets[target_addr] = ref
            clusters.append(cluster)
        self.clusters = clusters

    def do_move_targets(self):
        '''use cfg to get bytestrings for each basic block and put them into place'''
        for cluster in self.clusters:
            for i in range(len(cluster.targets)):
                node = self.cfg.get_any_node(cluster.targets[i])
                if node is not None:
                    cluster.targets[i] = node.block.bytes
                else:
                    # special case, faked branch
                    pass

    def __copy__(self):
        ocfi = OCFI(self.cfg)
        return ocfi

    def with_clusters_shuffled(self):
        ocfi = copy(self)
        shuf_order = list(range(len(ocfi.clusters)))
        random.shuffle(shuf_order)
        reverse_order = [0] * len(ocfi.clusters)
        for newid in range(len(shuf_order)):
            reverse_order[shuf_order[newid]] = newid

        for newid in range(len(shuf_order)):
            oldid = shuf_order[newid]
            newcluster = ocfi.clusters[oldid]
            newcluster.id = newid
            newcluster.update_refs(reverse_order)
        ocfi.clusters = sorted(ocfi.clusters, key=lambda c: c.id)
        return ocfi
        
    def with_bbls_shuffled(self):
        ocfi = copy(self)
        cluster_order = []
        for cluster in ocfi.clusters:
            order = cluster.shuffle()
            cluster_order.append(order)
        
        for cluster in ocfi.clusters:
            cluster.update_inner_refs(cluster_order)
        return ocfi

    def __str__(self):
        s = ''
        cid = 0
        for cluster in self.clusters:
            s += str(cluster)
        return s

class OCFICluster:
    def __init__(self, addr, id, nexus_cap=12):
        self.addr = addr
        self.id = id
        self.nexus_cap = nexus_cap
        self.nexus = []
        self.fartargets = []
        self.targets = []

    def __copy__(self):
        clus = OCFICluster(self.addr, self.id, self.nexus_cap)
        clus.nexus = copy(self.nexus)
        clus.targets = copy(self.targets)
        clus.fartargets = copy(self.fartargets)
        return clus

    def maybe_add_to_nexus(self, ref):
        if len(self.nexus) == self.nexus_cap:
            return
        self.nexus.append(ref)

    def add_target(self, target_addr):
        self.targets.append(target_addr)
        return (self.id, len(self.targets) - 1)

    def add_fartarget(self, ref):
        self.fartargets.append(ref)

    def closeness_key(self):
        def closeness(a):
            id_diff = abs(self.id - a[0])
            if a[0] < self.id:
                # if it's less, higher idxs are closer
                idx_diff = -a[1]
            else:
                idx_diff = a[1]
            return (id_diff, idx_diff)

    def fill_nexus(self):
        # farthest == farthest cluster id -- 
        fartargs = sorted(self.fartargets, key=self.closeness_key())
        for t in fartargs[-self.nexus_cap:]:
            self.maybe_add_to_nexus(t)
        if len(fartargs) < self.nexus_cap:
            # add close targets too
            for closeid in range(len(self.targets) - (self.nexus_cap - len(fartargs)), len(self.targets)):
                if closeid < 0:
                    continue
                self.maybe_add_to_nexus((self.id, closeid))

    def update_refs(self, new_order):
        assert not self.nexus
        for i in range(len(self.fartargets)):
            oldid, loc = self.fartargets[i]
            self.fartargets[i] = (new_order[oldid], loc)

    def update_inner_refs(self, cluster_order):
        assert not self.nexus
        for i in range(len(self.fartargets)):
            id, oldloc = self.fartargets[i]
            self.fartargets[i] = (id, cluster_order[id][oldloc])

    def shuffle(self):
        new_order = list(range(len(self.targets)))
        random.shuffle(new_order)
        reverse_order = [0] * len(self.targets)
        for newid in range(len(new_order)):
            reverse_order[new_order[newid]] = newid

        newtargets = []
        for oldid in new_order:
            newtargets.append(self.targets[oldid])
        self.targets = newtargets
        return reverse_order

    def __str__(self):
        tlist = '\n\t'.join([str(t) for t in self.targets])
        return f'''Cluster {self.id}:
\tHash={hash(self)}
\tNexus: {self.nexus}
\tTargets:
\t{tlist}
'''

    def __hash__(self):
        return hash((frozenset(self.nexus), frozenset(self.targets), len(self.nexus), len(self.targets)))

    def __eq__(self, other):
        return frozenset(self.nexus) == frozenset(other.nexus) \
            and frozenset(self.targets) == frozenset(other.targets) \
            and len(self.nexus) == len(other.nexus) \
            and len(self.targets) == len(other.targets)


def generate_shuffled_transparent(base_ocfi):
    return base_ocfi.with_bbls_shuffled().with_clusters_shuffled()


def generate_opaque(ocfi):
    newocfi = copy(ocfi)
    # make sure same clusters
    newclusters = []
    for clus in ocfi.clusters:
        newclusters.append(copy(clus))
    newocfi.clusters = newclusters

    #newocfi.make_portals()
    # the attack CANNOT access and must derive the br addresses
    # of each cluster, as well as the full target set.
    for clus in newocfi.clusters:
        clus.addr = -1
        clus.fartargets = None
    return newocfi


def get_target_addrs(cfg, br_addr):
    addrs = set()
    for n in cfg.get_all_nodes(br_addr):
        for target in n.successors:
            if target.block is None:
                # doesn't actually exist
                continue
            try:
                target.block.bytes
            except:
                continue
            addrs.add(target.addr)
    return frozenset(addrs)


def get_resolved_indirect_branches(cfg):
    return [addr for addr in get_processed_indirect_branches(cfg) if get_target_addrs(cfg, addr)]


def get_processed_indirect_branches(cfg):
    branches = []
    branches += list(cfg.indirect_jumps.keys())
    
    # now collect rets
    for bbl in cfg.model.nodes():
        try:
            cs = bbl.block.capstone
        except:
            continue
        if bbl.addr in branches:
            continue # don't readd
        for ins in cs.insns:
            if ins.insn.mnemonic == 'ret':
                break
        else:
            # no rets
            continue
        # check if successors
        branches.append(bbl.addr)
    
    assert len(set(branches)) == len(branches)
    return branches


def print_stats(cfg):
    total_indir = get_processed_indirect_branches(cfg)
    resolved_indir = get_resolved_indirect_branches(cfg)
    indir_targets = {addr: get_target_addrs(cfg, addr) for addr in resolved_indir}
    unique_targets = set(indir_targets.values())

    singular_targets_dict = {}
    for v in indir_targets.values():
        if v in singular_targets_dict:
            singular_targets_dict[v] = False
        else:
            singular_targets_dict[v] = True
    singular_targets = list(filter(lambda k: singular_targets_dict[k], singular_targets_dict))

    basic_blocks = {addr for targets in unique_targets for addr in targets}
    real_basic_blocks = {cfg.get_any_node(addr).block.bytes for addr in basic_blocks}
    print('Analysis stats:')
    print('Total indirect branches found in CFG: %d' % (len(total_indir)))
    print('Correctly resolved indirect branches: %d' % (len(resolved_indir)))
    print('Number of unique target sets found: %d' % (len(unique_targets)))
    print('Number of singular (non-duplicated) target sets: %d' % (len(singular_targets)))
    print('Number of unique address-taken basic blocks: %d' % (len(basic_blocks)))
    print('Number of non-duplicated basic blocks: %d' % (len(real_basic_blocks)))
    #print({addr: cfg.get_any_node(addr).block.bytes for addr in basic_blocks})
