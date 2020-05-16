import angr
import sys
import pickle
import random
from copy import copy 
import ocfi
from networkx.algorithms.components import number_strongly_connected_components

def get_unresolved_call_tset(cfg):
    # the target set of an unresolved call is every function, we can't
    # narrow past this
    return frozenset(cfg.functions)

def get_unresolved_ret_tset(cfg):
    # gather addresses of all BBLs preceded by calls
    tset = set()
    for n in cfg.model.nodes():
        try:
            cs = n.block.capstone
        except:
            pass
        insn = cs.insns[-1].insn
        if insn.mnemonic == 'call':
            nextaddr = insn.address + len(insn.bytes)
            assert cfg.get_any_node(nextaddr) is not None
            tset.add(nextaddr)
    return frozenset(tset)

def solve_for_addrs(ocfilocal, ocfitarget):
    # ocfilocal is our local randomization of OCFI -- we can correlate branches to clusters via analysis
    # ocfitarget is our target randomization -- this is what we are attacking
    # ocfitarget is currently opaque in terms of which branches go where
    # our goal is to "see through" this -- deduce which branches correlate to which clusters

    # replace nexus of both OCFIs with the actual target blocks they point to.
    # this will make mapping them much simpler with only a slight reduction in quality.
    
    big_nexus_clusters = {}
    for clus in ocfilocal.clusters:
        if len(clus.fartargets) >= clus.nexus_cap:
            # this makes things more difficult -- we don't know for sure which targets will show up in the randomization
            # check separately
            big_nexus_clusters[clus.id] = []
            for i in range(len(clus.fartargets)):
                ci, loc = clus.fartargets[i]
                clus.fartargets[i] = (ocfilocal.clusters[ci].targets[loc], frozenset(ocfilocal.clusters[ci].targets))
            clus.fartargets = clus.fartargets + [(-1, len(clus.targets))]
            clus.nexus = clus.fartargets + [-1]
            continue
        for i in range(len(clus.nexus)):
            ci, loc = clus.nexus[i]
            # add full target set of pointed-to cluster to increase quality of mapping
            if ci == clus.id:
                # self-target, don't resolve to block because there are many possibilities for ordering
                clus.nexus[i] = (-1, len(clus.targets))
            else:
                clus.nexus[i] = (ocfilocal.clusters[ci].targets[loc], frozenset(ocfilocal.clusters[ci].targets))
    
    for clus in ocfitarget.clusters:
        assert not clus.fartargets
        for i in range(len(clus.nexus)):
            ci, loc = clus.nexus[i]
            # add full target set of pointed-to cluster to increase quality of mapping
            if ci == clus.id:
                # self-target, don't resolve to block because there are many possibilities for ordering
                clus.nexus[i] = (-1, len(clus.targets))
            else:
                clus.nexus[i] = (ocfitarget.clusters[ci].targets[loc], frozenset(ocfitarget.clusters[ci].targets))

    # we can only do analysis on unduplicated clusters -- check this after the nexus replacement,
    # otherwise we might re-duplicate afterwards
    unduplicated_real_clusters_dict = {}
    for c in ocfilocal.clusters:
        # "in" operator checks target set and nexus
        if c in unduplicated_real_clusters_dict:
            unduplicated_real_clusters_dict[c] = False
        else:
            unduplicated_real_clusters_dict[c] = True
    unduplicated_real_clusters = {c for c, undup in unduplicated_real_clusters_dict.items() if undup}
    print(len(unduplicated_real_clusters))
    # now we can deduce addrs
    big_skip = set()
    for clus in ocfitarget.clusters:
        # the mapping essentially happens "automatically" -- the
        # eq and hash methods defined by cluster make everything smooth
        
        if clus not in ocfilocal.clusters and len(clus.nexus) == 12:
            # might be a bignexus cluster
            matched = False
            failed = False
            for k in big_nexus_clusters:
                bnclus = ocfilocal.clusters[k]
                if frozenset(bnclus.targets) != frozenset(clus.targets):
                    continue
                for t in clus.nexus:
                    if t not in bnclus.nexus:
                        break
                else:
                    if matched:
                        # if this cluster matches multiple big clusters, we can't know which it's a part of.
                        # however, we should still keep its entry in the big_nexus_clusters dict so that
                        # other clusters can't claim this big cluster
                        failed = True
                    # tentative match
                    matched = True
                    big_nexus_clusters[k].append(clus.id)
            # by here, we must have matched a big nexus cluster
            # or else there is no match
            assert matched
            if failed:
                big_skip.add(clus.id)
            continue

        if clus not in unduplicated_real_clusters:
            # can't uniquely map to one branch
            continue

        assert clus in ocfilocal.clusters
        i = ocfilocal.clusters.index(clus)
        # make sure this is really unique
        assert clus not in ocfilocal.clusters[:i] + ocfilocal.clusters[i+1:]
        clus.addr = ocfilocal.clusters[i].addr

    
    missedcount = 0
    hitcount = 0
    print(big_nexus_clusters)
    for k, l in big_nexus_clusters.items():
        if ocfilocal.clusters[k] not in unduplicated_real_clusters:
            continue
        assert l
        if len(l) != 1 or l[0] in big_skip:
            missedcount += 1
            print(l)
            continue
        hitcount += 1
        ocfitarget.clusters[l[0]].addr = ocfilocal.clusters[k].addr
    print(missedcount)
    print(hitcount)
        

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('Usage: python %s <pickled-cfg>' % (sys.argv[0]))
    filename = sys.argv[1]
    with open(filename, 'rb') as f:
        cfg = pickle.load(f)
    
    _ocfibase = ocfi.OCFI(cfg)
    local = ocfi.generate_shuffled_transparent(_ocfibase)
    
    local.do_move_targets()
    local.make_portals()
    target = ocfi.generate_shuffled_transparent(_ocfibase)
    
    target.do_move_targets()
    target.make_portals()
    real_target = ocfi.generate_opaque(target)
    real_target.do_move_targets()
    # local is our local copy, it is transparent to us in terms of 
    # which branches map to which clusters
    # real_target is the target program, its mem has been dumped and
    # parsed into the OCFI structure so we can see all of its clusters
    # but cannot see which branches map to which clusters
    # target is our ground truth for real_target's addrs

    solve_for_addrs(local, real_target)
    # check for correctness
    correct_count = 0
    duped_count = 0
    rem_addrs = []
    for i in range(len(real_target.clusters)):
        clus = real_target.clusters[i]
        trueclus = target.clusters[i]
        if clus.addr == -1:
            # skipped
            duped_count += 1
            rem_addrs.append(trueclus.addr)
            continue
        assert clus.addr == trueclus.addr, 'False positive detected! %d != %d\nClusters:\n%s\n%s' % (clus.addr, trueclus.addr, str(clus), str(trueclus))
        correct_count += 1

    ocfi.print_stats(cfg)
    print('\nMatching finished successfully!')
    print('----- RESULTS -----')
    print('Correctly matched clusters: %d' % (correct_count))
    print('Skipped clusters (duplicates): %d' % (duped_count))
    print('Strongly connected components of original subgraph: %d' % number_strongly_connected_components(cfg.graph))
    for addr in rem_addrs:
        for n in cfg.get_all_nodes(addr):
            oe = list(cfg.graph.out_edges(n))
            cfg.graph.remove_edges_from(oe)
    print('Strongly connected components of pruned subgraph: %d' % number_strongly_connected_components(cfg.graph))
