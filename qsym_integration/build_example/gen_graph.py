import sys
import ipdb
import glob
import time
import os
import pickle
from os import path
import subprocess
import networkit as nk
from collections import defaultdict


local_table_2_fun_name = {}
covered_node = []
node_2_callee, func_name_2_root_exit_dict = {}, {}

global_reverse_graph = defaultdict(list)
global_graph = defaultdict(list)
global_graph_weighted = defaultdict(dict)
global_back_edge = list()

def inline_counter_table(filename):

    bin_text = ''
    with open(filename, "r") as f:
        bin_text = f.read()

    line = subprocess.check_output('grep "llvm.compiler.used" ' + filename, shell=True, encoding='utf-8')[:-1]
    data = [ele for ele in line.split(', i8*') if ' i32]* @__sancov_gen_' in ele]
    data[0] = data[0].split(' [i8*')[1]

    # handle dummy counter which are not used by any functions.
    new_data = []
    for ele in data:
        idx = bin_text.find(' @' + ele.split('@')[1].split()[0] + ', ')
        if idx != -1:
            new_data.append(ele)
    data = new_data

    ans = {}
    ordered_key = []

    for ele in data:
        ans[ele.split()[4]] = int(ele.split()[1][2:])
        ordered_key.append(ele.split()[4])

    tmp_sum = 0
    inline_table= {}
    for key in ordered_key:
        inline_table[key] = tmp_sum
        tmp_sum += ans[key]
        print(key, tmp_sum)

    return inline_table

def detect_back_edge(graph):
    visited = set()
    back_edge = []
    def dfs(node, path):
        for nei in graph[node]:
            if nei not in visited:
                visited.add(nei)
                path.add(nei)
                dfs(nei, path)
                path.remove(nei)

            # detect back edge
            elif nei in path:
                back_edge.append((node, nei))

    cnt = 0
    for node,_ in graph.items():
        if node not in visited:
            visited.add(node)
            cur_path = set()
            cur_path.add(node)
            dfs(node, cur_path)
            cnt+=1

    return back_edge, cnt

def construct_graph_init(dot_file, inline_table, fun_list, node_2_callee, func_name_2_root_exit_dict):

    lines = open(dot_file, 'r').readlines()
    graph, reverse_graph = {}, {}

    root, exit = None, None

    my_func_name = dot_file.split('/')[-1].split('.')[0]

    dot_id_2_llvm_id = {}
    non_instrumented_node = []
    for line in lines:
        if line.startswith('\t'):
            if '[' in line:
                split_idx = line.index('[')
                node_id = line[:split_idx].strip()
                code = line.split('label=')[1].strip()[1:-3]
                # check instrumention basic block only
                loc = code.find('i32]* @__sancov_gen_')
                # convert opt node id to llvm node id
                if loc != -1:
                    local_table, local_edge = None, None

                    # parse the second and following node
                    if ',' not in code[loc:].split(')')[0]:
                        local_table = code[loc:].split(')')[0].split()[1]
                        local_edge = code[loc:].split(')')[1].split()[-1]
                    # parse the first node
                    else:
                        local_table = code[loc:].split(')')[0].split()[1][:-1]
                        local_edge = 0

                    if local_table not in local_table_2_fun_name:
                        local_table_2_fun_name[local_table] = my_func_name
                    global_edge = int(int(local_edge)/4) + inline_table[local_table]

                    dot_id_2_llvm_id[node_id] = global_edge
                    for inst in code.split('\\l  '):
                        # check if is call inst
                        if ('call' in inst or 'invoke' in inst) and '@' in inst:
                            fun_name = inst[inst.find('@')+1:inst.find('(')]
                            fun_name = fun_name.replace("\l...", '')
                            # check if is native function, not external func
                            if fun_name in fun_list:
                                # add callee to node
                                if global_edge not in node_2_callee:
                                    node_2_callee[global_edge] = [fun_name]
                                else:
                                    node_2_callee[global_edge].append(fun_name)
                        if not exit and 'ret ' in inst:
                            exit = node_id
                else:
                    non_instrumented_node.append(node_id)

                graph[node_id] = []
                if node_id not in reverse_graph:
                    reverse_graph[node_id] = []
            elif '->' in line:
                # ignore the last character ';'
                tokens = line.split('->')
                src_node = tokens[0].strip().split(':')[0]
                dst_node = tokens[1].strip()[:-1]
                if dst_node not in graph[src_node]:
                    graph[src_node].append(dst_node)
                if dst_node not in reverse_graph:
                    reverse_graph[dst_node] = [src_node]
                else:
                    if src_node not in reverse_graph[dst_node]:
                        reverse_graph[dst_node].append(src_node)

    if len(non_instrumented_node) == len(graph):
        return

    # delete dummy nodes(ASAN-node) on the graph
    for node in non_instrumented_node:
        children, parents = graph[node], reverse_graph[node]
        for child in children:
            for parent in parents:
                if child not in graph[parent]:
                    graph[parent].append(child)
                if parent not in reverse_graph[child]:
                    reverse_graph[child].append(parent)
        del graph[node]
        del reverse_graph[node]
        for parent in parents:
            graph[parent].remove(node)
        for child in children:
            reverse_graph[child].remove(node)

    # detect and delete back edge
    back_edge,cnt = detect_back_edge(graph)

    if back_edge:
        for parent,child in back_edge:
            global_back_edge.append(( dot_id_2_llvm_id[parent], dot_id_2_llvm_id[child]))
            graph[parent].remove(child)
            reverse_graph[child].remove(parent)

    for node, neis in reverse_graph.items():
        if len(neis) == 0:
            func_name_2_root_exit_dict[my_func_name] = (dot_id_2_llvm_id[node], -1)
            break

    # convert node id from dot_id to llvm_instrumented_id, add to global graph
    for node, neis in graph.items():
        if not neis:
            global_graph[dot_id_2_llvm_id[node]] = []
            global_graph_weighted[dot_id_2_llvm_id[node]] = {}
        for nei in neis:
            global_graph[dot_id_2_llvm_id[node]].append(dot_id_2_llvm_id[nei])
            global_graph_weighted[dot_id_2_llvm_id[node]][dot_id_2_llvm_id[nei]] = 1

    for node, neis in reverse_graph.items():
        if not neis:
            global_reverse_graph[dot_id_2_llvm_id[node]] = []
        for nei in neis:
            global_reverse_graph[dot_id_2_llvm_id[node]].append(dot_id_2_llvm_id[nei])

    return



if __name__ == '__main__':

    inline_table = inline_counter_table(sys.argv[1])

    fun_list = [dot_file.split('/')[-1].split('.')[0] for dot_file in glob.glob("./" + sys.argv[2] + "/*")]
    for dot_file in glob.glob("./" + sys.argv[2] +"/*"):
        construct_graph_init(dot_file, inline_table, fun_list, node_2_callee, func_name_2_root_exit_dict)

    # add edge link to calling site
    for node, callee_l in node_2_callee.items():
        if node not in global_graph: continue
        # skip external func
        callees = list(set([ele for ele in callee_l if ele in func_name_2_root_exit_dict]))
        for i in range(len(callees)):
            entry, _ = func_name_2_root_exit_dict[callees[i]]
            global_graph_weighted[node][entry] = 1
            global_graph[node].append(entry)
            global_reverse_graph[entry].append(node)

    # remove func-call level back edge
    back_edge,cnt = detect_back_edge(global_graph)
    if back_edge:
        for parent,child in back_edge:
            global_back_edge.append((parent, child))
            global_graph[parent].remove(child)
            del global_graph_weighted[parent][child]
            global_reverse_graph[child].remove(parent)

    graph_data_pack = [global_graph, global_reverse_graph, global_graph_weighted]
    pickle.dump(graph_data_pack, open("graph_data_pack", "wb"))

    # mapping discontinuous real node id into continuous tmp id for nk.graph modelling
    real_id_2_tmp_id = {}
    tmp_id_2_real_id = {}
    for idx, node in enumerate(sorted(global_graph_weighted.keys())):
        real_id_2_tmp_id[node] = idx
        tmp_id_2_real_id[idx] = node

    nk_new_graph = nk.Graph(n=len(global_graph_weighted), weighted=True, directed=True)
    for node, neis in global_graph_weighted.items():
        for nei, weight in neis.items():
            #nk_new_graph.addEdge( real_id_2_tmp_id[nei], real_id_2_tmp_id[node], w=( 0.5**(weight-1)))
            nk_new_graph.addEdge( real_id_2_tmp_id[nei], real_id_2_tmp_id[node], w=(1/weight))
    k = nk.centrality.KatzCentrality(nk_new_graph, alpha=0.5, beta=1.0, tol=1e-12)
    k.run()
    scaled_rank = {}
    max_score = max(k.scores())
    min_score = min(k.scores())
    for ele in k.ranking():
        real_id = tmp_id_2_real_id[ele[0]]

        if ele[1] == max_score:
            scaled_rank[real_id] = 10
        else:
            scaled_rank[real_id] = 10 / max_score * ele[1]

    with open("katz_cent", "w") as f:
        for key in sorted(scaled_rank.keys()):
            f.write(str(key+1) + " " + str(round(scaled_rank[key], 14)) + "\n")

    # add backedge to graph
    for parent, child in global_back_edge:
        global_graph[parent].append(child)
        global_reverse_graph[child].append(parent)

    with open("child_node", "w") as f:
        for key in sorted(global_graph.keys()):
            tmp = ' '.join([str(key+1)] + [str(ele+1) for ele in global_graph[key]]) + '\n'
            f.write(tmp)

    with open("parent_node", "w") as f:
        for key in sorted(global_reverse_graph.keys()):
            tmp = ' '.join([str(key)] + [str(ele) for ele in global_reverse_graph[key]]) + '\n'
            f.write(tmp)

    border_edges = []
    for node in sorted(global_graph.keys()):
        children = global_graph[node]
        children.sort()
        if len(children) > 1:
            for c in children:
                border_edges.append((node, c))
    with open("border_edges", "w") as f:
        for p, c in border_edges:
            f.write(str(p+1) + " " + str(c+1) + "\n")



