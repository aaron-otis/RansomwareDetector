import json
import math
import string
import angr
import capstone

# TODO: Determine better keywords.
KEYWORDS = ["aes", "rsa", "des", "chacha", "crypt", "encrypt", "ransom"]
FUNCTIONS = ["write"]


class Function:
    """Represents a function."""
    def __init__(self, function, project, cfg):
        self._function = function
        self._project = project
        self._cfg = cfg

        self.insns = {}
        self.bitops = 0
        self.syscalls = 0
        self.loops = []
        self.calls = {}

        for block in self._function.blocks:
            try:
                for insn in block.capstone.insns:
                    # Check for bitwise instructions.
                    if self._is_bitwise_insn(insn):
                        self.bitops += 1
                    # Check for syscalls.
                    elif self._is_syscall(insn):
                        # TODO: Determine syscall number as well.
                        self.syscalls += 1

                    # Count every instruction.
                    if insn.mnemonic in self.insns:
                        self.insns[insn.mnemonic] += 1
                    else:
                        self.insns[insn.mnemonic] = 1
            except KeyError:
                continue

        # Detect all loops inside this function.
        end_addr = self.entry + self.size
        for loop in [loop for loop in self._project.analyses.LoopFinder().loops
                     if self.entry <= loop.entry.addr <= end_addr]:
            self.loops.append(Loop(loop, self._cfg))

        # Get calls.
        self.calls = {key: 1 for key in
                      self._project.kb.callgraph.adj[self.entry].keys()}

        # Add up calls found in loops.
        # Don't parse subloops, they will be checked by each loop itself.
        subloops = []
        for loop in self.loops:
            subloops += loop.subloops

        for loop in [loop for loop in self.loops if loop.entry not in subloops]:
            for f, count in loop.calls().items():
                if f in self.calls:
                    self.calls[f] += count
                else:
                    self.calls[f] = count

    # TODO: Support other architectures.
    def _is_bitwise_insn(self, insn):
        if self._project.arch.cs_arch == capstone.CS_ARCH_X86:
            return (insn.id == capstone.x86.X86_INS_AND or
                    insn.id == capstone.x86.X86_INS_OR or
                    insn.id == capstone.x86.X86_INS_XOR or
                    insn.id == capstone.x86.X86_INS_ANDPS or
                    insn.id == capstone.x86.X86_INS_ANDNPS or
                    insn.id == capstone.x86.X86_INS_ORPS or
                    insn.id == capstone.x86.X86_INS_XORPS or
                    insn.id == capstone.x86.X86_INS_ANDPD or
                    insn.id == capstone.x86.X86_INS_ANDNPD or
                    insn.id == capstone.x86.X86_INS_ORPD or
                    insn.id == capstone.x86.X86_INS_XORPD or
                    insn.id == capstone.x86.X86_INS_PAND or
                    insn.id == capstone.x86.X86_INS_PANDN or
                    insn.id == capstone.x86.X86_INS_POR or
                    insn.id == capstone.x86.X86_INS_PXOR)

        return False

    # TODO: Support other architectures.
    def _is_syscall(self, insn):
        """
        Returns true if the instruction is used to call a syscall and False otherwise.
        """
        if self._project.arch.cs_arch == capstone.CS_ARCH_X86:
            return (insn.id == capstone.x86.X86_INS_SYSCALL or
                    insn.id == capstone.x86.X86_INS_SYSENTER or
                    insn.group(capstone.x86.X86_GRP_INT))

        return False

    def to_json(self):
        """Converts a Function object into a JSON string."""
        return json.dumps(self.to_dict())

    def to_dict(self):
        """Returns a dictionary representation of this Function."""
        return {"name": self.name,
                "entry": self.entry,
                "size": self.size,
                "instructions": self.insns,
                "bitops":  self.bitops,
                "syscalls": self.syscalls,
                "calls": {hex(call): count for call, count in self.calls.items()},
                "loops": [loop.to_dict() for loop in self.loops]
                }

    def __str__(self):
        s = "{} ({}):\n".format(self.name, hex(self.entry))
        s += "  Bitops: {}\n".format(self.bitops)
        s += "  Syscalls: {}\n".format(self.syscalls)
        s += "  Instruction counts:\n"

        for mnemonic, count in self.insns.items():
            s += "    {}: {}\n".format(mnemonic, count)

        if self.loops:
            s += "  Loops:\n"
            for loop in self.loops:
                s += "    {}\n".format(loop)

        if self.calls:
            s += "  Calls:\n" + "\n".join(["    {} {} times".format(hex(f), i)
                                           for f, i in self.calls.items()])

        return s

    # Properties.
    @property
    def name(self):
        return self._function.name

    @property
    def entry(self):
        return self._function.addr

    @property
    def size(self):
        return self._function.size


class Loop:
    """
    Represents a loop. Adds functionality to angr.analyses.loopfinder.Loop
    (https://angr.io/api-doc/angr.html#angr.analyses.loopfinder.Loop)
    """
    def __init__(self, loop, cfg):
        self._loop = loop  # Loops object from angr.
        self._cfg = cfg

    def calls(self):
        """
        Returns a dictionary of function_address: count key-value pairs.
        """
        result = {}

        # Get start addresses of all blocks in each subloop.
        subloop_addrs = [n.addr for sub in self._loop.subloops for n in sub.body_nodes]

        # Parse blocks in this loop but not subloops.
        for addr in [node.addr for node in self._loop.body_nodes
                     if node.addr not in subloop_addrs]:
            block = self._cfg.get_any_node(addr)
            for ins in block.block.capstone.insns:
                if ins.insn.id == capstone.x86.X86_INS_CALL:
                    op = ins.insn.operands[0]

                    if op.type == capstone.x86.X86_OP_IMM:
                        if op.imm in result:
                            result[op.imm] += 1
                        else:
                            result[op.imm] = 1

        # Get call counts in subloops.
        for loop in [Loop(sub, self._cfg) for sub in self._loop.subloops]:
            subcalls = loop.calls()
            for f, counts in subcalls.items():
                if f in result:
                    result[f] += counts
                else:
                    result[f] = counts

        # Multiply each count by the number of times this loop iterates.
        for f in result:
            result[f] *= self.iterations

        return result

    def to_json(self):
        """Returns a JSON string representing the object."""
        return json.dumps(self.to_dict())

    def to_dict(self):
        """
        Returns a dictionary representing the object.
        Does not include the angr objects.
        """
        return {"entry": self.entry,
                "iterations": self.iterations,
                "has_calls": self.has_calls,
                "size": self.size,
                "subloops": self.subloops,
                }

    def __str__(self):
        s = str(self._loop)[: -1] + ", {} iterations>".format(self.iterations)

        return s

    # Properties.
    @property
    def entry(self):
        return self._loop.entry.addr

    @property
    def iterations(self):
        # Attempt to find the value of the sentinel.
        # Get basic block the loop starts at (loop breaks here as well).
        block = self._cfg.get_any_node(self.entry)

        # Attempt to get an immediate value.
        # FIXME: Need to handle Intel STOSx like instructions.
        try:
            # Get comparison instruction before jump.
            insn = block.block.capstone.insns[-2].insn
        except IndexError:
            return math.inf

        # Attempt to determine an immediate value for comparison.
        # Note: Assumes Intel syntax!
        if insn.operands[1].type == capstone.CS_OP_IMM:
            sentinel = insn.operands[1].imm
        else:
            return math.inf

        # We need the memory location the counter is stored in.
        if insn.operands[0].type == capstone.CS_OP_MEM:
            counter_mem = insn.operands[0].mem
        else:
            return math.inf

        # Get value counter is initialized to.
        # Find predecessor block that is not part of the loop.
        predecessors = block.predecessors
        for edge in self._loop.continue_edges:
            for block in edge:
                if block in predecessors:
                    predecessors.remove(block)

        for predecessor in predecessors:
            # Get all instructions (except the jump at the end).
            instructions = predecessor.block.capstone.insns[:-1]

            # Reverse list, because the instruction we want is likely at the end.
            instructions.reverse()

            # Look for the instruction modifying the memory location of the counter.
            for pred_insn in instructions:
                if pred_insn.operands[0].type == capstone.CS_OP_MEM:
                    pred_mem = pred_insn.operands[0].mem

                    # If the following is true, we found the variable we need.
                    if (pred_mem.base == counter_mem.base and
                            pred_mem.disp == counter_mem.disp and
                            pred_mem.index == counter_mem.index and
                            pred_mem.scale == counter_mem.scale):

                        # Immediate values give great info.
                        if pred_insn.operands[1].type == capstone.CS_OP_IMM:
                            init = pred_insn.operands[1].imm
                            return abs(sentinel - init)
                        # Values in registers require further analysis.
                        elif pred_insn.operands[1].type == capstone.CS_OP_REG:
                            # TODO: Determine register value.
                            return math.inf

        return math.inf

    @property
    def has_calls(self):
        return self._loop.has_calls

    @property
    def size(self):
        return sum([node.size for node in self._loop.body_nodes])

    @property
    def subloops(self):
        return [sub.entry.addr for sub in self._loop.subloops]


class Sample:
    """
    Represents a binary sample.
    """

    def __init__(self, filename, load_libs=False, show_cfg=False,
                 show_cg=False, verbose=False):

        self._project = angr.Project(filename,
                                     load_options={'auto_load_libs': load_libs})
        self._show_cfg = show_cfg
        self._show_cg = show_cg
        self._verbose = verbose
        self._statistics = None
        self._main_object = self._project.loader.main_object
        self._cfg = self._project.analyses.CFGEmulated()
        self._loops = []

        self.indirect_jumps = {}
        self.loops = 0
        self.bitops = 0
        self.syscalls = 0
        self.string_table = {}
        self.functions = []

        resolved = len(self._project.kb.resolved_indirect_jumps)
        unresolved = len(self._project.kb.unresolved_indirect_jumps)
        self.indirect_jumps["resolved"] = resolved
        self.indirect_jumps["unresolved"] = unresolved

        # Package relocations into a usable dictionary.
        self._relocs = {r.dest_addr: {"name": r.symbol.name if r.symbol else "",
                                      "rebased": r.rebased_addr}
                        for r in self._main_object.relocs}

        # Get functions.
        for func_addr, func in self._project.kb.functions.items():
            f = Function(func, self._project, self._cfg)
            self.bitops += f.bitops
            self.syscalls += f.syscalls
            self.functions.append(f)

        # Find all strings.
        self.string_table = self.strings()


    def analyze(self):
        """
        Analyzes a binary. Returns a dictionary of statistics.
        """
        # Attempt detection.
        # TODO: Determine if keeping track of the strings that have a keyword
        #       is desirable.
        keywords = []
        for _, strings in self.string_table.items():
            for s in strings:
                for word in KEYWORDS:
                    if word in s.lower():
                        keywords.append(s)
        keywords = list(set(keywords))
        print("Found {} strings containing keywords.".format(len(keywords)))

        functions = []
        for _, r in self._relocs.items():
            for word in KEYWORDS:
                if word in r["name"].lower():
                    functions.append(r["name"])
        print("Found {} relocations that contain keywords.".format(len(functions)))

        # CFG and CG stuff. Not sure what to do with these yet...
        if self._show_cfg:
            self.traverse_cfg(self._cfg, self._project.entry)

        if self._show_cg:
            cg = self._project.kb.callgraph
            if self._verbose:
                print("Call graph has {} nodes and {} edges".format(len(cg.nodes()),
                                                                    len(cg.edges())))
            self.traverse_call_graph(cg)

        print("Analysis complete!")

        return self.statistics()

    def statistics(self):
        """Returns a dictionary of statistics."""

        return {"loops": self.loops,
                "bitops": self.bitops,
                "syscalls": self.syscalls,
                "indirect_jumps": self.indirect_jumps,
                "strings": self.string_table,
                "filename": self._project.filename,
                "main_object": {"execstack": self._main_object.execstack,
                                "pic": self._main_object.pic,
                                "relocations": {hex(addr): data for addr, data
                                                in self._relocs.items()},
                                },
                "binary_info": {"arch": self._project.arch.name,
                                "entry": hex(self._project.entry)
                                },
                "functions": self.functions,
                # Convert callgraph to something that can be printed.
                "callgraph": {hex(addr): {hex(call): {str(k): v for k, v
                                                      in info.items()}
                              for call, info in data.items()}
                              for addr, data in
                              self._project.kb.callgraph.adj.items()},
                }

    def strings(self):
        strings = {}

        for sec in self._main_object.sections:
            # Trim any possible padding bytes.
            name = sec.name.replace("\x00", "")

            if name != ".bss":
                str_list = self._section_string_search(sec, 4)

                if len(str_list) > 0:
                    if "." in name:
                        key = name.replace(".", "_")
                    else:
                        key = name

                    if name in strings:
                        strings[key] += str_list
                    else:
                        strings[key] = str_list

        return strings

    def _section_string_search(self, sec, min=2):
        """Returns a list of ASCII strings."""

        stream = self._main_object.binary_stream
        stream.seek(sec.offset)
        data = stream.read(sec.filesize)
        strings = []

        result = ""
        for c in data:
            c = chr(c)
            if c in string.printable:
                result += c
                continue
            if len(result) >= min:
                strings.append(result)
            result = ""

        if result:
            print("Found non zero-terminated string.")
            strings.append(result)

        #print("section {} size: {}".format(sec.name, len(strings)))
        return strings

    def traverse_cfg(self, cfg, entry):
        # Get first node and print info about it.
        node = cfg.get_any_node(entry)
        nodes = [node]
        seen = set()

        while nodes:
            node = nodes.pop(0)
            if node.block_id and node.block_id.addr in seen:
                continue

            if node.block_id:
                seen.add(node.block_id.addr)

            id = hex(node.block_id.addr) if node.block_id else ""
            size = node.size if node.size else 0
            print("ID: {}, name: {}, size: {} ({})".format(id, node.name,
                  size, hex(size)))
            print("Successors: {}".format(node.successors))
            self._print_basic_block(node.block)
            print("")
            nodes += node.successors

    def traverse_call_graph(self, cg):
        raise NotImplementedError

    def _print_basic_block(self, block):
        if block and block.capstone:
            for ins in block.capstone.insns:
                print(hex(ins.insn.address), ins.insn.mnemonic, ins.insn.op_str)

    def find_function(self, addr):
        entries = [f.entry for f in self.functions]
        for i in range(len(entries) - 1):
            if entries[i] <= addr <= entries[i + 1]:
                return self.functions[i]

    def _find_function_index(self, entry):
        for i in range(len(self.functions)):
            if self.functions[i].entry == entry:
                return i
