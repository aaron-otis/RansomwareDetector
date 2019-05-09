import angr
import capstone
import string
import sys

# TODO: Determine better keywords.
KEYWORDS = ["aes", "rsa", "des", "chacha", "crypt", "encrypt", "ransom"]

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
        self._main_object = None
        self._cfg = None
        self._relocs = {}

        self.indirect_jumps = {}
        self.loops = 0
        self.bitops = 0
        self.syscalls = 0
        self.string_table = {}
        self.ins_counts = {}

    def analyze(self):
        """
        Analyzes a binary. Returns a dictionary of statistics.
        """

        self._main_object = self._project.loader.main_object
        self._cfg = self._project.analyses.CFGEmulated()

        resolved = len(self._project.kb.resolved_indirect_jumps)
        unresolved = len(self._project.kb.unresolved_indirect_jumps)
        self.indirect_jumps["resolved"] = resolved
        self.indirect_jumps["unresolved"] = unresolved

        # Detect loops.
        self.loops = len(self._project.analyses.LoopFinder().loops)

        # Package relocations into a usable dictionary.
        self._relocs = {r.dest_addr: {"name": r.symbol.name if r.symbol else "",
                                      "rebased": r.rebased_addr}
                        for r in self._main_object.relocs}

        # Detect bitwise operations, syscalls, etc.
        for _, func in self._project.kb.functions.items():
            counts = self._analyze_instructions(func)
            self.bitops += counts[0]
            self.syscalls += counts[1]

        # Find all strings.
        self.string_table = self.strings()

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
        print("Found {} functions (relocs) that contain keywords.".format(len(functions)))

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
                "ins_counts": self.ins_counts,
                "indirect_jumps": self.indirect_jumps,
                "strings": self.string_table,
                "main_object": {"execstack": self._main_object.execstack,
                                "pic": self._main_object.pic,
                                #"filetypes": self._main_object.supported_filetypes,
                                "relocations": self._relocs
                                },
                "binary_info": {"filename": self._project.filename,
                                "arch": self._project.arch.name,
                                "entry": hex(self._project.entry)
                                },
                }

    def _analyze_instructions(self, func):
        """
        Analyses instructions in several ways. Currently counts instructions in
        order for later statistical analysis.
        """
        bitops = 0
        syscalls = 0

        if func:
            for block in func.blocks:
                try:
                    for insn in block.capstone.insns:
                        # Check for bitwise instructions.
                        if self._is_bitwise_insn(insn):
                            bitops += 1
                        # Check for syscalls.
                        elif self._is_syscall(insn):
                            # TODO: Determine syscall number as well.
                            syscalls += 1

                        # Count every instruction.
                        if insn.mnemonic in self.ins_counts:
                            self.ins_counts[insn.mnemonic] += 1
                        else:
                            self.ins_counts[insn.mnemonic] = 1
                except KeyError:
                    continue

        return (bitops, syscalls)

    def strings(self):
        strings = {}

        for sec in self._main_object.sections:
            # Trim any possible padding bytes.
            name = sec.name.replace("\x00", "")

            if name != ".bss":
                str_list = self._section_string_search(sec, 4)

                if len(str_list) > 0:
                    if name in strings:
                        strings[name] += str_list
                    else:
                        strings[name] = str_list

        return strings

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

        print("section {} size: {}".format(sec.name, len(strings)))
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
            print("Loops {} times".format(node.looping_times))
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
