import capstone
import json
import os
import time


# TODO: as database support.
class Result:
    def __init__(self, max_stats=8):
        self._statistics = []
        self._max_stats = max_stats
        self._outfile = open("_".join([str(x) for x in time.localtime()[:6]])
                             + ".json", "a")
        self._outfile.write("[")

    def __del__(self):
        self.write_file()
        self._outfile.seek(0, os.SEEK_END)
        if self._outfile.tell() > 1:
            self._outfile.seek(self._outfile.tell() - 2)

        self._outfile.write("]")
        self._outfile.close()

    def add_statistics(self, stats):
        self._statistics.append(stats)

        if len(self._statistics) > self._max_stats:
            self.write_file()
            for stats in self._statistics:
                for item in stats:
                    del item
                del stats
            del self._statistics
            self._statistics = []

    def collect_statistics(self):
        loops = 0
        binaries_with_loops = 0
        bitops = 0
        binaries_with_bitops = 0

        for stat in self._statistics:
            if "loops" in stat:
                loops += stat["loops"]
                binaries_with_loops += 1

            if "bitops" in stat:
                bitops += stat["bitops"]
                binaries_with_bitops += 1

        avg_loops = loops / binaries_with_loops if binaries_with_loops > 0 else 0
        avg_bitops = bitops / binaries_with_bitops if binaries_with_bitops > 0 else 0
        return {"avg_loops": avg_loops,
                "avg_bitops": avg_bitops}

    def write_file(self):
        for stat in self._statistics:
            self._outfile.write(json.dumps(stat) + ",")

def print_statistics(stats, strings=False):
    """Prints statistics in a meaningful way."""
    # Print basic info.
    bininfo = stats["binary_info"]
    print("\nFilename: {}".format(bininfo["filename"]))
    print("Arch: {}".format(bininfo["arch"]))
    print("Entry: {}".format(bininfo["entry"]))

    # Print info about the main object.
    obj = stats["main_object"]
    print("Executable stack? {}".format(obj["execstack"]))
    print("Position independent code? {}".format(obj["pic"]))
    #supported_filetypes = ",".join(obj["filetypes"])
    #print("Supported file types: {}".format(supported_filetypes))
    print("")

    # Print some statistics.
    r = stats["indirect_jumps"]["resolved"]
    u = stats["indirect_jumps"]["unresolved"]
    print("Resolved {}/{} indirect jumps".format(r, r + u))
    print("Found {} loops".format(stats["loops"]))
    print("Found {} bitwise instructions".format(stats["bitops"]))
    print("Found {} syscalls".format(stats["syscalls"]))
    print("")

    # Relocations.
    print("Relocations:")
    for addr, d in obj["relocations"].items():
        if len(d["name"]):
            print("  {}: '{}' rebased to {}".format(hex(addr), d["name"],
                                                    hex(d["rebased"])))
    print("")

    # Strings. Only printing certain sections for now...
    if strings:
        for sec in [".rodata", ".data", ".idata", ".pdata", ".xdata", ".tls",
                    ".rdata", ".dynstr"]:
            if sec in stats["strings"]:
                print("Strings in {}".format(sec))
                for s in stats["strings"][sec]:
                    if len(s) > 4:
                        print("  '{}'".format(s))
                print("")

    # Instruction counts.
    print("Found {} different instructions".format(len(stats["ins_counts"])))
    print("Instruction counts:")
    count = 0
    for ins in sorted(stats["ins_counts"].keys()):
        count += stats["ins_counts"][ins]
        print("  {}: {}".format(ins, stats["ins_counts"][ins]))
    print("  ---------")
    print("  Total: {}\n".format(count))

    fmt = "{} of {} ({}%) instructions are bitwise arithmetic"
    print(fmt.format(stats["bitops"], count, stats["bitops"] / count * 100))
