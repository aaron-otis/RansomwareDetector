import argparse
import cle
import os
from analysis import Sample
from results import Result, print_statistics

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Attempts to discover ransomeware")
    ap.add_argument("path", nargs="+", help="A file or path to analyze")
    ap.add_argument("--load_libs", action="store_true", default=False,
                    help="Toggle automatic loading of linked libraries")
    ap.add_argument("-c", "--cfg", action="store_true", default=False,
                    help="Display control flow graph (in a very unorganized way)")
    ap.add_argument("-C", "--callgraph", action="store_true", default=False,
                    help="Display call graph")
    ap.add_argument("-r", "--recursive", action="store_true", default=False,
                    help="Recursively process the given path")
    ap.add_argument("-d", "--depth", type=int, default=1,
                    help="Recursion depth")
    ap.add_argument("-v", "--verbose", action="store_true", default=False,
                    help="Be more verbose")
    args = ap.parse_args()

    result = Result()
    num_files = 0
    sample = None
    stats = None

    for path in args.path:
        if os.path.isdir(path):
            for root, _, files in os.walk(path):
                for f in files:
                    try:
                        filename = os.path.join(root, f)
                        if args.verbose or True:
                            print("Opening '{}'".format(filename))

                        if sample:
                            del sample

                        sample = Sample(filename,
                                        load_libs=args.load_libs,
                                        show_cfg=args.cfg,
                                        show_cg=args.callgraph,
                                        verbose=args.verbose)

                    except Exception as err:
                        print(err)
                        continue

                    stats = sample.analyze()
                    result.add_statistics(stats)
                    if args.verbose:
                        print_statistics(stats)

                    num_files += 1

                args.depth -= 1
                if args.depth <= 0:
                    break

        else:
            try:
                sample = Sample(path, load_libs=args.load_libs,
                                show_cfg=args.cfg, show_cg=args.callgraph,
                                verbose=args.verbose)

            except Exception as err:
                print(err)
                continue

            stats = sample.analyze()
            result.add_statistics(stats)

            if sample:
                del sample

            num_files += 1
            if args.verbose:
                print_statistics(stats)

    for k, v in result.collect_statistics().items():
        print("{}: {}".format(k.replace("_", " "), v))
