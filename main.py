import argparse
import os
from analysis import Sample
from results import Result, print_statistics


def main(args):
    result = Result(db=parse_server_info(args.server))
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

                        sample = Sample(filename,
                                        load_libs=args.load_libs,
                                        show_cfg=args.cfg,
                                        show_cg=args.callgraph,
                                        verbose=args.verbose)

                    except Exception as err:
                        print(err)
                        continue

                    if args.statistics:
                        stats = sample.statistics()
                    else:
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

            if args.statistics:
                stats = sample.statistics()
            else:
                stats = sample.analyze()

            result.add_statistics(stats)

            num_files += 1
            if args.verbose:
                print_statistics(stats, strings=True)

    for k, v in result.collect_statistics().items():
        print("{}: {}".format(k.replace("_", " "), v))


def parse_server_info(server):
    """
    Parses a server string. Currently supports 'server:port' or 'server'.
    Returns a dictionary suitable for use in a Result object if server is a
    nonempty string, or None otherwise.
    """
    db_info = None
    if server:
        if ":" in server:
            db_info = server.split(":")
            db_info = {"address": db_info[0], "port": db_info[1]}
        else:
            db_info = {"address": server}

    return db_info


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Attempts to discover ransomeware")
    ap.add_argument("path", nargs="+", help="A file or path to analyze")
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
    ap.add_argument("--server", default="", help="The database server to connect to, either 'server:port' or 'server'")
    ap.add_argument("--statistics", action="store_true", default=False,
                    help="Only gather statistics, do not perform analysis")
    ap.add_argument("--load_libs", action="store_true", default=False,
                    help="Toggle automatic loading of linked libraries")
    args = ap.parse_args()

    main(args)
