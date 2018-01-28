#!/usr/bin/env python

import argparse
import logging
import json
import os
import sys


def is_valid_input_dir(parser, arg):
    if not os.path.isdir(arg):
        parser.error("The input directory %s does not exist!" % arg)
    return arg


def parse_args():
    parser = argparse.ArgumentParser(description='osquery pack maker')
    parser.add_argument('-i', dest='input', required=True,
                        type=lambda x: is_valid_input_dir(parser, x),
                        help='Input Directory')
    parser.add_argument('-o', dest='output', required=True,
                        help='Output Pack File')
    parser.add_argument('-r', dest='readme', required=False,
                        help='Output Readme File (if present)')

    args = parser.parse_args()
    return args


def json_load(filepath):
    filedata = {}
    with open(filepath) as fh:
        try:
            filedata = json.load(fh)
        except ValueError as e:
            logger.error("Failed to parse %s" % filepath)
            logger.warning(e)

    return filedata


def merge_json_files(rootdir, files):
    data = {}
    for f in [f for f in files if f.endswith('.json')]:
        filepath = os.path.join(rootdir, f)
        logger.debug("Parsing %s" % filepath)
        data.update(json_load(filepath))
    return data


# parse the input directory, and build a hash of all the data. These
# will be merged at a later step.
def walk_input_dir(dir):
    confdb = {}
    for root, dirs, files in os.walk(dir):
        logger.debug("Starting on directory %s" % root)
        confdb[root] = merge_json_files(root, files)
        confdb[root]['name'] = os.path.basename(root)

        # If this is a query.sql file, note that we found a query, and
        # add it's contents to the confdb
        logger.debug(files)
        for f in [f for f in files if f == "query.sql"]:
            queryfile = os.path.join(root, f)
            confdb[root]['query'] = open(queryfile).read().lstrip().rstrip()

    return confdb


# Given the confdb, and a path, return a dict based on merging things
def merger(confdb, path):
    data = {}
    components = []
    while path:
        components.append(path)
        path = os.path.dirname(path)

    for c in reversed(components):
        data.update(confdb.get(c, {}))

    return data


def generate_readme(fh, pack_data):
    # Vague style guidance from https://osquery.io/schema/packs/
    # github markdown requires header rows. If we want to remove them,
    # need html tables.
    format_str = '''
| {name} | {description} |
| ------ | ------ |
| Query | {query} |
| Interval | {interval} |
| Platform | {platform} |
| Snapshot | {snapshot} |

----

'''
    for qname, qdata in pack_data['queries'].items():
        fh.write(format_str.format(
            name=qname,
            description=qdata['description'],
            query=qdata['query'],
            interval=qdata['interval'],
            platform=qdata.get('platform', 'all'),
            snapshot=qdata.get('snapshot', False)
        ))


def main():
    args = parse_args()
    confdb = walk_input_dir(args.input)

    pack_data = {
        'queries': {},
    }

    for path, confdata in confdb.items():
        data = merger(confdb, path)
        # with this new all-directories-are-queries thing, we get a
        # bit overbroad in what get's pulled into pack data. In my
        # test cases, we're now pulling in the top level dir, clearly
        # wrong. It's not what what other things will be
        # wrong. Likely, this will need some tweaking as more use
        # cases appear.
        if data['name'] == args.input:
            continue
        if 'query' in data:
            pack_data['queries'][data['name']] = data

    logger.debug(json.dumps(pack_data, indent=4, sort_keys=True))

    with open(args.output, 'w') as fh:
        json.dump(pack_data, fh,
                  indent=2,
                  sort_keys=True,
                  separators=(',', ': '))
        fh.write("\n")

    if args.readme:
        with open(args.readme, 'w') as fh:
            generate_readme(fh, pack_data)


if __name__ == "__main__":
    logger = logging.getLogger('osquery-packer')
    logging.basicConfig()
    logger.setLevel(logging.WARNING)
    main()
