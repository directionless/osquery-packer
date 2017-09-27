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
        filepath=os.path.join(rootdir, f)
        logger.debug("Parsing %s" % filepath)
        data.update(json_load(filepath))
    return data

    
# parse the input directory, and build a database of all the
# hashses. These will be merged at a later step.
def walk_input_dir(dir):
    confdb = {}
    queries = {}
    for root, dirs, files in os.walk(dir):
        logger.debug("Starting on directory %s" % root)
        confdb[root] = merge_json_files(root, files)

        # If this is a query.sql file, note that we found a query, and
        # add it's contents to the confdb
        logger.debug(files)
        for f in [f for f in files if f == "query.sql"]:
            queryname = os.path.basename(root)
            queryfile = os.path.join(root, f)
            if queryname in queries:
                logger.critical("Duplicate query name %s" % queryname)
                sys.exit(1)
            
            queries[queryname] = queryfile
            confdb[queryfile] = {
                'query': open(queryfile).read().lstrip().rstrip()
            }

    return queries, confdb


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
    # github markdown requires header rows. If we want to remove them, need html tables.
    format_str='''
| {name} | {description} |
| ------ | ------ |
| Value | {value} |
| Query | {query} |
| Interval | {interval} |
| Platform | {platform} |

----

'''
    for qname, qdata in pack_data['queries'].items():
        fh.write(format_str.format(
            name = qname,
            description = qdata['description'],
            query = qdata['query'],
            interval = qdata['interval'],
            platform = qdata.get('platform', 'all'),
            value = qdata['value']
        ))

def main():
    args = parse_args()
    queries, confdb =  walk_input_dir(args.input)

    pack_data = {
        'queries': {},
    }
    
    for name, path in queries.iteritems():
        data = merger(confdb, path)
        logger.debug("Found query {0}, defined as {1}".format(name, data))
        pack_data['queries'][name] = data

    logger.debug(confdb)
    logger.debug(queries)

    with open(args.output, 'w') as fh:
        json.dump(pack_data, fh,
                  indent=2,
                  sort_keys=True,
                  separators=(',', ': '))
        fh.write("\n")
    

    if args.readme:
        with open(args.readme, 'w') as fh:
            generate_readme(fh, pack_data)
          

logger = logging.getLogger('osquery-packer')
logging.basicConfig()
logger.setLevel(logging.INFO)

if __name__ == "__main__":
    main()
