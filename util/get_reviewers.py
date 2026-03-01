#!/usr/bin/python

import sys
import json
import jsonschema
import argparse
from unidiff import PatchSet
import re

def get_group_object(group_name, rev_json):
    for group in rev_json["groups"]:
        if group["name"] == group_name:
            return group
    return None

def get_patch_reviewers(args, rev_json):
    patch_set = PatchSet(sys.stdin)
    ids = []
    for file in patch_set:
        for group in rev_json["codegroups"]:
            for regex in group["filepathregexs"]:
                match = re.search(regex, file.path)
                if match:
                    for idgroup in group["groups"]:
                        namedgroup = get_group_object(idgroup, rev_json)
                        if namedgroup != None:
                            ids = ids + namedgroup["github_ids"] 
            for regex in group["filecontentregexs"]:
                match = re.search(regex, str(file))
                if match:
                    for idgroup in group["groups"]:
                        namedgroup = get_group_object(idgroup, rev_json)
                        if namedgroup != None:
                            ids = ids + namedgroup["github_ids"] 
    return ids
   
def get_target_reviewers(args, rev_json):
    ids = []
    if (args.target == None):
        return []
    for platform in rev_json["platforms"]:
        for regex in platform["regexs"]:
            match = re.search(regex, args.target)
            if match:
                for group in platform["groups"]:
                    ids = ids + rev_json["groups"][group]["github_ids"]
    return ids

def load_json_file(filename):
    try:
        with open(filename, 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        print(f"Unalbe to load {filename}\n")
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"{filename} is mis-formatted\n")
        sys.exit(1)

def lint_reviewers(args):
    rev_json = load_json_file(args.reviewers_file)
    rev_schema = load_json_file(args.schema)
    try:
        jsonschema.validate(instance=rev_json, schema=rev_schema)
        print(f"{args.reviewers_file} is valid\n")
    except jsonschema.exceptions.ValidationError as e:
        print("Invalid JSON data:")
        print(e)
        sys.exit(1)
    # Build a temporary list of groups to do reverse mapping checks
    grouprefcounts = {}
    for group in rev_json["groups"]:
        if group["name"] in grouprefcounts:
            print(f"Duplicate group name {group["name"]}\n")
            sys.exit(1)
        grouprefcounts[group["name"]] = 0

    # Make sure every group listed in all the platforms and 
    # codegroups arrays is valid
    for platform in rev_json["platforms"]:
        for group in platform["groups"]:
            namedgroup = get_group_object(group, rev_json)
            if namedgroup != None:
                grouprefcounts[group] += 1
            else:
                print(f"Group {group} does not exist for {platform["name"]}\n")
                sys.exit(1)
    for group in rev_json["codegroups"]:
        for groupid in group["groups"]:
            namedgroup = get_group_object(groupid, rev_json)
            if namedgroup != None:
                grouprefcounts[groupid] += 1
            else:
                print(f"Group {groupid} does not exist for {group["name"]}\n")
                sys.exit(1)

    # Check our group reference counts to note any that are unreferenced
    for groupkey in grouprefcounts:
        if grouprefcounts[groupkey] == 0:
            print(f"NOTE: {groupkey} is unreferenced\n")

    return

def load_and_parse_reviewers(args):
    reviewers = []
    rev_json = load_json_file(args.reviewers_file)

    target_reviewers = get_target_reviewers(args, rev_json)
    reviewers = reviewers + target_reviewers
    patch_reviewers = get_patch_reviewers(args, rev_json)
    reviewers = reviewers + patch_reviewers
    reviewers = list(set(reviewers))

    for reviewer in reviewers:
        print(f"{reviewer} ")

def main(argv):
    parser = argparse.ArgumentParser(description="Fetch reviewers")

    parser.add_argument("-r", "--reviewers_file", help="select REVIEWERS file",
                        default="./REVIEWERS.json")
    parser.add_argument("-t", "--target", help="specify target")
    parser.add_argument("-l", "--lint", action='store_true', help="lint REVIEWERS file")
    parser.add_argument("-s", "--schema", help="select validation schema",
                        default="./REVIEWERS.json.schema")
    parser.add_argument("-v", "--verbose", action='store_true', help="verbose parsing output")

    args = parser.parse_args(argv[1:])
   
    if args.lint == True:
        lint_reviewers(args)
        return 0

    load_and_parse_reviewers(args)
    return 0

if __name__ == "__main__":
    main(sys.argv)
