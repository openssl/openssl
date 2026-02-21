#!/usr/bin/python

import sys
import json
import argparse
from unidiff import PatchSet
import re

def get_patch_filepath_reviewers(patch_set, rev_json):
    ids = []
    for file in patch_set:
        for group in rev_json["codegroups"]:
            for regex in group["filepathregexs"]:
                match = re.search(regex, file.path)
                if match:
                    for idgroup in group["groups"]:
                        ids = ids + rev_json["groups"][idgroup]["github_ids"] 
    return ids

def get_patch_filecontent_reviewers(patch_set, rev_json):
    ids = []
    for file in patch_set:
        for group in rev_json["codegroups"]:
            for regex in group["filecontentregexs"]:
                match = re.search(regex, str(file))
                if match:
                    for idgroup in group["groups"]:
                        ids = ids + rev_json["groups"][idgroup]["github_ids"] 
    return ids

def get_patch_reviewers(args, rev_json):
    patch_set = PatchSet(sys.stdin)
    pathids = get_patch_filepath_reviewers(patch_set, rev_json)
    contentids = get_patch_filecontent_reviewers(patch_set, rev_json)
    return pathids + contentids

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

def lint_reviewers(args):
    if args.reviewers == None:
        args.reviewers = "./REVIEWERS"
    try:
        with open(args.reviewers, 'r') as file:
            rev_json = json.load(file)
    except FileNotFoundError:
        print(f"Unable to load {args.reviewers}\n")
        return
    except json.JSONDecodeError:
        print(f"Reviewers JSON is mis-formatted\n")
        return

    for platform in rev_json["platforms"]:
        for group in platform["groups"]:
            if group in rev_json["groups"]:
                continue
            else:
                print(f"Group {group} does not exist for {platform["name"]}\n")
    for group in rev_json["codegroups"]:
        for groupid in group["groups"]:
            if groupid in rev_json["groups"]:
                continue
            else:
                print(f"Group {groupid} does not exist for {group["name"]}\n")
        
def load_and_parse_reviewers(args):
    reviewers = []

    if args.reviewers == None:
        args.reviewers = "./REVIEWERS"
    try:
        with open(args.reviewers, 'r') as file:
            rev_json = json.load(file)
    except FileNotFoundError:
        print(f"Unable to load {args.reviewers}\n")
        return
    except json.JSONDecodeError:
        print(f"Reviewers JSON is mis-formatted\n")
        return

    target_reviewers = get_target_reviewers(args, rev_json)
    reviewers = reviewers + target_reviewers
    patch_reviewers = get_patch_reviewers(args, rev_json)
    reviewers = reviewers + patch_reviewers
    reviewers = list(set(reviewers))

    for reviewer in reviewers:
        print(f"{reviewer} ")

def main(argv):
    parser = argparse.ArgumentParser(description="Fetch reviewers")

    parser.add_argument("-r", "--reviewers", help="select reviewers file")
    parser.add_argument("-t", "--target", help="specify target")
    parser.add_argument("-l", "--lint", action='store_true', help="lint REVIEWERS file")

    args = parser.parse_args(argv[1:])
   
    if args.lint == True:
        lint_reviewers(args)
        return 0

    load_and_parse_reviewers(args)
    return 0

if __name__ == "__main__":
    main(sys.argv)
