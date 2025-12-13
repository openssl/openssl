#! /bin/sh -efu

# Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").
# You may not use this file except in compliance with the License.
# You can obtain a copy in the file LICENSE in the source distribution
# or at https://www.openssl.org/source/license.html


: "${TAG_PRE_FMT=%s-PRE-CLANG-FORMAT-WEBKIT}"
: "${TAG_POST_FMT=%s-POST-CLANG-FORMAT-WEBKIT}"
: "${GIT_CMD=git}"
: "${CLANG_FMT_CMD=clang-format-21}"
: "${EXCLUDE_FILES=crypto/asn1/charmap.h crypto/bn/bn_prime.h crypto/conf/conf_def.h crypto/objects/obj_dat.h crypto/objects/obj_xref.h include/openssl/obj_mac.h}"
: "${FMT_EXTENSIONS=.c .h .c.in .h.in}"

: "${GIT_REPO_URL=https://github.com/openssl/openssl.git}"
: "${GIT_REMOTE=origin}"
: "${GIT_REPO_DIR=}"
: "${OUT_DIR=out}"
: "${OPENSSL_BRANCH=master}"
: "${PATCH_BRANCH=}"

NO_CLEANUP=0
WORK_BRANCH_PRE='reformat-patches-pre'
WORK_BRANCH_POST='reformat-patches-post'
PROCESS_BRANCH_PRE='reformat-patches-process-pre'

cleanup_done=0

msg()
{
    printf >&2 "%s\n" "$@"
}

die()
{
    msg "$*"
    exit 1
}

exit_handler()
{
    if [ -n "${WORKTREE_DIR-}" ]; then
        "$GIT_CMD" -C "${WORKTREE_DIR}" worktree remove -f "${WORKTREE_DIR}"
        rm -rf "${WORKTREE_DIR}"
    fi

    [ 0 = "${cleanup_done}" ] || return;

    if [ 0 = "${PERMANENT_GIT_DIR:-}" -a -n "${GIT_DIR:-}" ]; then
        msg "The temporarily created git repository directory is located" \
            "at '${GIT_DIR}', feel free to remove it after it is no longer" \
            "needed."
    fi
}

trap exit_handler 0

usage()
{
    msg "Usage: $0 [-g GIT_REPO_DIR] [-D] [-u GIT_REPO_URL] [-o OUT_DIR]" \
        "       [-b OPENSSL_BRANCH] [-B PATCH_BRANCH] [-h] [patch...]"
}

help()
{
    msg "" \
        "Re-format OpenSSL patches using clang-format." \
        "" \
        "A script applies patches on top of a pre-format-tagged commit," \
        "processes them with clang-format, and re-generates them on top" \
        "of the corresponding post-format-tagged commit." \
        "" \
        "OPTIONS:" \
        "    -g     Path to a local openssl repository;  if no local" \
        "           directory is specified, the repository is checked out" \
        "           from GIT_REPO_URL into a temporary directory" \
        "           (Current: '${GIT_REPO_DIR}')." \
        "    -D     Do not remove the temporarily created repository." \
        "    -u     URL for cloning the openssl repository, if no git" \
        "           repository directory was provided" \
        "           (Current: '${GIT_REPO_DIR}')." \
        "    -o     Output directory for patches (Current: '${OUT_DIR}')." \
        "    -b     openssl branch to work on (Current: '${OPENSSL_BRANCH}')." \
        "    -B     If non-empty, the provided branch is used as a source" \
        "           of patches;  this branch will also be reset" \
        "           to the processed path set on success" \
        "           (Current: '${PATCH_BRANCH}')." \
        "    -h     Show this help message and exit." \
        "    patch  Path to a patch file to process, required" \
        "           if no PATCH_BRANCH is specified.  If PATCH_BRANCH" \
        "           is provided, patches are applied on top of it." \
        "" \
        "ENVIRONMENT:" \
        "    TAG_PRE_FMT     Format of the pre-format tag" \
        "                    (Current: '${TAG_PRE_FMT}')." \
        "    TAG_POST_FMT    Format of the post-format tag" \
        "                    (Current: '${TAG_POST_FMT}')." \
        "    GIT_CMD         git command (Current: '${GIT_CMD}')." \
        "    CLANG_FMT_CMD   clang-format command" \
        "                    (Current: '${CLANG_FMT_CMD}')." \
        "    EXCLUDE_FILES   Space-separated list of files to exclude" \
        "                    from clang-format processing" \
        "                    (Current: '${EXCLUDE_FILES}')." \
        "    FMT_EXTENSIONS  List of extensions of files to process" \
        "                    (Current: '${FMT_EXTENSIONS}')." \
        "    GIT_REPO_URL    URL to openssl git repository, can be overridden" \
        "                    with -u option." \
        "    GIT_REPO_DIR    openssl git repository dir, can be overridden" \
        "                    with -g option." \
        "    GIT_REMOTE      Remote to track (Current: '${GIT_REMOTE}')." \
        "    OUT_DIR         Output directory for patches, can be overridden" \
        "                    with -o option." \
        "    OPENSSL_BRANCH  openssl branch to work on, can be overridden" \
        "                    with -b option." \
        "    PATCH_BRANCH    If non-empty, uses the branch as a source" \
        "                    of patches"
}

while getopts "g:Du:o:b:B:h" opt; do
    case "${opt}" in
    g) GIT_REPO_DIR="${OPTARG}"   ;;
    D) NO_CLEANUP=1               ;;
    u) GIT_REPO_URL="${OPTARG}"   ;;
    o) OUT_DIR="${OPTARG}"        ;;
    b) OPENSSL_BRANCH="${OPTARG}" ;;
    B) PATCH_BRANCH="${OPTARG}"   ;;
    h)
        usage
        help
        exit 0
        ;;
    ?)
        usage
        exit 1
        ;;
    esac
done

shift "$((OPTIND - 1))"

[ 0 -eq "$#" -o "x--" != "x${1-}" ] || shift

if [ -z "${PATCH_BRANCH}" -a 1 -gt "$#" ]; then
    usage
    die "PATCH_BRANCH is empty and no patches supplied on the command line, exiting"
fi

# Getting the repo
PERMANENT_GIT_DIR=1
if [ -z "${GIT_REPO_DIR}" ]; then
    PERMANENT_GIT_DIR=0
    GIT_REPO_DIR=$(mktemp -d "$(pwd)/reformat-openssl-XXXXXX")
    "$GIT_CMD" clone "${GIT_REPO_URL}" "${GIT_REPO_DIR}"
fi
if [ 1 = "${NO_CLEANUP}" ]; then
    msg "Created a temporary directory for the repo: ${GIT_REPO_DIR}"
fi

# Determine the tag name
if [ "master" = "${OPENSSL_BRANCH}" ]; then
    TAG_PREFIX=4.0
else
    # Check that we can extract the tag prefix first
    [ "x${OPENSSL_BRANCH#openssl-}" != "x${OPENSSL_BRANCH}" ] ||
        die "Can't parse branch name: '${OPENSSL_BRANCH}'," \
            "only 'master' and 'openssl-X.Y' are supported."
    TAG_PREFIX="${OPENSSL_BRANCH#openssl-}"
fi
TAG_PRE=$(printf "${TAG_PRE_FMT}" "${TAG_PREFIX}")
TAG_POST=$(printf "${TAG_POST_FMT}" "${TAG_PREFIX}")

# Create the worktree
WORKTREE_DIR=$(mktemp -d "$(pwd)/reformat-openssl-worktree-XXXXXX")
"$GIT_CMD" -C "$GIT_REPO_DIR" worktree add "${WORKTREE_DIR}" "${TAG_PRE}"

# Get the branches set up
BASE_COMMIT="${PATCH_BRANCH}"
[ -n "$BASE_COMMIT" ] || BASE_BRANCH="${OPENSSL_BRANCH}"
"$GIT_CMD" -C "$WORKTREE_DIR" branch -f "${WORK_BRANCH_POST}" "${TAG_POST}"
"$GIT_CMD" -C "$WORKTREE_DIR" branch -f "${WORK_BRANCH_PRE}" "${BASE_COMMIT}"
"$GIT_CMD" -C "$WORKTREE_DIR" branch -u "${GIT_REMOTE}/${OPENSSL_BRANCH}" "${WORK_BRANCH_PRE}"

# Apply the patches
while [ 0 -lt "$#" ]; do
    "$GIT_CMD" -C "$WORKTREE_DIR" am "$1"
    shift
done

# Working inside the worktree from now on
(
cd "${WORKTREE_DIR}"

# Rebase the branch 
"$GIT_CMD" checkout "${WORK_BRANCH_PRE}"
"$GIT_CMD" rebase "${TAG_PRE}"

# Iterate over the commits and process each with clang-format
"$GIT_CMD" log --reverse --pretty="%H" "${TAG_PRE}..${WORK_BRANCH_PRE}" \
    | while read -r commit; do
        "$GIT_CMD" branch -f "${PROCESS_BRANCH_PRE}" "$commit"
        "$GIT_CMD" checkout "${PROCESS_BRANCH_PRE}"
        msg "Processing $("$GIT_CMD" log --pretty=oneline HEAD^..HEAD)"
        # Process only the touched files
        "$GIT_CMD" show --pretty="" --name-status --no-renames "$commit" \
            | while read -r line; do
                # Skip deletions
                [ "x${line}" = "x${line#D}" ] || continue

                fname="${line#*	}"

                do_process=0
                # Process only *.c *.h *.c.in *.h.in
                for i in ${FMT_EXTENSIONS}; do
                    if [ "x${fname}" != "x${fname%${i}}" ]; then
                        do_process=1
                        break
                    fi
                done

                # Process the exclusion list
                for i in ${EXCLUDE_FILES}; do
                    if [ "x${fname}" = "x${i}" ]; then
                        do_process=0
                        break;
                    fi
                done

                if [ 1 = "${do_process}" ]; then
                    msg "  Formatting ${fname}"
                    "$CLANG_FMT_CMD" -i --style=file:.clang-format "$fname"
                else
                    msg "  Including ${fname} without processing"
                fi
                "$GIT_CMD" add "$fname"
            done

        "$GIT_CMD" commit --amend --no-edit
        "$GIT_CMD" checkout "${WORK_BRANCH_POST}"

        "$GIT_CMD" show --pretty="" --name-status --no-renames "${PROCESS_BRANCH_PRE}" \
            | while read -r line; do
                fname="${line#*	}"

                # Process deletions
                if [ "x${line}" = "x${line#D}" ]; then
                    "$GIT_CMD" rm "$fname"
                    continue
                fi

                "$GIT_CMD" reset "${PROCESS_BRANCH_PRE}" -- "$fname"
            done

        "$GIT_CMD" commit -C "${commit}"
        "$GIT_CMD" reset --hard
    done
) # End of the subshell with pwd in the worktree

# Output the patches
mkdir -p "${OUT_DIR}"
OUT_DIR=$(realpath "${OUT_DIR}")
"$GIT_CMD" -C "${WORKTREE_DIR}" format-patch -o "$(pwd)/${OUT_DIR}" "${TAG_POST}..${WORK_BRANCH_POST}"
msg "The resulting patches are saved at '${OUT_DIR}'"

# Cleanup
if [ 0 = "${NO_CLEANUP}" ]; then
    [ 1 = "${PERMANENT_GIT_DIR}" ] || rm -rf "${GIT_REPO_DIR}"
fi

cleanup_done=1
