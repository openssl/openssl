HOW TO CONTRIBUTE TO OpenSSL
============================

Please visit our [Getting Started] page for other ideas about how to contribute.

  [Getting Started]: <https://openssl-library.org/community/getting-started>

Development is done on GitHub in the [openssl/openssl] repository.

  [openssl/openssl]: <https://github.com/openssl/openssl>

To request a new feature, ask a question, or report a bug,
please open an [issue on GitHub](https://github.com/openssl/openssl/issues).

Reporting security issues
-------------------------

If you believe you have found a security vulnerability, please do NOT
open a public GitHub issue or pull request for it.  Report it privately
to openssl-security@openssl.org instead; see our [security policy] for
details.

  [security policy]: <https://openssl-library.org/policies/general/security-policy/>

Submitting pull requests
------------------------

To submit a patch or implement a new feature, please open a
[pull request on GitHub](https://github.com/openssl/openssl/pulls).
Pull requests normally target the `master` branch; the release branches
(`openssl-3.x`) take bug fixes and documentation only, and changes that
apply to them are cherry-picked by the committers at merge time.

If you are thinking of making a large contribution,
open an issue for it before starting work, to get comments from the community.
Someone may be already working on the same thing,
or there may be special reasons why a feature is not implemented.

### How many pull requests at a time

Keep to no more than three or four open pull requests at a time, and let
those be reviewed to completion before opening more.  Review, not
authorship, is the scarce resource in this project: every pull request
consumes the attention of at least two committers, and a batch submitted
together does not get reviewed any faster than the same batch submitted
over months.  It merely displaces the review of everyone else's work,
including security fixes.  This applies regardless of how good the
individual changes are, and it is not satisfied by spacing submissions
out over a few hours or days.  Pull requests opened well in excess of
this may be closed without review, with a request to resubmit at a
sustainable rate.

If you are working through a list of candidate changes, choose those
three or four deliberately: send us the ones you consider most
important, rather than the first on the list or the quickest to write,
and explain in each why it matters.  You know your list; we do not, and
without that ranking the judgement of what to look at first falls on the
reviewers.

Nor is the answer to bundle them together.  A pull request carrying
twenty unrelated fixes is harder to review than any one of them alone,
cannot be merged a piece at a time, and leaves every change in it
blocked behind the one a reviewer disagrees with.  Each pull request
should address one logical change (perhaps spread across multiple
commits); what has to give is how many you submit, not how much you put
in each one.

### You are the author of what you submit

You are the author of everything you submit, whatever produced the first
draft of it.  Before opening a pull request you must have read the
change in full, understood why it is correct, built and tested it
yourself, and satisfied yourself that the problem it fixes is real.  You
must be prepared to answer a reviewer's questions about any line of it.
The `Assisted-by:` trailer (see below) discloses that a tool was used;
it does not transfer responsibility for the result.

### Descriptions and commit messages

Provide a clear description of the issue or feature being addressed,
including any relevant implementation details and, for performance
improvements, benchmark results.

Pull requests and commits should be self-contained, enabling readers to
understand what changed and why without needing to reference related
issues or having prior knowledge.  Commit messages should include all
relevant details to help future contributors follow the git history,
with clear explanations of what is changing and why.  Long descriptions
are encouraged if they aid understanding.  Commit message titles (their
first line) should be kept to 50-70 characters if possible.

### The review process

Pull requests (PRs) go through multiple phases before they are merged.
In the first phase the label 'approval: review pending' is added.  Once
you receive two or more approvals from [Committers] the label is changed
to 'approval: done', and 24 hours after this the label changes to
'approval: ready to merge', provided the PR has not been updated in the
meantime (any push, comment, or label change defers the transition,
which is then done manually by a committer).  At some time after this
your PR will be merged and the PR is closed.  Reviewers may ask you to
make changes at any phase before the pull request is merged, and any
changes (that are not just a rebase) will require re-approval.

[Committers]: https://openssl-library.org/about/committers/index.html

Pull request guidelines
-----------------------

To make it easier to review and accept your pull request, please follow these
guidelines:

 1. Anything other than a trivial contribution requires a [Contributor
    License Agreement] (CLA), giving us permission to use your code.
    If your contribution is too small to require a CLA (e.g., fixing a spelling
    mistake), then place the text "`CLA: trivial`" on a line by itself below
    the rest of your commit message separated by an empty line, like this:

    ```
        One-line summary of trivial change

        Optional main body of commit message. It might contain a sentence
        or two explaining the trivial change.

        CLA: trivial
    ```

    It is not sufficient to only place the text "`CLA: trivial`" in the GitHub
    pull request description.

    [Contributor License Agreement]: <https://www.openssl.org/policies/cla.html>

    To amend a missing "`CLA: trivial`" line after submission, do the following:

    ```
        git commit --amend
        # add the line, save and quit the editor
        git push -f [<repository> [<branch>]]
    ```

 2. Similarly, if a non-trivial portion of a contribution was created
    using an AI tool, you must declare which agent and model were used.
    This is done by adding `Assisted-by: {agent}:{model}` below the commit
    message:

    ```
        One-line summary of change with AI-generated portions

        Assisted-by: Claude:claude-sonnet-4-6
    ```

    Multiple Assisted-by trailers can be included if multiple tools were used:

    ```
        Assisted-by: Claude:claude-sonnet-4-6
        Assisted-by: ChatGPT:gpt-4o
        Assisted-by: GitHub Copilot:gpt-4.1
    ```

    You will need to have signed a CLA that includes the AI clauses
    (CLA v1.1 or later) in order to include AI-generated content in
    your contribution.

    Consult the [OpenSSL AI Code and Documentation Contribution
    Policy] if an AI model assisted with the creation of your
    contribution.

    [OpenSSL AI Code and Documentation Contribution
    Policy]: <https://openssl-library.org/policies/general/ai-policy/>

 3. All source files should start with the following text (with
    appropriate comment characters at the start of each line and the
    year(s) updated):

    ```
        Copyright 20xx-20yy The OpenSSL Project Authors. All Rights Reserved.

        Licensed under the Apache License 2.0 (the "License").  You may not use
        this file except in compliance with the License.  You can obtain a copy
        in the file LICENSE in the source distribution or at
        https://www.openssl.org/source/license.html
    ```

 4. Patches should be as current as possible; expect to have to rebase
    often. We do not accept merge commits, you will have to remove them
    (usually by rebasing) before it will be acceptable.

 5. Code provided should follow our [coding style](STYLE.md) and
    [documentation policy](DOCUMENTATION.md) and compile without warnings.
    Where `gcc` or `clang` is available, use the `--strict-warnings`
    `Configure` option to verify this.  OpenSSL compiles on many varied
    platforms: try to ensure you only use portable features.

    Consistent formatting is enforced by using `clang-format` with configuration
    stored in [.clang-format](.clang-format). OpenSSL uses `WebKit` style.
    You can configure git pre-commit to automatically reformat your code with
    [.pre-commit-config.yaml](.pre-commit-config.yaml) configuration.
    There is also a [Perl tool](util/reformat-patches.sh) to help with
    reformatting existing patches.

    Clean builds via GitHub Actions are required. They are started automatically
    whenever a PR is created or updated (for first-time contributors, a
    maintainer may need to approve the workflow runs).

 6. When at all possible, code contributions should include tests. These can
    either be added to an existing test, or completely new.  Please see
    [test/README.md](test/README.md) for information on the test framework.

 7. New features or changed functionality must include
    documentation. Please look at the `.pod` files in `doc/man[1357]` for
    examples of our style. Run `make doc-nits` to make sure that your
    documentation changes are clean.

 8. For user visible changes (API changes, behaviour changes, ...),
    consider adding a note in [CHANGES.md](CHANGES.md).
    This could be a summarising description of the change, and could
    explain the grander details.
    Have a look through existing entries for inspiration.
    Please note that this is NOT simply a copy of git-log one-liners.
    Also note that security fixes get an entry in CHANGES.md.
    This file helps users get more in-depth information of what comes
    with a specific release without having to sift through the higher
    noise ratio in git-log.

 9. Guidelines on how to integrate error output of new crypto library modules
    can be found in [crypto/err/README.md](crypto/err/README.md).

10. Once your Pull Request gets to the stage of being reviewed fixup commits
    should be used where possible. Fixup commits are squashed when the PR is
    finally merged. Fixup commits are done in the following way:

    ```
        # Add one or more updated files that needed changes
        git add <filename>

        # Do a fixup commit
        # <commit-id> is the id of a previous commit that you want to fix up.
        git commit --fixup <commit-id>

        # Do a non forced push
        git push
    ```

    To view commit-ids use:

    ```
       git log
    ```

11. If a Pull Request addresses an [issue](https://github.com/openssl/openssl/issues/)
    the commit should include the line:

    ```
        Fixes: LINK
    ```

    where LINK is the https link to the issue in GitHub.
