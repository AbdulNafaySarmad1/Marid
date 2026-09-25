# MARID repository knowledge graph

The [interactive Graphify map](../graphify-out/graph.html) and [Graphify report](../graphify-out/GRAPH_REPORT.md) describe the current source tree. The [machine-readable graph](../graphify-out/graph.json) contains 535 nodes, 832 edges, and 54 detected communities. It includes C#, SQL migrations, project files, tests, and scripts. Graphify's code-only mode skips the eight Markdown documents; those documents remain the source for release status and operating guidance.

The graph was generated with Graphify 0.9.67 using local AST extraction and its optional SQL grammar. The Windows SQL parser crashed, so extraction ran in a disposable Linux container; clustering and HTML generation then ran locally. No repository content was sent to an external model during this run.

To refresh after code changes, install `graphifyy[sql]` in an isolated environment and run `graphify extract . --code-only --max-workers 2 --force`, followed by `graphify cluster-only . --no-label`. Review and keep `graph.html`, `graph.json`, and `GRAPH_REPORT.md` alongside the code changes. The parser cache and machine-specific extraction metadata are ignored. Query it with `graphify query "how does tenant authorization reach PostgreSQL?"` or open `graph.html` in a browser.

The graph is a navigation aid. Its extracted edges show code structure, but inferred edges and community grouping may be imperfect; verify security claims against source and tests.
