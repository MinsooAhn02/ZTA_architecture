╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌
 Plan: final_report.tex IEEE Formatting Fixes

 Context

 The compiled PDF has several formatting issues vs. standard IEEE conference style:
 spacing anomalies, overly long figure captions, consecutive tables without intervening
 text, a double-column spanning table that wastes space, and minor indentation/word-break
 problems in source. All fixes are to docs/final_report.tex only.

 ---
 Changes (in source order)

 1. Fix \item continuation indentation (lines 79–89)

 Each \item whose content wraps to a second line has the continuation flush-left in
 source. Align continuation lines with the start of the item text (2-space indent is
 fine; the key is consistency and no accidental blank lines inside itemize).

 Also fix line 87–88:
   \item E: Device posture models access from risky or unmanaged devices, showing that
   identity alone is not sufficient.
 → continuation line indented to match item start.

 2. Shorten Kiali figure caption (lines 227–232)

 Current caption is 5 lines. IEEE standard: captions ≤ 2 sentences.

 Replace with:
 \caption{Kiali Workload Graph showing one representative test per scenario (A--E).
 The mTLS padlock on the frontend$\to$backend edge confirms STRICT enforcement;
 blocked paths (rogue pod, forged JWT) reach no further.}

 3. Change Kiali figure placement [H] → [t] (line 224)

 [H] forces the figure inline and can leave blank vertical space when page breaks
 awkwardly. IEEE prefers [t] (top-of-column float).

 4. Merge two-paragraph Performance intro into one (lines 237–243)

 Currently there is a blank line between:
 - "Performance testing uses Fortio… shown in Table~\ref{tab:perf}."
 - "Table~\ref{tab:policy-cost} provides…"

 Remove the blank line so they form one paragraph — eliminates the spurious indent
 on the second sentence that makes it look like "D. Performance [gap] text".

 5. Reorder Performance section to interleave table + figure + table

 Current order: Table perf → Table policy-cost → Figure bar chart
 Both tables carry [t] so LaTeX stacks them at the page top with no visual break.

 New order:
 1. Combined intro paragraph (fix #4)
 2. \begin{table}[t] — tab:perf (3-row summary)
 3. \begin{figure}[t] — bar chart (visual of tab:perf)
 4. One-sentence bridge: "Table~\ref{tab:policy-cost} breaks down per-scenario
 timing; blocked cases reflect policy-gate cost only."
 5. \begin{table}[t] — tab:policy-cost (8-row detail)

 This separates the two tables with a figure and a sentence, matching IEEE style.

 6. Shrink combined test matrix from table* → table (lines 178–216)

 A double-column table* for 18 rows is excessive for this content.

 Changes:
 - \begin{table*}[t] → \begin{table}[htbp]
 - \footnotesize → \scriptsize
 - Replace p{7.2cm} with tabularx X column (auto-fills column width)
 - Add \usepackage{tabularx} is already present ✓
 - Column spec: l l X c c inside \tabularx{\columnwidth}{...}

 This fits all 18 rows in one column without spanning.

 7. Fix broken hyphenated words in source (lines 345–346, 355)

 - Line 345–346: production-\n scale → production-scale (one line)
 - Line 355: time-\n consuming → time-consuming (one line)

 These don't affect compiled output but are bad source hygiene and can confuse
 some LaTeX hyphenation algorithms.

 8. Shorten per-scenario latency table caption (line 262)

 Current: "Per-scenario latency: allow = end-to-end, block = policy gate only (Fortio, 200 requests)"
 → "Per-scenario latency (Fortio, 200 requests): allow cases are end-to-end; block cases measure policy gate only."

 ---
 File to modify

 - docs/final_report.tex

 Verification

 cd docs && pdflatex final_report.tex && pdflatex final_report.tex
 Check compiled PDF for:
 - No ?? cross-references
 - Performance section: single flush paragraph intro, table → figure → sentence → table order
 - Combined test matrix fits in one column
 - Kiali caption ≤ 3 lines
 - No extra blank space after any figure