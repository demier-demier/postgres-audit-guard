#!/usr/bin/env python3
"""Exercise scripted human-review states on original synthetic transfer fixtures."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(binary, command, source, *args):
    result = subprocess.run(
        [str(binary), command, *source, *map(str, args)],
        check=True, capture_output=True, text=True,
    )
    return json.loads(result.stdout)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=Path('target/release/postgres-audit-guard'))
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--work-dir', type=Path, required=True)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    source_hash, report_hash = digest(args.input), digest(args.report)
    original = Path(__file__).resolve().parents[1] / 'examples/financial-crime/transfers.jsonl'
    expected_rows = [json.loads(line) for line in original.read_text().splitlines()]
    actual_rows = [json.loads(line) for line in args.input.read_text().splitlines()]
    if actual_rows != expected_rows:
        raise SystemExit('This runner requires the original repository synthetic fixture values')
    report = json.loads(args.report.read_text())
    # This runner accepts only the repository's named synthetic examples.
    merchant = next((i for i, a in enumerate(report['alerts'])
                     if a['source_record_ids'] == ['merchant-01', 'merchant-02', 'merchant-03', 'merchant-04']), None)
    onward = next((i for i, a in enumerate(report['alerts'])
                   if a['source_record_ids'] == ['pass-through-01', 'pass-through-02', 'pass-through-03', 'pass-through-04', 'pass-through-05']), None)
    if merchant is None or onward is None:
        raise SystemExit('Expected original synthetic merchant and pass-through fixtures')
    args.work_dir.mkdir(mode=0o700, parents=False, exist_ok=False)
    source = ['--input', str(args.input), '--report', str(args.report), '--report-anchor', report_hash]
    verified = []
    merchant_anchors = []
    # These notes are scripted fixture context, never purported real analyst findings.
    steps = [
        ('open', 'Scripted fixture review: merchant settlement matches TF001; business context requires human review.'),
        ('needs-information', 'Scripted request for settlement context; the amount pattern alone establishes no misconduct.'),
        ('closed-explained', 'Original fixture documentation labels this as an authorized merchant settlement. Close this scripted case without removing the alert.'),
        ('open', 'Scripted second review reopens the case; prior explanation remains preserved and no account action is taken.'),
    ]
    previous = None
    for version, (disposition, reason) in enumerate(steps, 1):
        output = args.work_dir / f'merchant-v{version}.json'
        note = args.work_dir / f'merchant-note-{version}.txt'
        note.write_text(reason + '\n', encoding='utf-8')
        common = ['--actor', 'synthetic-analyst-01', '--at', f'2026-11-03T12:0{version}:00Z',
                  '--reason-file', str(note), '--evidence-ref', 'merchant-01', '--evidence-ref', 'merchant-04', '--output', str(output)]
        if previous is None:
            outcome = run(binary, 'open-analyst-case', source, '--case-id', 'synthetic-merchant-review', '--alert-index', merchant, *common)
        else:
            outcome = run(binary, 'revise-analyst-case', source, '--case', previous,
                          '--case-anchor', merchant_anchors[-1], '--disposition', disposition, *common)
        anchor = outcome['case_sha256']
        checked = run(binary, 'verify-analyst-case', source, '--case', output, '--case-anchor', anchor)
        assert checked['verified'] and checked['revision'] == version
        assert checked['disposition'] == disposition.replace('-', '_')
        merchant_anchors.append(anchor)
        verified.append({'file': output.name, 'sha256': anchor, 'revision': version, 'disposition': checked['disposition']})
        previous = output
    # A second review route remains a human referral, with no external side effect.
    note = args.work_dir / 'referral-note.txt'
    note.write_text('Scripted referral for additional review of a synthetic pattern; no crime finding or automatic action.\n', encoding='utf-8')
    first = args.work_dir / 'referral-v1.json'
    first_anchor = run(binary, 'open-analyst-case', source, '--case-id', 'synthetic-referral', '--alert-index', onward,
                       '--actor', 'synthetic-analyst-02', '--at', '2026-11-03T12:10:00Z', '--reason-file', note,
                       '--evidence-ref', 'pass-through-01', '--output', first)['case_sha256']
    initial_check = run(binary, 'verify-analyst-case', source, '--case', first, '--case-anchor', first_anchor)
    assert initial_check['verified'] and initial_check['revision'] == 1
    last = args.work_dir / 'referral-v2.json'
    final = run(binary, 'revise-analyst-case', source, '--case', first, '--case-anchor', first_anchor,
                '--disposition', 'escalated-for-review', '--actor', 'synthetic-analyst-02', '--at', '2026-11-03T12:11:00Z',
                '--reason-file', note, '--evidence-ref', 'pass-through-05', '--output', last)
    checked = run(binary, 'verify-analyst-case', source, '--case', last, '--case-anchor', final['case_sha256'])
    assert checked['verified'] and checked['disposition'] == 'escalated_for_review'
    assert digest(args.input) == source_hash and digest(args.report) == report_hash
    assert len(json.loads(args.report.read_text())['alerts']) == 4
    for item in verified:
        assert digest(args.work_dir / item['file']) == item['sha256']
    summary = {
        'schema': 'analyst-case-synthetic-workflow/v1',
        'scope': 'Actual Rust CLI execution; original synthetic transfers and scripted unverified analyst identities/notes. Not real casework, accuracy or proof of crime.',
        'input_sha256': source_hash, 'report_sha256': report_hash,
        'merchant_timeline': verified, 'referral': {'file': last.name, 'sha256': final['case_sha256'], 'disposition': checked['disposition']},
        'original_alerts_preserved': 4, 'original_input_and_report_unchanged': True,
        'automatic_account_or_reporting_actions': 0,
        'verified_case_snapshots': 6,
        'verification': 'All four merchant snapshots and both referral snapshots verified in separate processes.',
        'anchor_note': 'Digests beside files are reproduction outputs, not an independent trusted anchor service.',
    }
    (args.work_dir / 'workflow-result.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    main()
