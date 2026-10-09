"""Document identity on re-run of `cve2at validate`: a renamed or moved URL must not change a Doc ID."""
import os

import pandas as pd

from cve2at import validate_report as vr

OLD_ICSA = "https://ics-cert.us-cert.gov/advisories/ICSA-15-181-01"
NEW_ICSA = "https://www.cisa.gov/news-events/ics-advisories/icsa-15-181-01"
OLD_ICSMA = "https://www.us-cert.gov/ics/advisories/icsma-20-170-04"
NEW_ICSMA = "https://www.cisa.gov/news-events/ics-medical-advisories/icsma-20-170-04"
VENDOR_PDF = "https://vendor.example/Spectrum_ICSA-15-181-01_notes.pdf"


def doc(did, url, alts="", tag="Third Party Advisory"):
    return {"Doc ID": did, "Advisory Tag": tag, "Reference URL": url, "Alternate URLs": alts}


def by_url(*recs):
    return {r["Reference URL"]: r for r in recs}


def test_fingerprint_follows_cisa_advisory_number_across_hosts():
    assert vr._url_fingerprint(OLD_ICSA) == vr._url_fingerprint(NEW_ICSA)
    assert vr._url_fingerprint(OLD_ICSMA) == vr._url_fingerprint(NEW_ICSMA)
    assert vr._url_fingerprint(OLD_ICSA) != vr._url_fingerprint(OLD_ICSMA)


def test_fingerprint_does_not_trust_an_advisory_number_on_another_host():
    assert vr._url_fingerprint(VENDOR_PDF) != vr._url_fingerprint(NEW_ICSA)


def test_fingerprint_ignores_scheme_www_trailing_slash_and_fragment():
    a = vr._url_fingerprint("http://www.Example.com/a/b/#top")
    assert a == vr._url_fingerprint("https://example.com/a/b")
    assert a != vr._url_fingerprint("https://example.com/a/c")


def test_renamed_url_keeps_its_doc_id_and_is_recorded_as_alternate():
    existing = by_url(doc("D0001", NEW_ICSA), doc("D0002", NEW_ICSMA))
    seen = {OLD_ICSA: {"Mitigation"}, OLD_ICSMA: {"Third Party Advisory"}}
    rows, ids, next_n, report = vr._reconcile_documents(existing, [], seen, 3)
    assert ids == {OLD_ICSA: "D0001", OLD_ICSMA: "D0002"}
    assert report["new"] == [] and next_n == 3
    assert [r["Doc ID"] for r in rows] == ["D0001", "D0002"]
    assert rows[0]["Alternate URLs"] == OLD_ICSA and rows[0]["Reference URL"] == NEW_ICSA


def test_second_run_is_stable_and_reports_nothing_new():
    existing = by_url(doc("D0001", NEW_ICSA))
    seen = {OLD_ICSA: set()}
    rows, _, n, _ = vr._reconcile_documents(existing, [], seen, 2)
    again = by_url(*rows)
    rows2, ids2, n2, report2 = vr._reconcile_documents(again, [], seen, n)
    assert rows2 == rows and ids2 == {OLD_ICSA: "D0001"}
    assert report2["aliased"] == [] and report2["new"] == []


def test_alternate_url_matches_exactly_even_when_fingerprints_differ():
    moved = "https://new.example/report-v2"
    old = "https://old.example/report"
    existing = by_url(doc("D0004", moved, alts=old))
    rows, ids, _, report = vr._reconcile_documents(existing, [], {old: set()}, 5)
    assert ids == {old: "D0004"} and report["new"] == [] and report["aliased"] == []


def test_unmatched_url_gets_the_next_id_and_ids_are_not_reused():
    existing = by_url(doc("D0001", NEW_ICSA))
    rows, ids, next_n, report = vr._reconcile_documents(
        existing, [], {"https://other.example/x": {"Patch"}}, 8)
    assert ids["https://other.example/x"] == "D0008" and next_n == 9
    assert report["new"] == [("D0008", "https://other.example/x")]
    assert report["unlinked"] == ["D0001"]            # kept, just not cited by any CVE


def test_duplicate_rows_fold_into_the_lowest_id_when_the_higher_is_not_cited():
    existing = by_url(doc("D0008", OLD_ICSA, tag="Mitigation"), doc("D0001", NEW_ICSA, tag="Patch"))
    rows, ids, _, report = vr._reconcile_documents(existing, [], {OLD_ICSA: set()}, 9, cited_ids={"D0001"})
    assert [r["Doc ID"] for r in rows] == ["D0001"]
    assert rows[0]["Alternate URLs"] == OLD_ICSA
    assert rows[0]["Advisory Tag"] == "Patch, Mitigation"
    assert report["merged"] == [("D0001", "D0008")] and ids == {OLD_ICSA: "D0001"}


def test_duplicate_rows_stay_apart_when_the_higher_id_is_cited_in_a_rationale():
    existing = by_url(doc("D0001", NEW_ICSA), doc("D0008", OLD_ICSA))
    rows, _, _, report = vr._reconcile_documents(existing, [], {}, 9, cited_ids={"D0008"})
    assert sorted(r["Doc ID"] for r in rows) == ["D0001", "D0008"]
    assert report["kept_apart"] == [("D0001", "D0008")]


def test_cited_doc_ids_reads_every_typed_column():
    judgments = {"A1": {"P001": {"Validation Rationale": "see D0003 and D0010", "Notes": ""}},
                 "Consensus": {"P001": {"Consensus Rationale": "D0001"}}}
    assert vr._cited_doc_ids(judgments) == {"D0003", "D0010", "D0001"}


def test_dangling_citations_flags_ids_with_no_document_row():
    path_df = pd.DataFrame([{"Path ID": "P001", "A1 Validation Rationale": "D0001, D0099",
                             "A1 Notes": "", "A2 Validation Rationale": "D0002", "A2 Notes": "",
                             "Consensus Rationale": ""}])
    doc_df = pd.DataFrame([{"Doc ID": "D0001"}, {"Doc ID": "D0002"}])
    assert vr._dangling_citations(path_df, doc_df) == [("A1", "P001", "D0099")]


def test_backup_is_written_and_only_the_newest_are_kept(tmp_path, monkeypatch):
    target = tmp_path / "validation_paths.xlsx"
    target.write_bytes(b"x")
    folder = tmp_path / "backups"
    folder.mkdir()
    for i in range(vr.BACKUP_KEEP + 3):
        (folder / f"validation_paths.2020010{i % 10}-0000{i:02d}.xlsx").write_bytes(b"old")
    dest = vr._backup_existing(str(target))
    assert os.path.isfile(dest)
    assert len([f for f in os.listdir(folder) if f.endswith(".xlsx")]) == vr.BACKUP_KEEP


def test_backup_of_a_missing_file_is_a_noop(tmp_path):
    assert vr._backup_existing(str(tmp_path / "nope.xlsx")) is None
