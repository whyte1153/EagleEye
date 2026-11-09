"""Case workflow rules and report building."""
from __future__ import annotations

from django.db import transaction
from django.utils import timezone

from apps.audit.services import log_event
from apps.forensics.models import EvidenceItem
from apps.network_analysis.models import NetworkImport
from apps.scanner.engine.datatypes import SEVERITY_LABELS
from apps.scanner.models import Scan

from .models import Case, CaseEvent, CaseLink

CAVEAT = ("This report is generated from records saved in EagleEye at the time shown. Scan findings are configuration "
          "observations, network indicators come from transparent heuristic rules, and neither is proof of compromise. "
          "A matching evidence hash proves the stored copy is unchanged since it was received, not before. "
          "Timeline entries are append-only inside the application.")

TRANSITIONS = {
    Case.OPEN: {Case.IN_PROGRESS, Case.ON_HOLD, Case.CLOSED},
    Case.IN_PROGRESS: {Case.OPEN, Case.ON_HOLD, Case.CLOSED},
    Case.ON_HOLD: {Case.OPEN, Case.IN_PROGRESS, Case.CLOSED},
    Case.CLOSED: {Case.OPEN},
}


class WorkflowError(Exception):
    pass


def fmt(dt) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC") if dt else ""


def add_event(case: Case, kind: str, user, detail: str = "") -> CaseEvent:
    ev = CaseEvent.objects.create(case=case, kind=kind, actor=user, actor_name=(user.get_username() if user else "")[:150],
                                  detail=detail[:3000])
    Case.objects.filter(pk=case.pk).update(updated_at=ev.created_at)
    case.updated_at = ev.created_at
    return ev


def create_case(request, user, title, description, priority, assignee) -> Case:
    with transaction.atomic():
        case = Case(title=title.strip()[:200], description=description, priority=priority, assigned_to=assignee, created_by=user)
        case.save()
        case.case_id = f"CS-{case.created_at.year}-{case.pk:06d}"
        case.save(update_fields=["case_id"])
        add_event(case, "created", user, f"Case opened with priority {case.get_priority_display()}"
                  + (f", assigned to {assignee.get_username()}" if assignee else ""))
    log_event(request, "case.created", target=case.case_id, detail=case.title[:200])
    return case


def update_case(request, user, case: Case, title, description, priority, assignee) -> list[str]:
    changes = []
    if case.is_closed:
        raise WorkflowError("A closed case must be reopened before it can be edited.")
    if title.strip() != case.title:
        changes.append(f"title: '{case.title}' -> '{title.strip()}'")
        case.title = title.strip()[:200]
    if description != case.description:
        changes.append("description updated")
        case.description = description
    if priority != case.priority:
        changes.append(f"priority: {case.get_priority_display()} -> {dict(Case.PRIORITY_CHOICES)[priority]}")
        case.priority = priority
    if (assignee.pk if assignee else None) != case.assigned_to_id:
        changes.append(f"assigned: {case.assigned_to.get_username() if case.assigned_to else 'nobody'} -> "
                       f"{assignee.get_username() if assignee else 'nobody'}")
        case.assigned_to = assignee
    if changes:
        case.save(update_fields=["title", "description", "priority", "assigned_to"])
        add_event(case, "edited", user, "; ".join(changes))
        log_event(request, "case.edited", target=case.case_id, detail="; ".join(changes)[:500])
    return changes


def change_status(request, user, case: Case, new_status: str, note: str) -> None:
    note = (note or "").strip()
    if new_status == case.status:
        raise WorkflowError("The case already has that status.")
    if new_status not in TRANSITIONS[case.status]:
        raise WorkflowError("That status change is not allowed.")
    if new_status == Case.CLOSED and not note:
        raise WorkflowError("A closing note is required: say what was found and what was done.")
    if case.status == Case.CLOSED and not note:
        raise WorkflowError("A note is required to reopen a case: say why.")
    old = case.get_status_display()
    case.status = new_status
    if new_status == Case.CLOSED:
        case.closed_at, case.closure_note = timezone.now(), note
        fields = ["status", "closed_at", "closure_note"]
    else:
        case.closed_at = None
        fields = ["status", "closed_at"]
    case.save(update_fields=fields)
    add_event(case, "status", user, f"{old} -> {case.get_status_display()}" + (f". {note}" if note else ""))
    log_event(request, "case.status_changed", target=case.case_id, detail=f"{old} -> {case.get_status_display()}")


def add_note(request, user, case: Case, text: str) -> None:
    add_event(case, "note", user, text.strip())
    log_event(request, "case.note_added", target=case.case_id)


# ------------------------------------------------------------------ links
def resolve(kind: str, ref: str):
    """Return (object, ref, label) for an existing scan / evidence item / network import, else None."""
    ref = (ref or "").strip()
    if kind == CaseLink.SCAN and ref.isdigit():
        o = Scan.objects.filter(pk=int(ref)).first()
        if o:
            return o, str(o.pk), f"Scan #{o.pk} {o.normalized_url or o.target_url}"[:300]
    elif kind == CaseLink.EVIDENCE:
        o = EvidenceItem.objects.filter(evidence_id=ref).first()
        if o:
            return o, o.evidence_id, f"{o.evidence_id} {o.original_filename}"[:300]
    elif kind == CaseLink.NETWORK:
        o = NetworkImport.objects.filter(import_id=ref).first()
        if o:
            return o, o.import_id, f"{o.import_id} {o.original_filename}"[:300]
    return None


def link_item(request, user, case: Case, kind: str, ref: str) -> CaseLink:
    if case.is_closed:
        raise WorkflowError("Reopen the case before linking items.")
    found = resolve(kind, ref)
    if not found:
        raise WorkflowError("That item does not exist.")
    _, ref, label = found
    if CaseLink.objects.filter(case=case, kind=kind, object_ref=ref, removed_at__isnull=True).exists():
        raise WorkflowError("That item is already linked to this case.")
    link = CaseLink.objects.create(case=case, kind=kind, object_ref=ref, label=label, linked_by=user)
    add_event(case, "linked", user, f"Linked {link.get_kind_display().lower()}: {label}")
    log_event(request, "case.item_linked", target=case.case_id, detail=f"{kind}:{ref}")
    return link


def unlink_item(request, user, case: Case, link: CaseLink) -> None:
    if case.is_closed:
        raise WorkflowError("Reopen the case before unlinking items.")
    if link.removed_at:
        raise WorkflowError("That link was already removed.")
    link.removed_at, link.removed_by = timezone.now(), user
    link.save(update_fields=["removed_at", "removed_by"])
    add_event(case, "unlinked", user, f"Unlinked {link.get_kind_display().lower()}: {link.label}")
    log_event(request, "case.item_unlinked", target=case.case_id, detail=f"{link.kind}:{link.object_ref}")


def linked_items(case: Case) -> dict:
    """Live details of every active link, grouped by kind.  Missing objects are reported, not hidden."""
    out = {"scans": [], "evidence": [], "network": []}
    links = [l for l in case.links.all() if l.active]
    scan_ids = [int(l.object_ref) for l in links if l.kind == CaseLink.SCAN]
    scans = {s.pk: s for s in Scan.objects.filter(pk__in=scan_ids)}
    evs = {e.evidence_id: e for e in EvidenceItem.objects.filter(evidence_id__in=[l.object_ref for l in links if l.kind == CaseLink.EVIDENCE])}
    nets = {n.import_id: n for n in NetworkImport.objects.filter(import_id__in=[l.object_ref for l in links if l.kind == CaseLink.NETWORK])}
    for l in links:
        if l.kind == CaseLink.SCAN:
            out["scans"].append({"link": l, "obj": scans.get(int(l.object_ref))})
        elif l.kind == CaseLink.EVIDENCE:
            out["evidence"].append({"link": l, "obj": evs.get(l.object_ref)})
        else:
            out["network"].append({"link": l, "obj": nets.get(l.object_ref)})
    return out


def suggestions(case: Case) -> dict:
    """Items whose free-text case_reference equals this case ID but are not linked yet."""
    have = {(l.kind, l.object_ref) for l in case.links.all() if l.active}
    ev = [e for e in EvidenceItem.objects.filter(case_reference__iexact=case.case_id) if ("evidence", e.evidence_id) not in have]
    ni = [n for n in NetworkImport.objects.filter(case_reference__iexact=case.case_id) if ("network", n.import_id) not in have]
    return {"evidence": ev, "network": ni}


def candidates(case: Case, limit: int = 100) -> dict:
    """Most recent items not yet linked, for the link drop-downs."""
    have = {(l.kind, l.object_ref) for l in case.links.all() if l.active}
    return {
        "scans": [s for s in Scan.objects.all()[:limit] if ("scan", str(s.pk)) not in have],
        "evidence": [e for e in EvidenceItem.objects.all()[:limit] if ("evidence", e.evidence_id) not in have],
        "network": [n for n in NetworkImport.objects.all()[:limit] if ("network", n.import_id) not in have],
    }


# ------------------------------------------------------------------ report
def build_case_report(case: Case, user) -> dict:
    items = linked_items(case)
    sections = [
        {"heading": "Case summary", "kv": [
            ("Case ID", case.case_id), ("Status", case.get_status_display()), ("Priority", case.get_priority_display()),
            ("Opened", f"{fmt(case.created_at)} by {case.created_by.get_username() if case.created_by else '-'}"),
            ("Assigned to", case.assigned_to.get_username() if case.assigned_to else "Unassigned"),
            ("Last updated", fmt(case.updated_at)),
            ("Closed", fmt(case.closed_at) or "-"),
        ], "paragraphs": [case.description] if case.description else []},
    ]
    if case.closure_note:
        sections.append({"heading": "Closure note", "paragraphs": [case.closure_note]})

    scan_rows, scan_findings = [], []
    for it in items["scans"]:
        s, l = it["obj"], it["link"]
        if s is None:
            scan_rows.append([l.label, "record missing", "", ""])
            continue
        scan_rows.append([f"Scan #{s.pk}", s.normalized_url or s.target_url, s.get_status_display(),
                          f"{s.findings_count} finding(s); highest: {s.highest_severity_label}"])
        for f in s.findings.all()[:15]:
            scan_findings.append([f"#{s.pk}", f.severity_label, f.title, f.remediation])
    sections.append({"heading": f"Linked scans ({len(scan_rows)})",
                     "table": {"columns": ["Scan", "Target", "Status", "Result"], "rows": scan_rows, "empty": "No scans linked."}})
    if scan_findings:
        sections.append({"heading": "Scan findings (top 15 per scan)",
                         "table": {"columns": ["Scan", "Severity", "Finding", "Suggested fix"], "rows": scan_findings}})

    ev_rows = []
    for it in items["evidence"]:
        e, l = it["obj"], it["link"]
        ev_rows.append([l.object_ref, "record missing", "", ""] if e is None else
                       [e.evidence_id, e.original_filename, e.integrity_status.upper(), e.sha256])
    sections.append({"heading": f"Linked evidence ({len(ev_rows)})",
                     "table": {"columns": ["ID", "File", "Integrity", "SHA-256"], "rows": ev_rows, "empty": "No evidence linked."}})

    net_rows = []
    for it in items["network"]:
        n, l = it["obj"], it["link"]
        if n is None:
            net_rows.append([l.object_ref, "record missing", "", ""])
        else:
            hi = SEVERITY_LABELS.get(n.max_severity, "none flagged")
            net_rows.append([n.import_id, f"{n.get_kind_display()}: {n.original_filename}", hi, n.sha256])
    sections.append({"heading": f"Linked network imports ({len(net_rows)})",
                     "table": {"columns": ["ID", "File", "Highest indicator", "SHA-256"], "rows": net_rows, "empty": "No network imports linked."}})

    removed = [l for l in case.links.all() if not l.active]
    if removed:
        sections.append({"heading": "Unlinked items (kept for the record)", "table": {
            "columns": ["Item", "Linked", "Unlinked"],
            "rows": [[l.label, f"{fmt(l.linked_at)} by {l.linked_by.get_username() if l.linked_by else '-'}",
                      f"{fmt(l.removed_at)} by {l.removed_by.get_username() if l.removed_by else '-'}"] for l in removed]}})

    sections.append({"heading": "Timeline", "table": {
        "columns": ["Time (UTC)", "Who", "Event", "Detail"],
        "rows": [[fmt(ev.created_at), ev.actor_name or "-", ev.kind, ev.detail] for ev in case.events.all()]}})
    return {"title": f"Case report {case.case_id}", "subtitle": case.title, "generated_at": fmt(timezone.now()),
            "generated_by": user.get_username(), "meta": [("Case ID", case.case_id), ("Status", case.get_status_display())],
            "sections": sections, "caveat": CAVEAT}
