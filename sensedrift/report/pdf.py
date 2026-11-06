"""Génération du rapport PDF client."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional
from xml.sax.saxutils import escape

from reportlab.graphics.shapes import Drawing, Rect, String, Wedge, Circle
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.lib.fonts import addMapping
from reportlab.pdfgen import canvas as rl_canvas
from reportlab.platypus import (CondPageBreak, KeepTogether, PageBreak, Paragraph,
                                SimpleDocTemplate, Spacer, Table, TableStyle)

from .. import __version__
from ..checks._util import eur
from ..models import COST, SEVERITY_ORDER, SCORE_PENALTY, Finding, Severity

W, H = A4
MARGIN = 2 * cm
CONTENT_W = W - 2 * MARGIN
MAX_RESOURCES_PER_CHECK = 25

MONTHS_SHORT = ["janv.", "févr.", "mars", "avr.", "mai", "juin", "juil.", "août",
                "sept.", "oct.", "nov.", "déc."]
MONTHS_FR = ["janvier", "février", "mars", "avril", "mai", "juin", "juillet", "août",
             "septembre", "octobre", "novembre", "décembre"]

# ─────────────────────────────────────────────
# Charte graphique
# ─────────────────────────────────────────────
C = {
    "navy": colors.HexColor("#0B1324"),
    "navy_2": colors.HexColor("#141C2F"),
    "accent": colors.HexColor("#4F46E5"),
    "accent_soft": colors.HexColor("#EEF2FF"),
    "ink": colors.HexColor("#0F172A"),
    "ink_2": colors.HexColor("#475569"),
    "ink_3": colors.HexColor("#94A3B8"),
    "line": colors.HexColor("#E2E8F0"),
    "zebra": colors.HexColor("#F8FAFC"),
    "code_bg": colors.HexColor("#F1F5F9"),
    "green": colors.HexColor("#047857"),
    "green_soft": colors.HexColor("#ECFDF5"),
}
SEV_COLOR = {
    Severity.CRITICAL: colors.HexColor("#B91C1C"),
    Severity.HIGH: colors.HexColor("#C2410C"),
    Severity.MEDIUM: colors.HexColor("#A16207"),
    Severity.LOW: colors.HexColor("#475569"),
}
SEV_BG = {
    Severity.CRITICAL: colors.HexColor("#FEF2F2"),
    Severity.HIGH: colors.HexColor("#FFF7ED"),
    Severity.MEDIUM: colors.HexColor("#FEFCE8"),
    Severity.LOW: colors.HexColor("#F1F5F9"),
}
GRADE_COLOR = {"A": "#047857", "B": "#4D7C0F", "C": "#A16207", "D": "#C2410C", "E": "#B91C1C"}

_FONT_DIR = os.path.join(os.path.dirname(__file__), "fonts")
_fonts_ready = False


def _register_fonts():
    global _fonts_ready
    if _fonts_ready:
        return
    pdfmetrics.registerFont(TTFont("SD", os.path.join(_FONT_DIR, "DejaVuSans.ttf")))
    pdfmetrics.registerFont(TTFont("SD-Bold", os.path.join(_FONT_DIR, "DejaVuSans-Bold.ttf")))
    pdfmetrics.registerFont(TTFont("SD-Mono", os.path.join(_FONT_DIR, "DejaVuSansMono.ttf")))
    addMapping("SD", 0, 0, "SD")
    addMapping("SD", 1, 0, "SD-Bold")
    addMapping("SD", 0, 1, "SD")
    addMapping("SD", 1, 1, "SD-Bold")
    _fonts_ready = True


def _styles() -> dict:
    def ps(name, **kw):
        base = dict(fontName="SD", fontSize=9.5, leading=14, textColor=C["ink"])
        base.update(kw)
        return ParagraphStyle(name, **base)
    return {
        "h1": ps("h1", fontName="SD-Bold", fontSize=20, leading=26, spaceAfter=4),
        "kicker": ps("kicker", fontName="SD-Bold", fontSize=8, leading=10,
                     textColor=C["accent"], spaceAfter=4),
        "lead": ps("lead", fontSize=10.5, leading=16, textColor=C["ink_2"], spaceAfter=14),
        "h2": ps("h2", fontName="SD-Bold", fontSize=12.5, leading=17, spaceBefore=16, spaceAfter=8),
        "h3": ps("h3", fontName="SD-Bold", fontSize=10.5, leading=14),
        "body": ps("body"),
        "muted": ps("muted", fontSize=8.5, leading=12.5, textColor=C["ink_2"]),
        "small": ps("small", fontSize=8, leading=11, textColor=C["ink_2"]),
        "cell": ps("cell", fontSize=8.5, leading=11.5),
        "cell_b": ps("cell_b", fontName="SD-Bold", fontSize=8.5, leading=11.5),
        "cell_r": ps("cell_r", fontSize=8.5, leading=11.5, alignment=TA_RIGHT),
        "cell_rb": ps("cell_rb", fontName="SD-Bold", fontSize=8.5, leading=11.5, alignment=TA_RIGHT),
        "cell_c": ps("cell_c", fontSize=8.5, leading=11.5, alignment=TA_CENTER),
        "res": ps("res", fontName="SD-Mono", fontSize=7.5, leading=10, wordWrap="CJK"),
        "th": ps("th", fontName="SD-Bold", fontSize=7.5, leading=10, textColor=C["ink_2"]),
        "th_r": ps("th_r", fontName="SD-Bold", fontSize=7.5, leading=10, textColor=C["ink_2"],
                   alignment=TA_RIGHT),
        "code": ps("code", fontName="SD-Mono", fontSize=7.5, leading=10.5, wordWrap="CJK",
                   textColor=C["ink"]),
        "kpi_v": ps("kpi_v", fontName="SD-Bold", fontSize=17, leading=21),
        "kpi_l": ps("kpi_l", fontSize=7.5, leading=10, textColor=C["ink_2"]),
    }


def _e(s) -> str:
    return escape(str(s or ""))


def _n(v) -> str:
    return f"{v:g}".replace(".", ",")


def _fr_date(d: datetime) -> str:
    return f"{d.day} {MONTHS_FR[d.month - 1]} {d.year}"


# ─────────────────────────────────────────────
# Regroupement des constats par contrôle
# ─────────────────────────────────────────────
@dataclass
class CheckGroup:
    check_id: str
    title: str
    service: str
    category: str
    severity: Severity
    description: str
    remediation: str
    effort: str
    references: List[str]
    remediation_cli: str = ""
    findings: List[Finding] = field(default_factory=list)

    @property
    def saving(self) -> float:
        return round(sum(f.monthly_saving_eur or 0 for f in self.findings), 2)

    @property
    def confidence(self) -> str:
        confs = {f.saving_confidence for f in self.findings if f.saving_confidence}
        for c in ("Indicative", "Moyenne", "Élevée"):
            if c in confs:
                return c
        return ""

    @property
    def count(self) -> int:
        return len(self.findings)

    @property
    def has_resources(self) -> bool:
        return any(f.resource_id or f.region != "global" for f in self.findings)


def group_findings(findings: List[Finding]) -> List[CheckGroup]:
    groups: dict = {}
    for f in findings:
        key = (f.check_id, f.title)
        g = groups.get(key)
        if g is None:
            g = groups[key] = CheckGroup(f.check_id, f.title, f.service, f.category, f.severity,
                                         f.description, f.remediation, f.effort,
                                         list(f.references), f.remediation_cli)
        if f.severity.rank < g.severity.rank:
            g.severity = f.severity
        g.findings.append(f)
    out = list(groups.values())
    out.sort(key=lambda g: (g.severity.rank, -g.saving, -g.count, g.title))
    return out


# ─────────────────────────────────────────────
# Canvas : numérotation « Page X / Y », en-tête, pied de page, couverture
# ─────────────────────────────────────────────
def _make_canvas_class(meta: dict):
    class NumberedCanvas(rl_canvas.Canvas):
        def __init__(self, *a, **kw):
            super().__init__(*a, **kw)
            self._saved = []

        def showPage(self):
            self._saved.append(dict(self.__dict__))
            self._startPage()

        def save(self):
            total = len(self._saved)
            for state in self._saved:
                self.__dict__.update(state)
                if self._pageNumber == 1:
                    _draw_cover(self, meta)
                else:
                    _draw_chrome(self, meta, total)
                super().showPage()
            super().save()
    return NumberedCanvas


def _logo(c, x, y, size, on_dark=True):
    c.setFillColor(C["accent"])
    c.roundRect(x, y, size, size, size * 0.22, fill=1, stroke=0)
    c.setFillColor(colors.white)
    # monogramme : deux barres décalées évoquant une « dérive »
    c.rect(x + size * 0.24, y + size * 0.56, size * 0.52, size * 0.12, fill=1, stroke=0)
    c.rect(x + size * 0.24, y + size * 0.32, size * 0.36, size * 0.12, fill=1, stroke=0)


def _draw_chrome(c, meta, total):
    c.saveState()
    _logo(c, MARGIN, H - 1.35 * cm, 0.42 * cm)
    c.setFont("SD-Bold", 8.5)
    c.setFillColor(C["ink"])
    c.drawString(MARGIN + 0.6 * cm, H - 1.25 * cm, "SenseDrift")
    c.setFont("SD", 8)
    c.setFillColor(C["ink_2"])
    c.drawRightString(W - MARGIN, H - 1.25 * cm, meta["header_right"])
    c.setStrokeColor(C["line"])
    c.setLineWidth(0.6)
    c.line(MARGIN, H - 1.55 * cm, W - MARGIN, H - 1.55 * cm)
    c.line(MARGIN, 1.35 * cm, W - MARGIN, 1.35 * cm)
    c.setFont("SD", 7.5)
    c.setFillColor(C["ink_3"])
    c.drawString(MARGIN, 0.95 * cm, f"CONFIDENTIEL — Document destiné à {meta['client']}")
    c.drawRightString(W - MARGIN, 0.95 * cm, f"Page {c._pageNumber} / {total}")
    c.restoreState()


def _draw_cover(c, meta):
    c.saveState()
    band_h = H * 0.58
    c.setFillColor(C["navy"])
    c.rect(0, H - band_h, W, band_h, fill=1, stroke=0)
    c.setFillColor(C["accent"])
    c.rect(0, H - band_h, W, 0.18 * cm, fill=1, stroke=0)

    _logo(c, MARGIN, H - 2.9 * cm, 0.8 * cm)
    c.setFillColor(colors.white)
    c.setFont("SD-Bold", 15)
    c.drawString(MARGIN + 1.1 * cm, H - 2.62 * cm, "SenseDrift")

    c.setFont("SD-Bold", 8.5)
    c.setFillColor(colors.HexColor("#A5B4FC"))
    c.drawString(MARGIN, H - 8.2 * cm, "RAPPORT D'AUDIT AWS")
    c.setFillColor(colors.white)
    c.setFont("SD-Bold", 27)
    c.drawString(MARGIN, H - 9.5 * cm, "Sécurité &")
    c.drawString(MARGIN, H - 10.65 * cm, "optimisation des coûts")
    c.setFont("SD", 12.5)
    c.setFillColor(colors.HexColor("#CBD5E1"))
    c.drawString(MARGIN, H - 12.0 * cm, f"Préparé pour {meta['client']}")
    c.setFont("SD", 10)
    c.drawString(MARGIN, H - 12.75 * cm, meta["date_long"])

    # bloc d'informations
    rows = [("Compte AWS", meta["account"]), ("Régions analysées", meta["regions"]),
            ("Période d'analyse", meta["period"]), ("Référence du rapport", meta["report_id"]),
            ("Préparé par", meta["prepared_by"])]
    y = H - band_h - 1.8 * cm
    for label, value in rows:
        c.setFont("SD", 8)
        c.setFillColor(C["ink_3"])
        c.drawString(MARGIN, y, label.upper())
        c.setFont("SD", 10.5)
        c.setFillColor(C["ink"])
        c.drawString(MARGIN + 5.2 * cm, y, value[:80])
        c.setStrokeColor(C["line"])
        c.setLineWidth(0.5)
        c.line(MARGIN, y - 0.35 * cm, W - MARGIN, y - 0.35 * cm)
        y -= 1.05 * cm

    c.setFont("SD", 7.5)
    c.setFillColor(C["ink_3"])
    text = c.beginText(MARGIN, 2.4 * cm)
    text.setLeading(11)
    for line in (
        "Document confidentiel. Il décrit des faiblesses de configuration et ne doit être communiqué",
        "qu'aux personnes habilitées. Audit réalisé en lecture seule : aucune ressource n'a été modifiée.",
    ):
        text.textLine(line)
    c.drawText(text)
    c.setFont("SD-Bold", 8)
    c.setFillColor(C["accent"])
    c.drawString(MARGIN, 3.3 * cm, meta["contact"])
    c.restoreState()


# ─────────────────────────────────────────────
# Composants
# ─────────────────────────────────────────────
def _section_title(kicker: str, title: str, lead: str, st) -> list:
    out = [Paragraph(_e(kicker).upper(), st["kicker"]), Paragraph(_e(title), st["h1"])]
    if lead:
        out.append(Paragraph(lead, st["lead"]))
    return out


def _sev_pill(sev: Severity, st, width=2.0 * cm) -> Table:
    p = Paragraph(f'<font color="white"><b>{sev.label.upper()}</b></font>',
                  ParagraphStyle("pill", parent=st["cell_c"], fontSize=6.3, leading=8,
                                 fontName="SD-Bold", textColor=colors.white))
    t = Table([[p]], colWidths=[width], rowHeights=[0.48 * cm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), SEV_COLOR[sev]),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 0), ("BOTTOMPADDING", (0, 0), (-1, -1), 1),
        ("ROUNDEDCORNERS", [3, 3, 3, 3]),
    ]))
    return t


def _score_gauge(score: int, grade: str) -> Drawing:
    size = 4.2 * cm
    d = Drawing(size, size)
    cx = cy = size / 2
    r, r1 = size / 2 - 2, size / 2 - 13
    track = colors.HexColor("#E2E8F0")
    col = colors.HexColor(GRADE_COLOR[grade])
    d.add(Wedge(cx, cy, r, 0, 180, radius1=r1, fillColor=track, strokeColor=None))
    d.add(Wedge(cx, cy, r, 180, 360, radius1=r1, fillColor=track, strokeColor=None))
    if score > 0:
        sweep = 360 * score / 100
        start = 90 - sweep
        if sweep >= 359.9:
            d.add(Wedge(cx, cy, r, 0, 180, radius1=r1, fillColor=col, strokeColor=None))
            d.add(Wedge(cx, cy, r, 180, 360, radius1=r1, fillColor=col, strokeColor=None))
        else:
            d.add(Wedge(cx, cy, r, start, 90, radius1=r1, fillColor=col, strokeColor=None))
    d.add(String(cx, cy + 2, str(score), fontName="SD-Bold", fontSize=30,
                 fillColor=C["ink"], textAnchor="middle"))
    d.add(String(cx, cy - 16, f"/ 100 · note {grade}", fontName="SD", fontSize=8.5,
                 fillColor=C["ink_2"], textAnchor="middle"))
    return d


def _kpi_card(value: str, label: str, st, color=None, bg=None) -> Table:
    t = Table([[Paragraph(value, ParagraphStyle("kv", parent=st["kpi_v"],
                                                textColor=color or C["ink"]))],
               [Paragraph(label, st["kpi_l"])]], colWidths=[None])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), bg or C["zebra"]),
        ("LEFTPADDING", (0, 0), (-1, -1), 10), ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, 0), 9), ("BOTTOMPADDING", (0, -1), (-1, -1), 9),
        ("TOPPADDING", (0, 1), (-1, 1), 0),
        ("ROUNDEDCORNERS", [4, 4, 4, 4]),
    ]))
    return t


def _table(rows, widths, st, *, header=True, zebra=True, align_right_cols=(), extra=None) -> Table:
    t = Table(rows, colWidths=widths, repeatRows=1 if header else 0)
    cmds = [
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 6), ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, C["line"]),
    ]
    if header:
        cmds += [("LINEBELOW", (0, 0), (-1, 0), 0.9, C["ink_3"]),
                 ("BOTTOMPADDING", (0, 0), (-1, 0), 6)]
    if zebra:
        for i in range(1 if header else 0, len(rows)):
            if (i % 2 == 0) == header:
                cmds.append(("BACKGROUND", (0, i), (-1, i), C["zebra"]))
    for col in align_right_cols:
        cmds.append(("ALIGN", (col, 0), (col, -1), "RIGHT"))
    t.setStyle(TableStyle(cmds + (extra or [])))
    return t


def _cost_chart(ctx) -> Optional[Drawing]:
    cost = ctx.cost
    if not cost or not cost.monthly_totals:
        return None
    labels = list(cost.months)
    values = list(cost.monthly_totals)
    forecast_idx = None
    if cost.forecast_current_month is not None:
        now = datetime.now()
        labels.append(f"{MONTHS_SHORT[now.month - 1]} (prév.)")
        values.append(cost.forecast_current_month)
        forecast_idx = len(values) - 1
    w, h = CONTENT_W * 0.5, 4.4 * cm
    d = Drawing(w, h)
    base_y, top = 18, h - 16
    vmax = max(values) or 1
    n = len(values)
    slot = w / n
    bar_w = min(1.6 * cm, slot * 0.55)
    d.add(Rect(0, base_y, w, 0.6, fillColor=C["ink_3"], strokeColor=None))
    for i, v in enumerate(values):
        bh = max(2, (top - base_y) * v / vmax)
        x = i * slot + (slot - bar_w) / 2
        fc = C["accent"] if i != forecast_idx else colors.HexColor("#C7D2FE")
        d.add(Rect(x, base_y, bar_w, bh, fillColor=fc, strokeColor=None, rx=2, ry=2))
        d.add(Rect(x, base_y, bar_w, min(bh, 2), fillColor=fc, strokeColor=None))
        d.add(String(x + bar_w / 2, base_y + bh + 4, eur(v), fontName="SD-Bold", fontSize=7.5,
                     fillColor=C["ink"], textAnchor="middle"))
        d.add(String(x + bar_w / 2, base_y - 11, labels[i], fontName="SD", fontSize=7,
                     fillColor=C["ink_2"], textAnchor="middle"))
    return d


# ─────────────────────────────────────────────
# Sections
# ─────────────────────────────────────────────
def _priorities(groups: List[CheckGroup]) -> List[CheckGroup]:
    sec = [g for g in groups if g.category != COST and g.severity in (Severity.CRITICAL, Severity.HIGH)]
    cost = sorted([g for g in groups if g.saving > 0], key=lambda g: -g.saving)
    picks = sec[:3] + [g for g in cost if g not in sec][:2]
    for g in groups:
        if len(picks) >= 5:
            break
        if g not in picks:
            picks.append(g)
    return picks[:5]


def _summary(ctx, groups, st) -> list:
    score = ctx.posture_score()
    grade = ctx.grade(score)
    counts = {s: sum(1 for f in ctx.findings if f.severity == s) for s in SEVERITY_ORDER}
    saving_m = ctx.total_monthly_saving
    spend = ctx.cost.monthly_totals[-1] if ctx.cost and ctx.cost.monthly_totals else None

    el = _section_title("Synthèse", "Synthèse exécutive", "", st)

    # Récit
    failed = len({g.check_id for g in groups if g.category != COST})
    txt = (f"L'analyse du compte <b>{_e(ctx.account_id)}</b> a porté sur "
           f"{len(ctx.regions)} région(s) et {len(_service_list(ctx))} services AWS. "
           f"Le score de posture sécurité est de <b>{score}/100 (note {grade})</b> : "
           f"{failed} contrôle(s) de sécurité, de résilience ou de traçabilité sont en échec, "
           f"dont <b>{counts[Severity.CRITICAL]} constat(s) critique(s)</b> et "
           f"<b>{counts[Severity.HIGH]} élevé(s)</b>. ")
    if saving_m > 0:
        txt += (f"Les gisements d'économies identifiés représentent environ "
                f"<b>{eur(saving_m)} par mois</b>, soit <b>{eur(saving_m * 12)} par an</b>")
        if spend:
            txt += f" ({saving_m / spend * 100:.0f} % de la dépense du dernier mois)"
        txt += "."
    else:
        txt += "Aucun gaspillage significatif n'a été détecté sur les ressources analysées."
    el.append(Paragraph(txt, st["lead"]))

    # Score + KPI
    kpis = [
        _kpi_card(eur(saving_m), "Économies estimées / mois", st, C["green"], C["green_soft"]),
        _kpi_card(eur(saving_m * 12), "Économies estimées / an", st, C["green"], C["green_soft"]),
        _kpi_card(eur(spend) if spend is not None else "n.d.", "Dépense du dernier mois", st),
        _kpi_card(str(counts[Severity.CRITICAL] + counts[Severity.HIGH]),
                  "Constats critiques et élevés", st,
                  SEV_COLOR[Severity.CRITICAL] if counts[Severity.CRITICAL] else C["ink"]),
    ]
    kw = (CONTENT_W - 4.8 * cm - 0.3 * cm) / 2
    grid = Table([[kpis[0], kpis[1]], [kpis[2], kpis[3]]], colWidths=[kw, kw])
    grid.setStyle(TableStyle([("LEFTPADDING", (0, 0), (-1, -1), 0),
                              ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                              ("TOPPADDING", (0, 0), (-1, -1), 0),
                              ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]))
    top = Table([[_score_gauge(score, grade), grid]], colWidths=[4.8 * cm + 0.3 * cm, None])
    top.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                             ("LEFTPADDING", (0, 0), (-1, -1), 0),
                             ("RIGHTPADDING", (0, 0), (-1, -1), 0)]))
    el.append(top)

    # Répartition par sévérité
    el.append(Paragraph("Répartition des constats", st["h2"]))
    tiles = []
    for s in SEVERITY_ORDER:
        tiles.append(Paragraph(
            f'<font size="15"><b>{counts[s]}</b></font><br/>'
            f'<font size="7.5" color="#475569">{s.label} · {s.deadline.lower()}</font>', st["body"]))
    sev_t = Table([tiles], colWidths=[CONTENT_W / 4] * 4)
    cmds = [("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING", (0, 0), (-1, -1), 10)]
    for i, s in enumerate(SEVERITY_ORDER):
        cmds += [("LINEBEFORE", (i, 0), (i, 0), 3, SEV_COLOR[s]),
                 ("BACKGROUND", (i, 0), (i, 0), SEV_BG[s])]
    sev_t.setStyle(TableStyle(cmds))
    el.append(sev_t)

    # Priorités
    prios = _priorities(groups)
    if prios:
        el.append(Paragraph("Les 5 actions prioritaires", st["h2"]))
        rows = [[Paragraph("#", st["th"]), Paragraph("Action", st["th"]),
                 Paragraph("Niveau", st["th"]), Paragraph("Gain / mois", st["th_r"])]]
        for i, g in enumerate(prios, 1):
            rows.append([
                Paragraph(f"<b>{i}</b>", st["cell"]),
                Paragraph(f"<b>{_e(g.title)}</b><br/><font color='#475569' size='7.5'>"
                          f"{_e(g.service)} · {g.count} ressource(s) · {_e(g.remediation.split('.')[0])}."
                          f"</font>", st["cell"]),
                _sev_pill(g.severity, st, 1.8 * cm),
                Paragraph(eur(g.saving) if g.saving else "—", st["cell_rb"] if g.saving else st["cell_r"]),
            ])
        el.append(_table(rows, [0.7 * cm, CONTENT_W - 0.7 * cm - 2.2 * cm - 2.4 * cm, 2.2 * cm, 2.4 * cm],
                         st, zebra=False))
    el.append(PageBreak())
    return el


def _costs_section(ctx, groups, st) -> list:
    el = _section_title(
        "Optimisation des coûts", "Où part votre budget AWS",
        "Les montants de dépense proviennent de la facturation AWS (Cost Explorer). Les économies "
        "sont des estimations calculées à partir des tarifs publics et de l'usage observé.", st)

    if ctx.cost and ctx.cost.monthly_totals:
        chart = _cost_chart(ctx)
        top = ctx.cost.by_service_last_month[:6]
        total = sum(v for _, v in ctx.cost.by_service_last_month) or 1
        rows = [[Paragraph("Service (dernier mois)", st["th"]), Paragraph("Montant", st["th_r"]),
                 Paragraph("Part", st["th_r"])]]
        for name, v in top:
            rows.append([Paragraph(_e(name.replace("Amazon ", "").replace("AWS ", "")), st["cell"]),
                         Paragraph(eur(v), st["cell_r"]),
                         Paragraph(f"{v / total * 100:.0f} %", st["cell_r"])])
        rest = total - sum(v for _, v in top)
        if rest > 0.01 and len(ctx.cost.by_service_last_month) > len(top):
            rows.append([Paragraph("Autres services", st["cell"]), Paragraph(eur(rest), st["cell_r"]),
                         Paragraph(f"{rest / total * 100:.0f} %", st["cell_r"])])
        svc_t = _table(rows, [4.6 * cm, 2.2 * cm, 1.4 * cm], st)
        left = [Paragraph("Dépense mensuelle", st["h3"]), Spacer(1, 8)]
        left.append(chart if chart else Paragraph("n.d.", st["muted"]))
        lay = Table([[left, svc_t]], colWidths=[CONTENT_W * 0.5, CONTENT_W * 0.5])
        lay.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"),
                                 ("LEFTPADDING", (0, 0), (-1, -1), 0),
                                 ("RIGHTPADDING", (0, 0), (-1, -1), 0)]))
        el.append(lay)
    else:
        el.append(Paragraph(
            "Les données de facturation n'étaient pas accessibles pour cet audit (Cost Explorer non "
            "autorisé ou désactivé). Les économies ci-dessous restent calculées à partir des "
            "ressources et des tarifs publics.", st["muted"]))

    cost_groups = sorted([g for g in groups if g.saving > 0], key=lambda g: -g.saving)
    el.append(Paragraph("Gisements d'économies identifiés", st["h2"]))
    if not cost_groups:
        el.append(Paragraph("Aucune économie chiffrable n'a été identifiée sur le périmètre analysé.",
                            st["muted"]))
    else:
        rows = [[Paragraph("Constat", st["th"]), Paragraph("Ress.", st["th_r"]),
                 Paragraph("Confiance", st["th"]), Paragraph("€ / mois", st["th_r"]),
                 Paragraph("€ / an", st["th_r"])]]
        for g in cost_groups:
            rows.append([Paragraph(f"{_e(g.title)}<br/><font size='7.5' color='#475569'>"
                                   f"{_e(g.service)}</font>", st["cell"]),
                         Paragraph(str(g.count), st["cell_r"]),
                         Paragraph(_e(g.confidence), st["cell"]),
                         Paragraph(eur(g.saving), st["cell_r"]),
                         Paragraph(eur(g.saving * 12), st["cell_r"])])
        total = ctx.total_monthly_saving
        rows.append([Paragraph("<b>Total estimé</b>", st["cell"]), "", "",
                     Paragraph(f"<b>{eur(total)}</b>", st["cell_r"]),
                     Paragraph(f"<b>{eur(total * 12)}</b>", st["cell_r"])])
        el.append(_table(rows, [CONTENT_W - 1.3 * cm - 2.2 * cm - 2.3 * cm - 2.5 * cm,
                                1.3 * cm, 2.2 * cm, 2.3 * cm, 2.5 * cm], st,
                         extra=[("BACKGROUND", (0, -1), (-1, -1), C["green_soft"]),
                                ("TEXTCOLOR", (0, -1), (-1, -1), C["green"]),
                                ("LINEABOVE", (0, -1), (-1, -1), 0.9, C["green"])]))
        el.append(Spacer(1, 6))
        el.append(Paragraph(
            "<b>Confiance</b> — Élevée : ressource facturée sans usage. Moyenne : dépend de la mise "
            "en œuvre. Indicative : ordre de grandeur. Les engagements (Savings Plans, réservations) "
            "se cumulent partiellement avec le redimensionnement : les souscrire en dernier.", st["small"]))
    el.append(CondPageBreak(9 * cm))
    el.append(Spacer(1, 16))
    return el


def _action_plan(groups, st) -> list:
    el = _section_title(
        "Plan d'action", "Plan de remédiation priorisé",
        "Chaque ligne regroupe toutes les ressources concernées par un même contrôle. Les "
        "échéances sont indicatives et proportionnées au niveau de risque.", st)
    rows = [[Paragraph(h, st["th"]) for h in ("Niveau", "Action", "Ress.", "Effort", "Échéance")]
            + [Paragraph("€ / mois", st["th_r"])]]
    for g in groups:
        rows.append([
            _sev_pill(g.severity, st, 1.85 * cm),
            Paragraph(f"<b>{_e(g.title)}</b><br/><font size='7.5' color='#475569'>{_e(g.service)}"
                      f" · {_e(g.category)}</font>", st["cell"]),
            Paragraph(str(g.count), st["cell_c"]),
            Paragraph(_e(g.effort), st["cell"]),
            Paragraph(g.severity.deadline, st["cell"]),
            Paragraph(eur(g.saving) if g.saving else "—", st["cell_r"]),
        ])
    widths = [2.05 * cm, None, 1.3 * cm, 1.5 * cm, 2.4 * cm, 2.0 * cm]
    widths[1] = CONTENT_W - sum(w for w in widths if w)
    el.append(_table(rows, widths, st))
    el.append(CondPageBreak(9 * cm))
    el.append(Spacer(1, 16))
    return el


def _details(groups, st) -> list:
    el = _section_title("Constats détaillés", "Détail des constats et remédiations",
                        "Pour chaque contrôle en échec : le risque, la correction recommandée et "
                        "la liste des ressources concernées.", st)
    for idx, g in enumerate(groups, 1):
        refs = f" · {', '.join(g.references)}" if g.references else ""
        head = Table([[
            _sev_pill(g.severity, st, 1.85 * cm),
            Paragraph(f"<b>{idx}. {_e(g.title)}</b>", st["h3"]),
            Paragraph(f"<font color='#475569'>{_e(g.service)}{_e(refs)}</font>",
                      ParagraphStyle("hr", parent=st["small"], alignment=TA_RIGHT)),
        ]], colWidths=[2.15 * cm, CONTENT_W - 2.15 * cm - 4.2 * cm, 4.2 * cm])
        head.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                                  ("LEFTPADDING", (0, 0), (-1, -1), 0),
                                  ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                                  ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]))
        body = [Paragraph(f"<b>Risque.</b> {_e(g.description)}", st["body"]), Spacer(1, 4),
                Paragraph(f"<b>Correction.</b> {_e(g.remediation)}", st["body"])]
        if g.saving:
            body += [Spacer(1, 4), Paragraph(
                f"<font color='#047857'><b>Économie estimée : {eur(g.saving)} / mois "
                f"({eur(g.saving * 12)} / an)</b></font>"
                + (f" <font color='#475569' size='7.5'>· confiance {g.confidence.lower()}</font>"
                   if g.confidence else ""), st["body"])]
        if g.remediation_cli:
            cli = Table([[Paragraph(_e(g.remediation_cli), st["code"])]], colWidths=[CONTENT_W])
            cli.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), C["code_bg"]),
                                     ("LEFTPADDING", (0, 0), (-1, -1), 8),
                                     ("TOPPADDING", (0, 0), (-1, -1), 6),
                                     ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]))
            label = "Exemple de commande" if g.count > 1 else "Commande"
            body += [Spacer(1, 6), Paragraph(f"<b>{label}</b>", st["small"]), Spacer(1, 2), cli]

        block = [head] + body
        if g.has_resources:
            mixed = len({f.severity for f in g.findings}) > 1
            has_saving = any(f.monthly_saving_eur for f in g.findings)
            hdr = [Paragraph("Ressource", st["th"]), Paragraph("Détail", st["th"]),
                   Paragraph("Région", st["th"])]
            if mixed:
                hdr.append(Paragraph("Niveau", st["th"]))
            if has_saving:
                hdr.append(Paragraph("€ / mois", st["th_r"]))
            rows = [hdr]
            shown = sorted(g.findings, key=lambda f: (f.severity.rank, -(f.monthly_saving_eur or 0)))
            for f in shown[:MAX_RESOURCES_PER_CHECK]:
                r = [Paragraph(_e(f.resource_id) or "—", st["res"]),
                     Paragraph(_e(f.resource_detail), st["cell"]),
                     Paragraph(_e(f.region), st["cell"])]
                if mixed:
                    r.append(Paragraph(f"<font color='{SEV_COLOR[f.severity].hexval().replace('0x', '#')}'>"
                                       f"{f.severity.label}</font>", st["cell"]))
                if has_saving:
                    r.append(Paragraph(eur(f.monthly_saving_eur) if f.monthly_saving_eur else "—",
                                       st["cell_r"]))
                rows.append(r)
            extra_w = (1.6 * cm if mixed else 0) + (1.8 * cm if has_saving else 0)
            widths = [5.2 * cm, None, 2.3 * cm] + ([1.6 * cm] if mixed else []) + \
                     ([1.8 * cm] if has_saving else [])
            widths[1] = CONTENT_W - 5.2 * cm - 2.3 * cm - extra_w
            block += [Spacer(1, 8), _table(rows, widths, st)]
            if len(shown) > MAX_RESOURCES_PER_CHECK:
                block.append(Paragraph(
                    f"… et {len(shown) - MAX_RESOURCES_PER_CHECK} autre(s) ressource(s) : liste "
                    "complète dans l'export CSV joint.", st["small"]))
        block.append(Spacer(1, 18))
        # garde l'en-tête et la description ensemble ; la table peut se couper
        el.append(CondPageBreak(5 * cm))
        el.append(KeepTogether(block[:4]))
        el.extend(block[4:])
    return el


def _service_list(ctx) -> List[str]:
    return sorted({c.split(" (")[0] for c in ctx.checks_run} |
                  {f.service for f in ctx.findings})


def _appendix(ctx, st, meta) -> list:
    el = [CondPageBreak(14 * cm), Spacer(1, 8)]
    el += _section_title("Annexe", "Périmètre, méthode et limites", "", st)

    dur = (ctx.finished_at - ctx.started_at).total_seconds() if ctx.finished_at else 0
    rows = [
        ("Compte", f"{ctx.account_id}" + (f" ({ctx.account_alias})" if ctx.account_alias else "")),
        ("Régions", ", ".join(ctx.regions)),
        ("Services analysés", ", ".join(_service_list(ctx))),
        ("Date et durée", f"{meta['date_long']} · {dur:.0f} s"),
        ("Fenêtre d'observation", f"{ctx.lookback_days} jours pour les métriques d'utilisation"),
        ("Mode d'accès", "Rôle IAM en lecture seule (aucune modification possible)"),
        ("Référentiels", "CIS AWS Foundations Benchmark v3.0, AWS Well-Architected "
                         "(piliers Sécurité et Optimisation des coûts)"),
        ("Taux de change", f"1 USD = {ctx.usd_eur:.2f} EUR (tarifs publics AWS eu-west-1)"),
        ("Version de l'outil", f"SenseDrift {__version__}"),
    ]
    el.append(_table([[Paragraph(f"<b>{_e(a)}</b>", st["cell"]), Paragraph(_e(b), st["cell"])]
                      for a, b in rows], [4.2 * cm, CONTENT_W - 4.2 * cm], st, header=False))

    el.append(Paragraph("Méthode de notation", st["h2"]))
    el.append(Paragraph(
        "Le score de posture part de 100. Chaque <b>contrôle</b> en échec (et non chaque ressource) "
        f"retire des points selon sa sévérité : critique −{_n(SCORE_PENALTY[Severity.CRITICAL])}, "
        f"élevée −{_n(SCORE_PENALTY[Severity.HIGH])}, moyenne −{_n(SCORE_PENALTY[Severity.MEDIUM])}, "
        f"faible −{_n(SCORE_PENALTY[Severity.LOW])}. Les constats de coûts n'entrent pas dans le score. "
        "Notes : A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 40, E < 40.", st["body"]))
    sev_rows = [[Paragraph("Niveau", st["th"]), Paragraph("Signification", st["th"]),
                 Paragraph("Échéance conseillée", st["th"])]]
    meaning = {
        Severity.CRITICAL: "Exposition directe ou compromission possible sans effort particulier.",
        Severity.HIGH: "Faiblesse exploitable ou perte de données probable en cas d'incident.",
        Severity.MEDIUM: "Écart aux bonnes pratiques augmentant le risque ou le coût.",
        Severity.LOW: "Amélioration recommandée, risque limité.",
    }
    for s in SEVERITY_ORDER:
        sev_rows.append([_sev_pill(s, st, 1.85 * cm), Paragraph(meaning[s], st["cell"]),
                         Paragraph(s.deadline, st["cell"])])
    el.append(Spacer(1, 6))
    el.append(_table(sev_rows, [2.3 * cm, CONTENT_W - 2.3 * cm - 3.4 * cm, 3.4 * cm], st, zebra=False))

    el.append(Paragraph("Couverture et limites", st["h2"]))
    if ctx.coverage:
        seen, rows = set(), [[Paragraph(h, st["th"]) for h in ("Service", "Région", "Statut")]]
        label = {"access_denied": "Non vérifié — permission manquante",
                 "not_subscribed": "Non vérifié — service non activé ou indisponible",
                 "error": "Non vérifié — erreur technique"}
        for c in ctx.coverage:
            key = (c.service, c.region, c.kind)
            if key in seen:
                continue
            seen.add(key)
            rows.append([Paragraph(_e(c.service), st["cell"]), Paragraph(_e(c.region), st["cell"]),
                         Paragraph(_e(label.get(c.kind, c.message)), st["cell"])])
        el.append(Paragraph("Les contrôles suivants n'ont pas pu être exécutés intégralement. "
                            "L'absence de constat sur ces points ne vaut pas conformité.", st["body"]))
        el.append(Spacer(1, 6))
        el.append(_table(rows, [4.5 * cm, 3 * cm, CONTENT_W - 7.5 * cm], st))
    else:
        el.append(Paragraph("Tous les contrôles prévus ont été exécutés.", st["body"]))

    el.append(Spacer(1, 10))
    el.append(Paragraph(
        "Cet audit est une évaluation automatisée de la configuration à la date indiquée. Il ne "
        "constitue ni un test d'intrusion, ni une certification. Les estimations financières sont "
        "fournies à titre indicatif et ne constituent pas un engagement. Toute modification doit "
        "être testée au préalable sur un environnement hors production.", st["small"]))

    return el


# ─────────────────────────────────────────────
# Point d'entrée
# ─────────────────────────────────────────────
def generate_pdf(ctx, output_path: str, *, client: str = "", prepared_by: str = "SenseDrift",
                 contact: str = "contact@sensedrift.fr · sensedrift.fr", report_id: str = ""):
    _register_fonts()
    st = _styles()
    now = ctx.finished_at or datetime.now()
    client = client or ctx.account_alias or f"compte {ctx.account_id}"
    meta = {
        "client": client,
        "account": ctx.account_id + (f" ({ctx.account_alias})" if ctx.account_alias else ""),
        "regions": ", ".join(ctx.regions),
        "period": f"{ctx.lookback_days} derniers jours (métriques) · 3 mois (facturation)",
        "report_id": report_id or f"SD-{ctx.account_id[-4:]}-{now.strftime('%Y%m%d-%H%M')}",
        "prepared_by": prepared_by,
        "contact": contact,
        "date_long": _fr_date(now),
        "header_right": f"{client} · Audit AWS du {now.strftime('%d/%m/%Y')}",
    }
    groups = group_findings(ctx.findings)

    doc = SimpleDocTemplate(output_path, pagesize=A4, leftMargin=MARGIN, rightMargin=MARGIN,
                            topMargin=2.3 * cm, bottomMargin=2 * cm,
                            title=f"Audit AWS — {client}", author="SenseDrift",
                            subject="Audit de sécurité et d'optimisation des coûts AWS",
                            creator=f"SenseDrift {__version__}")
    story: list = [Spacer(1, 1), PageBreak()]
    story += _summary(ctx, groups, st)
    story += _costs_section(ctx, groups, st)
    if groups:
        story += _action_plan(groups, st)
        story += _details(groups, st)
    story += _appendix(ctx, st, meta)
    doc.build(story, canvasmaker=_make_canvas_class(meta))
    return output_path
