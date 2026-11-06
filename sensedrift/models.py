"""Modèle de données : constats (findings), sévérités et contexte d'audit."""
from __future__ import annotations

import logging
import math
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Callable, Dict, List, Optional

import boto3
import botocore.exceptions
from botocore.config import Config

log = logging.getLogger("sensedrift")


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    @property
    def label(self) -> str:
        return {"CRITICAL": "Critique", "HIGH": "Élevée",
                "MEDIUM": "Moyenne", "LOW": "Faible"}[self.value]

    @property
    def rank(self) -> int:
        return SEVERITY_ORDER.index(self)

    @property
    def deadline(self) -> str:
        return {"CRITICAL": "Sous 48 h", "HIGH": "Sous 2 semaines",
                "MEDIUM": "Sous 1 mois", "LOW": "Sous 3 mois"}[self.value]


SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]

# Pénalité appliquée au score de posture, par contrôle en échec (et non par
# ressource : 40 instances sans tag ne doivent pas écraser le score).
SCORE_PENALTY = {Severity.CRITICAL: 12, Severity.HIGH: 6,
                 Severity.MEDIUM: 2, Severity.LOW: 0.5}

# Catégories
SECURITY = "Sécurité"
COST = "Coûts"
RESILIENCE = "Résilience"
COMPLIANCE = "Traçabilité & conformité"
GOVERNANCE = "Gouvernance"

# Niveaux de confiance d'une estimation d'économie
CONF_HIGH = "Élevée"
CONF_MEDIUM = "Moyenne"
CONF_LOW = "Indicative"


@dataclass
class Finding:
    check_id: str                 # identifiant stable, ex. "EC2.IMDSV2"
    severity: Severity
    category: str
    service: str
    title: str                    # titre générique du contrôle (sans nom de ressource)
    description: str
    remediation: str = ""
    resource_id: str = ""
    resource_detail: str = ""     # complément court affiché à côté de la ressource
    region: str = "global"
    monthly_saving_eur: Optional[float] = None
    saving_confidence: str = ""
    effort: str = "Faible"        # Faible / Moyen / Élevé
    references: List[str] = field(default_factory=list)
    remediation_cli: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class CoverageIssue:
    service: str
    region: str
    kind: str      # "access_denied" | "not_subscribed" | "error"
    message: str


@dataclass
class CostOverview:
    currency: str = "EUR"
    months: List[str] = field(default_factory=list)                 # libellés des mois
    monthly_totals: List[float] = field(default_factory=list)
    by_service_last_month: List[tuple] = field(default_factory=list)  # (service, montant)
    forecast_current_month: Optional[float] = None


class AuditContext:
    """État partagé d'un audit. Thread-safe pour l'ajout de constats."""

    def __init__(self, session: boto3.Session, regions: List[str], *,
                 usd_eur: float = 0.86, use_cost_explorer: bool = True,
                 lookback_days: int = 14):
        self.session = session
        self.regions = regions
        self.usd_eur = usd_eur
        self.use_cost_explorer = use_cost_explorer
        self.lookback_days = lookback_days
        self.started_at = datetime.now(timezone.utc)
        self.finished_at: Optional[datetime] = None
        self.account_id = ""
        self.account_alias = ""
        self.findings: List[Finding] = []
        self.coverage: List[CoverageIssue] = []
        self.checks_run: List[str] = []
        self.cost: Optional[CostOverview] = None
        self._lock = threading.Lock()
        self._client_cfg = Config(retries={"max_attempts": 10, "mode": "adaptive"},
                                  user_agent_extra="SenseDrift")
        self.cache: Dict[str, object] = {}

    # ── clients
    def client(self, service: str, region: Optional[str] = None):
        return self.session.client(service, region_name=region or self.regions[0],
                                   config=self._client_cfg)

    # ── enregistrement
    def add(self, check_id: str, severity: Severity, category: str, service: str,
            title: str, description: str, **kw) -> Finding:
        f = Finding(check_id=check_id, severity=severity, category=category,
                    service=service, title=title, description=description, **kw)
        with self._lock:
            self.findings.append(f)
        return f

    def usd(self, amount_usd: float) -> float:
        return round(amount_usd * self.usd_eur, 2)

    def record_error(self, service: str, region: str, exc: Exception):
        kind, msg = "error", str(exc)
        if isinstance(exc, botocore.exceptions.ClientError):
            code = exc.response.get("Error", {}).get("Code", "")
            if code in ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation",
                        "AuthorizationError", "UnrecognizedClientException"):
                kind = "access_denied"
                msg = "Permission manquante pour ce contrôle (rôle d'audit incomplet)."
            elif code in ("SubscriptionRequiredException", "OptInRequired",
                          "InvalidAccessException", "OptInRequiredException"):
                kind = "not_subscribed"
                msg = ("Service non activé ou non disponible sur ce compte "
                       "(compte récent ou plan gratuit AWS).")
        elif isinstance(exc, botocore.exceptions.EndpointConnectionError):
            kind, msg = "error", "Service non disponible dans cette région."
        log.debug("Erreur %s/%s : %s", service, region, exc)
        with self._lock:
            self.coverage.append(CoverageIssue(service, region, kind, msg))

    def run(self, name: str, region: str, fn: Callable, *args):
        """Exécute un contrôle en capturant ses erreurs dans la couverture."""
        label = f"{name} ({region})"
        try:
            fn(self, *args)
            with self._lock:
                self.checks_run.append(label)
        except Exception as exc:  # noqa: BLE001 — un check ne doit jamais tuer l'audit
            self.record_error(name, region, exc)

    # ── agrégats
    @property
    def security_findings(self) -> List[Finding]:
        return [f for f in self.findings if f.category != COST]

    @property
    def cost_findings(self) -> List[Finding]:
        return [f for f in self.findings if f.monthly_saving_eur]

    @property
    def total_monthly_saving(self) -> float:
        return round(sum(f.monthly_saving_eur or 0 for f in self.findings), 2)

    def posture_score(self) -> int:
        failed: Dict[str, Severity] = {}
        for f in self.security_findings:
            cur = failed.get(f.check_id)
            if cur is None or f.severity.rank < cur.rank:
                failed[f.check_id] = f.severity
        return max(0, math.floor(100 - sum(SCORE_PENALTY[s] for s in failed.values())))

    @staticmethod
    def grade(score: int) -> str:
        for threshold, g in ((90, "A"), (75, "B"), (60, "C"), (40, "D")):
            if score >= threshold:
                return g
        return "E"
