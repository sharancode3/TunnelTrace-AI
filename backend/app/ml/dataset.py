"""Dataset Builder & Session-Level Partitioning for Encrypted ESP Flow Classification."""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.capture import ProtocolObservation
from app.db.models.dataset import DatasetSession, DatasetSplit, DatasetVersion
from app.db.models.reconstruction import ESPFlow
from app.ml.auditor import LeakageAuditor
from app.ml.extractor import TabularFeatureExtractor
from app.ml.schema import FeatureSchema
from app.reconstruction.flow.aggregator import ESPFlowAggregator

# Canonical 7 supervised traffic categories (OOD_HOLDOUT is strictly excluded)
CANONICAL_CLASSES: list[str] = [
    "Web",
    "Video Streaming",
    "VoIP",
    "Chat/Messaging",
    "Email",
    "ICMP",
    "File Transfer",
]

LABEL_TO_INT: dict[str, int] = {name: i for i, name in enumerate(CANONICAL_CLASSES)}
INT_TO_LABEL: dict[int, str] = dict(enumerate(CANONICAL_CLASSES))


@dataclass
class MLDatasetPartition:
    """Encapsulates a single session-isolated dataset partition (Train, Validation, or Test)."""

    split_type: str  # TRAIN, VALIDATION, TEST
    X: pd.DataFrame  # Strictly approved feature columns in FeatureSchema order
    y: np.ndarray  # Integer-encoded class targets [0..6]
    groups: np.ndarray  # Session ID strings for GroupKFold
    metadata: pd.DataFrame  # Provenance and stratification metadata (kept separate from X)
    dataset_version_id: str
    manifest_hash: str
    split_manifest_hash: str
    feature_schema_hash: str

    @property
    def num_rows(self) -> int:
        return len(self.X)

    @property
    def class_counts(self) -> dict[str, int]:
        counts = {}
        unique, u_counts = np.unique(self.y, return_counts=True)
        for u, c in zip(unique, u_counts, strict=False):
            counts[INT_TO_LABEL.get(int(u), f"Unknown_{u}")] = int(c)
        return counts

    @property
    def session_counts(self) -> int:
        return len(np.unique(self.groups)) if len(self.groups) > 0 else 0


class MLDatasetBuilder:
    """Constructs session-isolated training, validation, and test datasets from Stage 4 & 5 DB records."""

    def __init__(
        self,
        schema: FeatureSchema | None = None,
        cache_dir: Path | None = None,
    ) -> None:
        self.schema = schema or FeatureSchema()
        self.extractor = TabularFeatureExtractor(self.schema)
        self.cache_dir = cache_dir

    @classmethod
    def get_canonical_label_mapping(cls) -> dict[str, Any]:
        """Return the authoritative versioned label mapping dictionary."""
        return {
            "version": "1.0",
            "num_classes": len(CANONICAL_CLASSES),
            "classes": CANONICAL_CLASSES,
            "label_to_int": LABEL_TO_INT,
            "int_to_label": {str(k): v for k, v in INT_TO_LABEL.items()},
        }

    async def build_partitions_from_db(
        self,
        session: AsyncSession,
        version_id: str | uuid.UUID,
        split_names: tuple[str, ...] = ("TRAIN", "VALIDATION", "TEST"),
    ) -> dict[str, MLDatasetPartition]:
        """Extract features and materialize session-isolated partitions from the database."""
        v_uuid = uuid.UUID(str(version_id)) if not isinstance(version_id, uuid.UUID) else version_id

        # 1. Fetch DatasetVersion
        version_query = select(DatasetVersion).where(DatasetVersion.id == v_uuid)
        version_res = await session.execute(version_query)
        dataset_version = version_res.scalar_one_or_none()
        if not dataset_version:
            raise ValueError(f"DatasetVersion {version_id} not found.")

        manifest_hash = dataset_version.manifest_hash or "DRAFT_DATASET_INPUT"

        # 2. Fetch all splits for this version
        splits_query = select(DatasetSplit).where(DatasetSplit.version_id == v_uuid)
        splits_res = await session.execute(splits_query)
        splits_records = splits_res.scalars().all()

        partition_sessions: dict[str, list[str]] = {s: [] for s in split_names}
        session_to_split: dict[str, str] = {}

        for sp in splits_records:
            stype = sp.split_type.upper()
            sess_id_str = str(sp.session_id)
            if stype in partition_sessions:
                partition_sessions[stype].append(sess_id_str)
                session_to_split[sess_id_str] = stype

        # 3. Enforce strict session isolation
        LeakageAuditor.audit_session_isolation(partition_sessions)

        # 4. Fetch accepted DatasetSessions
        sessions_query = select(DatasetSession).where(
            DatasetSession.version_id == v_uuid,
            DatasetSession.quality_status == "ACCEPTED",
        )
        sessions_res = await session.execute(sessions_query)
        accepted_sessions = sessions_res.scalars().all()

        # Build map of session_id -> DatasetSession
        session_by_id = {str(s.id): s for s in accepted_sessions}

        # 5. Extract flow records and features partition by partition
        partition_data: dict[str, dict[str, list[Any]]] = {
            s: {"feature_rows": [], "labels": [], "groups": [], "meta_rows": []}
            for s in split_names
        }

        for sess_id_str, sess in session_by_id.items():
            if sess.workload_class not in LABEL_TO_INT:
                # Exclude OOD_HOLDOUT or unrecognized classes from supervised splits
                continue

            target_split = session_to_split.get(sess_id_str)
            if not target_split or target_split not in partition_data:
                continue

            label_int = LABEL_TO_INT[sess.workload_class]

            # Fetch ESPFlows for this session's analysis
            flows_query = select(ESPFlow).where(ESPFlow.analysis_id == sess.analysis_id)
            flows_res = await session.execute(flows_query)
            flows = flows_res.scalars().all()

            # Fetch ProtocolObservation records for this analysis
            obs_query = select(ProtocolObservation).where(
                ProtocolObservation.analysis_id == sess.analysis_id
            )
            obs_res = await session.execute(obs_query)
            observations = obs_res.scalars().all()

            # Extract packets from observations using Stage 4 ESPFlowAggregator
            aggregator = ESPFlowAggregator(sess.analysis_id)
            raw_packets = aggregator.extract_packets(observations)

            for flow in flows:
                # Match packets belonging to this flow (forward or reverse SPI)
                flow_packets = []
                fwd_spi = flow.spi.lower() if flow.spi else None
                rev_spi = flow.reverse_spi.lower() if flow.reverse_spi else None

                for p in raw_packets:
                    pkt_spi = str(p.get("spi", "")).lower()
                    if pkt_spi == fwd_spi:
                        p_copy = dict(p)
                        p_copy["direction"] = 1
                        flow_packets.append(p_copy)
                    elif rev_spi and pkt_spi == rev_spi:
                        p_copy = dict(p)
                        p_copy["direction"] = -1
                        flow_packets.append(p_copy)

                if not flow_packets:
                    continue

                flow_meta = {
                    "flow_id": str(flow.id),
                    "session_id": sess_id_str,
                    "analysis_id": str(sess.analysis_id),
                    "workload_class": sess.workload_class,
                    "scenario_id": sess.scenario_id,
                    "mode": sess.mode,
                    "cipher_suite": sess.cipher_suite,
                    "ip_version": sess.ip_version,
                    "is_nat_t": sess.is_nat_t,
                    "network_impairment_profile": sess.network_impairment_profile,
                    "encrypted_capture_sha256": sess.encrypted_capture_sha256,
                    "spi": flow.spi,
                    "orientation_basis": flow.orientation_basis,
                }

                feat_dict, prov_dict = self.extractor.extract_features(flow_packets, flow_meta)

                partition_data[target_split]["feature_rows"].append(feat_dict)
                partition_data[target_split]["labels"].append(label_int)
                partition_data[target_split]["groups"].append(sess_id_str)
                partition_data[target_split]["meta_rows"].append(prov_dict)

        # 6. Assemble MLDatasetPartition objects
        result: dict[str, MLDatasetPartition] = {}
        expected_cols = self.schema.feature_names
        split_hash = hashlib.sha256(json.dumps(partition_sessions, sort_keys=True).encode("utf-8")).hexdigest()

        for stype in split_names:
            rows = partition_data[stype]["feature_rows"]
            if rows:
                df_X = pd.DataFrame(rows)[expected_cols]
                # Mandatory feature leakage audit
                LeakageAuditor.audit_forbidden_columns(list(df_X.columns))
                y_arr = np.array(partition_data[stype]["labels"], dtype=np.int32)
                groups_arr = np.array(partition_data[stype]["groups"], dtype=object)
                meta_df = pd.DataFrame(partition_data[stype]["meta_rows"])
            else:
                df_X = pd.DataFrame(columns=expected_cols)
                y_arr = np.array([], dtype=np.int32)
                groups_arr = np.array([], dtype=object)
                meta_df = pd.DataFrame()

            result[stype] = MLDatasetPartition(
                split_type=stype,
                X=df_X,
                y=y_arr,
                groups=groups_arr,
                metadata=meta_df,
                dataset_version_id=str(version_id),
                manifest_hash=manifest_hash,
                split_manifest_hash=split_hash,
                feature_schema_hash=self.schema.sha256_hash,
            )

        return result
