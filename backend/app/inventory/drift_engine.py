"""Deterministic strongSwan Configuration Drift Engine.

Compares baseline configuration snapshots against observed snapshots to detect
field-level drift across connection topology, proposals, traffic selectors, and lifetimes.
Maintains strict separation from security compliance scoring and secret redaction.
"""

from __future__ import annotations

from typing import Any

from app.inventory.schemas import ComparisonStatus, FieldDriftItem, FieldDriftStatus


class ConfigurationDriftEngine:
    """Evaluates field-level configuration differences between two strongSwan snapshots."""

    @classmethod
    def compare_snapshots(
        cls,
        baseline_ir: dict[str, Any],
        observed_ir: dict[str, Any],
        baseline_identity: str,
        observed_identity: str,
    ) -> tuple[ComparisonStatus, dict[str, Any], list[FieldDriftItem]]:
        """Compare normalized baseline vs observed configuration IR.

        Returns:
            tuple of (comparison_status, drift_summary, list of FieldDriftItem)
        """
        # 1. Compatibility check
        if baseline_identity.strip().lower() != observed_identity.strip().lower():
            summary = {
                "total_fields": 0,
                "matched_count": 0,
                "changed_count": 0,
                "missing_count": 0,
                "new_count": 0,
                "not_comparable_count": 1,
                "reason": f"Gateway identity mismatch: '{baseline_identity}' vs '{observed_identity}'",
            }
            item = FieldDriftItem(
                field_path="gateway_identity",
                baseline_value=baseline_identity,
                observed_value=observed_identity,
                status=FieldDriftStatus.NOT_COMPARABLE,
                description=f"Snapshots belong to different gateways ({baseline_identity} vs {observed_identity})",
            )
            return ComparisonStatus.INCOMPARABLE, summary, [item]

        base_conns = baseline_ir.get("connections", {})
        obs_conns = observed_ir.get("connections", {})

        field_drifts: list[FieldDriftItem] = []

        all_conn_names = sorted(set(base_conns.keys()) | set(obs_conns.keys()))

        for conn_name in all_conn_names:
            base_conn = base_conns.get(conn_name)
            obs_conn = obs_conns.get(conn_name)

            if base_conn is not None and obs_conn is None:
                field_drifts.append(
                    FieldDriftItem(
                        field_path=f"connections.{conn_name}",
                        baseline_value=f"connection({conn_name})",
                        observed_value=None,
                        status=FieldDriftStatus.MISSING_IN_OBSERVED,
                        description=f"Connection '{conn_name}' configured in baseline but missing in observed state",
                    )
                )
                continue
            elif base_conn is None and obs_conn is not None:
                field_drifts.append(
                    FieldDriftItem(
                        field_path=f"connections.{conn_name}",
                        baseline_value=None,
                        observed_value=f"connection({conn_name})",
                        status=FieldDriftStatus.NEW_IN_OBSERVED,
                        description=f"Connection '{conn_name}' not in baseline but present in observed state",
                    )
                )
                continue

            # Both present: compare top-level connection attributes
            conn_scalar_fields = [
                ("version", "IKE Version"),
                ("local_addrs", "Local Address Endpoint"),
                ("remote_addrs", "Remote Address Endpoint"),
                ("encap", "UDP Encapsulation (NAT-T)"),
                ("rekey_time", "IKE Rekey Interval"),
            ]
            for attr, label in conn_scalar_fields:
                b_val = base_conn.get(attr)
                o_val = obs_conn.get(attr)
                path = f"connections.{conn_name}.{attr}"
                if b_val == o_val:
                    field_drifts.append(
                        FieldDriftItem(
                            field_path=path,
                            baseline_value=b_val,
                            observed_value=o_val,
                            status=FieldDriftStatus.MATCHED,
                            description=f"{label} matches baseline",
                        )
                    )
                else:
                    field_drifts.append(
                        FieldDriftItem(
                            field_path=path,
                            baseline_value=b_val,
                            observed_value=o_val,
                            status=FieldDriftStatus.CHANGED,
                            description=f"{label} changed from '{b_val}' to '{o_val}'",
                        )
                    )

            # Compare raw_proposals or proposals
            b_props = base_conn.get("raw_proposals") or [p.get("encryption") for p in base_conn.get("proposals", [])]
            o_props = obs_conn.get("raw_proposals") or [p.get("encryption") for p in obs_conn.get("proposals", [])]
            prop_path = f"connections.{conn_name}.proposals"
            if b_props == o_props:
                field_drifts.append(
                    FieldDriftItem(
                        field_path=prop_path,
                        baseline_value=b_props,
                        observed_value=o_props,
                        status=FieldDriftStatus.MATCHED,
                        description="IKE proposal suite matches baseline",
                    )
                )
            else:
                field_drifts.append(
                    FieldDriftItem(
                        field_path=prop_path,
                        baseline_value=b_props,
                        observed_value=o_props,
                        status=FieldDriftStatus.CHANGED,
                        description=f"IKE proposals drift: baseline has '{b_props}', observed has '{o_props}'",
                    )
                )

            # Compare local and remote identity blocks
            for role in ("local", "remote"):
                b_role = base_conn.get(role, {})
                o_role = obs_conn.get(role, {})
                for k in ("id", "auth", "certs", "cacerts"):
                    b_k = b_role.get(k)
                    o_k = o_role.get(k)
                    if b_k is None and o_k is None:
                        continue
                    path = f"connections.{conn_name}.{role}.{k}"
                    if b_k == o_k:
                        field_drifts.append(
                            FieldDriftItem(
                                field_path=path,
                                baseline_value=b_k,
                                observed_value=o_k,
                                status=FieldDriftStatus.MATCHED,
                                description=f"Connection {role}.{k} matches baseline",
                            )
                        )
                    elif b_k is not None and o_k is None:
                        field_drifts.append(
                            FieldDriftItem(
                                field_path=path,
                                baseline_value=b_k,
                                observed_value=None,
                                status=FieldDriftStatus.MISSING_IN_OBSERVED,
                                description=f"Connection {role}.{k} present in baseline ('{b_k}') but missing in observed",
                            )
                        )
                    elif b_k is None and o_k is not None:
                        field_drifts.append(
                            FieldDriftItem(
                                field_path=path,
                                baseline_value=None,
                                observed_value=o_k,
                                status=FieldDriftStatus.NEW_IN_OBSERVED,
                                description=f"Connection {role}.{k} newly defined in observed ('{o_k}')",
                            )
                        )
                    else:
                        field_drifts.append(
                            FieldDriftItem(
                                field_path=path,
                                baseline_value=b_k,
                                observed_value=o_k,
                                status=FieldDriftStatus.CHANGED,
                                description=f"Connection {role}.{k} changed from '{b_k}' to '{o_k}'",
                            )
                        )

            # Compare children (Child SAs)
            b_children = base_conn.get("children", {})
            o_children = obs_conn.get("children", {})
            all_child_names = sorted(set(b_children.keys()) | set(o_children.keys()))

            for child_name in all_child_names:
                b_child = b_children.get(child_name)
                o_child = o_children.get(child_name)

                child_prefix = f"connections.{conn_name}.children.{child_name}"
                if b_child is not None and o_child is None:
                    field_drifts.append(
                        FieldDriftItem(
                            field_path=child_prefix,
                            baseline_value=f"child_sa({child_name})",
                            observed_value=None,
                            status=FieldDriftStatus.MISSING_IN_OBSERVED,
                            description=f"Child SA '{child_name}' configured in baseline but missing in observed state",
                        )
                    )
                    continue
                elif b_child is None and o_child is not None:
                    field_drifts.append(
                        FieldDriftItem(
                            field_path=child_prefix,
                            baseline_value=None,
                            observed_value=f"child_sa({child_name})",
                            status=FieldDriftStatus.NEW_IN_OBSERVED,
                            description=f"Child SA '{child_name}' not in baseline but present in observed state",
                        )
                    )
                    continue

                # Both present: compare child attributes
                child_attrs = [
                    ("mode", "IPsec Mode"),
                    ("local_ts", "Local Traffic Selector"),
                    ("remote_ts", "Remote Traffic Selector"),
                    ("start_action", "Start Action"),
                    ("rekey_time", "ESP Rekey Interval"),
                    ("replay_window", "Replay Window Size"),
                ]
                for cattr, clabel in child_attrs:
                    b_val = b_child.get(cattr)
                    o_val = o_child.get(cattr)
                    cpath = f"{child_prefix}.{cattr}"
                    if b_val == o_val:
                        field_drifts.append(
                            FieldDriftItem(
                                field_path=cpath,
                                baseline_value=b_val,
                                observed_value=o_val,
                                status=FieldDriftStatus.MATCHED,
                                description=f"{clabel} matches baseline",
                            )
                        )
                    else:
                        field_drifts.append(
                            FieldDriftItem(
                                field_path=cpath,
                                baseline_value=b_val,
                                observed_value=o_val,
                                status=FieldDriftStatus.CHANGED,
                                description=f"{clabel} changed from '{b_val}' to '{o_val}'",
                            )
                        )

                # ESP proposals
                b_esp = b_child.get("raw_esp_proposals") or [p.get("encryption") for p in b_child.get("esp_proposals", [])]
                o_esp = o_child.get("raw_esp_proposals") or [p.get("encryption") for p in o_child.get("esp_proposals", [])]
                esp_path = f"{child_prefix}.esp_proposals"
                if b_esp == o_esp:
                    field_drifts.append(
                        FieldDriftItem(
                            field_path=esp_path,
                            baseline_value=b_esp,
                            observed_value=o_esp,
                            status=FieldDriftStatus.MATCHED,
                            description="ESP proposals match baseline",
                        )
                    )
                else:
                    field_drifts.append(
                        FieldDriftItem(
                            field_path=esp_path,
                            baseline_value=b_esp,
                            observed_value=o_esp,
                            status=FieldDriftStatus.CHANGED,
                            description=f"ESP proposals drift: baseline has '{b_esp}', observed has '{o_esp}'",
                        )
                    )

        # Mark secrets as NOT_COMPARABLE
        if "secrets" in baseline_ir or "secrets" in observed_ir:
            field_drifts.append(
                FieldDriftItem(
                    field_path="secrets",
                    baseline_value="[REDACTED_SECRET]",
                    observed_value="[REDACTED_SECRET]",
                    status=FieldDriftStatus.NOT_COMPARABLE,
                    description="Authentication secrets are strictly redacted and excluded from direct comparison",
                )
            )

        # Compute summary metrics
        matched_count = sum(1 for d in field_drifts if d.status == FieldDriftStatus.MATCHED)
        changed_count = sum(1 for d in field_drifts if d.status == FieldDriftStatus.CHANGED)
        missing_count = sum(1 for d in field_drifts if d.status == FieldDriftStatus.MISSING_IN_OBSERVED)
        new_count = sum(1 for d in field_drifts if d.status == FieldDriftStatus.NEW_IN_OBSERVED)
        not_comp_count = sum(1 for d in field_drifts if d.status == FieldDriftStatus.NOT_COMPARABLE)

        drift_detected = (changed_count > 0 or missing_count > 0 or new_count > 0)
        overall_status = ComparisonStatus.DRIFT_DETECTED if drift_detected else ComparisonStatus.MATCHED

        summary = {
            "total_fields": len(field_drifts),
            "matched_count": matched_count,
            "changed_count": changed_count,
            "missing_count": missing_count,
            "new_count": new_count,
            "not_comparable_count": not_comp_count,
            "drift_detected": drift_detected,
        }

        return overall_status, summary, field_drifts
