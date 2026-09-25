"""
TunnelTrace AI - Testbed Command Line Interface (CLI)
=====================================================
Provides clean, structured CLI commands for:
  - environment doctor & capability probing
  - scenario listing and validation
  - executing isolated IPsec experiments
  - stale resource emergency recovery
"""

import sys
import os
import json
import argparse
from typing import List

from lab.agent.operations.runner import SystemRunner
from lab.agent.doctor import EnvironmentDoctor
from lab.agent.cleanup.tracker import LabResourceTracker
from lab.scenarios.loader import ScenarioLoader
from lab.agent.experiment import ExperimentRunner


def cmd_doctor(args: argparse.Namespace) -> int:
    """Runs the environment doctor pre-flight probe."""
    runner = SystemRunner()
    doctor = EnvironmentDoctor(runner)
    report = doctor.check_environment()
    
    print("\n" + "=" * 65)
    print("TUNNELTRACE AI - LAB ENVIRONMENT DOCTOR REPORT")
    print("=" * 65)
    print(f"OS Platform:       {report.get('os')} ({report.get('release')})")
    print(f"WSL2 Environment:  {report.get('is_wsl')}")
    print(f"Elevated Privs:    {report.get('is_root')}")
    print(f"strongSwan Ver:    {report.get('strongswan_version')}")
    print(f"swanctl Ver:       {report.get('swanctl_version')}")
    print(f"tcpdump Ver:       {report.get('tcpdump_version')}")
    print(f"Active Stale Lab:  {report.get('active_lab_namespaces', 0)} namespaces detected")
    print("-" * 65)
    print("CAPABILITY CHECKS:")
    for check_name, status in report.get("checks", {}).items():
        symbol = "[PASS]" if status else "[FAIL]"
        print(f"  {symbol} {check_name.ljust(22)}: {'AVAILABLE' if status else 'MISSING/BLOCKED'}")
    print("-" * 65)
    overall = "READY FOR IPSEC LAB EXPERIMENTS" if report.get("ready") else "BLOCKED - PREREQUISITES MISSING"
    print(f"OVERALL STATUS: {overall}")
    print("=" * 65 + "\n")
    
    if args.json:
        print(json.dumps(report, indent=2))
        
    return 0 if report.get("ready") else 1


def cmd_list_profiles(args: argparse.Namespace) -> int:
    """Lists all valid scenario profiles in the lab repository."""
    profiles_dir = os.path.join(os.path.dirname(__file__), "scenarios", "profiles")
    if not os.path.isdir(profiles_dir):
        print(f"Error: Profiles directory not found at {profiles_dir}")
        return 1

    print("\n" + "=" * 70)
    print("TUNNELTRACE AI - REGISTERED LAB SCENARIO PROFILES")
    print("=" * 70)
    for fname in sorted(os.listdir(profiles_dir)):
        if fname.endswith(".yaml") or fname.endswith(".yml"):
            fpath = os.path.join(profiles_dir, fname)
            try:
                sc = ScenarioLoader.load_from_yaml(fpath)
                print(f"• ID:          {sc.scenario_id}")
                print(f"  Topology:    {sc.topology.value} ({sc.ip_version.value})")
                print(f"  Crypto:      {sc.crypto_profile.value} | PFS: {sc.pfs.value}")
                print(f"  Encaps:      {sc.encapsulation.value} | Impairment: {sc.netem.has_impairment()}")
                print(f"  SHA-256:     {sc.sha256_hash[:16]}...")
                print(f"  File:        {fname}")
                print("-" * 70)
            except Exception as e:
                print(f"• File {fname} [INVALID SCHEMA]: {str(e)}")
    print("=" * 70 + "\n")
    return 0


def cmd_run_scenario(args: argparse.Namespace) -> int:
    """Executes a scenario end-to-end and outputs genuine validation evidence."""
    scenario_path = args.scenario_path
    if not os.path.isfile(scenario_path):
        # Check in profiles dir
        candidate = os.path.join(os.path.dirname(__file__), "scenarios", "profiles", scenario_path)
        if os.path.isfile(candidate):
            scenario_path = candidate
        else:
            print(f"Error: Scenario file not found: {scenario_path}")
            return 1

    print(f"\n[+] Loading scenario definition from {scenario_path}...")
    scenario = ScenarioLoader.load_from_yaml(scenario_path)
    print(f"[+] Scenario: {scenario.scenario_id} ({scenario.topology.value}, {scenario.ip_version.value})")
    print(f"[+] Crypto Profile: {scenario.crypto_profile.value}, PFS: {scenario.pfs.value}")

    runner = SystemRunner()
    exp_runner = ExperimentRunner(runner=runner)
    
    print(f"[+] Commencing isolated testbed execution...")
    manifest = exp_runner.execute_scenario(
        scenario=scenario,
        cleanup_after=not args.no_cleanup
    )

    print("\n" + "=" * 70)
    print(f"TESTBED RUN COMPLETED: {manifest.run_id}")
    print("=" * 70)
    print(f"Validation Status:     {manifest.validation_status}")
    print(f"Summary:               {manifest.status_summary}")
    print(f"Duration:              {manifest.duration_seconds}s")
    print(f"SA Established:        {manifest.sa_established}")
    print(f"Traffic Probe Passed:  {manifest.traffic_probe_passed}")
    print(f"Captures Produced:     {len(manifest.captures)}")
    for cap in manifest.captures:
        print(f"  • [{cap.role}] {os.path.basename(cap.output_path)}")
        print(f"    Size: {cap.file_size_bytes} bytes | Packets: {cap.packet_count} | SHA256: {cap.sha256[:16]}...")
    print(f"Evidence Directory:    {manifest.evidence_directory}")
    print("=" * 70 + "\n")

    return 0 if manifest.validation_status == "VALIDATED" else 1


def cmd_replay_scenario(args: argparse.Namespace) -> int:
    """Reruns a previously recorded scenario, linking provenance and checking semantic reproducibility."""
    from lab.agent.models.manifest import RunManifest

    parent_manifest_path = args.parent_manifest
    if not os.path.isfile(parent_manifest_path):
        candidate = os.path.join("storage", "lab", "runs", parent_manifest_path, "manifest.json")
        if os.path.isfile(candidate):
            parent_manifest_path = candidate
        else:
            print(f"Error: Parent manifest not found at {parent_manifest_path}")
            return 1

    with open(parent_manifest_path, "r", encoding="utf-8") as f:
        parent_manifest = RunManifest.model_validate_json(f.read())

    scenario_path = args.scenario_path
    if not scenario_path:
        profiles_dir = os.path.join(os.path.dirname(__file__), "scenarios", "profiles")
        candidate = None
        for fname in os.listdir(profiles_dir):
            if fname.endswith(".yaml") or fname.endswith(".yml"):
                p = os.path.join(profiles_dir, fname)
                try:
                    sc = ScenarioLoader.load_from_yaml(p)
                    if sc.scenario_id == parent_manifest.scenario_id:
                        candidate = p
                        break
                except Exception:
                    continue
        if candidate:
            scenario_path = candidate
        else:
            print(f"Error: Could not automatically locate scenario profile for '{parent_manifest.scenario_id}'. Specify --scenario-path.")
            return 1

    scenario = ScenarioLoader.load_from_yaml(scenario_path)
    runner = SystemRunner()
    exp_runner = ExperimentRunner(runner=runner)

    print(f"\n[+] Replaying scenario {scenario.scenario_id} (Parent Run: {parent_manifest.run_id})...")
    child_manifest, comparison = exp_runner.replay_scenario(
        scenario=scenario,
        parent_manifest=parent_manifest,
        cleanup_after=not args.no_cleanup,
    )

    print("\n" + "=" * 70)
    print(f"SCENARIO REPLAY COMPLETED: {child_manifest.run_id}")
    print("=" * 70)
    print(f"Replay Mode:           {child_manifest.replay_mode}")
    print(f"Parent Run ID:         {child_manifest.parent_run_id}")
    print(f"Comparison Status:     {comparison.get('comparison_status')}")
    print(f"Comparison Summary:    {comparison.get('summary')}")
    print(f"Validation Status:     {child_manifest.validation_status}")
    print(f"Summary:               {child_manifest.status_summary}")
    print("=" * 70 + "\n")

    return 0 if comparison.get("comparison_status") == "SEMANTIC_MATCH" else 1


def cmd_clean_stale(args: argparse.Namespace) -> int:
    """Safely cleans up any leaked or stale tt-* namespaces and locks."""
    runner = SystemRunner()
    tracker = LabResourceTracker(runner)
    print("\n[+] Purging stale TunnelTrace lab resources...")
    tracker.clean_all_stale_resources()
    print("[+] Cleanup complete.\n")
    return 0


def main(argv: List[str] = None) -> int:
    parser = argparse.ArgumentParser(description="TunnelTrace AI - Linux Namespace & strongSwan IPsec Testbed CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # doctor
    p_doc = subparsers.add_parser("doctor", help="Run preflight environment capability doctor")
    p_doc.add_argument("--json", action="store_true", help="Output raw JSON report")
    p_doc.set_defaults(func=cmd_doctor)

    # list-profiles
    p_list = subparsers.add_parser("list-profiles", help="List all registered testbed scenario profiles")
    p_list.set_defaults(func=cmd_list_profiles)

    # run-scenario
    p_run = subparsers.add_parser("run-scenario", help="Execute an IPsec testbed scenario end-to-end")
    p_run.add_argument("scenario_path", help="Path or profile filename of scenario YAML")
    p_run.add_argument("--no-cleanup", action="store_true", help="Preserve namespaces after run for debugging")
    p_run.set_defaults(func=cmd_run_scenario)

    # replay-scenario
    p_rep = subparsers.add_parser("replay-scenario", help="Replay a previously recorded scenario and check semantic reproducibility")
    p_rep.add_argument("parent_manifest", help="Parent run ID or path to parent manifest.json")
    p_rep.add_argument("--scenario-path", help="Optional explicit path to scenario YAML")
    p_rep.add_argument("--no-cleanup", action="store_true", help="Preserve namespaces after run")
    p_rep.set_defaults(func=cmd_replay_scenario)

    # clean-stale
    p_clean = subparsers.add_parser("clean-stale", help="Purge any stale tt-* testbed namespaces and processes")
    p_clean.set_defaults(func=cmd_clean_stale)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
