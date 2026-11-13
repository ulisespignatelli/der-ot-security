import json
import unittest
from pathlib import Path

from lab import detector, live, run_lab
from tools import expert_consensus, risk_matrix, validate_architecture

ROOT = Path(__file__).resolve().parent.parent


class Architecture(unittest.TestCase):
    def test_model_is_consistent_and_flags_known_violations(self):
        report = validate_architecture.validate(validate_architecture.load())
        self.assertEqual(report["errors"], [])
        bad = {f["id"] for f in report["flows"] if f["status"] == "violación"}
        self.assertEqual(bad, {"F13", "F14", "F15"})


class Risk(unittest.TestCase):
    def test_levels(self):
        threats = {t["id"]: t for t in risk_matrix.assess(risk_matrix.load())}
        self.assertEqual(threats["A15"]["risk"], 16)
        self.assertEqual(threats["A15"]["level"], "Crítico")
        self.assertEqual(threats["A17"]["level"], "Medio")

    def test_every_threat_points_to_a_real_asset(self):
        assets = {a["id"] for a in validate_architecture.load()["assets"]}
        for t in risk_matrix.load()["threats"]:
            self.assertIn(t["asset"], assets)

    def test_lab_scenarios_and_threats_point_to_each_other(self):
        threats = {t["id"]: t for t in risk_matrix.load()["threats"]}
        for sc in run_lab.SCENARIOS:
            if sc["threat"]:
                self.assertEqual(threats[sc["threat"]]["lab_scenario"], sc["id"])


class Consensus(unittest.TestCase):
    def test_kendall_w_bounds(self):
        self.assertAlmostEqual(expert_consensus.kendall_w([[1, 2, 3, 4]] * 5), 1.0)
        self.assertAlmostEqual(expert_consensus.kendall_w([[1, 2, 3, 4], [4, 3, 2, 1]]), 0.0)

    def test_ranks_with_ties(self):
        self.assertEqual(expert_consensus.ranks([10, 20, 20, 30]), [1.0, 2.5, 2.5, 4.0])


class Laboratory(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.results = {r["id"]: r for r in run_lab.main(baseline_seconds=1.0, save=False)}

    def test_no_false_positives_in_normal_operation(self):
        self.assertEqual(self.results["S0"]["alerts"], [])

    def test_expected_rules_fire(self):
        for r in self.results.values():
            self.assertEqual(r["missing_rules"], [], r["id"])

    def test_stealth_scenarios_are_not_detected(self):
        self.assertEqual(self.results["S6"]["outcome"], "no detectado")
        self.assertEqual(self.results["S8"]["outcome"], "no detectado")

    def test_coherence_rule_fires_only_on_impossible_telemetry(self):
        fired = {r["id"] for r in self.results.values() if "R8" in r["fired_rules"]}
        self.assertEqual(fired, {"S7"})

    def test_false_data_does_not_change_the_process(self):
        self.assertEqual(self.results["S7"]["inverter_state"]["potencia_w"], 4000)

    def test_attack_changes_the_process(self):
        self.assertFalse(self.results["S5"]["inverter_state"]["conectado"])
        self.assertEqual(self.results["S1"]["inverter_state"]["limite_pct"], 30)


class LiveLaboratory(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lab = live.LiveLab()

    @classmethod
    def tearDownClass(cls):
        cls.lab.stop()

    def setUp(self):
        self.lab.reset()

    def test_attack_is_detected_while_it_happens(self):
        result = self.lab.run_attack("S1")
        self.assertEqual(result["outcome"], "detectado")
        self.assertIn("R2", result["fired_rules"])
        self.assertEqual(self.lab.state()["limite_pct"], 30)

    def test_repeated_attack_alerts_again_after_cooldown(self):
        policy = self.lab.policy
        det = detector.Detector(policy, cooldown=3.0)
        write = b"\x00\x01\x00\x00\x00\x06\x01\x06\x00\x0b\x00\x00"  # desconexión
        args = ("10.10.40.99", 50000, "10.10.40.21", 502, write)
        self.assertTrue(det.feed(100.0, *args))
        self.assertEqual(det.feed(101.0, *args), [])
        self.assertTrue(det.feed(104.0, *args))

    def test_false_data_shows_in_reported_power_but_not_in_real_power(self):
        import threading, time
        worker = threading.Thread(target=self.lab.run_attack, args=("S7",))
        worker.start()
        time.sleep(1.0)
        state = self.lab.state()
        worker.join()
        self.assertEqual(state["potencia_w"], 4000)
        self.assertEqual(state["potencia_reportada_w"], 6500)

    def test_stealth_attack_is_not_detected_and_reset_restores(self):
        self.assertEqual(self.lab.run_attack("S6")["outcome"], "no detectado")
        self.assertEqual(self.lab.state()["limite_pct"], 60)
        self.lab.reset()
        self.assertEqual(self.lab.state()["limite_pct"], 100)


if __name__ == "__main__":
    unittest.main()
