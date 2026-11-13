import json
import unittest
from pathlib import Path

import struct
import tempfile

from lab import detector, live, run_lab
from sensor import baseline, engine, pcap
from sensor.__main__ import main as sensor_cli
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


def to_pcapng(pcap_path, out_path):
    """Convierte una captura PCAP del laboratorio a PCAPNG, para probar el lector."""
    data = Path(pcap_path).read_bytes()
    def block(kind, body):
        body += b"\x00" * (-len(body) % 4)
        size = struct.pack("<I", len(body) + 12)
        return struct.pack("<I", kind) + size + body + size
    out = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)) + block(1, struct.pack("<HHI", 1, 0, 65535))
    pos = 24
    while pos + 16 <= len(data):
        sec, usec, caplen, _ = struct.unpack("<IIII", data[pos:pos + 16])
        frame = data[pos + 16:pos + 16 + caplen]
        pos += 16 + caplen
        stamp = sec * 1_000_000 + usec
        out += block(6, struct.pack("<IIIII", 0, stamp >> 32, stamp & 0xFFFFFFFF, caplen, caplen) + frame)
    Path(out_path).write_bytes(out)


class Sensor(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        run_lab.main(baseline_seconds=2.0, save=False)
        cls.pcaps = ROOT / "results" / "pcap"
        cls.policy = json.loads((ROOT / "lab" / "policy.json").read_text(encoding="utf-8"))
        cls.tmp = tempfile.TemporaryDirectory()

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def rules(self, capture, policy=None):
        return {a["rule"] for a in engine.analyse(capture, policy)["alerts"]}

    def test_pcapng_gives_the_same_result_as_pcap(self):
        out = Path(self.tmp.name) / "S5.pcapng"
        to_pcapng(self.pcaps / "S5.pcap", out)
        a, b = engine.analyse(self.pcaps / "S5.pcap", self.policy), engine.analyse(out, self.policy)
        self.assertEqual(a["stats"], b["stats"])
        self.assertEqual([x["rule"] for x in a["alerts"]], [x["rule"] for x in b["alerts"]])

    def test_vlan_tagged_frames_are_decoded(self):
        ip = bytes([0x45, 0, 0, 44, 0, 0, 0, 0, 64, 6, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2])
        tcp = struct.pack(">HHIIBBHHH", 40000, 502, 7, 0, 5 << 4, 0x18, 0, 0, 0) + b"abcd"
        frame = b"\x00" * 12 + b"\x81\x00\x00\x64\x08\x00" + ip + tcp
        self.assertEqual(pcap.decode_frame(pcap.ETHERNET, frame), ("10.0.0.1", 40000, "10.0.0.2", 502, 7, 0x18, b"abcd", "00:00:00:00:00:00"))

    def test_retransmissions_and_duplicates_are_dropped(self):
        d, flow = pcap.TcpDeduplicator(), ("a", 1, "b", 502)
        self.assertEqual(d.new_data(flow, 100, 0x18, b"abcd"), b"abcd")
        self.assertEqual(d.new_data(flow, 100, 0x18, b"abcd"), b"")
        self.assertEqual(d.new_data(flow, 102, 0x18, b"cdef"), b"ef")
        self.assertEqual(d.new_data(flow, 106, 0x18, b"gh"), b"gh")

    def test_without_policy_it_builds_the_inventory(self):
        result = engine.analyse(self.pcaps / "S2.pcap")
        devices = {d["ip"]: d for d in result["inventory"]}
        self.assertEqual(devices["10.10.40.21"]["identification"], "Inversor emulado")
        self.assertEqual(devices["10.10.40.21"]["roles"], ["esclavo"])
        self.assertEqual(set(devices), {"10.10.15.30", "10.10.40.21", "10.10.40.99"})

    def test_learned_baseline_has_no_false_positives_and_flags_novel_writes(self):
        learned = baseline.learn(self.pcaps / "S0.pcap")
        self.assertEqual(learned["authorized_masters"], ["10.10.15.30"])
        self.assertEqual(learned["slaves"]["10.10.40.21"]["function_codes"], [3])
        self.assertEqual(self.rules(self.pcaps / "S0.pcap", learned), set())
        self.assertEqual(self.rules(self.pcaps / "S6.pcap", learned), {"R9", "R10"})
        self.assertEqual(self.rules(self.pcaps / "S8.pcap", learned), set())

    def test_baseline_with_writes_accepts_values_in_range_only(self):
        learned = baseline.learn(self.pcaps / "S6.pcap")          # contiene una escritura del valor 60
        self.assertEqual(learned["slaves"]["10.10.40.21"]["write_ranges"], {"10": {"min": 60, "max": 60}})
        self.assertEqual(self.rules(self.pcaps / "S6.pcap", learned), set())
        self.assertEqual(self.rules(self.pcaps / "S3.pcap", learned), {"R3"})   # mismo maestro, valor 5

    def test_cli_learn_and_analyze(self):
        policy = str(Path(self.tmp.name) / "base.json")
        self.assertEqual(sensor_cli(["learn", str(self.pcaps / "S0.pcap"), "-o", policy]), 0)
        self.assertEqual(sensor_cli(["analyze", str(self.pcaps / "S0.pcap"), "--policy", policy]), 0)
        self.assertEqual(sensor_cli(["analyze", str(self.pcaps / "S1.pcap"), "--policy", policy]), 1)

    def test_ip_with_a_second_hardware_address_raises_r12(self):
        det = engine.Detector()
        self.assertEqual(det.link(1.0, "10.0.0.5", "aa:aa:aa:aa:aa:01"), [])
        self.assertEqual(det.link(2.0, "10.0.0.5", "aa:aa:aa:aa:aa:01"), [])
        self.assertEqual([a["rule"] for a in det.link(3.0, "10.0.0.5", "aa:aa:aa:aa:aa:02")], ["R12"])
        self.assertEqual(det.link(4.0, "10.0.0.6", "aa:aa:aa:aa:aa:02"), [])       # un router: varias IP, una dirección
        base = engine.Detector({"hardware_addresses": {"10.0.0.5": ["aa:aa:aa:aa:aa:01"]}})
        self.assertEqual([a["rule"] for a in base.link(1.0, "10.0.0.5", "aa:aa:aa:aa:aa:02")], ["R12"])

    def test_replay_feeds_a_capture_to_the_sensor_and_finishes(self):
        import time
        replay = live.Replay(self.pcaps / "S5.pcap", self.policy, "política del laboratorio", speed=50)
        try:
            deadline = time.time() + 10
            while not replay.state()["finished"] and time.time() < deadline:
                time.sleep(0.05)
            state = replay.state()
            self.assertTrue(state["finished"])
            self.assertEqual({a["rule"] for a in replay.alerts}, {"R1", "R2", "R4"})
            self.assertEqual(len(state["inventory"]), 3)
            self.assertEqual(replay.post(["replay", "speed", "0"]), None)
            self.assertEqual(replay.post(["replay", "restart"]), {"ok": True})
        finally:
            replay.stop()

    def test_sensor_package_cannot_transmit(self):
        for source in (ROOT / "sensor").glob("*.py"):
            text = source.read_text(encoding="utf-8")
            for forbidden in (".send(", ".sendall(", ".sendto(", "create_connection", ".connect("):
                self.assertNotIn(forbidden, text, f"{source.name} contiene {forbidden}")


if __name__ == "__main__":
    unittest.main()
