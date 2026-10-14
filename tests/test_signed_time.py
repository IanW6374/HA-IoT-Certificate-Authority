"""Offline clock/signature tests; no public NTP, hardware, or CA private keys."""
import hashlib
import json
import re
import socket
import struct
import tempfile
import threading
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock
from urllib.request import urlopen

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from iot_ca import signed_time as module
from iot_ca.web import create_app
from iot_ca.service import CertificateService
from tests.helpers import FakeEngine, FakeExternalACME

MAC = "3cdc755be290"
EPOCH = 1791979200.0
ROOT = Path(__file__).resolve().parents[1]


class SignedTimeTests(unittest.TestCase):
    def test_defaults_disabled_host_clock_nts_required_and_no_server_contacts(self):
        c = module.configuration({})
        self.assertEqual(c, module.DEFAULTS)
        self.assertFalse(c["signed_time_enabled"])
        self.assertTrue(c["time_require_nts"])

    def test_named_servers_devices_ports_and_explicit_plain_ntp(self):
        c = module.configuration(dict(signed_time_enabled=True, time_source="ntp",
            time_ntp_servers=["ntp1.example.test", "192.0.2.5"], time_device_macs=["3C:DC:75:5B:E2:90"],
            time_hostname="iot-ca.home.arpa", time_require_nts=False, time_port=9911))
        self.assertEqual(c["time_device_macs"], [MAC])
        text = module.chrony_config(c, "/run/iot-ca-time")
        self.assertIn("server ntp1.example.test iburst minpoll 4 maxpoll 5\n", text)
        self.assertIn("authselectmode ignore", text)
        self.assertIn("port 0\ncmdport 0", text)
        c["time_require_nts"] = True
        text = module.chrony_config(c, "/run/iot-ca-time")
        self.assertIn("authselectmode require", text)
        self.assertIn("server ntp1.example.test iburst minpoll 4 maxpoll 5 nts", text)
        self.assertNotIn("makestep", text)
        self.assertNotIn("allow", text)

    def test_configuration_rejects_injection_unbounded_unknown_or_empty_sources(self):
        variants = [dict(time_source="unknown"), dict(time_source="ntp"),
            dict(time_ntp_servers=["ntp.test\nlocal stratum 1"]), dict(time_ntp_servers=["a"]*5),
            dict(time_ntp_servers=["a", "A"]), dict(signed_time_enabled=True),
            dict(time_require_nts="false"), dict(time_port=True), dict(time_port=65536),
            dict(time_device_macs=["0"*12]), dict(time_device_macs=[MAC,MAC]),
            dict(time_hostname="http://time.test"), dict(time_ntp_servers="ntp.test")]
        for c in variants:
            with self.subTest(c=c), self.assertRaises(ValueError):
                module.configuration(c)

    def test_key_persists_is_private_separate_and_never_silently_replaced(self):
        with tempfile.TemporaryDirectory() as folder:
            a = module.load_signer(folder); b = module.load_signer(folder)
            self.assertEqual(a.private_numbers(), b.private_numbers())
            p = Path(folder)/"secrets/time-signing-key.pem"
            self.assertEqual(p.stat().st_mode&0o777, 0o600)
            self.assertEqual(list(p.parent.iterdir()), [p])
            p.write_bytes(b"corrupt fixture")
            with self.assertRaises(ValueError): module.load_signer(folder)
            self.assertEqual(p.read_bytes(), b"corrupt fixture")
            p.unlink(); p.symlink_to(Path(folder)/"missing")
            with self.assertRaises(OSError): module.load_signer(folder)

    def test_host_clock_query_is_read_only_bounded_and_rejects_unsynchronized_kernel(self):
        def run(value):
            callback = mock.Mock(return_value=SimpleNamespace(stdout=json.dumps(value)))
            return callback
        good = run(dict(result=0,status=0,maxerror=50000))
        self.assertEqual(module.host_sample(lambda:EPOCH,good), EPOCH)
        good.assert_called_once_with(["iot-ca-clock-status"],check=True,timeout=1,capture_output=True,text=True)
        for state in (dict(result=5,status=0,maxerror=0),dict(result=0,status=64,maxerror=0),
                      dict(result=0,status=0,maxerror=1000001),dict(result=True,status=0,maxerror=0)):
            with self.assertRaises(ValueError): module.host_sample(lambda:EPOCH,run(state))
        source=(ROOT/"iot_certificate_authority/rootfs/opt/iot-ca/clock_status.c").read_text()
        self.assertIn("struct timex state = {0}",source)
        self.assertIn("adjtimex(&state)",source)
        for forbidden in ("ADJ_", "settimeofday", "clock_settime"):
            self.assertNotIn(forbidden,source)

    def tracking(self, **changes):
        values={"Reference ID":"C0000201 (time.test)","Stratum":"3",
                "Ref time (UTC)":datetime.fromtimestamp(EPOCH,timezone.utc).strftime("%a %b %d %H:%M:%S %Y"),
                "System time":"0.250 seconds slow of NTP time", "Root delay":"0.020 seconds",
                "Root dispersion":"0.010 seconds", "Skew":"1.0 ppm", "Leap status":"Normal"}
        values.update(changes)
        return "\n".join(k+" : "+v for k,v in values.items())

    def test_ntp_virtual_clock_offsets_are_applied_without_changing_host_time(self):
        self.assertEqual(module.chrony_sample(self.tracking(),EPOCH),EPOCH+.25)
        self.assertEqual(module.chrony_sample(self.tracking(**{"System time":"0.250 seconds fast of NTP time"}),EPOCH+1),EPOCH+.75)

    def test_ntp_staleness_uncertainty_local_reference_leap_and_invalid_samples_rejected(self):
        for changes in ({"Leap status":"Not synchronised"},{"Stratum":"0"},{"Stratum":"16"},
                        {"Reference ID":"7F7F0101"},{"Root delay":"nan seconds"},
                        {"Root dispersion":"2 seconds"},{"Root delay":"-1 seconds"},
                        {"Skew":"101 ppm"},{"System time":"bad"}):
            with self.subTest(changes=changes),self.assertRaises(ValueError):
                module.chrony_sample(self.tracking(**changes),EPOCH)
        with self.assertRaises(ValueError): module.chrony_sample(self.tracking(),EPOCH+121)

    def test_clock_lease_and_failure_close_signing_without_resetting_sensors(self):
        now=[10.0];sample=[EPOCH]
        clock=module.Clock(lambda:sample[0],lambda:now[0])
        with self.assertRaises(ValueError):clock.now()
        clock.refresh();now[0]+=10;self.assertEqual(clock.now(),EPOCH+10)
        now[0]+=6
        with self.assertRaises(ValueError):clock.now()
        sample[0]+=16;clock.refresh();self.assertEqual(clock.now(),EPOCH+16)
        clock.sample=mock.Mock(side_effect=OSError("clock unavailable"));clock.refresh()
        with self.assertRaises(ValueError):clock.now()

    def test_clock_step_fault_latches_until_operator_restart_even_after_recovery(self):
        now=[10.0];sample=[EPOCH];clock=module.Clock(lambda:sample[0],lambda:now[0])
        clock.refresh();now[0]+=5;sample[0]+=10;clock.refresh()
        self.assertTrue(clock.fault)
        with self.assertRaises(ValueError):clock.now()
        now[0]+=5;sample[0]=EPOCH+10;clock.refresh()
        with self.assertRaises(ValueError):clock.now()

    def authority(self):
        signer=ec.generate_private_key(ec.SECP256R1())
        now=[10.0];clock=module.Clock(lambda:EPOCH,lambda:now[0]);clock.refresh()
        return module.Authority(signer,[MAC],clock,lambda:now[0]),now

    def test_exact_native_wire_signature_mac_nonce_utc_low_s_and_rate_bounds(self):
        authority,now=self.authority();nonce="01"*32
        code,body=authority.response("GET",f"/iotmd/v1/time?device={MAC}&nonce={nonce}")
        self.assertEqual(code,200);self.assertEqual(len(body),118)
        self.assertEqual(body[:8],b"IMDT01\0\0");self.assertEqual(body[8:14],bytes.fromhex(MAC))
        self.assertEqual(body[14:46],bytes.fromhex(nonce));self.assertEqual(struct.unpack_from("<Q",body,46)[0],int(EPOCH))
        r=int.from_bytes(body[54:86],"big");s=int.from_bytes(body[86:],"big")
        self.assertLessEqual(s,module.ORDER//2)
        authority.signer.public_key().verify(utils.encode_dss_signature(r,s),body[:54],ec.ECDSA(hashes.SHA256()))
        self.assertEqual(authority.response("GET",f"/iotmd/v1/time?device={MAC}&nonce={nonce}")[0],429)
        now[0]+=1
        other=authority.response("GET",f"/iotmd/v1/time?device={MAC}&nonce={'02'*32}")[1]
        self.assertNotEqual(body,other)
        self.assertEqual(len(authority.rate),1)
        now[0]+=16
        self.assertEqual(authority.response("GET",f"/iotmd/v1/time?device={MAC}&nonce={nonce}")[0],503)

    def test_endpoint_methods_allowlist_query_injection_and_bounds(self):
        a,_=self.authority();valid=f"/iotmd/v1/time?device={MAC}&nonce={'01'*32}"
        for path in (valid+"&extra=1",valid+"&device="+MAC,"/other",valid+"#fragment",valid.replace('01'*32,'00')):
            self.assertIn(a.response("GET",path)[0],(400,404))
        self.assertEqual(a.response("POST",valid)[0],405)
        self.assertEqual(a.response("GET",valid.replace(MAC,"010203040506"))[0],403)
        self.assertEqual(a.response("GET","x"*257)[0],400)
        self.assertEqual(a.rate,{})

    def test_real_loopback_http_content_length_and_no_cache_or_chunking(self):
        a,_=self.authority()
        with module.Server(("127.0.0.1",0),a) as server:
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            try:
                with urlopen(f"http://127.0.0.1:{server.server_port}/iotmd/v1/time?device={MAC}&nonce={'01'*32}",timeout=2) as response:
                    self.assertEqual(response.headers["Content-Length"],"118")
                    self.assertEqual(response.headers["Cache-Control"],"no-store")
                    self.assertIsNone(response.headers.get("Transfer-Encoding"))
                    self.assertEqual(len(response.read()),118)
            finally:
                server.shutdown();thread.join(timeout=2)

    def test_worker_slots_are_capped_and_overflow_connections_closed(self):
        a,_=self.authority()
        with module.Server(("127.0.0.1",0),a) as server:
            for _ in range(4):self.assertTrue(server.slots.acquire(blocking=False))
            connection=mock.Mock()
            with mock.patch.object(server,"shutdown_request") as closed:
                server.process_request(connection,("127.0.0.1",1));closed.assert_called_once_with(connection)
            for _ in range(4):server.slots.release()

    def test_stale_health_file_never_claims_live_trust_and_exports_only_public_pin(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);key=module.load_signer(root)
            point=key.public_key().public_bytes(serialization.Encoding.X962,serialization.PublicFormat.UncompressedPoint)[1:]
            c=module.configuration(dict(signed_time_enabled=True,time_device_macs=[MAC]))
            module.atomic_json(root/"settings.json",dict(ca_dns="iot-ca.home.arpa"))
            status=dict(public_key_xy=point.hex(),fingerprint=hashlib.sha256(point).hexdigest(),healthy=True,
                        boot_id=module.boot_id(),monotonic=0,configuration_hash=module.configuration_hash(c))
            module.atomic_json(root/"signed-time-status.json",status)
            public=module.public_configuration(root,c)
            self.assertFalse(public["healthy"]);self.assertEqual(public["hostname"],"iot-ca.home.arpa")
            self.assertNotIn("PRIVATE",json.dumps(public))
            service=CertificateService(root,engine=FakeEngine(),external_acme=FakeExternalACME())
            app=create_app(data_root=root,service=service);client=app.test_client()
            with mock.patch("iot_ca.signed_time.load_options",return_value=c):
                page=client.get("/settings");self.assertEqual(page.status_code,200)
                self.assertIn(b"Signed time",page.data);self.assertIn(b"Unavailable / not synchronized",page.data)
                export=client.get("/settings/signed-time/provisioning.json")
                self.assertEqual(export.json,dict(hostname="iot-ca.home.arpa",port=9011,public_key_xy=point.hex()))
                self.assertEqual(set(export.json),{"hostname","port","public_key_xy"})
            self.assertEqual(client.get("/settings/signed-time/provisioning.json").status_code,409)

    def test_config_change_requires_restart_and_stale_health_is_not_synchronized(self):
        with tempfile.TemporaryDirectory() as folder:
            c=module.configuration(dict(signed_time_enabled=True,time_device_macs=[MAC],time_hostname="time.test"))
            status=dict(healthy=True,boot_id=module.boot_id(),monotonic=module.time.monotonic(),
                        configuration_hash=module.configuration_hash(c),reason="synchronized")
            module.atomic_json(Path(folder)/"signed-time-status.json",status)
            self.assertTrue(module.public_configuration(folder,c)["healthy"])
            altered=dict(c,time_require_nts=False)
            self.assertEqual(module.public_configuration(folder,altered)["reason"],"restart-required")
            status["monotonic"]-=16;module.atomic_json(Path(folder)/"signed-time-status.json",status)
            public=module.public_configuration(folder,c)
            self.assertFalse(public["healthy"]);self.assertEqual(public["reason"],"status-stale-or-not-running")

    def test_corrupt_public_status_does_not_break_settings_or_claim_health(self):
        with tempfile.TemporaryDirectory() as folder:
            p=Path(folder)/"signed-time-status.json"
            c=module.configuration(dict(signed_time_enabled=True,time_device_macs=[MAC]))
            for value in ('broken', '[1,2]', '{"healthy":true,"monotonic":"invalid"}', 'x'*8193):
                p.write_text(value)
                status=module.public_configuration(folder,c)
                self.assertFalse(status["healthy"])

    def test_host_options_clock_dependencies_and_native_manifest_contract_documented(self):
        source=(ROOT/"iot_certificate_authority/rootfs/opt/iot-ca/iot_ca/signed_time.py").read_text()
        self.assertIn('["chronyd", "-d", "-x", "-U", "-u", "root"',source)
        self.assertNotIn("intermediate-password",source)
        self.assertNotIn("root-key",source)
        self.assertIn('timeout=1',source)
        self.assertIn('ThreadPoolExecutor(max_workers=4)',source)
        self.assertIn('threading.Timer(3, self.expire)',source)
        self.assertIn('time-signing-key.pem',source)


if __name__ == "__main__":
    unittest.main()
