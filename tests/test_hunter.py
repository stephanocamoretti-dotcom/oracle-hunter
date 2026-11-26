import os
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import oci
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import hunter


def _generate_ephemeral_pem() -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")


def _base_api_key_env(private_key: str = "FAKE-PEM-CONTENT") -> dict[str, str]:
    return {
        "OCI_TENANCY_ID": "ocid1.tenancy.oc1..aaaaaaaatesttenancy1234567890",
        "OCI_USER_ID": "ocid1.user.oc1..aaaaaaaatestuser1234567890",
        "OCI_FINGERPRINT": "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99",
        "OCI_REGION": "sa-santiago-1",
        "OCI_COMPARTMENT_ID": "ocid1.compartment.oc1..aaaaaaaatestcomp1234567890",
        "OCI_AD_NAME": "TEST:SA-SANTIAGO-1-AD-1",
        "OCI_IMAGE_ID": "ocid1.image.oc1.sa-santiago-1.aaaaaaaatestimage1234567890",
        "OCI_SUBNET_ID": "ocid1.subnet.oc1.sa-santiago-1.aaaaaaaatestsubnet1234567890",
        "OCI_PRIVATE_KEY": private_key,
        "SSH_PUBLIC_KEY": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey user@example",
    }


def _make_service_error(status: int, code: str, message: str) -> oci.exceptions.ServiceError:
    return oci.exceptions.ServiceError(
        status=status,
        code=code,
        headers={},
        message=message,
    )


class TestConfigValidation(unittest.TestCase):
    def test_missing_tenancy_and_user_have_no_defaults(self):
        env = _base_api_key_env()
        del env["OCI_TENANCY_ID"]
        del env["OCI_USER_ID"]

        with self.assertRaises(ValueError) as ctx:
            hunter.load_config(env)

        msg = str(ctx.exception)
        self.assertIn("OCI_TENANCY_ID", msg)
        self.assertIn("OCI_USER_ID", msg)

    def test_missing_compartment_id_does_not_fallback_to_tenancy(self):
        env = _base_api_key_env()
        del env["OCI_COMPARTMENT_ID"]

        with self.assertRaises(ValueError) as ctx:
            hunter.load_config(env)

        self.assertIn("OCI_COMPARTMENT_ID", str(ctx.exception))

    def test_missing_ad_image_subnet_are_rejected(self):
        env = _base_api_key_env()
        del env["OCI_AD_NAME"]
        del env["OCI_IMAGE_ID"]
        del env["OCI_SUBNET_ID"]

        with self.assertRaises(ValueError) as ctx:
            hunter.load_config(env)

        msg = str(ctx.exception)
        self.assertIn("OCI_AD_NAME", msg)
        self.assertIn("OCI_IMAGE_ID", msg)
        self.assertIn("OCI_SUBNET_ID", msg)

    def test_empty_ssh_public_key_is_rejected(self):
        env = _base_api_key_env()
        env["SSH_PUBLIC_KEY"] = "   "

        with self.assertRaises(ValueError) as ctx:
            hunter.load_config(env)

        self.assertIn("SSH_PUBLIC_KEY", str(ctx.exception))

    def test_session_token_mode_requires_private_key_without_leaking_secret(self):
        secret_token = "super-secret-session-token-value"
        env = {
            "OCI_REGION": "sa-santiago-1",
            "OCI_COMPARTMENT_ID": "ocid1.compartment.oc1..aaaaaaaatestcomp1234567890",
            "OCI_AD_NAME": "TEST:SA-SANTIAGO-1-AD-1",
            "OCI_IMAGE_ID": "ocid1.image.oc1.sa-santiago-1.aaaaaaaatestimage1234567890",
            "OCI_SUBNET_ID": "ocid1.subnet.oc1.sa-santiago-1.aaaaaaaatestsubnet1234567890",
            "OCI_SECURITY_TOKEN": secret_token,
            "SSH_PUBLIC_KEY": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey user@example",
        }

        with self.assertRaises(ValueError) as ctx:
            hunter.load_config(env)

        msg = str(ctx.exception)
        self.assertIn("OCI_PRIVATE_KEY", msg)
        self.assertNotIn(secret_token, msg)

    def test_region_mismatch_with_resources_is_rejected(self):
        env = _base_api_key_env()
        env["OCI_REGION"] = "us-ashburn-1"

        with self.assertRaises(ValueError) as ctx:
            hunter.load_config(env)

        self.assertIn("Inconsistencia de región", str(ctx.exception))

    def test_region_mismatch_with_image_ocid_is_rejected(self):
        env = _base_api_key_env()
        env["OCI_REGION"] = "us-ashburn-1"
        env["OCI_AD_NAME"] = "kWVD:US-ASHBURN-1-AD-1"
        env["OCI_IMAGE_ID"] = "ocid1.image.oc1.sa-santiago-1.aaaaaaaademo"
        env["OCI_SUBNET_ID"] = "ocid1.subnet.oc1.us-ashburn-1.aaaaaaaademo"

        with self.assertRaises(ValueError) as ctx:
            hunter.load_config(env)

        self.assertIn("OCI_IMAGE_ID", str(ctx.exception))

    def test_consistent_custom_region_config_succeeds(self):
        env = _base_api_key_env()
        env["OCI_REGION"] = "us-ashburn-1"
        env["OCI_AD_NAME"] = "kWVD:US-ASHBURN-1-AD-1"
        env["OCI_IMAGE_ID"] = "ocid1.image.oc1.us-ashburn-1.aaaaaaaademo"
        env["OCI_SUBNET_ID"] = "ocid1.subnet.oc1.us-ashburn-1.aaaaaaaademo"

        cfg = hunter.load_config(env)
        self.assertEqual(cfg.region, "us-ashburn-1")
        self.assertEqual(cfg.ad_name, "kWVD:US-ASHBURN-1-AD-1")

    def test_empty_optional_env_vars_use_documented_defaults(self):
        env = _base_api_key_env()
        env["OCI_REGION"] = ""
        env["OCI_INSTANCE_NAME"] = ""

        cfg = hunter.load_config(env)
        self.assertEqual(cfg.region, hunter.DEFAULT_REGION)
        self.assertEqual(cfg.instance_name, hunter.DEFAULT_INSTANCE_NAME)


class TestClientInitialization(unittest.TestCase):
    def test_api_key_client_initializes_in_memory_without_tmp_file(self):
        pem = _generate_ephemeral_pem()
        cfg = hunter.load_config(_base_api_key_env(private_key=pem))

        tmp_key_path = "/tmp/oci_key.pem"
        had_tmp_before = os.path.exists(tmp_key_path)

        client = hunter.get_compute_client(cfg)

        self.assertIsInstance(client, oci.core.ComputeClient)
        if not had_tmp_before:
            self.assertFalse(os.path.exists(tmp_key_path))

    def test_session_token_client_initializes_in_memory(self):
        pem = _generate_ephemeral_pem()
        env = {
            "OCI_REGION": "sa-santiago-1",
            "OCI_COMPARTMENT_ID": "ocid1.compartment.oc1..aaaaaaaatestcomp1234567890",
            "OCI_AD_NAME": "TEST:SA-SANTIAGO-1-AD-1",
            "OCI_IMAGE_ID": "ocid1.image.oc1.sa-santiago-1.aaaaaaaatestimage1234567890",
            "OCI_SUBNET_ID": "ocid1.subnet.oc1.sa-santiago-1.aaaaaaaatestsubnet1234567890",
            "OCI_SECURITY_TOKEN": "dummy.jwt.token",
            "OCI_PRIVATE_KEY": pem,
            "SSH_PUBLIC_KEY": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey user@example",
        }
        cfg = hunter.load_config(env)

        client = hunter.get_compute_client(cfg)
        self.assertIsInstance(client, oci.core.ComputeClient)


class TestHuntBehavior(unittest.TestCase):
    def test_invalid_max_attempts_rejected(self):
        cfg = hunter.load_config(_base_api_key_env())
        for bad_value in (0, -1, True):
            with self.subTest(bad_value=bad_value):
                with self.assertRaises(ValueError):
                    hunter.hunt(max_attempts=bad_value, retry_delay=0, config=cfg)

    def test_non_retryable_service_error_fails_immediately_without_sleep(self):
        cfg = hunter.load_config(_base_api_key_env())
        mock_client = MagicMock()
        mock_client.launch_instance.side_effect = _make_service_error(
            400, "InvalidParameter", "Bad subnet"
        )

        with (
            patch("hunter.get_compute_client", return_value=mock_client),
            patch("hunter.time.sleep") as mock_sleep,
            patch("hunter.send_telegram") as mock_tg,
        ):
            with self.assertRaises(oci.exceptions.ServiceError):
                hunter.hunt(max_attempts=5, retry_delay=20, config=cfg)

        self.assertEqual(mock_client.launch_instance.call_count, 1)
        mock_sleep.assert_not_called()
        mock_tg.assert_not_called()

    def test_auth_service_error_alerts_and_fails_immediately(self):
        cfg = hunter.load_config(_base_api_key_env())
        mock_client = MagicMock()
        mock_client.launch_instance.side_effect = _make_service_error(
            401, "NotAuthenticated", "The required information to complete authentication was not provided."
        )

        with (
            patch("hunter.get_compute_client", return_value=mock_client),
            patch("hunter.time.sleep") as mock_sleep,
            patch("hunter.send_telegram") as mock_tg,
        ):
            with self.assertRaises(oci.exceptions.ServiceError):
                hunter.hunt(max_attempts=3, retry_delay=20, config=cfg)

        self.assertEqual(mock_client.launch_instance.call_count, 1)
        mock_sleep.assert_not_called()
        mock_tg.assert_called_once()

    def test_transient_errors_retry_and_sleep_only_between_attempts(self):
        cfg = hunter.load_config(_base_api_key_env())
        mock_client = MagicMock()
        created_instance = SimpleNamespace(id="ocid1.instance.oc1.sa-santiago-1.created")
        mock_client.launch_instance.side_effect = [
            _make_service_error(500, "InternalError", "Out of host capacity"),
            _make_service_error(429, "TooManyRequests", "Rate limit exceeded"),
            _make_service_error(503, "ServiceUnavailable", "Temporarily unavailable"),
            SimpleNamespace(data=created_instance),
        ]

        with (
            patch("hunter.get_compute_client", return_value=mock_client),
            patch("hunter.time.sleep") as mock_sleep,
            patch("hunter.send_telegram") as mock_tg,
        ):
            result = hunter.hunt(max_attempts=5, retry_delay=15, config=cfg)

        self.assertEqual(result.id, created_instance.id)
        self.assertEqual(mock_client.launch_instance.call_count, 4)
        self.assertEqual(mock_sleep.call_count, 3)
        mock_sleep.assert_called_with(15)
        mock_tg.assert_called_once()

        launch_details = mock_client.launch_instance.call_args[0][0]
        self.assertEqual(launch_details.compartment_id, cfg.compartment_id)
        self.assertNotEqual(launch_details.compartment_id, cfg.tenancy_id)

    def test_exhausted_attempts_raises_explicit_error_without_trailing_sleep(self):
        cfg = hunter.load_config(_base_api_key_env())
        mock_client = MagicMock()
        mock_client.launch_instance.side_effect = _make_service_error(
            500, "InternalError", "Out of host capacity"
        )

        with (
            patch("hunter.get_compute_client", return_value=mock_client),
            patch("hunter.time.sleep") as mock_sleep,
        ):
            with self.assertRaises(RuntimeError) as ctx:
                hunter.hunt(max_attempts=3, retry_delay=10, config=cfg)

        self.assertIn("3 intentos", str(ctx.exception))
        self.assertEqual(mock_client.launch_instance.call_count, 3)
        self.assertEqual(mock_sleep.call_count, 2)

    def test_main_exits_nonzero_on_failure(self):
        with (
            patch("hunter.hunt", side_effect=ValueError("missing config")),
            self.assertRaises(SystemExit) as ctx,
        ):
            hunter.main()

        self.assertEqual(ctx.exception.code, 1)


if __name__ == "__main__":
    unittest.main()
