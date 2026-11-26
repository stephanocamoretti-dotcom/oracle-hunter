from dataclasses import dataclass
import os
import sys
import time
import oci
import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

# Región por defecto si no se especifica OCI_REGION.
# OCI_AD_NAME, OCI_IMAGE_ID y OCI_SUBNET_ID deben configurarse explícitamente para evitar exponer OCIDs en el repositorio.
DEFAULT_REGION = "sa-santiago-1"

# Parámetros del Servidor Always Free
DEFAULT_INSTANCE_NAME = "oci-always-free"
DEFAULT_SHAPE = "VM.Standard.A1.Flex"
DEFAULT_OCPUS = 2
DEFAULT_MEMORY_IN_GBS = 12
DEFAULT_BOOT_VOLUME_SIZE_IN_GBS = 50
DEFAULT_MAX_ATTEMPTS = 30
DEFAULT_RETRY_DELAY_SECONDS = 20


@dataclass(frozen=True)
class HunterConfig:
    tenancy_id: str
    user_id: str
    fingerprint: str
    region: str
    private_key: str
    security_token: str
    compartment_id: str
    ad_name: str
    image_id: str
    subnet_id: str
    ssh_public_key: str
    instance_name: str = DEFAULT_INSTANCE_NAME
    shape: str = DEFAULT_SHAPE
    ocpus: int | float = DEFAULT_OCPUS
    memory_in_gbs: int | float = DEFAULT_MEMORY_IN_GBS
    boot_volume_size_in_gbs: int = DEFAULT_BOOT_VOLUME_SIZE_IN_GBS
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""

    @property
    def auth_mode(self) -> str:
        return "session_token" if self.security_token else "api_key"


def send_telegram(msg: str, bot_token: str = "", chat_id: str = "") -> None:
    print(f"\n[TELEGRAM] {msg}")
    if bot_token and chat_id:
        try:
            url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
            requests.post(
                url,
                json={"chat_id": chat_id, "text": msg, "parse_mode": "Markdown"},
                timeout=10,
            )
        except Exception as exc:
            print(f"Error enviando notificación a Telegram: {type(exc).__name__}")


def _extract_ocid_region(ocid: str) -> str:
    parts = ocid.split(".")
    if len(parts) >= 5 and parts[0] == "ocid1":
        return parts[3]
    return ""


def validate_region_consistency(region: str, ad_name: str, image_id: str, subnet_id: str) -> None:
    region_upper = region.upper()
    if f":{region_upper}-AD-" not in ad_name.upper():
        raise ValueError(
            f"Inconsistencia de región: OCI_AD_NAME ('{ad_name}') no corresponde a OCI_REGION ('{region}')."
        )

    image_region = _extract_ocid_region(image_id)
    if image_region and image_region != region:
        raise ValueError(
            f"Inconsistencia de región: OCI_IMAGE_ID pertenece a '{image_region}' pero OCI_REGION es '{region}'."
        )

    subnet_region = _extract_ocid_region(subnet_id)
    if subnet_region and subnet_region != region:
        raise ValueError(
            f"Inconsistencia de región: OCI_SUBNET_ID pertenece a '{subnet_region}' pero OCI_REGION es '{region}'."
        )


def load_config(environ=None) -> HunterConfig:
    env = os.environ if environ is None else environ

    tenancy_id = env.get("OCI_TENANCY_ID", "").strip()
    user_id = env.get("OCI_USER_ID", "").strip()
    fingerprint = env.get("OCI_FINGERPRINT", "").strip()
    region = env.get("OCI_REGION", "").strip() or DEFAULT_REGION
    private_key = env.get("OCI_PRIVATE_KEY", "").strip()
    security_token = env.get("OCI_SECURITY_TOKEN", "").strip()
    compartment_id = env.get("OCI_COMPARTMENT_ID", "").strip()
    ad_name = env.get("OCI_AD_NAME", "").strip()
    image_id = env.get("OCI_IMAGE_ID", "").strip()
    subnet_id = env.get("OCI_SUBNET_ID", "").strip()
    instance_name = env.get("OCI_INSTANCE_NAME", "").strip() or DEFAULT_INSTANCE_NAME
    ssh_public_key = env.get("SSH_PUBLIC_KEY", "").strip()
    telegram_bot_token = env.get("TELEGRAM_BOT_TOKEN", "").strip()
    telegram_chat_id = env.get("TELEGRAM_CHAT_ID", "").strip()

    missing = []
    if not region:
        missing.append("OCI_REGION")
    if not compartment_id:
        missing.append("OCI_COMPARTMENT_ID")
    if not ad_name:
        missing.append("OCI_AD_NAME")
    if not image_id:
        missing.append("OCI_IMAGE_ID")
    if not subnet_id:
        missing.append("OCI_SUBNET_ID")
    if not ssh_public_key:
        missing.append("SSH_PUBLIC_KEY")

    if security_token:
        # Modo token de sesión (SecurityTokenSigner)
        if not private_key:
            missing.append("OCI_PRIVATE_KEY")
    else:
        # Modo API Key estática
        if not tenancy_id:
            missing.append("OCI_TENANCY_ID")
        if not user_id:
            missing.append("OCI_USER_ID")
        if not fingerprint:
            missing.append("OCI_FINGERPRINT")
        if not private_key:
            missing.append("OCI_PRIVATE_KEY")

    if missing:
        auth_label = "token de sesión" if security_token else "API Key"
        raise ValueError(
            f"Faltan variables requeridas para el modo {auth_label}: {', '.join(missing)}"
        )

    validate_region_consistency(region, ad_name, image_id, subnet_id)

    return HunterConfig(
        tenancy_id=tenancy_id,
        user_id=user_id,
        fingerprint=fingerprint,
        region=region,
        private_key=private_key,
        security_token=security_token,
        compartment_id=compartment_id,
        ad_name=ad_name,
        image_id=image_id,
        subnet_id=subnet_id,
        ssh_public_key=ssh_public_key,
        instance_name=instance_name,
        telegram_bot_token=telegram_bot_token,
        telegram_chat_id=telegram_chat_id,
    )


def get_compute_client(config: HunterConfig) -> oci.core.ComputeClient:
    if config.auth_mode == "session_token":
        pk = serialization.load_pem_private_key(
            config.private_key.encode("utf-8"),
            password=None,
            backend=default_backend(),
        )
        signer = oci.auth.signers.SecurityTokenSigner(config.security_token, pk)
        cfg = {"region": config.region}
        if config.tenancy_id:
            cfg["tenancy"] = config.tenancy_id
        return oci.core.ComputeClient(cfg, signer=signer)

    # Modo API Key estática usando key_content en memoria (sin escribir clave privada en /tmp)
    cfg = {
        "tenancy": config.tenancy_id,
        "region": config.region,
        "user": config.user_id,
        "fingerprint": config.fingerprint,
        "key_content": config.private_key,
    }
    return oci.core.ComputeClient(cfg)


def is_transient_error(exc: Exception) -> bool:
    if isinstance(exc, oci.exceptions.ServiceError):
        status = exc.status
        message = (exc.message or "").lower()
        code = (exc.code or "").lower()
        if status == 429:
            return True
        if status is not None and 500 <= status < 600:
            return True
        if "capacity" in message or code == "outofcapacity":
            return True
        return False
    if isinstance(exc, oci.exceptions.RequestException):
        return True
    return False


def hunt(
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    retry_delay: float = DEFAULT_RETRY_DELAY_SECONDS,
    config: HunterConfig | None = None,
):
    if not isinstance(max_attempts, int) or isinstance(max_attempts, bool) or max_attempts <= 0:
        raise ValueError("max_attempts debe ser un entero mayor que cero.")
    if retry_delay < 0:
        raise ValueError("retry_delay no puede ser negativo.")

    cfg = load_config() if config is None else config

    print(f"🚀 Iniciando ciclo de cacería en GitHub Actions ({max_attempts} intentos máx)...")
    try:
        compute = get_compute_client(cfg)
    except Exception as exc:
        print(f"Error inicializando cliente OCI: {exc}")
        send_telegram(
            f"⚠️ *Error de autenticación en GitHub Actions:* {exc}",
            cfg.telegram_bot_token,
            cfg.telegram_chat_id,
        )
        raise

    launch_details = oci.core.models.LaunchInstanceDetails(
        compartment_id=cfg.compartment_id,
        availability_domain=cfg.ad_name,
        display_name=cfg.instance_name,
        shape=cfg.shape,
        shape_config=oci.core.models.LaunchInstanceShapeConfigDetails(
            ocpus=cfg.ocpus,
            memory_in_gbs=cfg.memory_in_gbs,
        ),
        source_details=oci.core.models.InstanceSourceViaImageDetails(
            image_id=cfg.image_id,
            boot_volume_size_in_gbs=cfg.boot_volume_size_in_gbs,
        ),
        create_vnic_details=oci.core.models.CreateVnicDetails(
            subnet_id=cfg.subnet_id,
            assign_public_ip=True,
        ),
        metadata={"ssh_authorized_keys": cfg.ssh_public_key},
    )

    for attempt in range(1, max_attempts + 1):
        print(f"[{time.strftime('%H:%M:%S')}] Intento #{attempt}/{max_attempts} lanzando instancia...", end=" ")
        try:
            res = compute.launch_instance(launch_details).data
            success_msg = (
                f"🎉 *¡ÉXITO TOTAL EN GITHUB ACTIONS!*\n\n"
                f"Tu servidor gratuito Always Free `{cfg.instance_name}` ha sido creado en Oracle Cloud.\n\n"
                f"*ID:* `{res.id}`\n*IP:* Se asignará en breve."
            )
            send_telegram(success_msg, cfg.telegram_bot_token, cfg.telegram_chat_id)
            print("\n" + success_msg)
            return res
        except Exception as exc:
            if is_transient_error(exc):
                print(f"❌ Error transitorio: {exc}")
                if attempt < max_attempts:
                    time.sleep(retry_delay)
                continue

            if isinstance(exc, oci.exceptions.ServiceError):
                print(f"⚠️ Error no reintentable {exc.status}: {exc.message}")
                msg_lower = (exc.message or "").lower()
                if exc.status == 401 or "notauthenticated" in msg_lower or "expired" in msg_lower:
                    send_telegram(
                        "⚠️ *Error de autenticación / token expirado en Oracle:* Verifica las credenciales en GitHub Actions.",
                        cfg.telegram_bot_token,
                        cfg.telegram_chat_id,
                    )
            else:
                print(f"⚠️ Error inesperado no reintentable: {exc}")
            raise

    raise RuntimeError(
        f"Se agotaron los {max_attempts} intentos sin poder crear la instancia en {cfg.region}."
    )


def main() -> None:
    try:
        hunt()
    except Exception as exc:
        print(f"❌ Ejecución fallida: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

