"""Helm chart template rendering tests."""

import subprocess


def _helm_template(*set_args: str) -> str:
    cmd = ["helm", "template", "test-release", "./helm/certmesh"]
    for arg in set_args:
        cmd.extend(["--set", arg])
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    return result.stdout


class TestVaultPkiTlsTemplate:
    def test_init_container_not_rendered_when_disabled(self):
        output = _helm_template("vaultPkiTls.enabled=false")
        assert "vault-tls-init" not in output

    def test_init_container_rendered_when_enabled(self):
        output = _helm_template("vaultPkiTls.enabled=true", "vault.url=http://vault:8200")
        assert "vault-tls-init" in output
        assert "vault write -format=json" in output

    def test_ca_chain_fetch_enabled(self):
        output = _helm_template(
            "vaultPkiTls.enabled=true",
            "vaultPkiTls.fetchCaChain=true",
            "vault.url=http://vault:8200",
        )
        assert "Fetching intermediate CA" in output
        assert "Fetching root CA" in output

    def test_ca_chain_fetch_disabled(self):
        output = _helm_template(
            "vaultPkiTls.enabled=true",
            "vaultPkiTls.fetchCaChain=false",
            "vault.url=http://vault:8200",
        )
        assert "fetchCaChain=false" in output
        assert "Fetching intermediate CA" not in output

    def test_approle_auth_sets_env(self):
        output = _helm_template(
            "vaultPkiTls.enabled=true",
            "vault.url=http://vault:8200",
            "vault.authMethod=approle",
            "vault.approle.existingSecret=vault-creds",
        )
        assert "VAULT_ROLE_ID" in output
        assert "VAULT_SECRET_ID" in output
        assert "AppRole" in output

    def test_kubernetes_auth(self):
        output = _helm_template(
            "vaultPkiTls.enabled=true",
            "vault.url=http://vault:8200",
            "vault.authMethod=kubernetes",
        )
        assert "Kubernetes ServiceAccount" in output


class TestCertRenewalTemplate:
    def test_cronjob_not_rendered_when_disabled(self):
        output = _helm_template("certRenewal.enabled=false")
        assert "CronJob" not in output

    def test_cronjob_rendered_when_enabled(self):
        output = _helm_template("certRenewal.enabled=true")
        assert "kind: CronJob" in output
        assert "certmesh-renewal" in output
        assert "certmesh" in output
        assert "renewal" in output
        assert "check" in output

    def test_cronjob_custom_schedule(self):
        output = _helm_template(
            "certRenewal.enabled=true",
            "certRenewal.schedule=0 */6 * * *",
        )
        assert "0 */6 * * *" in output

    def test_cronjob_custom_provider(self):
        output = _helm_template(
            "certRenewal.enabled=true",
            "certRenewal.provider=vault-pki",
        )
        assert "vault-pki" in output

    def test_cronjob_custom_unit(self):
        output = _helm_template(
            "certRenewal.enabled=true",
            "certRenewal.unit=hour",
            "certRenewal.beforeExpiry=12",
        )
        assert "hour" in output


class TestIngressTemplate:
    def test_ingress_disabled_by_default(self):
        output = _helm_template()
        assert "kind: Ingress" not in output

    def test_ingress_with_nginx_class(self):
        output = _helm_template("ingress.enabled=true", "ingress.className=nginx")
        assert "ingressClassName: nginx" in output

    def test_ingress_with_traefik_class(self):
        output = _helm_template("ingress.enabled=true", "ingress.className=traefik")
        assert "ingressClassName: traefik" in output

    def test_ingress_with_tls(self):
        output = _helm_template(
            "ingress.enabled=true",
            "ingress.tls[0].secretName=certmesh-tls",
            "ingress.tls[0].hosts[0]=certmesh.example.com",
        )
        assert "certmesh-tls" in output
