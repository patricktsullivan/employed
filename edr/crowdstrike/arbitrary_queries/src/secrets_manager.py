import subprocess
import shutil

class SecretsManager:
    @staticmethod
    def op_read(reference: str) -> str:
        """
        Read a secret from 1Password using op:// URI.
        Example reference: op://<vault-name>/<item-name>/<field-name>
        """
        # Check if 'op' is installed
        if not shutil.which("op"):
            raise RuntimeError("1Password CLI (op) not found in PATH.")

        try:
            # Added --no-newline to prevent trailing whitespace issues
            result = subprocess.run(
                ["op", "read", reference, "--no-newline"],
                capture_output=True,
                text=True,
                check=True,
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            error_msg = e.stderr.strip() if e.stderr else "Unknown error"
            raise RuntimeError(f"1Password error reading {reference}: {error_msg}") from e