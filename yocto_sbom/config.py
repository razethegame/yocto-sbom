"""Configuration management for yocto-sbom."""

import configparser
import os


class SbomConfig(object):
    """Holds all configuration for SBOM generation.

    Values can come from an INI config file, CLI arguments, or defaults.
    CLI arguments take precedence over config file values.
    """

    def __init__(self):
        # Project
        self.product_name = "firmware"
        self.version = ""

        # Vendor
        self.vendor_name = ""
        self.vendor_id = ""
        self.supplier = "NOASSERTION"
        self.namespace_uri = "https://example.com/spdx"

        # Paths
        self.recipes_dir = ""
        self.gitmodules = ""
        self.bblayers = ""
        self.yocto_dirs = []

        # Build
        self.build_config = "default"

        # Output
        self.output_spdx = "sbom-spdx.json"
        self.output_cdx = "sbom-cdx.json"
        self.output_format = "both"  # spdx, cdx, or both
        self.validate = False
        self.quiet = False

    @classmethod
    def from_ini(cls, ini_path):
        """Load configuration from an INI file.

        Args:
            ini_path: Path to the INI config file.

        Returns:
            SbomConfig instance with values from the file.
        """
        config = cls()

        if not os.path.isfile(ini_path):
            raise FileNotFoundError("Config file not found: {}".format(ini_path))

        parser = configparser.ConfigParser()
        parser.read(ini_path)

        # [project]
        if parser.has_section("project"):
            config.product_name = parser.get("project", "product_name", fallback=config.product_name)
            config.version = parser.get("project", "version", fallback=config.version)

        # [vendor]
        if parser.has_section("vendor"):
            config.vendor_name = parser.get("vendor", "name", fallback=config.vendor_name)
            config.vendor_id = parser.get("vendor", "id", fallback=config.vendor_id)
            config.supplier = parser.get("vendor", "supplier", fallback=config.supplier)
            config.namespace_uri = parser.get("vendor", "namespace_uri", fallback=config.namespace_uri)

        # [paths]
        if parser.has_section("paths"):
            config.recipes_dir = parser.get("paths", "recipes_dir", fallback=config.recipes_dir)
            config.gitmodules = parser.get("paths", "gitmodules", fallback=config.gitmodules)
            config.bblayers = parser.get("paths", "bblayers", fallback=config.bblayers)
            yocto_dir_val = parser.get("paths", "yocto_dir", fallback="")
            if yocto_dir_val:
                config.yocto_dirs = [yocto_dir_val]

        # [output]
        if parser.has_section("output"):
            config.output_spdx = parser.get("output", "spdx", fallback=config.output_spdx)
            config.output_cdx = parser.get("output", "cdx", fallback=config.output_cdx)

        return config

    def apply_cli_args(self, args):
        """Override config values with CLI arguments (non-None values only).

        Args:
            args: argparse.Namespace from CLI parsing.
        """
        if getattr(args, "recipes_dir", None):
            self.recipes_dir = args.recipes_dir
        if getattr(args, "version", None):
            self.version = args.version
        if getattr(args, "product_name", None):
            self.product_name = args.product_name
        if getattr(args, "vendor_id", None):
            self.vendor_id = args.vendor_id
        if getattr(args, "vendor_name", None):
            self.vendor_name = args.vendor_name
        if getattr(args, "namespace_uri", None):
            self.namespace_uri = args.namespace_uri
        if getattr(args, "gitmodules", None):
            self.gitmodules = args.gitmodules
        if getattr(args, "bblayers", None):
            self.bblayers = args.bblayers
        if getattr(args, "yocto_dir", None):
            val = args.yocto_dir
            if isinstance(val, list):
                self.yocto_dirs = val
            else:
                self.yocto_dirs = [val]
        if getattr(args, "build_config", None):
            self.build_config = args.build_config
        if getattr(args, "output_spdx", None):
            self.output_spdx = args.output_spdx
        if getattr(args, "output_cdx", None):
            self.output_cdx = args.output_cdx
        if getattr(args, "format", None):
            self.output_format = args.format
        if getattr(args, "validate", None):
            self.validate = args.validate
        if getattr(args, "quiet", None):
            self.quiet = args.quiet

        # Derive supplier from vendor_name if not explicitly set
        if self.vendor_name and self.supplier == "NOASSERTION":
            self.supplier = "Organization: {}".format(self.vendor_name)

    def validate_required(self):
        """Check that required fields are set.

        Returns:
            List of error messages (empty if valid).
        """
        errors = []
        if not self.recipes_dir:
            errors.append("--recipes-dir is required")
        if not self.version:
            errors.append("--version is required")
        return errors
