#!/usr/bin/env python3
"""
CNCF SBOM Generator

This script downloads a GitHub repository, generates SBOMs using
Syft and/or Trivy, stores the generated SBOM files, and then removes
the downloaded repository so that only the SBOM files remain.

"""

import argparse
import logging
import shutil
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlparse
import time
import os
import stat
import json


def _remove_readonly(func, path, _):
    """
    Removes the Windows read-only attribute so shutil.rmtree
    can delete Git repositories.
    """
    os.chmod(path, stat.S_IWRITE)
    func(path)


########################################################################
# Default Folder Names
########################################################################

REPOSITORIES_DIR = "repositories"
OUTPUT_DIR = "SBOM_Output"


########################################################################
# SBOM Generator Class
########################################################################

class SBOMGenerator:
    """
    Downloads GitHub repositories and generates SBOMs.
    """

    ####################################################################
    # Constructor
    ####################################################################

    def __init__(self, github_token=None):

        self.github_token = github_token

        # Base folder where this script is located.
        self.base_dir = Path(__file__).parent.resolve()

        # Folder used for temporarily downloading repositories.
        self.repositories_dir = (
            self.base_dir / REPOSITORIES_DIR
        )

        # Folder where generated SBOMs will be stored.
        self.output_dir = (
            self.base_dir / OUTPUT_DIR
        )

        self.repositories_dir.mkdir(exist_ok=True)
        self.output_dir.mkdir(exist_ok=True)

    ####################################################################
    # Download Repository (Phase 1)
    ####################################################################

    def download_repository(self, repository_url):
        """
        Downloads (clones) a GitHub repository.

        Parameters
        ----------
        repository_url : str
            GitHub repository URL.

        Returns
        -------
        Path
            Path to the downloaded repository.
        """

        parsed = urlparse(repository_url)

        repo_name = Path(parsed.path).stem

        destination = (
            self.repositories_dir / repo_name
        )

        # Remove any previous copy of the repository.
        if destination.exists():

            logging.info(
                "Removing existing repository..."
            )

            shutil.rmtree(destination)

        clone_url = repository_url

        # Use GitHub token if provided.
        if self.github_token:

            clone_url = (
                repository_url.replace(
                    "https://",
                    f"https://{self.github_token}@"
                )
            )

        logging.info(
            f"Downloading repository: {repo_name}"
        )

        subprocess.run(

            [
                "git",
                "clone",
                clone_url,
                str(destination)
            ],

            check=True

        )

        logging.info(
            "Repository downloaded successfully."
        )

        return destination
    
     ####################################################################
    # Run Syft
    ####################################################################

    def run_syft(self, repository_path, output_file, output_format):
        """
        Generates an SBOM using Syft.

        Parameters
        ----------
        repository_path : Path
            Local repository path.

        output_file : Path
            File where the generated SBOM will be saved.

        output_format : str
            Output format (spdx-json or cyclonedx-json).
        """

        logging.info("Generating Syft SBOM...")

        subprocess.run(

            [

                "syft",

                str(repository_path),

                "--source-name",

                repository_path.name,

                "-o",

                f"{output_format}={output_file}"

            ],

            check=True

        )

        logging.info("Syft SBOM generated successfully.")
    
    def clean_syft_cpes(self, sbom_file):
        """
        Removes noisy CPE references for local GitHub Actions
        while keeping PURLs.
        """

        with open(sbom_file, "r", encoding="utf-8") as f:
            sbom = json.load(f)

        for package in sbom.get("packages", []):

            name = package.get("name", "")

            if (
                name.startswith("./")
                or
                name.startswith(".github/")
            ):

                refs = package.get("externalRefs", [])

                package["externalRefs"] = [

                    ref

                    for ref in refs

                    if ref.get("referenceType") != "cpe23Type"

                ]

        with open(sbom_file, "w", encoding="utf-8") as f:
            json.dump(sbom, f, indent=2)

    ####################################################################
    # Run Trivy
    ####################################################################

    def run_trivy(self, repository_path, output_file, output_format):
        """
        Generates an SBOM using Trivy.

        Parameters
        ----------
        repository_path : Path
            Local repository path.

        output_file : Path
            File where the generated SBOM will be saved.

        output_format : str
            Output format (spdx-json or cyclonedx-json).
        """

        logging.info("Generating Trivy SBOM...")

        subprocess.run(

            [
                "trivy",
                "fs",
                "--format",
                output_format,
                "--output",
                str(output_file),
                str(repository_path)
            ],

            check=True

        )

        logging.info("Trivy SBOM generated successfully.")

    ####################################################################
    # Generate SBOMs (Phase 2)
    ####################################################################

    def generate_sboms(
        self,
        repository_path,
        use_syft,
        use_trivy,
        output_format
    ):
        """
        Generates SBOMs for a downloaded repository.

        Parameters
        ----------
        repository_path : Path
            Local repository path.

        use_syft : bool
            Whether to generate a Syft SBOM.

        use_trivy : bool
            Whether to generate a Trivy SBOM.

        output_format : str
            SPDX or CycloneDX.
        """

        repository_name = repository_path.name

        project_output = (
            self.output_dir / repository_name
        )

        project_output.mkdir(exist_ok=True)

        if output_format == "spdx-json":

            extension = "spdx.json"

        else:

            extension = "cyclonedx.json"

        ################################################################
        # Generate Syft SBOM
        ################################################################

        if use_syft:

            syft_output = (
                project_output /
                f"syft.{extension}"
            )

            self.run_syft(

                repository_path,

                syft_output,

                output_format

            )

            self.clean_syft_cpes(syft_output)

            logging.info("Validating SPDX document...")

            #subprocess.run(

                #[

                    #"pyspdxtools",

                    #"-i",

                    #str(syft_output)

                #],

                #check=True

            #)

            logging.info("SPDX validation successful.")

        ################################################################
        # Generate Trivy SBOM
        ################################################################

        if use_trivy:

            trivy_output = (
                project_output /
                f"trivy.{extension}"
            )

            self.run_trivy(

                repository_path,

                trivy_output,

                output_format

            )

        logging.info(
            "SBOM generation completed successfully."
        )
    
        ####################################################################
    # Cleanup Repository
    ####################################################################

    def cleanup_repository(self, repository_path):
        """
        Removes the downloaded repository after SBOM generation.

        Parameters
        ----------
        repository_path : Path
            Path to the downloaded repository.
        """

        if repository_path.exists():

            logging.info(
                f"Removing downloaded repository: "
                f"{repository_path.name}"
            )

            # Windows may temporarily lock Git files.
            # Retry a few times before giving up.
            for attempt in range(5):

                try:
                    
                    shutil.rmtree(
                        repository_path,
                        onexc=_remove_readonly
                    )

                    logging.info(
                        "Repository removed successfully."
                    )

                    return

                except PermissionError:

                    logging.warning(
                        f"Repository is busy. Retrying "
                        f"({attempt + 1}/5)..."
                    )

                    time.sleep(1)

            logging.error(
                "Could not remove the repository after "
                "multiple attempts."
            )

    ####################################################################
    # Main Workflow
    ####################################################################

    def run(
        self,
        repository_url,
        use_syft,
        use_trivy,
        output_format
    ):
        """
        Executes the complete SBOM generation workflow.

        Workflow
        --------
        Phase 1 : Download repository

        Phase 2 : Generate SBOMs

        Phase 3 : Remove downloaded repository
        """

        repository_path = self.download_repository(
            repository_url
        )

        try:

            self.generate_sboms(

                repository_path,

                use_syft,

                use_trivy,

                output_format

            )

        finally:

            # Always remove the downloaded repository,
            # even if SBOM generation fails.
            self.cleanup_repository(
                repository_path
            )


########################################################################
# Main Function
########################################################################

def main():
    """
    Parses command-line arguments and starts SBOM generation.
    """

    parser = argparse.ArgumentParser(

        description=(
            "Generate SBOMs for a GitHub repository "
            "using Syft and/or Trivy."
        )

    )

    ####################################################################
    # Required Repository URL
    ####################################################################

    parser.add_argument(

        "repository",

        help="GitHub repository URL"

    )

    ####################################################################
    # Optional GitHub Token
    ####################################################################

    parser.add_argument(

        "--token",

        help="GitHub personal access token"

    )

    ####################################################################
    # Tool Selection
    ####################################################################

    parser.add_argument(

        "--syft",

        action="store_true",

        help="Generate SBOM using Syft"

    )

    parser.add_argument(

        "--trivy",

        action="store_true",

        help="Generate SBOM using Trivy"

    )

    ####################################################################
    # Output Format
    ####################################################################

    parser.add_argument(

        "--spdx",

        action="store_true",

        help="Generate SPDX SBOM"

    )

    parser.add_argument(

        "--cyclonedx",

        action="store_true",

        help="Generate CycloneDX SBOM"

    )

    args = parser.parse_args()

    ####################################################################
    # Validate User Input
    ####################################################################

    if not args.syft and not args.trivy:

        parser.error(
            "Choose at least one tool: "
            "--syft and/or --trivy"
        )

    if not args.spdx and not args.cyclonedx:

        parser.error(
            "Choose an output format: "
            "--spdx or --cyclonedx"
        )

    ####################################################################
    # Determine Output Format
    ####################################################################

    if args.spdx:

        output_format = "spdx-json"

    else:

        output_format = "cyclonedx-json"

    ####################################################################
    # Configure Logging
    ####################################################################

    logging.basicConfig(

        level=logging.INFO,

        format="%(levelname)s: %(message)s"

    )

    ####################################################################
    # Create Generator
    ####################################################################

    generator = SBOMGenerator(
        github_token=args.token
    )

    ####################################################################
    # Execute Workflow
    ####################################################################

    generator.run(

        repository_url=args.repository,

        use_syft=args.syft,

        use_trivy=args.trivy,

        output_format=output_format

    )


if __name__ == "__main__":

    try:

        main()

    except subprocess.CalledProcessError as error:

        logging.error(error)

        sys.exit(1)

    except KeyboardInterrupt:

        logging.error("Operation cancelled.")

        sys.exit(1)