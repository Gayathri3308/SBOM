"""
PURL Comparison Tool

This script compares PURLs found in a Syft SPDX SBOM
and a Trivy SPDX SBOM.

Part 1:
- Accept two SPDX JSON files from the command line
- Verify that both files exist
- Load both SPDX documents
- Determine the project name automatically
"""

import argparse
import json
import sys
from pathlib import Path


def load_spdx_file(file_path):
    """
    Load an SPDX JSON file and return the parsed data.

    Parameters:
        file_path (Path): Path to the SPDX JSON file.

    Returns:
        dict: Parsed SPDX document.
    """

    try:
        with open(file_path, "r", encoding="utf-8") as file:
            return json.load(file)

    except json.JSONDecodeError:
        print(f"ERROR: Invalid JSON file:\n{file_path}")
        sys.exit(1)

    except OSError as error:
        print(f"ERROR: Could not read file:\n{file_path}")
        print(f"Details: {error}")
        sys.exit(1)

def extract_purls(spdx_data):
    """
    Extract PURLs from an SPDX SBOM.

    PURLs are stored in the externalRefs section of
    each SPDX package.

    Returns:
        set: Unique PURL strings found in the SBOM.
    """

    purls = set()

    # Get the list of packages from the SPDX document.
    packages = spdx_data.get("packages", [])

    for package in packages:

        # Each package can contain external references.
        external_refs = package.get("externalRefs", [])

        for reference in external_refs:

            # Check whether this reference is a PURL.
            reference_type = reference.get("referenceType", "")

            if reference_type.lower() == "purl":

                # Get the exact PURL string.
                purl = reference.get("referenceLocator")

                if purl:
                    purls.add(purl)

    return purls


def compare_purls(syft_purls, trivy_purls):
    """
    Compare the exact PURL strings from Syft and Trivy.

    Returns:
        dict: Shared, Syft-only, and Trivy-only PURLs.
    """

    shared = syft_purls & trivy_purls

    only_syft = syft_purls - trivy_purls

    only_trivy = trivy_purls - syft_purls

    return {
        "shared": sorted(shared),
        "only_syft": sorted(only_syft),
        "only_trivy": sorted(only_trivy),
    }

def save_purl_report(project_name, syft_purls, trivy_purls, comparison):
    """Save the PURL comparison report to a project report folder."""

    report_directory = Path(__file__).resolve().parent / "PURL_Comparison_Reports"
    report_directory.mkdir(exist_ok=True)

    report_file = report_directory / f"{project_name}_purl_comparison.txt"

    with open(report_file, "w", encoding="utf-8") as report:

        report.write(f"PURL COMPARISON REPORT - {project_name}\n")
        report.write("=" * 70 + "\n\n")

        report.write(f"SYFT PURLs ({len(syft_purls)})\n")
        report.write("-" * 70 + "\n")
        for purl in sorted(syft_purls):
            report.write(f"{purl}\n")

        report.write(f"\nTRIVY PURLs ({len(trivy_purls)})\n")
        report.write("-" * 70 + "\n")
        for purl in sorted(trivy_purls):
            report.write(f"{purl}\n")

        report.write(f"\nPURLs FOUND IN BOTH ({len(comparison['shared'])})\n")
        report.write("-" * 70 + "\n")
        for purl in comparison["shared"]:
            report.write(f"{purl}\n")

        report.write(f"\nPURLs FOUND ONLY IN SYFT ({len(comparison['only_syft'])})\n")
        report.write("-" * 70 + "\n")
        for purl in comparison["only_syft"]:
            report.write(f"{purl}\n")

        report.write(f"\nPURLs FOUND ONLY IN TRIVY ({len(comparison['only_trivy'])})\n")
        report.write("-" * 70 + "\n")
        for purl in comparison["only_trivy"]:
            report.write(f"{purl}\n")



def main():
    """
    Main entry point for the PURL comparison program.
    """

    ####################################################################
    # Parse command-line arguments
    ####################################################################

    parser = argparse.ArgumentParser(
        description="Compare PURLs in Syft and Trivy SPDX SBOM files."
    )

    parser.add_argument(
        "syft_file",
        type=Path,
        help="Path to the Syft SPDX JSON file."
    )

    parser.add_argument(
        "trivy_file",
        type=Path,
        help="Path to the Trivy SPDX JSON file."
    )

    args = parser.parse_args()

    ####################################################################
    # Verify that both input files exist
    ####################################################################

    if not args.syft_file.is_file():
        print(f"ERROR: Syft file not found:")
        print(args.syft_file)
        sys.exit(1)

    if not args.trivy_file.is_file():
        print(f"ERROR: Trivy file not found:")
        print(args.trivy_file)
        sys.exit(1)

    ####################################################################
    # Determine the project name automatically
    #
    # Example:
    #
    # SBOM_Output/
    #     aeraki/
    #         syft.spdx.json
    #         trivy.spdx.json
    #
    # Project name = aeraki
    ####################################################################

    project_name = args.syft_file.parent.name

    ####################################################################
    # Load both SPDX files
    ####################################################################

    print("=" * 70)
    print(f"PURL Comparison")
    print(f"Project: {project_name}")
    print("=" * 70)

    print("\nLoading Syft SPDX...")
    syft_data = load_spdx_file(args.syft_file)

    print("Loading Trivy SPDX...")
    trivy_data = load_spdx_file(args.trivy_file)

    print("\nSPDX files loaded successfully.")

    ####################################################################
    # Extract PURLs from both SBOMs
    ####################################################################

    print("\nExtracting PURLs from Syft...")
    syft_purls = extract_purls(syft_data)

    print("Extracting PURLs from Trivy...")
    trivy_purls = extract_purls(trivy_data)

    ####################################################################
    # Compare the exact PURL strings
    ####################################################################

    print("\nComparing PURLs...")

    comparison = compare_purls(
        syft_purls,
        trivy_purls
    )

    ####################################################################
    # Display comparison summary
    ####################################################################

    print("\nPURL Comparison Summary")
    print("-" * 70)

    print(f"Syft PURLs : {len(syft_purls)}")
    print(f"Trivy PURLs: {len(trivy_purls)}")

    print(f"Shared PURLs     : {len(comparison['shared'])}")
    print(f"Syft-only PURLs  : {len(comparison['only_syft'])}")
    print(f"Trivy-only PURLs : {len(comparison['only_trivy'])}")


    save_purl_report(
        project_name,
        syft_purls,
        trivy_purls,
        comparison
    )



if __name__ == "__main__":
    main()