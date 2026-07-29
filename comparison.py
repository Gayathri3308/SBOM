"""
SBOM Comparison Tool
--------------------

This program compares Syft and Trivy SPDX SBOM files generated
for the same GitHub project.

Input:
    1. Syft SPDX file
    2. Trivy SPDX file

Example:

python compare_sboms.py ^
"SBOM_output\\Aeraki Mesh\\syft.spdx" ^
"SBOM_output\\Aeraki Mesh\\trivy.spdx"

Author: Gayathri
"""

########################################################################
# Imports
########################################################################

import argparse
import json
import os
import sys
from pathlib import Path
from datetime import datetime


########################################################################
# Helper Functions
########################################################################

def load_spdx_file(file_path):
    """
    Load an SPDX JSON file.

    Parameters
    ----------
    file_path : Path
        Path to an SPDX file.

    Returns
    -------
    dict
        Parsed SPDX document.

    Raises
    ------
    FileNotFoundError
        If the file does not exist.

    json.JSONDecodeError
        If the file is not valid JSON.
    """

    with open(file_path, "r", encoding="utf-8") as file:
        return json.load(file)

########################################################################
# SPDX Information Extraction
########################################################################

def extract_sbom_information(spdx_data):
    """
    Extract important information from an SPDX document.

    Parameters
    ----------
    spdx_data : dict
        Parsed SPDX JSON document.

    Returns
    -------
    dict
        Dictionary containing extracted package information.
    """

    # Store extracted information
    sbom_info = {
        "packages": [],
        "package_names": set(),
        "versions": set(),
        "licenses": set(),
        "purls": set(),
        "cpes": set(),
        "suppliers": set(),
        "external_refs": [],
        "ecosystems": set()
    }

    ####################################################################
    # Iterate through every package in the SPDX document
    ####################################################################

    for package in spdx_data.get("packages", []):

        sbom_info["packages"].append(package)

        ###############################################################
        # Package Name
        ###############################################################

        package_name = package.get("name")

        if package_name:
            sbom_info["package_names"].add(package_name)

        ###############################################################
        # Version
        ###############################################################

        version = package.get("versionInfo")

        if version:
            sbom_info["versions"].add(
                f"{package_name}=={version}"
            )

        ###############################################################
        # License
        ###############################################################

        # First check the concluded license. If it is missing or
        # marked as NOASSERTION, check the declared license instead.
        license_name = package.get("licenseConcluded")

        if (
            not license_name
            or license_name == "NOASSERTION"
        ):
            license_name = package.get("licenseDeclared")

        # Add the license only when an actual license value is available.
        if (
            license_name
            and license_name != "NOASSERTION"
        ):
            sbom_info["licenses"].add(license_name)

        ###############################################################
        # Supplier
        ###############################################################

        supplier = package.get("supplier")

        if supplier:
            sbom_info["suppliers"].add(supplier)

        ###############################################################
        # External References
        ###############################################################

        for ref in package.get("externalRefs", []):

            sbom_info["external_refs"].append(ref)

            ref_type = ref.get("referenceType")
            ref_locator = ref.get("referenceLocator")

            ###########################################################
            # Package URL (PURL)
            ###########################################################

            if (
                ref_type
                and "purl" in ref_type.lower()
                and ref_locator
            ):
                # Convert the PURL to lowercase before storing it so that
                # capitalization differences do not create false differences.
                normalized_purl = ref_locator.lower()

                sbom_info["purls"].add(normalized_purl)

                #######################################################
                # Determine package ecosystem
                #######################################################

                if ref_locator.startswith("pkg:"):

                    ecosystem = (
                        ref_locator
                        .split("/")[0]
                        .replace("pkg:", "")
                    )

                    sbom_info["ecosystems"].add(ecosystem)

            ###########################################################
            # CPE
            ###########################################################

            if (
                ref_type
                and "cpe" in ref_type.lower()
                and ref_locator
            ):
                sbom_info["cpes"].add(ref_locator)

    return sbom_info

########################################################################
# SBOM Comparison Functions
########################################################################

def compare_sets(title, syft_set, trivy_set):
    """
    Compare two sets of information.

    Parameters
    ----------
    title : str
        Name of the metric being compared.

    syft_set : set
        Values extracted from Syft.

    trivy_set : set
        Values extracted from Trivy.

    Returns
    -------
    dict
        Comparison results.
    """

    only_syft = syft_set - trivy_set
    only_trivy = trivy_set - syft_set
    shared = syft_set & trivy_set

    return {
        "title": title,
        "only_syft": sorted(only_syft),
        "only_trivy": sorted(only_trivy),
        "shared": sorted(shared)
    }


########################################################################
# Print Comparison Results
########################################################################

def print_comparison(comparison):
    """
    Print a formatted comparison report.
    """

    print("\n")
    print("=" * 70)
    print(comparison["title"])
    print("=" * 70)

    print(f"Shared: {len(comparison['shared'])}")

    print(f"Only in Syft: {len(comparison['only_syft'])}")

    if comparison["only_syft"]:

        for item in comparison["only_syft"]:
            print(f"   + {item}")

    print()

    print(f"Only in Trivy: {len(comparison['only_trivy'])}")

    if comparison["only_trivy"]:

        for item in comparison["only_trivy"]:
            print(f"   + {item}")

########################################################################
# Report Generation
########################################################################

def generate_report(
    project_name,
    syft_info,
    trivy_info,
    comparisons
):
    """
    Generate a text report summarizing the comparison.

    Parameters
    ----------
    project_name : str
        Name of the project.

    syft_info : dict
        Information extracted from Syft.

    trivy_info : dict
        Information extracted from Trivy.

    comparisons : list
        List of comparison dictionaries.
    """

    ###############################################################
    # Create output directory if it doesn't exist
    ###############################################################

    output_directory = Path("Comparison_Reports")

    output_directory.mkdir(exist_ok=True)

    ###############################################################
    # Create report filename
    ###############################################################

    report_file = (
        output_directory /
        f"{project_name}_comparison_report.txt"
    )

    ###############################################################
    # Write report
    ###############################################################

    with open(report_file, "w", encoding="utf-8") as report:

        report.write("=" * 75 + "\n")
        report.write("SBOM COMPARISON REPORT\n")
        report.write("=" * 75 + "\n\n")

        report.write(f"Project: {project_name}\n")
        report.write(
            f"Generated: {datetime.now()}\n\n"
        )

        ###########################################################
        # Summary
        ###########################################################

        report.write("-" * 75 + "\n")
        report.write("SUMMARY\n")
        report.write("-" * 75 + "\n\n")

        report.write(
            f"Syft Packages : {len(syft_info['packages'])}\n"
        )

        report.write(
            f"Trivy Packages: {len(trivy_info['packages'])}\n\n"
        )

        report.write(
            f"Syft Licenses : {len(syft_info['licenses'])}\n"
        )

        report.write(
            f"Trivy Licenses: {len(trivy_info['licenses'])}\n\n"
        )

        report.write(
            f"Syft PURLs : {len(syft_info['purls'])}\n"
        )

        report.write(
            f"Trivy PURLs: {len(trivy_info['purls'])}\n\n"
        )

        report.write(
            f"Syft CPEs : {len(syft_info['cpes'])}\n"
        )

        report.write(
            f"Trivy CPEs: {len(trivy_info['cpes'])}\n\n"
        )

        report.write(
            f"Syft Suppliers : {len(syft_info['suppliers'])}\n"
        )

        report.write(
            f"Trivy Suppliers: {len(trivy_info['suppliers'])}\n\n"
        )

        report.write(
            f"Syft Ecosystems : {len(syft_info['ecosystems'])}\n"
        )

        report.write(
            f"Trivy Ecosystems: {len(trivy_info['ecosystems'])}\n\n"
        )

        ###########################################################
        # Detailed Comparisons
        ###########################################################

        for comparison in comparisons:

            report.write("\n")
            report.write("=" * 75 + "\n")
            report.write(comparison["title"] + "\n")
            report.write("=" * 75 + "\n\n")

            report.write(
                f"Shared: {len(comparison['shared'])}\n\n"
            )

            report.write(
                f"Only in Syft ({len(comparison['only_syft'])})\n"
            )

            report.write("-" * 40 + "\n")

            for item in comparison["only_syft"]:
                report.write(f"{item}\n")

            report.write("\n")

            report.write(
                f"Only in Trivy ({len(comparison['only_trivy'])})\n"
            )

            report.write("-" * 40 + "\n")

            for item in comparison["only_trivy"]:
                report.write(f"{item}\n")

            report.write("\n")

    print(f"\nComparison report saved to:\n{report_file}")

########################################################################
# Main
########################################################################

def main():
    """
    Main entry point for the comparison program.
    """

    ####################################################################
    # Parse command-line arguments
    ####################################################################

    parser = argparse.ArgumentParser(
        description="Compare Syft and Trivy SPDX SBOM files."
    )

    parser.add_argument(
        "syft_file",
        type=Path,
        help="Path to the Syft SPDX file."
    )

    parser.add_argument(
        "trivy_file",
        type=Path,
        help="Path to the Trivy SPDX file."
    )

    args = parser.parse_args()

    ####################################################################
    # Verify both files exist
    ####################################################################

    if not args.syft_file.exists():
        print(f"ERROR: Syft file not found:\n{args.syft_file}")
        sys.exit(1)

    if not args.trivy_file.exists():
        print(f"ERROR: Trivy file not found:\n{args.trivy_file}")
        sys.exit(1)

    ####################################################################
    # Determine the project name automatically
    #
    # Example:
    #
    # SBOM_output/
    #   Aeraki Mesh/
    #       syft.spdx
    #
    # -> Project Name = Aeraki Mesh
    ####################################################################

    project_name = args.syft_file.parent.name

    ####################################################################
    # Load both SPDX files
    ####################################################################

    print("=" * 70)
    print(f"Project : {project_name}")
    print("=" * 70)

    print("Loading Syft SPDX...")
    syft_data = load_spdx_file(args.syft_file)

    print("Loading Trivy SPDX...")
    trivy_data = load_spdx_file(args.trivy_file)

    print("SPDX files loaded successfully.")

    ####################################################################
    # Extract useful information
    ####################################################################

    print("\nExtracting Syft information...")
    syft_info = extract_sbom_information(syft_data)

    print("Extracting Trivy information...")
    trivy_info = extract_sbom_information(trivy_data)

    ####################################################################
    # Display Summary
    ####################################################################

    print("\nBasic Summary")
    print("-" * 70)

    print(f"Syft Packages : {len(syft_info['packages'])}")
    print(f"Trivy Packages: {len(trivy_info['packages'])}")

    print()

    print(f"Syft Licenses : {len(syft_info['licenses'])}")
    print(f"Trivy Licenses: {len(trivy_info['licenses'])}")

    print()

    print(f"Syft PURLs : {len(syft_info['purls'])}")
    print(f"Trivy PURLs: {len(trivy_info['purls'])}")

    print()

    print(f"Syft CPEs : {len(syft_info['cpes'])}")
    print(f"Trivy CPEs: {len(trivy_info['cpes'])}")

    print()

    print(f"Syft Suppliers : {len(syft_info['suppliers'])}")
    print(f"Trivy Suppliers: {len(trivy_info['suppliers'])}")

    print()

    print(f"Syft Ecosystems : {len(syft_info['ecosystems'])}")
    print(f"Trivy Ecosystems: {len(trivy_info['ecosystems'])}")

    ####################################################################
    # Compare Metrics
    ####################################################################

    package_comparison = compare_sets(
        "Package Names",
        syft_info["package_names"],
        trivy_info["package_names"]
    )

    version_comparison = compare_sets(
        "Package Versions",
        syft_info["versions"],
        trivy_info["versions"]
    )

    license_comparison = compare_sets(
        "Licenses",
        syft_info["licenses"],
        trivy_info["licenses"]
    )

    ecosystem_comparison = compare_sets(
        "Package Ecosystems",
        syft_info["ecosystems"],
        trivy_info["ecosystems"]
    )

    supplier_comparison = compare_sets(
        "Suppliers",
        syft_info["suppliers"],
        trivy_info["suppliers"]
    )

    purl_comparison = compare_sets(
        "Package URLs (PURLs)",
        syft_info["purls"],
        trivy_info["purls"]
    )

    cpe_comparison = compare_sets(
        "Common Platform Enumerations (CPEs)",
        syft_info["cpes"],
        trivy_info["cpes"]
    )

    ####################################################################
    # Print Results
    ####################################################################

    print_comparison(package_comparison)

    print_comparison(version_comparison)

    print_comparison(license_comparison)

    print_comparison(ecosystem_comparison)

    print_comparison(supplier_comparison)

    print_comparison(purl_comparison)

    print_comparison(cpe_comparison)

    ####################################################################
    # Save Report
    ####################################################################

    generate_report(
        project_name,
        syft_info,
        trivy_info,
        [
            package_comparison,
            version_comparison,
            license_comparison,
            ecosystem_comparison,
            supplier_comparison,
            purl_comparison,
            cpe_comparison
        ]
    )


########################################################################
# Run Program
########################################################################

if __name__ == "__main__":
    main()