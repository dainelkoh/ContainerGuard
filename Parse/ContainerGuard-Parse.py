import argparse
import json
import re
import pdfplumber
import sys

START_PAGE_NO = 10
END_PAGE_NO = 253
NO_OF_INDENTS = 3
COMPONENTS_LIST = [
        "Profile Applicability",
        "Description",
        "Rationale",
        "Impact",
        "Audit",
        "Remediation",
        "Default Value",
        "References"
    ]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('pdf_file', type=str, help='CIS Docker Benchmark PDF File')
    args = parser.parse_args()
    benchmark_filename = args.pdf_file

    benchmark_dictionary = parse_pdf(benchmark_filename)
    save_json(benchmark_dictionary, ".".join(benchmark_filename.split(".")[:-1]) + ".json")


def parse_pdf(filename):
    # Create sections from pages
    pdf = pdfplumber.open(filename)

    sections_list = []
    titles_list = []
    audit_commands_list = []
    for i in range(START_PAGE_NO, END_PAGE_NO + 1):
        sys.stdout.write(f"\rParsing {i - START_PAGE_NO + 1}/{END_PAGE_NO - START_PAGE_NO + 1} pages into sections...")
        sys.stdout.flush()
        # All texts
        page = pdf.pages[i].filter(lambda obj: obj["object_type"] == "char" and obj["size"] <= 16).extract_text()
        lines = page.split("\n")
        # Titles
        title = pdf.pages[i].filter(lambda obj: obj["object_type"] == "char" and ((obj["fontname"] == "Arial-BoldMT" and obj["size"] in (14, 16)) or (obj["fontname"] == "Arial-ItalicMT" and obj["size"] == 16))).extract_text()
        # Audit commands
        audit_commands = pdf.pages[i].filter(lambda obj: obj["object_type"] == "char" and obj["fontname"] == "BCDGEE+CourierNewPSMT").extract_text()

        # Start of section
        if any([re.search(r"^\d+" + r"\.\d+" * j + " ", lines[0]) for j in range(NO_OF_INDENTS)]):
            sections_list.append("\n".join(page.split("\n")[:-1]))
            titles_list.append(title.replace("\n", " "))
            audit_commands_list.append(audit_commands)
        # Not start of section
        else:
            sections_list[-1] += "\n" + "\n".join(page.split("\n")[:-1])
            audit_commands_list[-1] += "\n" + audit_commands
    print()

    # Populate dictionary with contents from sections
    benchmark_dictionary = {}
    section_titles = [""] * NO_OF_INDENTS
    subsection = {}
    for i in range(len(sections_list)):
        lines = sections_list[i].split("\n")

        # Titles
        for j in range(NO_OF_INDENTS):
            if re.search(r"^\d+" + r"\.\d+" * j + " ", lines[0]):
                subsection = benchmark_dictionary
                for k in range(j):
                    subsection = subsection[section_titles[k]]

                title = ""
                for k in range(len(titles_list)):
                    if lines[0] in titles_list[k]:
                        title = titles_list[k]
                        break

                section_titles[j] = title
                subsection[title] = {}
                print("\t" * j + title)

                subsection = subsection[title]
                break

        # Components
        for j in range(len(COMPONENTS_LIST)):
            value = ""
            previous_audit_command = ""
            audit_commands = []
            m = 1
            for k in range(len(lines)):
                if lines[k][:-1] == COMPONENTS_LIST[j]:
                    while lines[k + m][:-1] not in COMPONENTS_LIST[j:] + ["CIS Controls"]:
                        value += lines[k + m] + " "

                        if COMPONENTS_LIST[j] == "Audit" and lines[k + m] in audit_commands_list[i].split("\n"):
                            not_commands = lines[k + m][:5] == "--tls" or lines[k + m] == "Security Options:" or lines[k + m][:5] == "stat:" or lines[k + m][:5] == "Ports"
                            quotation_marks_syntax = previous_audit_command.count("'") % 2 == 0
                            while_syntax = "while" not in previous_audit_command or re.search(r"while.*;.*", previous_audit_command)
                            docker_network_syntax = "docker network" not in previous_audit_command or not re.search(r"docker network$", previous_audit_command)
                            grep_syntax = "grep" not in previous_audit_command or re.search(r"grep\s[^ -]", previous_audit_command) or re.search(r"grep\s-\S+\s\S+", previous_audit_command)
                            command_line_syntax = lines[k + m][0] != "|"
                            if not_commands:
                                pass
                            elif quotation_marks_syntax and while_syntax and docker_network_syntax and grep_syntax and command_line_syntax:
                                audit_commands.append(lines[k + m])
                            else:
                                audit_commands[-1] += " " + lines[k + m]
                            previous_audit_command = audit_commands[-1]

                        m += 1

            if len(value) != 0:
                if COMPONENTS_LIST[j] == "Profile Applicability":
                    value = [x.strip() for x in value.split("•") if len(x) > 0]
                elif COMPONENTS_LIST[j] == "References":
                    value = [x.replace(" ", "") for x in re.split(r"\d+\. ", value) if len(x) > 0]
                else:
                    value = value.strip()

                subsection[COMPONENTS_LIST[j]] = value
                print("\t" * NO_OF_INDENTS + COMPONENTS_LIST[j])
                print("\t" * (NO_OF_INDENTS + 1) + str(subsection[COMPONENTS_LIST[j]]))
                if COMPONENTS_LIST[j] == "Audit":
                    subsection["audit_commands"] = audit_commands
                    subsection["audit_output"] = [""] * len(audit_commands)
                    subsection["audit_errors"] = [""] * len(audit_commands)
                    for component in ["audit_commands", "audit_output", "audit_errors"]:
                        print("\t" * NO_OF_INDENTS + component)
                        print("\t" * (NO_OF_INDENTS + 1) + str(subsection[component]))

    return benchmark_dictionary


def save_json(dictionary, filename):
    with open(filename, "w") as file:
        json.dump(dictionary, file, indent=4)


if __name__ == "__main__":
    main()
