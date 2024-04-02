import argparse
import json
import os
import re
import subprocess
from docxtpl import DocxTemplate, RichText

DOC_TEMPLATE_FILENAME = "template.docx"
REPORT_DIRECTORY_FILENAME = "Audit Reports"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('json_file', type=str, help='CIS Docker Benchmark JSON File')
    args = parser.parse_args()
    benchmark_filename = args.json_file

    print(f"{'='*50}\nLOADING BENCHMARK...\n{'='*50}")
    benchmark_dictionary = load_json(benchmark_filename)

    print(f"{'='*50}\nCHECKING FOR RUNNING CONTAINER INSTANCES...\n{'='*50}")
    basic_information_dictionary = get_basic_information()

    print(f"{'='*50}\nARGUMENTS\n{'='*50}")
    arguments_dictionary = arguments_input()

    print(f"{'='*50}\nRUNNING AUDIT COMMANDS...\n{'='*50}")
    iterate_and_run_commands(benchmark_dictionary, arguments_dictionary)
    print("\nAudit completed.\n")

    print(f"{'='*50}\nGENERATING REPORT...\n{'='*50}")
    for title, value in benchmark_dictionary.items():
        if re.search(r"^7[ .]", title) and arguments_dictionary["docker_swarm"] == "n":
            continue
        basic_information_dictionary["title"] = title
        report_content = []
        template = DocxTemplate(DOC_TEMPLATE_FILENAME)
        get_report_content(value, report_content, template)
        write_report(title, [basic_information_dictionary], report_content, template)
    print("\nReport generation completed.\n")


def load_json(filename):
    try:
        with open(filename, "r") as file:
            dictionary = json.load(file)
        print(f"{filename} loaded.\n")
        return dictionary
    except FileNotFoundError:
        print(f"{filename} not found.")
        exit()


def get_basic_information():
    dictionary = {}
    dictionary["containers"] = subprocess.Popen("docker ps --quiet", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True).communicate()[0].decode().strip("\n")
    dictionary["ip_addresses"] = subprocess.Popen(" && ".join(["docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' " + x for x in dictionary["containers"].split("\n")]), stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True).communicate()[0].decode().strip("\n")
    print("HOSTNAME\tIP ADDRESS")
    for i in range(len(dictionary["containers"].split("\n"))):
        print(dictionary["containers"].split("\n")[i] + "\t" + dictionary["ip_addresses"].split("\n")[i])
    print()
    return dictionary


def arguments_input():
    dictionary = {}
    dictionary["docker_swarm"] = input("Docker Swarm? (Y/N): ").lower()
    if dictionary["docker_swarm"] not in ("y", "n"):
        print("Invalid input.")
        exit()
    dictionary["tls_ca_certificate"] = input("File path to TLS CA Certificate: ")
    dictionary["docker_server_certificate"] = input("File path to Docker Server Certificate: ")
    dictionary["docker_server_certificate_key"] = input("File path to Docker Server Certificate Key: ")
    print()
    return dictionary


def iterate_and_run_commands(benchmark_dictionary, arguments_dictionary, title="", indent=0):
    for key, value in benchmark_dictionary.copy().items():
        if isinstance(value, dict):
            if not re.search(r"^7[ .]", key) or (re.search(r"^7[ .]", key) and arguments_dictionary["docker_swarm"] == "y"):
                print(key)
                iterate_and_run_commands(value, arguments_dictionary, key, indent + 1)
        else:
            if key == "audit_commands":
                run_commands(benchmark_dictionary, arguments_dictionary, title, value)


def run_commands(benchmark_dictionary, arguments_dictionary, title, commands):
    title_no = [x.group().strip() for x in [re.search(r"^\d+" + r"\.\d+" * j + " ", title) for j in range(3)] if x is not None][0]

    audit_commands = []
    audit_output = []
    audit_errors = []

    # Add command to get docker image id
    if title_no in ["4.6", "4.8"]:
        commands.insert(0, "docker ps --quiet")

    for i in range(len(commands)):
        # Output into input
        if title_no == "1.1.9":
            if i == 1:
                commands[i] = commands[i][:commands[i].index("<")] + audit_output[i-1][audit_output[i-1].index("=")+1:].strip("\n")
        elif title_no in ["4.2", "4.7", "4.9", "4.10", "4.11"]:
            if i == 1:
                commands[i] = " && ".join([commands[i][:commands[i].index("<")] + ":".join(x.split()[:2]) + commands[i][commands[i].index(">")+1:] for x in audit_output[i-1].strip("\n").split("\n")[1:]])
        elif title_no == "4.3":
            if i == 1:
                proc = subprocess.Popen("rpm", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
                proc.communicate()
                if proc.returncode == 127:
                    commands[i] = commands[i][:commands[i].index("rpm")] + "dpkg -l"
                commands[i] = " && ".join([commands[i][:commands[i].index("$")] + x + commands[i][commands[i].index("D")+1:] for x in audit_output[i-1].strip("\n").split("\n")])
        elif title_no in ["4.6", "4.8", "5.7"]:
            if i == 1:
                commands[i] = " && ".join([commands[i][:commands[i].index("<")] + x + commands[i][commands[i].index(">")+1:] for x in audit_output[i-1].strip("\n").split("\n")])

        # Certificate files
        if title_no in ["3.9", "3.10"]:
            commands[i] = commands[i][:commands[i].index("<")] + arguments_dictionary["tls_ca_certificate"] + commands[i][commands[i].index(">")+1:]
        elif title_no in ["3.11", "3.12"]:
            commands[i] = commands[i][:commands[i].index("<")] + arguments_dictionary["docker_server_certificate"] + commands[i][commands[i].index(">")+1:]
        elif title_no in ["3.13", "3.14"]:
            commands[i] = commands[i][:commands[i].index("<")] + arguments_dictionary["docker_server_certificate_key"] + commands[i][commands[i].index(">")+1:]

        # Do not run second command if file does not exist
        if title_no in ["1.1.7", "1.1.8", "1.1.9", "3.1", "3.2", "3.3", "3.4"]:
            if i == len(commands)-1 and len(audit_output[len(commands)-2]) == 0:
                break

        # Run command
        print("\t" + commands[i])
        audit_commands.append(commands[i])
        proc = subprocess.Popen(commands[i], stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        o, e = proc.communicate()
        audit_output.append(o.decode())
        audit_errors.append(e.decode())

    # Add to dictionary
    benchmark_dictionary["audit_commands"] = audit_commands
    benchmark_dictionary["audit_output"] = audit_output
    benchmark_dictionary["audit_errors"] = audit_errors


def get_report_content(dictionary, report_content, template):
    for key, value in dictionary.items():
        if isinstance(value, dict):
            if "Description" in value:
                section = {
                    'Title': key,
                    'Description': value.get("Description", ""),
                    'Rationale': value.get("Rationale", ""),
                    'Audit': value.get("Audit", ""),
                    'Remediation': value.get("Remediation", "")
                }

                # References
                references_rt = RichText()
                for i in range(len(value.get("References", []))):
                    references_rt.add(value.get("References", [])[i] + "\n", size=24, underline=True, color="#0563C1", url_id=template.build_url_id(value.get("References", [])[i]))
                section['References'] = references_rt

                # Audit commands, output and errors
                audit_rt = RichText()
                for i in range(len(value.get("audit_commands", []))):
                    audit_rt.add("Audit Command:\n", size=24, bold=True)
                    audit_rt.add(value.get("audit_commands", [])[i] + "\n", size=24)
                    audit_rt.add("Audit Output:\n", size=24, bold=True)
                    if len(value.get("audit_errors", [])[i]) == 0:
                        audit_rt.add(value.get("audit_output", [])[i] + "\n\n", size=24, italic=True)
                    else:
                        audit_rt.add(value.get("audit_errors", [])[i] + "\n\n", size=24, italic=True, color="#FF0000")
                section['audit_commands_output_errors'] = audit_rt

                report_content.append(section)

            get_report_content(value, report_content, template)


def write_report(title, basic_information, report_content, template):
    context = {"basic_information": basic_information, "report_content": report_content}
    template.render(context, autoescape=True)
    if not os.path.exists(REPORT_DIRECTORY_FILENAME):
        os.makedirs(REPORT_DIRECTORY_FILENAME)
        print(f"Created directory: {REPORT_DIRECTORY_FILENAME}")
    template.save(f"{REPORT_DIRECTORY_FILENAME}/{title}.docx")
    print(f"Generated report: {REPORT_DIRECTORY_FILENAME}/{title}.docx")


if __name__ == "__main__":
    main()
