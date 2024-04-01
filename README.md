# ContainerGuard
ContainerGuard is a packaged solution that uses Python and consists of two components: Parse & Audit.
`ContainerGuard-Parse.py` to parse the CIS Docker Benchmark PDF file into a formatted structured data. 
`ContainerGuard-Audit.py` to perform audit on Dockers based on the benchmark from the parser and generate audit reports. 
Currently, the solution has only been tested on `CIS Docker Benchmark v1.6.0`.

## Parse
### Install required Python packages
- pdfplumber
```
pip install pdfplumber
```

### Download
You can download and run the script on any machine that has Python. A copy of the CIS Docker Benchmark PDF file is included.

### Run
Parse CIS Docker Benchmark from `.pdf` to `.json`. The syntax is `python ContainerGuard-Parse.py <pdf_file>`.
```
python ContainerGuard-Parse.py CIS_Docker_Benchmark_V1.6.0.PDF
```

## Audit
### Install required Python packages
- docxtpl
```
sudo pip install docxtpl
```

### Download and Extract
Download the files into the Docker Host machine. A parsed CIS Docker Benchmark JSON file is included.
```
wget -O Audit.zip https://github.com/dainelkoh/ContainerGuard/blob/main/Audit.zip?raw=true && unzip Audit.zip && cd Audit
```

### Run
Audit Docker with CIS Docker Benchmark. Root privileges are required. The syntax is `sudo python3 ContainerGuard-Audit.py <json_file>`.
```
sudo python3 ContainerGuard-Audit.py CIS_Docker_Benchmark_V1.6.0.json
```

### Audit Reports
After the audit completes, audit reports `.docx` will be generated in `Audit Reports` directory. You can use `scp` to copy out the reports to a machine that can view them.
