# Blowhole
Blowhole is a Python-based script that enumerates container configurations and calls Dockerized auditing tools (Batten and Docker Security Benchmark) to investigate Docker configurations and settings on the host machine.

## Usage
```
python blowhole.py -h
usage: blowhole.py [-h] [-i] [-a] -o OUTDIR

Blowhole

optional arguments:
  -h, --help            show this help message and exit
  -i, --invasive        Invasive mode - Runs enumeration scripts in containers
  -a, --audit           Extended auditing - Runs Dockerized auditing scripts
  -o OUTDIR, --outdir OUTDIR
                        Output directory for data results

One shot script for Docker auditing and enumeration.
```

![Script_Image](https://github.com/Keramas/Blowhole/blob/master/images/blowhole_exec.png?raw=true)

### Invasive mode (-i)
Invasive mode adds files and executes scripts from within each running container. Currently only loads and runs the [LinEnum script](https://github.com/rebootuser/LinEnum) and outputs the results to the specified output directory. If the host machine has internet connectivity, LinEnum can be downloaded when prompted by the script. If no internet connectivity, it's recommended to transfer the script onto the host along with Blowhole.

### Audit mode (-a):
Performs a comprehensive audit of the Docker environment using two Dockerized auditing tools:

* [Docker Security Benchmark](https://github.com/docker/dockerbench-security)
* [Batten](https://github.com/dockersecuritytools/batten)

Only warning and failed check items will be output to the terminal; however, the complete output of the results with details on each item are saved to the specified output directory.

## Docker Resources for Analyzing (And Exploiting) Results
* [Docker Components Explained](http://alexander.holbreich.org/docker-components-explained/)
A great, short read about how Docker works by breaking it down component by component.

* [SANS - A Checklist for Audit of Docker Containers](https://www.sans.org/reading-room/whitepapers/auditing/checklist-audit-docker-containers-37437)
Brief paper that contains good explanations about various Docker security points with accompanying checklists.

* [Docker Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)
Run down of several larger security checks to perform when assessing containers.

* [OWASP Docker Security](https://github.com/OWASP/Docker-Security)
Amazing repository that illustrates ten of the most important security points for container environments. Includes threat scenarios, ways to validate, and possible avenues for remediation.

* [Capabilities](http://man7.org/linux/man-pages/man7/capabilities.7.html)
Good man-page reference for auditing capabilities granted to containers.

* Articles on exploiting Docker containers:
https://www.cyberark.com/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host/
https://www.cyberark.com/threat-research-blog/the-route-to-root-container-escape-using-kernel-exploitation/
https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/
https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html
https://github.com/Frichetten/CVE-2019-5736-PoC
