#!/usr/bin/env python3
import sys
import os
import json
import subprocess
import re
import argparse


green = '\033[32m'
yellow = '\033[33m'
blue = '\033[94m'
red = '\033[91m'
end = '\033[0m'
linebreak = "^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^"

banner = blue + """

 ______          _____  _  _  _ _     _  _____         _______
 |_____] |      |     | |  |  | |_____| |     | |      |______
 |_____] |_____ |_____| |__|__| |     | |_____| |_____ |______

                               b
                            .  $  .
        ....             d  *  *  $    .
   .ze$$$$$$$$be..       ^b ^L 4F $    $
  e$$$$$$$$$$$$$$$$e      "L $  b $   J%
.$$$$$$$$$$$$$P**""**      3r'L $ $  4F
 "*$$$$$$$$*"               *.$ 3 $  $
   *$$$$$"                  ^$'r'$P d"
   ^$$$"                     ^$$ $F4F
    $$$                       "$r*bP
    $$$F                        "4$"
    $$$$                         ^"
    $$$$b              ..eeeed$$$$$$$$eeee...
    *$$$$b.       .ze$$$$$$$$$$$$$$$$$$$$$$$$$be..
    '$$$$$$bee..e$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$bc
     3$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$c
      "*$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$r
        ^''''$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$e..        P
             "$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$bee.z@"
              ^*$$$$$$$$*'''     ''''**$$$$$$$$$$$$$"
    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
""" + end

def get_args():
    parser = argparse.ArgumentParser(description="Blowhole",epilog="One shot script for Docker auditing and enumeration.")
    parser.add_argument('-i','--invasive',action='store_true', help="Invasive mode - Runs enumeration scripts in containers", required=False)
    parser.add_argument('-a','--audit',action='store_true', help="Extended auditing - Runs Dockerized auditing scripts", required=False)
    parser.add_argument('-o','--outdir',type=str, help="Output directory for data results", required=True)
    args = parser.parse_args()
    invasive = args.invasive
    audit = args.audit
    out_dir = args.outdir
    return invasive,audit,out_dir


def exec_cmd(cmd):
    ps = subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    output = ps.communicate()[0]
    print output
    return output


def parser(item,data):
    i = 0
    while i >= 0:
        try:
            print(str(item[i]))
            i += 1
        except IndexError:
            item = 'null'
            break
    print("\n")


def containerEnum(out_dir):
    out_dir = out_dir
    print(green+"[+] Running LinEnum.sh on each container..."+end)
    enum = "for i in $(docker ps | cut -d ' ' -f 1 | sed '1d'); do docker exec -i $i /bin/bash -c 'cat > /tmp/LinEnum.sh' < LinEnum.sh; docker exec -it $i chmod +x /tmp/LinEnum.sh; docker exec -it $i /tmp/LinEnum.sh -t | tee " + out_dir + "/${i}_LinEnum_results_$(date '+%Y%m%d').txt; docker exec -it $i rm /tmp/LinEnum.sh; done"
    exec_cmd(enum)


def main(out_dir):
    out_dir = out_dir
    print(banner)
    print("\t Thar she blows! Are you ready to have a whale of a good time?")
    print(green+"\n[!] Blowhole opening up to blast out Docker data..."+end)

    try:
        os.stat(out_dir)
    except:
        os.mkdir(out_dir)

    print(green+"[+] Starting to enumerate Docker host..."+end)
    print(yellow+"[*] Host kernel:"+end)
    hostname = "uname -a"
    exec_cmd(hostname)

    print(yellow+"[*] Docker-related processes:"+end)
    docker_processes = "ps aux | grep docker"
    process_list = exec_cmd(docker_processes)

    print(yellow+"[*] Checking for shared Docker socket...")
    if "/var/run/docker.sock" in process_list:
        print(red+"\t[!] Potential shared Docker socket found!\n"+end)
    else:
        print(green+"[!] No shared Docker socket present.\n"+end)

    tally = 0
    print(yellow+"[*] Checking for subuid and subgid files..."+end)
    if os.path.exists('/etc/subuid'):
        print(green+"[!] Subuid files exists.\n"+end)

    else:
        print(red+"[!] No subuid file.\n"+end)
        tally += 1

    if os.path.exists('/etc/subgid'):
        print(green+"[!] Subgid files exists.\n"+end)

    else:
        print(red+"[!] No subgid file.\n"+end)
        tally += 1

    print(yellow+"[*] Checking /var/lib/docker directory..."+end)
    list_docker_dir = "ls -al /var/lib/docker"
    exec_cmd(list_docker_dir)

    user_check = "ls -al /var/lib/docker | cut -d ' ' -f 3,4 | sed '1d'"
    checked = exec_cmd(user_check)
    if re.match(r"^((?!root).)*$",checked):
        print(green+"[!] User other than root found.\n"+end)

    else:
        print(red+"[!] Only root:root found.\n"+end)
        tally += 1


    print(yellow+"[*] Checking docker daemon file..."+end)
    check_daemon = "cat /etc/docker/daemon.json"
    daemon_config = exec_cmd(check_daemon)
    if "userns-remap" in daemon_config:
        print("[!] User remapping found in daemon config.\n")
    else:
        print(red+"[!] No user remapping found in daemon config.\n"+end)
        tally += 1


    if tally != 0:
        print(red+"[!] Docker containers likely running as root with no user remapping.\n"+end)

    print(yellow+"[+] Checking for containerd.toml file..."+end)
    check_toml = "cat /var/run/docker/containerd/containerd.toml"
    exec_cmd(check_toml)

    print(yellow+"[*] Enumerating running Docker containers:"+end)
    print("[Container]  [Image Name]")
    container_list = "docker ps | cut -d ' ' -f 1,9 | sed '1d'"
    exec_cmd(container_list)

    print(green+"[+] Enumerating containers..."+end)
    inspect_dump = "for i in $(docker ps | cut -d ' ' -f 1 | sed '1d'); do docker inspect $i > " + out_dir + "/${i}_container_details.json; done"
    exec_cmd(inspect_dump)

    for filename in os.listdir(out_dir):
        if ".json" in filename:
            with open(out_dir+ "/" + filename,"r") as container_file:
                data = json.load(container_file)
                container_file.close()
                print(green+"[+] Analyzing container " + str(data[0]['Id']) + end)

                print(yellow+"Name:"+end)
                print(str(data[0]['Name']))
                print("\n")

                print(yellow+"Host file system mount binds (host:guest): "+end)
                binds = data[0]['HostConfig']['Binds']
                parser(binds,data)

                print(yellow+"Privileged:"+end)
                print(str(data[0]['HostConfig']['Privileged']))
                print("\n")

                print(yellow+"Capabilities: "+end)
                capabilities = data[0]['HostConfig']['CapAdd']
                parser(capabilities,data)

                print(yellow+"Seccomp setting:"+end)
                print(str(data[0]['HostConfig']['SecurityOpt']))
                print("\n")

                print(yellow+"CapDrop setting:"+end)
                print(str(data[0]['HostConfig']['CapDrop']))
                print("\n")

                print(yellow+"AppArmor Profile:"+end)
                print(str(data[0]['AppArmorProfile']))
                print("\n")

                print(yellow+"Exposed ports: "+end)
                ports = data[0]['Config']['ExposedPorts']
                print(str(ports))
                print("\n")

                print(yellow+"Environment variables: "+end)
                env = data[0]['Config']['Env']
                parser(env,data)

    print(green+"\n[+] Checking container history comments..."+end)
    history = """for i in $(docker ps | cut -d ' ' -f 9 | sed '1d'); do echo -e "\e[33m[*] Container name: $i\e[0m";docker history $i --no-trunc | awk '{$1=$2=$3=$4=$5=""; print $0}';echo -e "\n"; done"""
    exec_cmd(history)
    print(linebreak)


def fullAudit(out_dir):
    #Launch Dockerized auditing tools
    #Lauches Batten Benchmark Tool
    out_dir = out_dir
    launch_batten = "docker run -v /var/run/docker.sock:/var/run/docker.sock jerbi/batten | tee " + out_dir + "/Batten_results_$(date '+%Y%m%d').txt | grep FAILED"

    #Launches Docker Security Benchmark
    launch_benchmark = "docker run -it --net host --pid host --userns host --cap-add audit_control -e DOCKER_CONTENT_TRUST=$DOCKER_CONTENT_TRUST -v /etc:/etc:ro -v /usr/bin/docker-containerd:/usr/bin/docker-containerd:ro -v /usr/bin/docker-runc:/usr/bin/docker-runc:ro -v /usr/lib/systemd:/usr/lib/systemd:ro -v /var/lib:/var/lib:ro -v /var/run/docker.sock:/var/run/docker.sock:ro --label docker_bench_security docker/docker-bench-security | tee " + out_dir +"/BenchSecurity_results_$(date '+%Y%m%d').txt | grep WARN"

    print(green+"\n[+] Initializing Docker auditing scripts (Filtering for warn/fail messages only)."+end)
    print(yellow+"[*] Launching Batten audit script...\n"+end)
    exec_cmd(launch_batten)
    print(yellow+"\n[*] Launching Docker Bench Security script...\n"+end)
    exec_cmd(launch_benchmark)
    print(linebreak)


if __name__ == "__main__":
    invasive,audit,out_dir = get_args()
    main(out_dir)

    if audit:
        fullAudit(out_dir)

    if invasive:
        if os.path.exists('LinEnum.sh'):
            containerEnum(out_dir)
        else:
            print(red+"[x] LinEnum.sh not found in current working directory. Is the file name different?"+end)
            try:
                input = raw_input
            except NameError:
                pass
            answer = str(input(yellow+"[?] Would you like to download LinEnum.sh? (Y/N): "+end))
            if answer == "Y" or answer == "y":
                download = "wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh"
                exec_cmd(download)
                containerEnum(out_dir)
            else:
                print(red+"[x] Container enumeration was not performed.\n"+end)

    print(green+"[!] All done! Output files saved to: %s\n" % out_dir+end)
    sys.exit(0)
