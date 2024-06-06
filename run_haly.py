# script to start haly for previously downloaded apps in file with joblog
import argparse
import os
from pathlib import Path
import json
import shutil
import subprocess
import time
import yaml
import concurrent.futures

# command needed to reach next stage
stage_command_map = {
    0: "download",
    1: "prepare",
    2: "prepare",
    3: "prepare",
    4: "prepare",
    5: "static",
    6: "dynamic",
    7: "report"
}
reverse_dict = {v: k for k, v in stage_command_map.items()}

joblog_csv = 'Seq   ID   StartTime   EndTime   Stage   Success   Device\n'

def kill_server():
    command = "adb kill-server"
    try:
        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, timeout=60)
        return True, output.decode("utf-8", "ignore"), 0
    except subprocess.CalledProcessError as e:
        return False, e.output.decode("utf-8", "ignore"), e.returncode
def start_adb_server():
    command = "adb start-server"
    try:
        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, timeout=60)
        return True, output.decode("utf-8", "ignore"), 0
    except subprocess.CalledProcessError as e:
        return False, e.output.decode("utf-8", "ignore"), e.returncode

def _run_analysis(os: str, config_path=str, stage: int = 1):
    kwargs = dict(bufsize=0,  # No buffering.
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,  # Redirect stderr to stdout.
                universal_newlines=True)
    command = ["python3", "main.py", "-c", config_path, "-f", f"--{os}", stage_command_map[stage]]
    proc = subprocess.Popen(command, **kwargs)
    error = False
    log = ""
    with proc.stdout as output:
        for line in output:
            #print(line, end='')  # Process the output...
            log += line
            if ("- ERROR -" in line and "- ERROR - App crashed too many times" not in line) or ("Exception" in line and "Traceback" in line):
                error = True
    proc.wait()
    # if proc exited with error
    return proc.returncode == 0 and not error, log
    
def app_worker(app_stage):
    app = app_stage['app']
    stage = app_stage['stage'] # current stage
    id = app.get('app_id')
    
    startTime = time.time()
    
    app_path = app.get('path')
    full_path = os.path.join(mount_dir, app_path)

    print(f'Starting {stage_command_map[stage]} analysis of {id}...')

    if args.android:
        app_analysis_path = os.path.join(android_path, id)
        destination_path = os.path.join(app_analysis_path, "base.apk")
    elif args.ios:
        app_analysis_path = os.path.join(ios_path, id)
        destination_path = os.path.join(app_analysis_path, "base.ipa")

    if not os.path.exists(app_analysis_path):
        os.makedirs(app_analysis_path)
    if not os.path.exists(destination_path):
        # os.makedirs(os.path.join(android_path, id))
        if args.link:
            print(f"Linking apk: {full_path}->{destination_path}...")
            os.symlink(full_path, destination_path)
        elif args.copy:
            print(f"Copying apk: {full_path}->{destination_path}...")
            shutil.copy(full_path, destination_path)
        else:
            raise Exception("You need to specify either --link or --copy")
        with open(os.path.join(app_analysis_path, "stage"), "w") as fp:
            fp.write("1")
            fp.flush()
            os.fsync(fp.fileno())
            stage = 1
    elif os.path.exists(os.path.join(app_analysis_path, "stage")):
        with open(os.path.join(app_analysis_path, "stage"), "r") as fp:
            stage_f = int(fp.read())
            if stage_f >= 1:
                #print(f"App {id} already exists in {app_analysis_path}. Skipping linking...")
                downloaded = True
    mos = "ios" if args.ios else "android"
    
    # Append app id to config yaml file
    with (open(config_path, 'r')) as config_file:
        config = yaml.safe_load(config_file)
        config['apps'][mos] = [id]
    
    thread_config_path = config_path.replace('.yaml', f'_{id}_{stage_command_map[stage]}.yaml')
    with open(thread_config_path, 'w') as config_file:
        yaml.safe_dump(config, config_file)
        config_file.flush()
        os.fsync(config_file.fileno())
    
    # execute analysis
    if stage == 6:
        kill_server()
        time.sleep(3)
        start_adb_server()
        time.sleep(3)
    ret_code, out = _run_analysis(os=mos, config_path=thread_config_path, stage=stage)
    
    if stage == 6:
        kill_server()
    # remove the copy of the apk
    # copy_apk_path = os.path.join(destination_path, os.path.basename(full_path))
    #print(f'Removing config file: {thread_config_path}...')
    Path(thread_config_path).unlink(missing_ok=True)

    endTime = time.time()
    ret = (id, startTime, endTime, out)

    if not ret_code:
        #print(f'Return code: {ret_code}')
        raise Exception(ret)
    with open(os.path.join(app_analysis_path, "stage"), "r") as stage_file:
        assert int(stage_file.read()) > stage, ret
    print(f'Finished {stage_command_map[stage]} analysis of {id}!')
    return ret

"""
The main entry point for this wrapper
"""
def parse_args():
    parser = argparse.ArgumentParser(description='Starts the HALY Pipeline.')
    parser.add_argument('-o', '--output-path', default='./out',
                        help='Local destination directory where the apk is temporally copied to.'
                        )

    parser.add_argument("-m", "--mount-dir",
                        help="In case you store the apps on a server: path where the server is mounted. Is prepended to the paths in the file.", default="./")

    parser.add_argument("-f", "--file",
                        help="File containing the app ids and paths to the binaries (JSON format, [{'app_id': <id>, 'path': <path>}])")

    parser.add_argument("-j", "--joblog", type=str, help="Path to joblog file.", required=True)

    parser.add_argument("-c", "--config", type=str, help="Path to config file for the analysis tool.", required=True)
    
    parser.add_argument("-n", "--num-apps", type=int, help="Number of apps to analyze.")
    
    parser.add_argument("--prepare", action="store_true")
    parser.add_argument("--static", action="store_true")
    parser.add_argument("--dynamic", nargs="*")
    
    parser.add_argument("-r", "--retry", action="store_true", help="Retry failed jobs.")

    os_arg = parser.add_mutually_exclusive_group(required=True)
    os_arg.add_argument("--android", action="store_true")
    os_arg.add_argument("--ios", action="store_true")

    link_or_copy = parser.add_mutually_exclusive_group()
    link_or_copy.add_argument("--link", action="store_true")
    link_or_copy.add_argument("--copy", action="store_true")


    # Parse command line arguments
    args = parser.parse_args()
    return args

args = parse_args()
output_path = os.path.abspath(args.output_path)

mount_dir = args.mount_dir
file_path = os.path.abspath(args.file)
config_path = os.path.abspath(args.config)

prepare = args.prepare
static = args.static
#dynamic argument
dynamic = args.dynamic is not None and len(args.dynamic) > 0
dynamic_devices = args.dynamic
device = dynamic_devices[0] if dynamic else "all"

if not prepare and not static and not dynamic:
    prepare = True
    static = True
    dynamic = True
    
print('Setting up Joblog...')

# Write Job Log so the program can be stopped and continued anytime.
seq = 1
jobs_done = {}
failed_jobs = {}
if not os.path.exists(args.joblog):
    with open(args.joblog, 'w') as joblog:
        joblog.write('Seq   ID   StartTime   EndTime   Stage   Success   Device\n')
else:
    with open(args.joblog, 'r') as joblog:
        # Skip first line, because it contains the header information
        joblog.readline()
        for line in joblog:
            parts = line.split('   ', 6)
            seq_read = int(parts[0])
            seq = max(seq, seq_read + 1)
                   
            id = parts[1]
            stage = reverse_dict[parts[4].strip()]
            success = int(parts[5])
                        
            if (args.retry and success == 0):
                continue
            
            if success == 0:
                failed_jobs[id] = stage
            
            # If the job is already in the dictionary and the new stage is higher, update it
            if id in jobs_done and jobs_done[id] < stage:
                jobs_done[id] = stage
            # If the job is not in the dictionary, add it
            elif id not in jobs_done:
                jobs_done[id] = stage
            
        print(f'Already done jobs ({len(jobs_done)}): {jobs_done}')

with open(file_path, 'r') as fp:
    apps_read = json.loads(fp.read())
    
apps_read = {app['app_id']: app['path'] for app in apps_read}

# Remove the apps that are already done
apps = {}
for (id, _) in apps_read.items():
    if args.num_apps is not None and len(apps) >= args.num_apps:
        break
    
    if id in failed_jobs:
        print(f'Failed job {id} at stage {stage_command_map[failed_jobs[id]]}. Skipping...')
        continue
    
    if id in jobs_done:
        stage_list = range(jobs_done[id]+1, 7)
    else:
        stage_list = range(1, 7)
    # remove [2,3,4] from stage_list and only add the stages that are specified
    stage_list = [x for x in stage_list if x not in [2, 3, 4] and (x == 1 and prepare or x == 5 and static or x == 6 and dynamic)]
    if len(stage_list) > 0:
        apps[id] = stage_list
    
# apps = sorted(apps, key=lambda x: x['stage'])

# unique_apps = set(app['app']['app_id'] for app in apps)
print(f'Number of apps to analyze: {len(apps)}')

destination_path = output_path

binary_path = os.path.join(destination_path, "binary")
android_path = os.path.join(binary_path, "android")
ios_path = os.path.join(binary_path, "ios")


# create necessary folder structure.
if not os.path.exists(destination_path):
    os.makedirs(destination_path)
if not os.path.exists(binary_path):
    os.makedirs(binary_path)
if not os.path.exists(ios_path):
    os.makedirs(ios_path)
if not os.path.exists(android_path):
    os.makedirs(android_path)
#print(apps)
single_thread_jobs = []
with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count() if len(apps) > os.cpu_count() else 1) as executor:
    def exception_handler(app, stage, log):       
        print(f'{app} generated an exception at stage {stage_command_map[stage]}')
        with (open(destination_path + "/error.log", 'a')) as error_log:
            error_log.write(f'{app} generated an exception at stage {stage_command_map[stage]}:\n{log}\n\n')
    def log_appworker(seq, id, startTime, endTime, stage, success, device):
        # Seq   ID   StartTime   EndTime   Stage   Success   Device
        to_log = f'{seq}   {id}   {startTime}   {endTime}   {stage_command_map[stage]}   {int(success)}   {device}\n'
        with open(args.joblog, 'a') as joblog:
            joblog.write(to_log)
        seq += 1
        return seq
        
    # Use the executor to run the worker function for each app
    futures = {}
    
    for job in apps:
        app = {'app': {'app_id': job, 'path': apps_read[job]}, 'stage': apps[job].pop(0)}
        if (app['stage'] == 6):
            single_thread_jobs.append(app)
            continue
        futures[executor.submit(app_worker, app)] = app
    #not_done = futures
    while True:
        #check if app is in jobs_done with the stage being the previous stage and successful, if not then wait for it to finish
        
        if len(futures) == 0:
            break
        # Wait for any future to complete and remove it from the dictionary
        done, not_done = concurrent.futures.wait(futures.keys(), return_when=concurrent.futures.FIRST_COMPLETED, timeout=60)
        
        for future in done:
            app_stage = futures.pop(future)
            app = app_stage['app']
            stage = app_stage['stage']
            success = True
            try:
                id, startTime, endTime, out = future.result()
                
            except Exception as exc:
                success = False
                id, startTime, endTime, out = exc.args[0]
                exception_handler(app, stage, out)
                
            seq = log_appworker(seq, id, startTime, endTime, stage, success, device)
         
            if success:
                if len(apps[id]) > 0:
                    next_stage = {'app': app, 'path': apps_read[job], 'stage': apps[id].pop(0)}
                    print(f'Queueing next stage for {id}: {stage_command_map[next_stage["stage"]]}')
                    if (next_stage['stage'] == 6):
                        single_thread_jobs.append(app)
                        continue
                    futures[executor.submit(app_worker, next_stage)] = next_stage
            else:
                print(f'Stopping further stages for {id} due to failure.')
for app_stage in single_thread_jobs:
    app = app_stage['app']
    stage = app_stage['stage']
    success = True
    try:
        id, startTime, endTime, out = app_worker(app_stage)
        
    except Exception as exc:
        success = False
        id, startTime, endTime, out = exc.args[0]
        exception_handler(app, stage, out)
  
    seq = log_appworker(seq, id, startTime, endTime, stage, success, device)

    time.sleep(1)
            
print('All apps done.')

