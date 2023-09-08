import threading
import requests
import paramiko
import getpass
import time
import subprocess

script_name = 'Ubuntu_Script.sh'

try:
    res = requests.get("https://raw.githubusercontent.com/catember/vulnerability-check/master/LINUX/Ubuntu/Ubuntu_Script.sh")
    script = res.text
except:
    print("Script를 가져오는 도중 오류가 발생하였습니다.")

with open(script_name, 'w', encoding='utf-8') as f:
        f.write(script)

def checkResultFile(pid, ssh_client):
    while True:
        line_count = execute_command(ssh_client, f"sudo ps -ef | grep {pid} | grep -v grep | wc -l")

        if int(line_count) == 0:
            return

def connect_ssh(ssh_info: dict):
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh_client.connect(
        hostname = ssh_info['hostname'],
        port = ssh_info['port'],
        username = ssh_info['username'],
        password = ssh_info['password'])

    return ssh_client

def execute_command(ssh, cmd):
    stdin, stdout, stderr = ssh.exec_command(cmd)

    error_msg = stderr.read().decode()

    if error_msg:
        hostname = ssh.get_transport().getpeername()[0]
        raise Exception(f'호스트 {hostname}에서 명령어 {cmd} 수행 중 오류가 발생하였습니다. \n{error_msg}')

    return stdout.read().decode().strip()


def main(ssh_info: dict, results):
    '''
    main : 원격 서버에서 쉘파일을 실행시키고, 결과 파일을 다운받는 함수

    파라미터
        param dict ssh_info : 원격 서버와 ssh 연결을 수행하기 위한 정보 - hostname, port, username, password
        param results : 결과 파일의 정보가 저장될 배열
    '''
    try:
        # ssh, sftp 연결 생성
        ssh_client = connect_ssh(ssh_info)
        sftp = ssh_client.open_sftp()

        # 원격 서버에 스크립트 파일 업로드
        sftp.put(script_name, script_name)


        # 원격 서버에 업로드한 스크립트 파일 백그라운드 실행, 해당 프로세스 PID의 존재여부를 통해 결과파일 작성 완료 여부 확인
        pid = execute_command(ssh_client, f'sudo bash ./{script_name} & echo $!')    
        checkResultFile(pid,ssh_client)

        # 생성된 결과파일명 확인, 다운로드 및 연결 종료
        filename = execute_command(ssh_client, f"ls -t *Results* | head -n 1")    
        sftp.get(f'{filename}', f'{ssh_info["hostname"]}_{filename}')
        sftp.close()
        ssh_client.close()


        # 다운받은 결과파일 데이터 및 전체 라인 수 result 배열에 저장
        with open(f'{ssh_info["hostname"]}_{filename}', 'r') as f:
            result = f.read()

        word_count = subprocess.run(f"wc -l {ssh_info['hostname']}_{filename} | awk '{{ print $1 }}'", shell=True, text=True, stdout=subprocess.PIPE)

        results.append({
            'result' : result,
            'line_count' : word_count.stdout,
            'filename' : f'{ssh_info["hostname"]}_{filename}'
        })

    except Exception as e:
        print(e)



if __name__ == '__main__':
    '''
    프로그램의 메인 스레드

    Ubuntu_Script.sh 파일을 실행할 서버의 개수를 입력받고
    해당 개수만큼의 스레드 생성하여 병렬 진행

    결과 배열에 생성된 결과 파일 내용, 파일의 라인 수, 파일 명을 저장하고
    각 서버에서 생성된 파일명을 출력
    '''
    results = []
    threads = []
    
    # 스크립트를 실행할 서버 개수 입력
    infra_yn = int(input('진단을 수행할 Linux서버의 개수를 입력해주세요. ( 0 입력시 프로그램 종료 ) : '))

    if infra_yn == 0:
        exit()

    # 입력한 개수만큼 서버 정보를 입력받고, 스레드 생성
    for i in range(infra_yn):
        ssh_info = dict()
        ssh_info['hostname'] = input('원격 서버의 주소를 입력해주세요. : ')
        ssh_info['port'] = int(input('원격 서버의 ssh 포트를 입력해주세요. : '))
        ssh_info['username'] = input('진단 스크립트를 실행할 유저명을 입력해주세요. : ')
        ssh_info['password'] = getpass.getpass('해당 유저의 비밀번호를 입력해주세요. : ')
        t = threading.Thread(target=main, args=(ssh_info,results,))
        threads.append(t)
        t.start()
    
    # 모든 스레드 종료까지 대기
    for thread in threads:
        thread.join()

    # 생성된 결과 파일의 파일명 출력
    for result in results:
        print(result['filename'])

