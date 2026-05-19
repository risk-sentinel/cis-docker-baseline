# encoding: UTF-8

control 'C-5.17' do
  title 'Ensure that the host\'s IPC namespace is not shared'
  desc  "
    IPC (POSIX/SysV IPC) namespace provides separation of named shared memory segments, semaphores and message queues. The IPC namespace on the host should therefore not be shared with containers and should remain isolated.

    The IPC namespace provides separation of IPC between the host and containers. If the host's IPC namespace is shared with the container, it would allow processes within the container to see all of IPC communications on the host system. This would remove the benefit of IPC level isolation between host and containers. An attacker with access to a container could get access to the host at this level with major consequences. The IPC namespace should therefore not be shared between the host and its containers.
  "
  desc  'rationale', "
    IPC (POSIX/SysV IPC) namespace provides separation of named shared memory segments, semaphores and message queues. The IPC namespace on the host should therefore not be shared with containers and should remain isolated.

    The IPC namespace provides separation of IPC between the host and containers. If the host's IPC namespace is shared with the container, it would allow processes within the container to see all of IPC communications on the host system. This would remove the benefit of IPC level isolation between host and containers. An attacker with access to a container could get access to the host at this level with major consequences. The IPC namespace should therefore not be shared between the host and its containers.
  "
  desc  'check', "
    You should run the following command:
    ```
    docker ps --quiet --all | xargs docker inspect --format '{{ .Id }}: IpcMode={{ .HostConfig.IpcMode }}'
    ```
    If the command returns `host`, it means that the host IPC namespace is shared with the container. Any other result means that it is not shared, and that the system is therefore configured in line with good security practice.
  "
  desc  'fix', "
    You should not start a container with the `--ipc=host` argument. For example, do not start a container as below:

    ```
    docker run --interactive --tty --ipc=host centos /bin/bash
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['AC-8 a']
  tag cci:                   ['CCI-000051']
  tag cis_number:            '5.17'
  tag cis_rid:               '5.17'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0517r1_rule'
  tag cis_version:           '1.8.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'alternative'
  tag exec_validated:        false

  describe 'Requires manual review and attestation' do
    skip "Requires manual review and attestation provided for this control (host IPC namespace sharing is asserted from the task-definition ipcMode; not visible from inside the container without host-namespace comparison)"
  end
end
