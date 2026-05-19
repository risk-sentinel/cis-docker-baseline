# encoding: UTF-8

control 'C-5.16' do
  title 'Ensure that the host\'s process namespace is not shared'
  desc  "
    The Process ID (PID) namespace isolates the process ID space, meaning that processes in different PID namespaces can have the same PID. This creates process level isolation between the containers and the host.

    PID namespace provides separation between processes. It prevents system processes from being visible, and allows process ids to be reused including PID `1`. If the host's PID namespace is shared with containers, it would basically allow these to see all of the processes on the host system. This reduces the benefit of process level isolation between the host and the containers. Under these circumstances a malicious user who has access to a container could get access to processes on the host itself, manipulate them, and even be able to kill them.  This could allow for the host itself being shut down, which could be extremely serious, particularly in a multi-tenanted environment. You should not share the host's process namespace with the containers running on it.
  "
  desc  'rationale', "
    The Process ID (PID) namespace isolates the process ID space, meaning that processes in different PID namespaces can have the same PID. This creates process level isolation between the containers and the host.

    PID namespace provides separation between processes. It prevents system processes from being visible, and allows process ids to be reused including PID `1`. If the host's PID namespace is shared with containers, it would basically allow these to see all of the processes on the host system. This reduces the benefit of process level isolation between the host and the containers. Under these circumstances a malicious user who has access to a container could get access to processes on the host itself, manipulate them, and even be able to kill them.  This could allow for the host itself being shut down, which could be extremely serious, particularly in a multi-tenanted environment. You should not share the host's process namespace with the containers running on it.
  "
  desc  'check', "
    You should run the following command:
    ```
    docker ps --quiet --all | xargs docker inspect --format '{{ .Id }}: PidMode={{ .HostConfig.PidMode }}'
    ```

    If the command above returns `host`, it means that the host PID namespace is shared with its containers; any other result means that the system is configured in line with good security practice.
  "
  desc  'fix', "
    You should not start a container with the `--pid=host` argument.

    For example, do not start a container with the command below:
    ```
    docker run --interactive --tty --pid=host centos /bin/bash
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['AC-8 a']
  tag cci:                   ['CCI-000051']
  tag cis_number:            '5.16'
  tag cis_rid:               '5.16'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0516r1_rule'
  tag cis_version:           '1.8.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'alternative'
  tag exec_validated:        false

  describe 'Requires manual review and attestation' do
    skip "Requires manual review and attestation provided for this control (host PID namespace sharing — pidMode=host on ECS task definition, hostPID=true on Kubernetes, --pid=host on docker run — is configured at the orchestration layer and is not visible from inside the container. Operator attests from the orchestrator's spec.)"
  end
end
