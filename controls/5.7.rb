# encoding: UTF-8

control 'C-5.7' do
  title 'Ensure sshd is not run within containers'
  desc  "
    The SSH daemon should not be running within the container. You should SSH into the Docker host, and use `docker exec` to enter a container.

    Running SSH within the container increases the complexity of security management by making it

    - Difficult to manage access policies and security compliance for SSH server
    - Difficult to manage keys and passwords across various containers
    - Difficult to manage security upgrades for SSH server

    It is possible to have shell access to a container without using SSH, the needlessly increasing the complexity of security management should be avoided.
  "
  desc  'rationale', "
    The SSH daemon should not be running within the container. You should SSH into the Docker host, and use `docker exec` to enter a container.

    Running SSH within the container increases the complexity of security management by making it

    - Difficult to manage access policies and security compliance for SSH server
    - Difficult to manage keys and passwords across various containers
    - Difficult to manage security upgrades for SSH server

    It is possible to have shell access to a container without using SSH, the needlessly increasing the complexity of security management should be avoided.
  "
  desc  'check', "
    List all the running instances of containers by executing below command:
    ```
    docker ps --quiet 
    ```

    For each container instance, execute the below command:
    ```
    docker exec ps -el
    ```
    Ensure that there is no process for SSH server.
  "
  desc  'fix', "
    Uninstall the SSH daemon from the container and use and use `docker exec` to enter a container on the remote host.

    ```
    docker exec --interactive --tty sh
    ```
    OR
    ```
    docker attach ```
  "
  impact 0.5
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-7 a', 'SI-4 (11)']
  tag cci:                   ['CCI-000381', 'CCI-002668']
  tag cis_number:            '5.7'
  tag cis_rid:               '5.7'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0507r1_rule'
  tag cis_version:           '1.8.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  describe processes('sshd') do
    it { should_not exist }
  end
end
