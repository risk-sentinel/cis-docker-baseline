# encoding: UTF-8

control 'C-5.9' do
  title 'Ensure that only needed ports are open on the container'
  desc  "
    The dockerfile for a container image defines the ports which are opened by default on a container instance. The list of ports are relevant to the application you are running within the container and should only be open if they are needed.

    A container can be run with only the ports defined in the Dockerfile for its image or can alternatively be arbitrarily passed run time parameters to open a list of ports. Additionally, in the course of time, the Dockerfile may undergo various changes and the list of exposed ports may or may not still be relevant to the application you are running within the container. Opening unneeded ports increases the attack surface of the container and the associated containerized application. Good security practice is to only open ports that are needed for the correct operation of the application.
  "
  desc  'rationale', "
    The dockerfile for a container image defines the ports which are opened by default on a container instance. The list of ports are relevant to the application you are running within the container and should only be open if they are needed.

    A container can be run with only the ports defined in the Dockerfile for its image or can alternatively be arbitrarily passed run time parameters to open a list of ports. Additionally, in the course of time, the Dockerfile may undergo various changes and the list of exposed ports may or may not still be relevant to the application you are running within the container. Opening unneeded ports increases the attack surface of the container and the associated containerized application. Good security practice is to only open ports that are needed for the correct operation of the application.
  "
  desc  'check', "
    You should list all the running instances of containers and their associated port mappings by executing the command below:

    ```
    docker ps --quiet | xargs docker inspect --format '{{ .Id }}: Ports={{ .NetworkSettings.Ports }}'
    ```
    You should then review the list and ensure that all the ports mapped are in fact genuinely required by each container.
  "
  desc  'fix', "
    You should ensure that the Dockerfile for each container image only exposes needed ports. You can also completely ignore the list of ports defined in the Dockerfile by NOT using `-P` (UPPERCASE) or the `--publish-all` flag when starting the container. Instead, use the `-p` (lowercase) or `--publish` flag to explicitly define the ports that you need for a particular container instance.

    For example:
    ```
    docker run --interactive --tty --publish 5000 --publish 5001 --publish 5002 centos /bin/bash
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['SI-4 (11)', 'AC-17 (1)']
  tag cci:                   ['CCI-002668', 'CCI-000067']
  tag cis_number:            '5.9'
  tag cis_rid:               '5.9'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0509r1_rule'
  tag cis_version:           '1.8.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'alternative'
  tag exec_validated:        false

  describe 'Requires manual review and attestation' do
    skip "Requires manual review and attestation provided for this control (\"only needed ports\" is consumer-policy-specific (which ports each service legitimately exposes); operators attest from the task-definition portMappings)"
  end
end
