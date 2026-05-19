# encoding: UTF-8

control 'C-5.30' do
  title 'Ensure that Docker\'s default bridge "docker0" is not used'
  desc  "
    You should not use Docker's default bridge `docker0`. Instead you should use Docker's user-defined networks for container networking.

    Docker connects virtual interfaces created in bridge mode to a common bridge called `docker0`. This default networking model is vulnerable to ARP spoofing and MAC flooding attacks as there is no filtering applied to it.
  "
  desc  'rationale', "
    You should not use Docker's default bridge `docker0`. Instead you should use Docker's user-defined networks for container networking.

    Docker connects virtual interfaces created in bridge mode to a common bridge called `docker0`. This default networking model is vulnerable to ARP spoofing and MAC flooding attacks as there is no filtering applied to it.
  "
  desc  'check', "
    You should run the command below, and verify that containers are on a user-defined network and not the default `docker0` bridge.
    ```
    docker network ls --quiet | xargs docker network inspect --format '{{ .Name }}: {{ .Options }}' 
    ```
  "
  desc  'fix', "
    You should follow the Docker documentation and set up a user-defined network. All the containers should be run in this network.
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['CM-7 a']
  tag cci:                   ['CCI-000381']
  tag cis_number:            '5.30'
  tag cis_rid:               '5.30'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0530r1_rule'
  tag cis_version:           '1.8.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'alternative'
  tag exec_validated:        false

  describe 'Requires manual review and attestation' do
    skip "Requires manual review and attestation provided for this control (default docker0 bridge usage is detectable only from daemon-side network configuration; Fargate doesn't expose a Docker bridge network)"
  end
end
