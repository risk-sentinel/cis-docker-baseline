# encoding: UTF-8

control 'C-5.32' do
  title 'Ensure that the Docker socket is not mounted inside any containers'
  desc  "
    The Docker socket `docker.sock` should not be mounted inside a container.

    If the Docker socket is mounted inside a container it could allow processes running within the container to execute Docker commands which would effectively allow for full control of the host.
  "
  desc  'rationale', "
    The Docker socket `docker.sock` should not be mounted inside a container.

    If the Docker socket is mounted inside a container it could allow processes running within the container to execute Docker commands which would effectively allow for full control of the host.
  "
  desc  'check', "
    You should run the following command:
    ```
    docker ps --quiet --all | xargs docker inspect --format '{{ .Id }}: Volumes={{ .Mounts }}' | grep docker.sock 
    ```
    This would return any instances where `docker.sock` had been mapped to a container as a volume.
  "
  desc  'fix', "
    You should ensure that no containers mount `docker.sock` as a volume.
  "
  impact 0.5
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-2 c']
  tag nist_r4:               ['AC-2 c']
  tag cci:                   ['CCI-002113']
  tag cis_number:            '5.32'
  tag cis_rid:               '5.32'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0532r1_rule'
  tag cis_version:           '1.8.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  socket_paths = Array(input('docker_socket_paths'))
  mounts_content = file('/proc/mounts').content.to_s
  offenders = socket_paths.select { |p| mounts_content.include?(p) }
  describe 'docker socket paths bind-mounted inside the container' do
    subject { offenders }
    it { should be_empty }
  end
end
