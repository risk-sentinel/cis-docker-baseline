# encoding: UTF-8

control 'C-5.12' do
  title 'Ensure that CPU priority is set appropriately on containers'
  desc  "
    By default, all containers on a Docker host share resources equally. By using the resource management capabilities of the Docker host you can control the host CPU resources that a container may consume.

    By default, CPU time is divided between containers equally. If you wish to control available CPU resources amongst container instances, you can use the CPU sharing feature. CPU sharing allows you to prioritize one container over others and prevents lower priority containers from absorbing CPU resources which may be required by other processes. This ensures that high priority containers are able to claim the CPU runtime they require.
  "
  desc  'rationale', "
    By default, all containers on a Docker host share resources equally. By using the resource management capabilities of the Docker host you can control the host CPU resources that a container may consume.

    By default, CPU time is divided between containers equally. If you wish to control available CPU resources amongst container instances, you can use the CPU sharing feature. CPU sharing allows you to prioritize one container over others and prevents lower priority containers from absorbing CPU resources which may be required by other processes. This ensures that high priority containers are able to claim the CPU runtime they require.
  "
  desc  'check', "
    You should run the following command.
    ```
    docker ps --quiet --all | xargs docker inspect --format '{{ .Id }}: CpuShares={{ .HostConfig.CpuShares }}'
    ```
    If the above command returns `0` or `1024`, it means that CPU shares are not in place. If it returns a non-zero value other than `1024`, it means that they are in place.
  "
  desc  'fix', "
    You should manage the CPU runtime between your containers dependent on their priority within your organization. To do so start the container using the `--cpu-shares` argument. 

    For example, you could run a container as below:
    ```
    docker run -d --cpu-shares 512 centos sleep 1000
    ```

    In the example above, the container is started with CPU shares of 50% of what other containers use. So if the other container has CPU shares of 80%, this container will have CPU shares of 40%.

    Every new container will have `1024` shares of CPU by default. However, this value is shown as `0` if you run the command mentioned in the audit section.

    If you set one container's CPU shares to `512` it will receive half of the CPU time compared to the other containers. So if you take `1024` as 100% you can then derive the number that you should set for respective CPU shares. For example, use `512` if you want to set it to 50% and `256` if you want to set it 25%.

    You can also view the current CPU shares in the file `/sys/fs/cgroup/cpu/docker/ /cpu.shares`.
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '5.12'
  tag cis_rid:               '5.12'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0512r1_rule'
  tag cis_version:           '1.8.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'alternative'
  tag attestation_category:  'policy'
  tag exec_validated:        false

  uri = input('c_5_12_attestation_uri', value: '')
  uri = attestation_uri(:boundary, 'C-5.12') if uri.to_s.empty?
  if uri.to_s.empty?
    describe 'Requires manual review and attestation' do
      skip "Requires manual review and attestation provided for this control (\"appropriate\" CPU priority depends on the workload mix and capacity-planning record; operators cross-reference task-definition cpu reservations) [Lift: set boundary_docs_base / c_5_12_attestation_uri, or `saf attest apply`.]"
    end
  else
    doc = document_attestation(uri, max_age_days: input('attestation_max_age_days', value: 365))
    describe "Boundary policy attestation (C-5.12) (#{uri})" do
      it('reachable') { expect(doc.connection_error).to be_nil, "attestation unreachable: #{doc.connection_error}" }
      it('exists') { expect(doc.exists?).to eq(true) }
      it("current") { expect(doc.current?).to eq(true) }
    end
  end
end
