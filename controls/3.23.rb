# encoding: UTF-8

control 'C-3.23' do
  title 'Ensure that the Containerd socket file ownership is set to root:root'
  desc  "
    You should verify that the Containerd socket file is owned by `root` and group owned by `root`.

    Containerd is an underlying component used by Docker to create and manage containers. It provides a socket file similar to the Docker socket, which must be protected from unauthorized access. If any other user or process owns this socket, it might be possible for that non-privileged user or process to interact with the Containerd daemon. Additionally, in this case a non-privileged user or process might be able to  interact with containers which is neither a secure nor desired behavior.

    Unlike the Docker socket, there is usually no requirement for non-privileged users to connect to the socket, so the ownership should be root:root.
  "
  desc  'rationale', "
    You should verify that the Containerd socket file is owned by `root` and group owned by `root`.

    Containerd is an underlying component used by Docker to create and manage containers. It provides a socket file similar to the Docker socket, which must be protected from unauthorized access. If any other user or process owns this socket, it might be possible for that non-privileged user or process to interact with the Containerd daemon. Additionally, in this case a non-privileged user or process might be able to  interact with containers which is neither a secure nor desired behavior.

    Unlike the Docker socket, there is usually no requirement for non-privileged users to connect to the socket, so the ownership should be root:root.
  "
  desc  'check', "
    You should execute the below command to verify that the Containerd socket file is owned by `root` and group owned by `root`:
    ```
    stat -c %U:%G /run/containerd/containerd.sock | grep -v root:root
    ```

    The command above should return no results.
  "
  desc  'fix', "
    You should execute the following command:
    ```
    chown root:root /run/containerd/containerd.sock
    ```

    This sets the ownership to `root` and group ownership to `root` for the default Containerd socket file.
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['AC-2 c']
  tag cci:                   ['CCI-002113']
  tag cis_number:            '3.23'
  tag cis_rid:               '3.23'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0323r1_rule'
  tag cis_version:           '1.8.0'
  tag cis_level:             1
  tag cis_scored:            true
  if input('docker_target_mode') == 'container_only'
    tag implementation_status:  'inherited'
    tag inherited_from:         'aws-shared-responsibility'
    tag attestation_references: ['AWS SOC 2 Type II', 'AWS FedRAMP Moderate', 'AWS FedRAMP High', 'AWS ISO 27001']
  else
    tag implementation_status:  'implemented'
  end
  tag exec_validated:           false

  if input('docker_target_mode') == 'container_only'
    uri = input('inherited_evidence_uri', value: '')
    uri = attestation_uri(:leveraged, 'aws-soc2-type2', ext: 'json') if uri.to_s.empty?
    if uri.to_s.empty?
      describe 'AWS shared-responsibility evidence (no leveraged source configured)' do
        skip 'inherited-from-aws: set leveraged_evidence_base / inherited_evidence_uri to the pulled AWS evidence manifest (SOC 2 / FedRAMP / ISO), or `saf attest apply`.'
      end
    else
      doc = document_attestation(uri, max_age_days: input('leveraged_evidence_max_age_days', value: 365))
      describe "AWS shared-responsibility leveraged evidence (#{uri})" do
        it('reachable') { expect(doc.connection_error).to be_nil, "evidence unreachable: #{doc.connection_error}" }
        it('exists') { expect(doc.exists?).to eq(true) }
        it("current") { expect(doc.current?).to eq(true) }
      end
    end
  else
    describe file('/run/containerd/containerd.sock') do
    it { should exist }
    it { should be_owned_by 'root' }
    its('group') { should eq 'root' }
  end
  end
end
