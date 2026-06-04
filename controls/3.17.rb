# encoding: UTF-8

control 'C-3.17' do
  title 'Ensure that the daemon.json file ownership is set to root:root'
  desc  "
    You should verify that the `daemon.json` file individual ownership and group ownership is correctly set to `root`, if it is in use.

    The `daemon.json` file contains sensitive parameters that could alter the behavior of the docker daemon. It should therefore be owned and group owned by `root` to ensure it can not be modified by less privileged users.
  "
  desc  'rationale', "
    You should verify that the `daemon.json` file individual ownership and group ownership is correctly set to `root`, if it is in use.

    The `daemon.json` file contains sensitive parameters that could alter the behavior of the docker daemon. It should therefore be owned and group owned by `root` to ensure it can not be modified by less privileged users.
  "
  desc  'check', "
    You should execute the command below to verify that the file is owned and group owned by `root`:
    ```
    stat -c %U:%G /etc/docker/daemon.json | grep -v root:root 
    ```
    The command above should not return any results or, if there is no daemon.json file present it will return:

    ```
    stat: cannot stat '/etc/docker/daemon.json': No such file or directory
    ```
  "
  desc  'fix', "
    If the daemon.json file is present, you should execute the command below:
    ```
    chown root:root /etc/docker/daemon.json
    ```
    This sets the ownership and group ownership for the file to `root`.
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['AC-2 c']
  tag cci:                   ['CCI-002113']
  tag cis_number:            '3.17'
  tag cis_rid:               '3.17'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0317r1_rule'
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
    describe file('/etc/docker/daemon.json') do
    it { should exist }
    it { should be_owned_by 'root' }
    its('group') { should eq 'root' }
  end
  end
end
