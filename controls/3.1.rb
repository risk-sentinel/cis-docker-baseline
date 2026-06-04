# encoding: UTF-8

control 'C-3.1' do
  title 'Ensure that the docker.service file ownership is set to root:root'
  desc  "
    You should verify that the `docker.service` file ownership and group ownership are correctly set to `root`.

    The `docker.service` file contains sensitive parameters that may alter the behavior of the Docker daemon. It should therefore be individually and group owned by the `root` user in order to ensure that it is not modified or corrupted by a less privileged user.
  "
  desc  'rationale', "
    You should verify that the `docker.service` file ownership and group ownership are correctly set to `root`.

    The `docker.service` file contains sensitive parameters that may alter the behavior of the Docker daemon. It should therefore be individually and group owned by the `root` user in order to ensure that it is not modified or corrupted by a less privileged user.
  "
  desc  'check', "
    Step 1: Find out the file location:
    ```
    systemctl show -p FragmentPath docker.service
    ```


    Step 2: If the file does not exist, this recommendation is not applicable. If the file exists, execute the command below including the correct file path in order to verify that the file is owned and group owned by `root`.

    For example:
    ```
    stat -c %U:%G /usr/lib/systemd/system/docker.service | grep -v root:root 
    ```
    The command above should not return anything.
  "
  desc  'fix', "
    Step 1: Find out the file location:
    ```
    systemctl show -p FragmentPath docker.service
    ```


    Step 2: If the file does not exist, this recommendation is not applicable. If the file does exist, you should execute the command below, including the correct file path, in order to set the ownership and group ownership for the file to `root`.

    For example,
    ```
    chown root:root /usr/lib/systemd/system/docker.service
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['AC-2 c']
  tag cci:                   ['CCI-002113']
  tag cis_number:            '3.1'
  tag cis_rid:               '3.1'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0301r1_rule'
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
    describe file('/usr/lib/systemd/system/docker.service') do
    it { should exist }
    it { should be_owned_by 'root' }
    its('group') { should eq 'root' }
  end
  end
end
