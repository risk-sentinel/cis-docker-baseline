# encoding: UTF-8

control 'C-1.1.8' do
  title 'Ensure auditing is configured for Docker files and directories - containerd.sock'
  desc  "
    Audit `containerd.sock`, if applicable.

    As well as auditing the normal Linux file system and system calls, you should also audit the Docker daemon. Because this daemon runs with root privileges, it is very important to audit its activities and usage. Its behavior depends on some key files and directories with `containerd.sock` being one such file, and as this holds various parameters for the Docker daemon, it should be audited.
  "
  desc  'rationale', "
    Audit `containerd.sock`, if applicable.

    As well as auditing the normal Linux file system and system calls, you should also audit the Docker daemon. Because this daemon runs with root privileges, it is very important to audit its activities and usage. Its behavior depends on some key files and directories with `containerd.sock` being one such file, and as this holds various parameters for the Docker daemon, it should be audited.
  "
  desc  'check', "
    Step 1: Find out the file location:
    ```
    grep 'containerd.sock' /etc/containerd/config.toml
    ```
    or by checking the Docker `--containerd` option.

    Step 2: If the file does not exist, this recommendation is not applicable. If the file exists, you should verify that there is an audit rule corresponding to the file:

    For example, you could execute the command below:
    ```
    auditctl -l | grep containerd.sock
    ```
    This should display a rule for `containerd.sock`.
  "
  desc  'fix', "
    If the file exists, you should add a rule for it.

    For example:

    Add the line below to the `/etc/audit/rules.d/audit.rules` file:
    ```
    -w /run/containerd/containerd.sock -k docker 
    ```
    Then restart the audit daemon. 

    For example:
    ```
    systemctl restart auditd
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AU-3 a', 'SC-12 (3)']
  tag cci:                   ['CCI-000130', 'CCI-002447']
  tag cis_number:            '1.1.8'
  tag cis_rid:               '1.1.8'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-010108r1_rule'
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
    describe auditd do
    its('lines') { should include(match(%r{-w\s+/run/containerd/containerd\.sock})) }
  end
  end
end
